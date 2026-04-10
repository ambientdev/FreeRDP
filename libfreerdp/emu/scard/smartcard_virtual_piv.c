/**
 * FreeRDP: PIV smart card virtual implementation
 *
 * Ports the Rust PIV applet in
 *   lib/srv/desktop/rdp/rdpclient/src/piv.rs
 * to C so that FreeRDP's smart-card-emulation path (smartcard_emulate.c)
 * can present a NIST SP 800-73-4 PIV card to Windows instead of the
 * default GIDS card.
 *
 * The ambient-dll credential provider (CAmbientCredential.cpp) speaks
 * PIV and looks for a reader whose name contains "Teleport" – both of
 * which this implementation satisfies when combined with the changes to
 * smartcard_emulate.c.
 *
 * Licensed under the Apache License, Version 2.0 (the "License").
 */

#include <freerdp/config.h>

#include <string.h>
#include <stdio.h>
#include <stdlib.h>

#include <winpr/wlog.h>
#include <winpr/crypto.h>

#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/bn.h>

#include <freerdp/channels/log.h>
#include <freerdp/crypto/certificate.h>

#include "../../crypto/certificate.h"
#include "../../crypto/privatekey.h"
#include "smartcard_virtual_piv.h"

#define TAG CHANNELS_TAG("smartcard.piv")

/* ── PIV AID ──────────────────────────────────────────────────────────── */

/* Full 11-byte AID used when matching SELECT commands */
static const BYTE PIV_AID_FULL[] = {
    0xA0, 0x00, 0x00, 0x03, 0x08, 0x00, 0x00, 0x10, 0x00, 0x01, 0x00
};
/* Truncated 5-byte AID returned in the SELECT response */
static const BYTE PIV_AID_SHORT[] = { 0xA0, 0x00, 0x00, 0x03, 0x08 };

/* ── APDU constants ───────────────────────────────────────────────────── */

#define INS_SELECT           0xA4u
#define INS_VERIFY           0x20u
#define INS_GET_DATA         0xCBu
#define INS_GET_RESPONSE     0xC0u
#define INS_GENERAL_AUTH     0x87u

/* CLA chaining bit: set when more command fragments follow */
#define CLA_CHAIN_BIT        0x10u

/* Status words */
#define SW1_SUCCESS          0x90u
#define SW2_SUCCESS          0x00u
#define SW1_MORE_DATA        0x61u  /* SW2 = remaining byte count (0 = >=256) */
#define SW_FILE_NOT_FOUND    0x6A82u
#define SW_INS_NOT_SUPPORTED 0x6D00u
#define SW_WRONG_P1P2        0x6B00u
#define SW_VERIFY_FAILED     0x6300u
#define SW_CONDITION_NOT_SAT 0x6985u  /* PIN not verified */

/* ── TLV tags ─────────────────────────────────────────────────────────── */

#define TAG_PIV_APT          0x61u  /* Application Property Template */
#define TAG_AID              0x4Fu
#define TAG_COEXISTENT_TAA   0x79u
#define TAG_DATA_FIELD       0x53u
#define TAG_FASC_N           0x30u
#define TAG_GUID             0x34u
#define TAG_EXPIRY           0x35u
#define TAG_ISSUER_SIG       0x3Eu
#define TAG_ERROR_DETECT     0xFEu
#define TAG_CERTIFICATE      0x70u
#define TAG_CERTINFO         0x71u
#define TAG_DYN_AUTH_TMPL    0x7Cu
#define TAG_CHALLENGE        0x81u
#define TAG_RESPONSE         0x82u

/* Data object IDs used in GET DATA (inner primitive value of tag 0x5C) */
#define DO_CHUID_HEX         "5FC102"
#define DO_CERT_HEX          "5FC105"

#define PIV_AUTH_KEY_REF     0x9Au
#define PIV_ALG_RSA2048      0x07u

/* Maximum bytes returned per GET RESPONSE chunk (matches piv.rs CHUNK_SIZE) */
#define CHUNK_SIZE           256u

/* ── Context ──────────────────────────────────────────────────────────── */

struct piv_context
{
    rdpCertificate* certificate;
    rdpPrivateKey*  privateKey;
    char*           pin;

    /* Prebuilt CHUID TLV blob (tag 0x53 …) */
    BYTE*  chuid;
    DWORD  chuid_len;

    /* Prebuilt PIV auth cert TLV blob (tag 0x53 …) */
    BYTE*  piv_cert;
    DWORD  piv_cert_len;

    /* Pending GET RESPONSE buffer (chunked reads) */
    BYTE*  pending_resp;
    DWORD  pending_resp_len;
    DWORD  pending_resp_pos;

    /* Pending chained-command accumulation buffer */
    BYTE*  pending_cmd;
    DWORD  pending_cmd_len;
    DWORD  pending_cmd_cap;

    BOOL   piv_selected;
};

/* ── TLV helpers ──────────────────────────────────────────────────────── */

/*
 * Write a BER-TLV length.  Returns number of bytes written (1, 2, or 3).
 * Matches piv.rs len_to_vec: single-byte form for len < 0x7F.
 */
static int tlv_write_len(BYTE* buf, size_t len)
{
    if (len < 0x7Fu)
    {
        buf[0] = (BYTE)len;
        return 1;
    }
    else if (len < 0x100u)
    {
        buf[0] = 0x81u;
        buf[1] = (BYTE)len;
        return 2;
    }
    else
    {
        buf[0] = 0x82u;
        buf[1] = (BYTE)(len >> 8u);
        buf[2] = (BYTE)(len & 0xFFu);
        return 3;
    }
}

/*
 * Returns the total byte size of a TLV with single-byte tag and given value length.
 * (tag 1 byte) + (length 1-3 bytes) + (value len bytes)
 */
static size_t tlv_size(size_t value_len)
{
    size_t len_bytes = (value_len < 0x7Fu) ? 1u : (value_len < 0x100u) ? 2u : 3u;
    return 1u + len_bytes + value_len;
}

/*
 * Append a primitive TLV to buf at offset *pos.
 * buf must have at least tlv_size(value_len) bytes available.
 */
static void tlv_append(BYTE* buf, size_t* pos, BYTE tag, const BYTE* value, size_t value_len)
{
    buf[(*pos)++] = tag;
    *pos += (size_t)tlv_write_len(buf + *pos, value_len);
    if (value && value_len)
    {
        memcpy(buf + *pos, value, value_len);
        *pos += value_len;
    }
}

/*
 * Parse a BER-TLV length from buf[*pos], advance *pos.
 * Returns the decoded length or (DWORD)-1 on parse error.
 */
static DWORD tlv_read_len(const BYTE* buf, DWORD buflen, DWORD* pos)
{
    if (*pos >= buflen)
        return (DWORD)-1;

    BYTE first = buf[(*pos)++];
    if (first < 0x80u)
        return first;

    if (first == 0x81u)
    {
        if (*pos >= buflen)
            return (DWORD)-1;
        return buf[(*pos)++];
    }
    if (first == 0x82u)
    {
        if (*pos + 1 >= buflen)
            return (DWORD)-1;
        DWORD hi = buf[(*pos)++];
        DWORD lo = buf[(*pos)++];
        return (hi << 8u) | lo;
    }
    return (DWORD)-1;
}

/* ── CHUID builder ────────────────────────────────────────────────────── */

/*
 * Builds the CHUID data object (tag 0x53) matching piv.rs build_chuid().
 * A random 16-byte UUID is generated for the GUID field.
 */
static BOOL build_chuid(BYTE** out, DWORD* out_len)
{
    /* FASC-N: fixed 25-byte encoding from piv.rs */
    static const BYTE FASC_N[] = {
        0xd4, 0xe7, 0x39, 0xda, 0x73, 0x9c, 0xed, 0x39, 0xce, 0x73, 0x9d, 0x83,
        0x68, 0x58, 0x21, 0x08, 0x42, 0x10, 0x84, 0x21, 0xc8, 0x42, 0x10, 0xc3, 0xeb
    };
    static const BYTE EXPIRY[] = { '2', '0', '3', '0', '0', '1', '0', '1' };
    BYTE uuid[16] = { 0 };

    if (winpr_RAND(uuid, sizeof(uuid)) != 0)
    {
        WLog_ERR(TAG, "Failed to generate random UUID for CHUID");
        return FALSE;
    }

    /*
     * Inner content size (matches piv.rs, all lengths are short):
     *   30 19 [25]   = 2 + 25 = 27
     *   34 10 [16]   = 2 + 16 = 18
     *   35 08 [8]    = 2 +  8 = 10
     *   3E 00        = 2
     *   FE 00        = 2
     *   Total        = 59 = 0x3B
     */
    const size_t inner = 27u + 18u + 10u + 2u + 2u; /* = 59 */
    const size_t total = 1u + 1u + inner;            /* 53 3B [...] = 61 bytes */

    BYTE* buf = malloc(total);
    if (!buf)
        return FALSE;

    size_t pos = 0;
    buf[pos++] = TAG_DATA_FIELD;   /* 0x53 */
    buf[pos++] = (BYTE)inner;      /* 0x3B */

    buf[pos++] = TAG_FASC_N;       /* 0x30 */
    buf[pos++] = (BYTE)sizeof(FASC_N);
    memcpy(buf + pos, FASC_N, sizeof(FASC_N));
    pos += sizeof(FASC_N);

    buf[pos++] = TAG_GUID;         /* 0x34 */
    buf[pos++] = (BYTE)sizeof(uuid);
    memcpy(buf + pos, uuid, sizeof(uuid));
    pos += sizeof(uuid);

    buf[pos++] = TAG_EXPIRY;       /* 0x35 */
    buf[pos++] = (BYTE)sizeof(EXPIRY);
    memcpy(buf + pos, EXPIRY, sizeof(EXPIRY));
    pos += sizeof(EXPIRY);

    buf[pos++] = TAG_ISSUER_SIG;   /* 0x3E */
    buf[pos++] = 0x00;

    buf[pos++] = TAG_ERROR_DETECT; /* 0xFE */
    buf[pos++] = 0x00;

    *out     = buf;
    *out_len = (DWORD)pos;
    return TRUE;
}

/* ── PIV auth cert builder ────────────────────────────────────────────── */

/*
 * Builds the PIV Authentication Certificate data object (tag 0x53):
 *   53 LL
 *     70 LL [cert_der]
 *     71 01 00
 *     FE 00
 * Matches piv.rs build_piv_auth_cert().
 */
static BOOL build_piv_cert(const BYTE* cert_der, size_t cert_len,
                            BYTE** out, DWORD* out_len)
{
    /* Inner size: tlv_size(cert_len) + 3 (71 01 00) + 2 (FE 00) */
    size_t cert_tlv_sz = tlv_size(cert_len);
    size_t inner = cert_tlv_sz + 3u + 2u;
    size_t outer = tlv_size(inner);
    size_t total = outer;

    BYTE* buf = malloc(total);
    if (!buf)
        return FALSE;

    size_t pos = 0;
    /* Outer 53 TLV */
    buf[pos++] = TAG_DATA_FIELD;   /* 0x53 */
    pos += (size_t)tlv_write_len(buf + pos, inner);

    /* 70 TLV – certificate */
    buf[pos++] = TAG_CERTIFICATE;  /* 0x70 */
    pos += (size_t)tlv_write_len(buf + pos, cert_len);
    memcpy(buf + pos, cert_der, cert_len);
    pos += cert_len;

    /* 71 01 00 – certinfo (uncompressed) */
    buf[pos++] = TAG_CERTINFO;     /* 0x71 */
    buf[pos++] = 0x01;
    buf[pos++] = 0x00;

    /* FE 00 – error detection code */
    buf[pos++] = TAG_ERROR_DETECT; /* 0xFE */
    buf[pos++] = 0x00;

    *out     = buf;
    *out_len = (DWORD)pos;
    return TRUE;
}

/* ── SELECT response (fixed, matches piv.rs handle_select) ───────────── */

/*
 * Hardcoded SELECT response bytes (before the 90 00 status).
 *
 *   61 11
 *     4F 06 00 00 10 00 01 00    (AID response)
 *     79 07                      (COEXISTENT_TAG_ALLOCATION_AUTHORITY)
 *       4F 05 A0 00 00 03 08     (PIV AID truncated)
 */
static const BYTE SELECT_RESPONSE[] = {
    0x61, 0x11,
    0x4F, 0x06, 0x00, 0x00, 0x10, 0x00, 0x01, 0x00,
    0x79, 0x07,
    0x4F, 0x05, 0xA0, 0x00, 0x00, 0x03, 0x08
};

/* ── Response helpers ─────────────────────────────────────────────────── */

/* Build a 2-byte status word response (no data payload) */
static BOOL make_sw_response(BYTE sw1, BYTE sw2, BYTE** resp, DWORD* resp_len)
{
    BYTE* buf = malloc(2u);
    if (!buf)
        return FALSE;
    buf[0] = sw1;
    buf[1] = sw2;
    *resp     = buf;
    *resp_len = 2;
    return TRUE;
}

/* Build a response: data bytes followed by a 2-byte status word */
static BOOL make_data_response(const BYTE* data, DWORD data_len,
                                BYTE sw1, BYTE sw2,
                                BYTE** resp, DWORD* resp_len)
{
    BYTE* buf = malloc((size_t)data_len + 2u);
    if (!buf)
        return FALSE;
    if (data && data_len)
        memcpy(buf, data, data_len);
    buf[data_len]     = sw1;
    buf[data_len + 1] = sw2;
    *resp     = buf;
    *resp_len = data_len + 2u;
    return TRUE;
}

/*
 * Set ctx->pending_resp to buf/len (takes ownership of buf).
 * Frees any previous pending response.
 */
static void set_pending_resp(pivContext* ctx, BYTE* buf, DWORD len)
{
    free(ctx->pending_resp);
    ctx->pending_resp     = buf;
    ctx->pending_resp_len = len;
    ctx->pending_resp_pos = 0;
}

/*
 * Emit the next chunk from the pending response buffer.
 * Matches piv.rs handle_get_response().
 */
static BOOL emit_pending_chunk(pivContext* ctx, BYTE** resp, DWORD* resp_len)
{
    if (!ctx->pending_resp)
        return make_sw_response(0x6A, 0x82, resp, resp_len); /* FILE_NOT_FOUND */

    DWORD avail   = ctx->pending_resp_len - ctx->pending_resp_pos;
    DWORD chunk   = (avail > CHUNK_SIZE) ? CHUNK_SIZE : avail;
    DWORD remain  = avail - chunk;

    BYTE sw1, sw2;
    if (remain == 0)
    {
        sw1 = SW1_SUCCESS;
        sw2 = SW2_SUCCESS;
    }
    else
    {
        sw1 = SW1_MORE_DATA;
        sw2 = (remain < CHUNK_SIZE) ? (BYTE)remain : 0x00u;
    }

    BOOL ok = make_data_response(ctx->pending_resp + ctx->pending_resp_pos,
                                  chunk, sw1, sw2, resp, resp_len);
    if (ok)
    {
        ctx->pending_resp_pos += chunk;
        if (remain == 0)
        {
            free(ctx->pending_resp);
            ctx->pending_resp     = NULL;
            ctx->pending_resp_len = 0;
            ctx->pending_resp_pos = 0;
        }
    }
    return ok;
}

/* ── RSA raw sign ─────────────────────────────────────────────────────── */

/*
 * Compute result = challenge ^ d  mod  n  (raw RSA, no padding).
 * Matches piv.rs sign_auth_challenge() which does the same modpow.
 *
 * Returns a malloc'd buffer of key_size bytes (left-padded with zeros if
 * the BN result is shorter), or NULL on error.
 */
static BYTE* rsa_raw_sign(rdpPrivateKey* key, const BYTE* challenge, DWORD chal_len,
                           DWORD* sig_len)
{
    BYTE*          result   = NULL;
    EVP_PKEY*      pkey     = NULL;
    EVP_PKEY_CTX*  ctx      = NULL;
    size_t         outlen   = 0;

    pkey = freerdp_key_get_evp_pkey(key);
    if (!pkey)
    {
        WLog_ERR(TAG, "rsa_raw_sign: failed to get EVP_PKEY");
        goto done;
    }

    /* EVP_PKEY_decrypt with RSA_NO_PADDING computes m = c^d mod n */
    ctx = EVP_PKEY_CTX_new(pkey, NULL);
    if (!ctx)
    {
        WLog_ERR(TAG, "rsa_raw_sign: EVP_PKEY_CTX_new failed");
        goto done;
    }

    if (EVP_PKEY_decrypt_init(ctx) <= 0)
    {
        WLog_ERR(TAG, "rsa_raw_sign: EVP_PKEY_decrypt_init failed");
        goto done;
    }

    if (EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_NO_PADDING) <= 0)
    {
        WLog_ERR(TAG, "rsa_raw_sign: set_rsa_padding failed");
        goto done;
    }

    /* Determine output size */
    if (EVP_PKEY_decrypt(ctx, NULL, &outlen, challenge, (size_t)chal_len) <= 0)
    {
        WLog_ERR(TAG, "rsa_raw_sign: size query failed");
        goto done;
    }

    result = malloc(outlen);
    if (!result)
        goto done;

    if (EVP_PKEY_decrypt(ctx, result, &outlen, challenge, (size_t)chal_len) <= 0)
    {
        WLog_ERR(TAG, "rsa_raw_sign: decrypt failed");
        free(result);
        result = NULL;
        goto done;
    }

    *sig_len = (DWORD)outlen;

done:
    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_free(pkey);
    return result;
}

/* ── Hex comparison helper ────────────────────────────────────────────── */

/* Convert bytes to uppercase hex string.  out must hold 2*len+1 bytes. */
static void bytes_to_hex(const BYTE* bytes, DWORD len, char* out)
{
    static const char HEX[] = "0123456789ABCDEF";
    for (DWORD i = 0; i < len; i++)
    {
        out[2 * i]     = HEX[(bytes[i] >> 4u) & 0x0Fu];
        out[2 * i + 1] = HEX[bytes[i] & 0x0Fu];
    }
    out[2 * len] = '\0';
}

/* ── APDU handlers ────────────────────────────────────────────────────── */

static BOOL handle_select(pivContext* ctx,
                           BYTE p1, BYTE p2,
                           const BYTE* data, DWORD data_len,
                           BYTE** resp, DWORD* resp_len)
{
    /* P1=04, P2=00 means select by AID (DF name) */
    if (p1 != 0x04u || p2 != 0x00u)
        return make_sw_response(0x6A, 0x82, resp, resp_len);

    /* Check that the provided AID matches PIV (prefix match using first 5 bytes) */
    if (data_len < 5u ||
        memcmp(data, PIV_AID_SHORT, sizeof(PIV_AID_SHORT)) != 0)
        return make_sw_response(0x6A, 0x82, resp, resp_len);

    ctx->piv_selected = TRUE;

    /* Return fixed SELECT response followed by 90 00 */
    return make_data_response(SELECT_RESPONSE, (DWORD)sizeof(SELECT_RESPONSE),
                               SW1_SUCCESS, SW2_SUCCESS, resp, resp_len);
}

static BOOL handle_verify(pivContext* ctx,
                           const BYTE* data, DWORD data_len,
                           BYTE** resp, DWORD* resp_len)
{
    if (!ctx->pin)
        return make_sw_response(0x69, 0x85, resp, resp_len);

    size_t pin_len = strlen(ctx->pin);
    if (data_len == (DWORD)pin_len &&
        memcmp(data, ctx->pin, pin_len) == 0)
    {
        return make_sw_response(SW1_SUCCESS, SW2_SUCCESS, resp, resp_len);
    }

    WLog_WARN(TAG, "PIV VERIFY failed: PIN mismatch");
    return make_sw_response(0x63, 0x00, resp, resp_len);
}

static BOOL handle_get_data(pivContext* ctx,
                             BYTE p1, BYTE p2,
                             const BYTE* data, DWORD data_len,
                             BYTE** resp, DWORD* resp_len)
{
    /* Matches piv.rs: if p1 != 0x3F && p2 != 0xFF => not found */
    if (p1 != 0x3Fu && p2 != 0xFFu)
        return make_sw_response(0x6A, 0x82, resp, resp_len);

    /*
     * Request data should be: 5C 03 5F C1 XX
     * Tag 0x5C = "Tag list", value is the 3-byte data object ID.
     */
    if (data_len < 5u || data[0] != 0x5Cu || data[1] != 0x03u)
        return make_sw_response(0x6A, 0x82, resp, resp_len);

    char id_hex[7];
    bytes_to_hex(data + 2, 3, id_hex);

    if (strcmp(id_hex, DO_CHUID_HEX) == 0)
    {
        /* CHUID fits in one chunk – return directly */
        return make_data_response(ctx->chuid, ctx->chuid_len,
                                   SW1_SUCCESS, SW2_SUCCESS, resp, resp_len);
    }

    if (strcmp(id_hex, DO_CERT_HEX) == 0)
    {
        /* Certificate may be large – set pending and emit first chunk */
        BYTE* copy = malloc(ctx->piv_cert_len);
        if (!copy)
            return FALSE;
        memcpy(copy, ctx->piv_cert, ctx->piv_cert_len);
        set_pending_resp(ctx, copy, ctx->piv_cert_len);
        return emit_pending_chunk(ctx, resp, resp_len);
    }

    return make_sw_response(0x6A, 0x82, resp, resp_len);
}

static BOOL handle_get_response(pivContext* ctx, BYTE** resp, DWORD* resp_len)
{
    return emit_pending_chunk(ctx, resp, resp_len);
}

static BOOL handle_general_authenticate(pivContext* ctx,
                                         BYTE p1, BYTE p2,
                                         const BYTE* data, DWORD data_len,
                                         BYTE** resp, DWORD* resp_len)
{
    /* P1=0x07 means RSA-2048 */
    if (p1 != PIV_ALG_RSA2048)
    {
        WLog_ERR(TAG, "PIV GENERAL AUTHENTICATE: unsupported algorithm P1=0x%02X", p1);
        return make_sw_response(0x6B, 0x00, resp, resp_len);
    }
    /* P2=0x9A means PIV Authentication Key */
    if (p2 != PIV_AUTH_KEY_REF)
    {
        WLog_ERR(TAG, "PIV GENERAL AUTHENTICATE: unsupported key ref P2=0x%02X", p2);
        return make_sw_response(0x6B, 0x00, resp, resp_len);
    }

    /*
     * Parse: 7C LL
     *          81 LL [challenge]
     */
    if (data_len < 4u || data[0] != TAG_DYN_AUTH_TMPL)
    {
        WLog_ERR(TAG, "PIV GENERAL AUTHENTICATE: bad outer TLV");
        return make_sw_response(0x6A, 0x80, resp, resp_len);
    }

    DWORD pos = 1;
    DWORD outer_len = tlv_read_len(data, data_len, &pos);
    if (outer_len == (DWORD)-1 || pos + outer_len > data_len)
    {
        WLog_ERR(TAG, "PIV GENERAL AUTHENTICATE: truncated outer TLV");
        return make_sw_response(0x6A, 0x80, resp, resp_len);
    }

    /* Find TAG_CHALLENGE (0x81) inside the outer TLV */
    const BYTE* challenge     = NULL;
    DWORD       challenge_len = 0;
    DWORD       end           = pos + outer_len;

    while (pos < end)
    {
        BYTE tag = data[pos++];
        DWORD vlen = tlv_read_len(data, data_len, &pos);
        if (vlen == (DWORD)-1 || pos + vlen > data_len)
            break;

        if (tag == TAG_CHALLENGE)
        {
            challenge     = data + pos;
            challenge_len = vlen;
            break;
        }
        pos += vlen;
    }

    if (!challenge || challenge_len == 0)
    {
        WLog_ERR(TAG, "PIV GENERAL AUTHENTICATE: no challenge in TLV");
        return make_sw_response(0x6A, 0x80, resp, resp_len);
    }

    /* Sign the challenge: result = challenge^d mod n */
    DWORD sig_len = 0;
    BYTE* sig = rsa_raw_sign(ctx->privateKey, challenge, challenge_len, &sig_len);
    if (!sig)
    {
        WLog_ERR(TAG, "PIV GENERAL AUTHENTICATE: RSA sign failed");
        return make_sw_response(0x69, 0x82, resp, resp_len);
    }

    /*
     * Build response TLV:
     *   7C LL
     *     82 LL [sig_len bytes]
     */
    size_t inner_sz  = tlv_size(sig_len);   /* 82 LL [sig] */
    size_t outer_sz  = tlv_size(inner_sz);  /* 7C LL [...] */
    BYTE*  resp_buf  = malloc(outer_sz);

    if (!resp_buf)
    {
        free(sig);
        return FALSE;
    }

    size_t wpos = 0;
    resp_buf[wpos++] = TAG_DYN_AUTH_TMPL;
    wpos += (size_t)tlv_write_len(resp_buf + wpos, inner_sz);
    tlv_append(resp_buf, &wpos, TAG_RESPONSE, sig, sig_len);
    free(sig);

    /* The response TLV may exceed CHUNK_SIZE – use pending-response path */
    set_pending_resp(ctx, resp_buf, (DWORD)wpos);
    return emit_pending_chunk(ctx, resp, resp_len);
}

/* ── Chained-command buffer helpers ──────────────────────────────────── */

static BOOL chain_append(pivContext* ctx, const BYTE* data, DWORD len)
{
    DWORD need = ctx->pending_cmd_len + len;
    if (need > ctx->pending_cmd_cap)
    {
        DWORD new_cap = (need < 4096u) ? 4096u : need * 2u;
        BYTE* tmp = realloc(ctx->pending_cmd, new_cap);
        if (!tmp)
            return FALSE;
        ctx->pending_cmd     = tmp;
        ctx->pending_cmd_cap = new_cap;
    }
    memcpy(ctx->pending_cmd + ctx->pending_cmd_len, data, len);
    ctx->pending_cmd_len += len;
    return TRUE;
}

static void chain_reset(pivContext* ctx)
{
    ctx->pending_cmd_len = 0;
}

/* ── Public API ───────────────────────────────────────────────────────── */

pivContext* piv_new(void)
{
    pivContext* ctx = calloc(1, sizeof(pivContext));
    return ctx;
}

BOOL piv_init(pivContext* ctx, const char* cert_pem, const char* key_pem, const char* pin)
{
    if (!ctx || !cert_pem || !key_pem || !pin)
    {
        WLog_ERR(TAG, "piv_init: NULL argument");
        return FALSE;
    }

    /* Parse certificate */
    ctx->certificate = freerdp_certificate_new_from_pem(cert_pem);
    if (!ctx->certificate)
    {
        WLog_ERR(TAG, "piv_init: failed to parse certificate PEM");
        return FALSE;
    }

    /* Parse private key */
    ctx->privateKey = freerdp_key_new_from_pem(key_pem);
    if (!ctx->privateKey)
    {
        WLog_ERR(TAG, "piv_init: failed to parse private key PEM");
        return FALSE;
    }

    /* Get DER encoding of the certificate */
    size_t cert_der_len = 0;
    BYTE*  cert_der     = freerdp_certificate_get_der(ctx->certificate, &cert_der_len);
    if (!cert_der || cert_der_len == 0)
    {
        WLog_ERR(TAG, "piv_init: failed to get certificate DER");
        return FALSE;
    }

    /* Copy PIN */
    ctx->pin = _strdup(pin);
    if (!ctx->pin)
    {
        free(cert_der);
        return FALSE;
    }

    /* Build CHUID blob */
    if (!build_chuid(&ctx->chuid, &ctx->chuid_len))
    {
        WLog_ERR(TAG, "piv_init: failed to build CHUID");
        free(cert_der);
        return FALSE;
    }

    /* Build PIV auth cert blob */
    if (!build_piv_cert(cert_der, cert_der_len, &ctx->piv_cert, &ctx->piv_cert_len))
    {
        WLog_ERR(TAG, "piv_init: failed to build PIV cert TLV");
        free(cert_der);
        return FALSE;
    }

    free(cert_der);

    WLog_DBG(TAG, "piv_init: PIV card initialised (cert %zu bytes)", cert_der_len);
    return TRUE;
}

BOOL piv_process_apdu(pivContext* ctx, const BYTE* data, DWORD dataSize,
                      BYTE** response, DWORD* responseSize)
{
    if (!ctx || !data || dataSize < 4u || !response || !responseSize)
        return FALSE;

    BYTE cla = data[0];
    BYTE ins = data[1];
    BYTE p1  = data[2];
    BYTE p2  = data[3];

    /* Parse Lc and command data (short and extended APDU) */
    const BYTE* cmd_data = NULL;
    DWORD       cmd_len  = 0;

    if (dataSize > 4u)
    {
        if (data[4] == 0x00u && dataSize >= 7u)
        {
            /* Extended APDU: 00 Lc_hi Lc_lo data [Le_hi Le_lo] */
            cmd_len  = ((DWORD)data[5] << 8u) | (DWORD)data[6];
            cmd_data = (cmd_len > 0u) ? data + 7u : NULL;
        }
        else
        {
            /* Short APDU: Lc data [Le] */
            cmd_len  = data[4];
            cmd_data = (cmd_len > 0u) ? data + 5u : NULL;
        }
    }

    /* Handle command chaining (CLA bit 4 set = not the last fragment) */
    if (cla & CLA_CHAIN_BIT)
    {
        /* Accumulate this fragment and return 90 00 */
        if (!chain_append(ctx, cmd_data ? cmd_data : (const BYTE*)"", cmd_len))
            return FALSE;
        return make_sw_response(SW1_SUCCESS, SW2_SUCCESS, response, responseSize);
    }

    /* If we have accumulated chain fragments, append this final piece */
    const BYTE* effective_data = cmd_data;
    DWORD       effective_len  = cmd_len;
    BYTE*       assembled      = NULL;

    if (ctx->pending_cmd_len > 0u)
    {
        if (!chain_append(ctx, cmd_data ? cmd_data : (const BYTE*)"", cmd_len))
            return FALSE;

        assembled      = ctx->pending_cmd;
        effective_data = assembled;
        effective_len  = ctx->pending_cmd_len;
        /* Reset length (keep buffer allocated for reuse) */
        ctx->pending_cmd_len = 0;
    }

    BOOL ok = FALSE;

    switch (ins)
    {
        case INS_SELECT:
            ok = handle_select(ctx, p1, p2, effective_data, effective_len,
                               response, responseSize);
            break;

        case INS_VERIFY:
            ok = handle_verify(ctx, effective_data, effective_len,
                               response, responseSize);
            break;

        case INS_GET_DATA:
            if (!ctx->piv_selected)
            {
                ok = make_sw_response(0x69, 0x82, response, responseSize);
                break;
            }
            ok = handle_get_data(ctx, p1, p2, effective_data, effective_len,
                                  response, responseSize);
            break;

        case INS_GET_RESPONSE:
            ok = handle_get_response(ctx, response, responseSize);
            break;

        case INS_GENERAL_AUTH:
            if (!ctx->piv_selected)
            {
                ok = make_sw_response(0x69, 0x82, response, responseSize);
                break;
            }
            ok = handle_general_authenticate(ctx, p1, p2, effective_data, effective_len,
                                              response, responseSize);
            break;

        default:
            WLog_WARN(TAG, "PIV: unimplemented INS 0x%02X", ins);
            ok = make_sw_response(0x6D, 0x00, response, responseSize);
            break;
    }

    return ok;
}

void piv_free(pivContext* ctx)
{
    if (!ctx)
        return;

    freerdp_certificate_free(ctx->certificate);
    freerdp_key_free(ctx->privateKey);
    free(ctx->pin);
    free(ctx->chuid);
    free(ctx->piv_cert);
    free(ctx->pending_resp);
    free(ctx->pending_cmd);
    free(ctx);
}
