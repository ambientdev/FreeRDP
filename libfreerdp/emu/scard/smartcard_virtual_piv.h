/**
 * FreeRDP: PIV smart card virtual implementation
 *
 * Implements a NIST SP 800-73-4 PIV applet that the ambient-dll credential
 * provider (CAmbientCredential.cpp) can talk to over the RDP smart card
 * virtual channel.  The interface is identical to the GIDS shim so that
 * smartcard_emulate.c can swap them with a single #include change.
 *
 * Licensed under the Apache License, Version 2.0 (the "License").
 */

#ifndef SMARTCARD_VIRTUAL_PIV_H
#define SMARTCARD_VIRTUAL_PIV_H

#include <winpr/winpr.h>
#include <winpr/wtypes.h>

/* Opaque PIV card context */
typedef struct piv_context pivContext;

/* Allocate a new (uninitialised) PIV context */
pivContext* piv_new(void);

/**
 * Initialise the PIV context.
 *   cert_pem  – PEM-encoded X.509 certificate for the PIV Authentication slot
 *   key_pem   – PEM-encoded RSA private key matching the certificate
 *   pin       – PIN string that protects the private key
 * Returns TRUE on success, FALSE on any error.
 */
BOOL piv_init(pivContext* ctx, const char* cert_pem, const char* key_pem, const char* pin);

/**
 * Process one APDU (or a fragment when command chaining is active).
 *   data         – raw APDU bytes from the RDP SCARD_IOCTL_TRANSMIT
 *   dataSize     – byte count of data
 *   response     – *response is set to a malloc'd buffer the caller must free
 *   responseSize – byte count placed in *response
 * Returns TRUE on success, FALSE on fatal error.
 */
BOOL piv_process_apdu(pivContext* ctx, const BYTE* data, DWORD dataSize,
                      BYTE** response, DWORD* responseSize);

/* Free a previously created PIV context */
void piv_free(pivContext* ctx);

#endif /* SMARTCARD_VIRTUAL_PIV_H */
