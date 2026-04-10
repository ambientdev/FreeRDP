/**
 * Virtual drive device for Teleport directory sharing.
 *
 * Public header installed alongside the other FreeRDP channel headers.
 * Included by freerdp_wrapper.c to call virtual_drive_new() and
 * virtual_drive_complete_irp().
 */

#ifndef FREERDP_CHANNELS_DRIVE_VIRTUAL_H
#define FREERDP_CHANNELS_DRIVE_VIRTUAL_H

#include <stdint.h>
#include <freerdp/api.h>
#include <freerdp/channels/rdpdr.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Called whenever Windows sends an IRP to the virtual drive.
 *
 * @param userdata       Opaque pointer registered with virtual_drive_new().
 * @param device_id      RDPDR device ID assigned to this virtual drive.
 * @param completion_id  Completion ID – must be echoed back to
 *                       virtual_drive_complete_irp().
 * @param major_function IRP_MJ_* constant (see rdpdr.h enum IRP_MJ).
 * @param minor_function IRP_MN_* constant (non-zero only for
 *                       DIRECTORY_CONTROL).
 * @param file_id        File handle assigned by Windows for this request.
 * @param input          Raw bytes from the IRP input stream, starting just
 *                       after the common DR_DEVICE_IOREQUEST header.
 * @param input_len      Byte count of @p input.
 */
typedef void (*VirtualDriveIrpCallback)(void*          userdata,
                                        uint32_t       device_id,
                                        uint32_t       completion_id,
                                        uint32_t       major_function,
                                        uint32_t       minor_function,
                                        uint32_t       file_id,
                                        const uint8_t* input,
                                        uint32_t       input_len);

/**
 * Register a new virtual drive with the RDPDR device manager.
 *
 * @param devman   DEVMAN pointer obtained from rdpdr_get_devman().
 * @param name     ASCII drive name shown to Windows (≤8 printable chars).
 * @param irp_cb   Callback fired for every incoming IRP.
 * @param userdata Opaque pointer forwarded verbatim to @p irp_cb.
 * @return Assigned RDPDR device ID on success, 0 on failure.
 */
FREERDP_API UINT32 virtual_drive_new(DEVMAN*                 devman,
                                     const char*             name,
                                     VirtualDriveIrpCallback irp_cb,
                                     void*                   userdata);

/**
 * Phase-1 of a two-phase registration: allocate the virtual drive device,
 * assign a device ID, and start the IRP worker thread — but do NOT yet
 * insert the device into devman->devices.
 *
 * Safe to call from any thread at any time (no ListDictionary lock taken).
 * The caller MUST later call virtual_drive_insert() from a context where
 * the devman->devices lock is NOT already held (e.g. the FreeRDP event-loop
 * thread when rdpdr_is_ready() returns TRUE).
 *
 * @return Opaque device pointer (cast to void*) on success, NULL on failure.
 *         The RDPDR device ID is vd->device.id of the returned struct.
 */
FREERDP_API void* virtual_drive_alloc(DEVMAN*                 devman,
                                      const char*             name,
                                      VirtualDriveIrpCallback irp_cb,
                                      void*                   userdata);

/**
 * Phase-2 of a two-phase registration: insert a device previously created
 * by virtual_drive_alloc() into devman->devices.
 *
 * Must be called from a thread that does NOT hold devman->devices lock
 * (i.e. the FreeRDP event-loop thread, outside of device_foreach).
 *
 * @param devman Device manager (same one used in virtual_drive_alloc).
 * @param vd     Pointer returned by virtual_drive_alloc().
 * @return TRUE on success, FALSE on failure (device is freed on failure).
 */
FREERDP_API BOOL virtual_drive_insert(DEVMAN* devman, void* vd);

/**
 * Return the RDPDR device ID pre-assigned inside the handle from
 * virtual_drive_alloc().  Returns 0 if handle is NULL.
 */
FREERDP_API UINT32 virtual_drive_get_id(void* handle);

/**
 * Complete a pending IRP from any thread (typically a Go goroutine).
 *
 * @param devman        DEVMAN pointer obtained from rdpdr_get_devman().
 * @param device_id     RDPDR device ID returned by virtual_drive_new().
 * @param completion_id Completion ID received in the IRP callback.
 * @param ntstatus      NTSTATUS result (0 = STATUS_SUCCESS).
 * @param output        Response payload (may be NULL when output_len is 0).
 * @param output_len    Byte count of @p output.
 */
FREERDP_API void virtual_drive_complete_irp(DEVMAN*        devman,
                                            UINT32         device_id,
                                            UINT32         completion_id,
                                            UINT32         ntstatus,
                                            const uint8_t* output,
                                            UINT32         output_len);

/**
 * Return the DEVMAN pointer for the current RDPDR session.
 * Returns NULL if the rdpdr channel has not connected yet.
 */
FREERDP_API DEVMAN* rdpdr_get_devman(void);

/**
 * Trigger a PAKID_CORE_DEVICELIST_ANNOUNCE for all registered devices.
 * Returns CHANNEL_RC_OK on success, ERROR_NOT_READY if the channel is not
 * in the READY state yet.
 */
FREERDP_API UINT rdpdr_announce_devices(void);

/**
 * Returns TRUE if the RDPDR channel has reached the READY or USER_LOGGEDON
 * state and can accept device-list announce requests.
 */
FREERDP_API BOOL rdpdr_is_ready(void);

/** Human-readable RDPDR FSM state for logging (never NULL). */
FREERDP_API const char* rdpdr_debug_channel_state_name(void);

#ifdef __cplusplus
}
#endif

#endif /* FREERDP_CHANNELS_DRIVE_VIRTUAL_H */
