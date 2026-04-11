/**
 * validation_data.h — C FFI interface for generating Apple APNs validation data
 *
 * Link with: -framework Foundation -fobjc-arc
 */

#ifndef VALIDATION_DATA_H
#define VALIDATION_DATA_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Generate APNs validation data for IDS registration.
 *
 * This function handles the entire NAC protocol:
 *   1. Fetches the validation certificate from Apple
 *   2. Initializes a NAC context (NACInit)
 *   3. Sends session info request to Apple (HTTP POST)
 *   4. Performs key establishment (NACKeyEstablishment)
 *   5. Signs and produces validation data (NACSign)
 *
 * The hardware identifiers are read automatically from IOKit.
 *
 * @param out_buf      On success, receives a malloc'd buffer with validation data.
 *                     Caller must free() this buffer.
 * @param out_len      On success, receives the length of the validation data.
 * @param out_err_buf  On failure, receives a malloc'd error message string.
 *                     Caller must free() this buffer. May be NULL.
 * @return 0 on success, non-zero error code on failure.
 *
 * Error codes:
 *   1  = Failed to load AppleAccount.framework
 *   2  = Failed to fetch validation certificate
 *   3  = Invalid certificate plist format
 *   4  = AAAbsintheContext class not found
 *   5  = NACInit failed
 *   6  = HTTP request to initializeValidation failed
 *   7  = Invalid response plist
 *   8  = Server returned non-zero status
 *   9  = No session-info in response
 *  10  = NACKeyEstablishment failed
 *  11  = NACSign failed
 */
int nac_generate_validation_data(uint8_t **out_buf, size_t *out_len, char **out_err_buf);

/* ------------------------------------------------------------------------- */
/* 3-step NAC API.                                                           */
/*                                                                           */
/* Exposes NACInit / NACKeyEstablishment / NACSign as individual entry       */
/* points so a caller that already owns the id-initialize-validation POST    */
/* (e.g. rustpush's `MacOSConfig::generate_validation_data`) can drive each  */
/* step of the AAAbsintheContext protocol directly. This is how              */
/* open-absinthe's `ValidationCtx` Native mode delegates macOS Local NAC     */
/* without requiring any modifications to upstream rustpush.                 */
/* ------------------------------------------------------------------------- */

/**
 * Step 1: NACInit.
 *
 * Loads AppleAccount.framework, creates an AAAbsintheContext, discovers the
 * NAC selectors, and calls NACInit(cert) to produce session-info request
 * bytes that the caller should POST to id-initialize-validation.
 *
 * On success the opaque handle must be released with nac_ctx_free.
 */
int nac_ctx_init(const uint8_t *cert_buf,
                 size_t cert_len,
                 void **out_handle,
                 uint8_t **out_request_buf,
                 size_t *out_request_len,
                 char **out_err_buf);

/**
 * Step 2: NACKeyEstablishment.
 *
 * Feeds Apple's session-info response into the context created by
 * nac_ctx_init.
 */
int nac_ctx_key_establishment(void *handle,
                              const uint8_t *session_info_buf,
                              size_t session_info_len,
                              char **out_err_buf);

/**
 * Step 3: NACSign.
 *
 * Produces the final validation data from the established context.
 * Caller must free() out_buf on success.
 */
int nac_ctx_sign(void *handle,
                 uint8_t **out_buf,
                 size_t *out_len,
                 char **out_err_buf);

/**
 * Release the context handle. Safe to call with NULL.
 */
void nac_ctx_free(void *handle);

#ifdef __cplusplus
}
#endif

#endif /* VALIDATION_DATA_H */
