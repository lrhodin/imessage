#ifndef XNU_ENCRYPT_H
#define XNU_ENCRYPT_H

#include <stdint.h>

/// Encrypt a plaintext IOKit property value using the XNU kernel function.
/// Writes exactly 17 bytes to `output`.
/// Extracted from the macOS XNU kernel (open-absinthe).
void sub_ffffff8000ec7320(const uint8_t *data, uint64_t size, uint8_t *output);

#endif
