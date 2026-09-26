#ifndef BRAIN_CLASSIFIER_H
#define BRAIN_CLASSIFIER_H
#include <stddef.h>
#include <stdint.h>
#ifdef __cplusplus
extern "C" {
#endif

/* ABI v1, size_t follows the host target. No owned Rust pointer crosses the ABI.
 * See README.md for host authorization, accounting, memory and panic boundaries.
 */
size_t brain_classifier_output_capacity_v1(void);

/* UTF-8 canonical bundle path; 64-byte lowercase SHA256; bounded JSON request.
 * All pointer/length pairs must be valid and output pointers must not overlap
 * any other argument. Allocate output_capacity_v1() bytes before calling.
 * Returns 0=success, 1=invalid ABI arguments, 2=rejected, 3=caught unwind.
 * output_len is zero on invalid arguments; otherwise it counts JSON bytes,
 * without a trailing NUL. No result may be treated as write authority.
 */
int32_t brain_classifier_classify_v1(
    const uint8_t *bundle_path, size_t path_len,
    const uint8_t *expected_sha256, size_t pin_len,
    const uint8_t *request, size_t request_len,
    uint8_t *output, size_t output_capacity, size_t *output_len);

#ifdef __cplusplus
}
#endif
#endif
