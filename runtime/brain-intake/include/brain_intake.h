#ifndef BRAIN_INTAKE_H
#define BRAIN_INTAKE_H
#include <stddef.h>
#include <stdint.h>
#ifdef __cplusplus
extern "C" {
#endif

typedef struct brain_intake_response {
    uint8_t *data;
    size_t length;
} brain_intake_response;

enum brain_intake_status {
    BRAIN_INTAKE_OK = 0,
    BRAIN_INTAKE_INVALID_ARGUMENT = 1,
    BRAIN_INTAKE_UNAVAILABLE = 2,
    BRAIN_INTAKE_NO_MEMORY = 3,
    BRAIN_INTAKE_ENGINE_MISMATCH = 4,
    BRAIN_INTAKE_INITIALIZATION_FAILED = 5
};

/* Trusted host arguments must never be selected by request/model data.
 * engine_scripts is one trusted installed engine directory per process.
 * The caller must not hold a Python GIL; Python bindings use ctypes.CDLL.
 * Input is bounded JSON. On success, free the response with response_free_v1.
 * Reading its length/data never repeats the operation. No hard cancellation,
 * crash isolation, Python finalization or library-unload guarantee is provided.
 */
uint32_t brain_intake_abi_version(void);
int brain_intake_plan_v1(const char *engine_scripts, const char *root,
                        const char *config, const char *actor,
                        const uint8_t *request, size_t request_length,
                        brain_intake_response **response);
int brain_intake_operate_v1(const char *engine_scripts, const char *root,
                           const char *config, const char *actor,
                           const uint8_t *request, size_t request_length,
                           brain_intake_response **response);
void brain_intake_response_free_v1(brain_intake_response *response);

#ifdef __cplusplus
}
#endif
#endif
