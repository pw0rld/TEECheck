#include <tee_internal_api.h>

struct header {
    uint32_t magic;
    uint32_t length;
};

TEE_Result TA_InvokeCommandEntryPoint(void *sess_ctx, uint32_t cmd_id, uint32_t param_types, TEE_Param params[4]) {
    struct header hdr;
    (void)sess_ctx;
    (void)cmd_id;

    if (param_types != TEE_PARAM_TYPES(
            TEE_PARAM_TYPE_MEMREF_INPUT,
            TEE_PARAM_TYPE_NONE,
            TEE_PARAM_TYPE_NONE,
            TEE_PARAM_TYPE_NONE)) {
        return TEE_ERROR_BAD_PARAMETERS;
    }

    if (params[0].memref.size < sizeof(struct header)) {
        return TEE_ERROR_BAD_PARAMETERS;
    }

    memcpy(&hdr, params[0].memref.buffer, sizeof(hdr));
    return TEE_SUCCESS;
}
