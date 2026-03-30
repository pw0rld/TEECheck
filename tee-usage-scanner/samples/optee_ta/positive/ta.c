#include <tee_internal_api.h>

struct header {
    uint32_t magic;
    uint32_t length;
};

static TEE_Result handle_parse_request(uint32_t param_types, TEE_Param params[4]) {
    struct header hdr;
    (void)param_types;

    if (params[0].memref.size < sizeof(struct header)) {
        return TEE_ERROR_BAD_PARAMETERS;
    }

    memcpy(&hdr, params[0].memref.buffer, sizeof(hdr));
    return TEE_SUCCESS;
}

TEE_Result TA_InvokeCommandEntryPoint(void *sess_ctx, uint32_t cmd_id, uint32_t param_types, TEE_Param params[4]) {
    (void)sess_ctx;

    switch (cmd_id) {
    case 1:
        return handle_parse_request(param_types, params);
    default:
        return TEE_ERROR_NOT_SUPPORTED;
    }
}
