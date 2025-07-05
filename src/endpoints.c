#include "mingit.h"

#include <string.h>
#include <git2.h>

enum MHD_Result endpoint_root(endpoint_data *data) {
    const char *page = "{\"status\": \"ok\"}";

    struct MHD_Response *response = MHD_create_response_from_buffer(
        16, (void *)page, MHD_RESPMEM_PERSISTENT);

    int ret;
    if ((ret = MHD_add_response_header(response, "Content-Type",
                                       "application/json")) == MHD_NO) {
        MHD_destroy_response(response);
        return ret;
    }

    if ((ret = MHD_add_response_header(response, "Access-Control-Allow-Origin",
                                       "*")) == MHD_NO) {
        MHD_destroy_response(response);
        return ret;
    }

    ret = MHD_queue_response(data->connection, MHD_HTTP_OK, response);
    MHD_destroy_response(response);
    return ret;
}

enum MHD_Result endpoint_repo_new(endpoint_data *data) {
    const char *page = "{\"status\": \"repo/new\"}";

    struct MHD_Response *response = MHD_create_response_from_buffer(
        strlen(page), (void *)page, MHD_RESPMEM_PERSISTENT);

    int ret;
    if ((ret = MHD_add_response_header(response, "Content-Type",
                                       "application/json")) == MHD_NO) {
        MHD_destroy_response(response);
        return ret;
    }

    if ((ret = MHD_add_response_header(response, "Access-Control-Allow-Origin",
                                       "*")) == MHD_NO) {
        MHD_destroy_response(response);
        return ret;
    }

    ret = MHD_queue_response(data->connection, MHD_HTTP_OK, response);
    MHD_destroy_response(response);
    return ret;
}
