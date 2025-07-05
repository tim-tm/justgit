#include "mingit.h"

enum MHD_Result send_page(struct MHD_Connection *connection,
                          unsigned int status_code, const char *message,
                          const char *content_type) {
    if (connection == NULL || message == NULL || content_type == NULL)
        return MHD_NO;

    size_t message_len = strnlen(message, MAX_PAGE_SIZE);
    struct MHD_Response *response = MHD_create_response_from_buffer(
        message_len, (void *)message, MHD_RESPMEM_PERSISTENT);

    int ret;
    if ((ret = MHD_add_response_header(response, "Content-Type",
                                       content_type)) == MHD_NO) {
        MHD_destroy_response(response);
        return ret;
    }

    ret = MHD_queue_response(connection, status_code, response);
    MHD_destroy_response(response);
    return ret;
}

enum MHD_Result send_page_plain(struct MHD_Connection *connection,
                                unsigned int status_code, const char *message) {
    return send_page(connection, status_code, message, "text/plain");
}
