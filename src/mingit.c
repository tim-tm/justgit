#include "mingit.h"

#define PATH_MAX 4096
#define NOB_IMPLEMENTATION
#include "../nob.h"

#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

enum MHD_Result endpoint_root(struct MHD_Connection *connection) {
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

    ret = MHD_queue_response(connection, MHD_HTTP_OK, response);
    MHD_destroy_response(response);
    return ret;
}

enum MHD_Result handle_connection(void *cls, struct MHD_Connection *connection,
                                  const char *url, const char *method,
                                  const char *version, const char *upload_data,
                                  size_t *upload_data_size, void **con_cls) {
    (void)(cls);
    (void)(method);
    (void)(version);
    (void)(upload_data);
    (void)(upload_data_size);
    (void)(con_cls);

    for (size_t i = 0; i < endpoints_len; i++) {
        if (strncmp(endpoints[i].url, url, MAX_ENDPOINT_LEN) == 0) {
            return endpoints[i].run(connection);
        }
    }
    return MHD_NO;
}

int parse_arguments(const char *program_name, int argc, char **argv,
                    arguments *args) {
    const char *command_name = nob_shift(argv, argc);
    if (strncmp(command_name, "-p", 2) == 0) {
        if (argc <= 0) {
            printf(USAGE_STR, program_name);
            return 1;
        }

        const char *port_str = nob_shift(argv, argc);
        long port_long = strtol(port_str, NULL, 10);
        if (port_long == LONG_MIN || port_long == LONG_MAX || port_long < 0 ||
            port_long > USHRT_MAX) {
            nob_log(NOB_ERROR, "Invalid port number: %s", port_str);
            return 1;
        }

        args->port = (unsigned short)port_long;
    } else {
        printf(USAGE_STR, program_name);
        return 1;
    }
    return 0;
}

int main(int argc, char *argv[]) {
    const char *program_name = nob_shift(argv, argc);
    arguments args = {.port = 80};
    if (argc > 0) {
        if (parse_arguments(program_name, argc, argv, &args) != 0)
            return 1;
    }
    nob_log(NOB_INFO, "Using port %d", args.port);

    struct MHD_Daemon *daemon =
        MHD_start_daemon(MHD_USE_INTERNAL_POLLING_THREAD, args.port, NULL, NULL,
                         &handle_connection, NULL, MHD_OPTION_END);
    if (NULL == daemon) {
        nob_log(NOB_ERROR,
                "Could not create server. You need elevated privilages "
                "to run on any port below 1024.");
        return 1;
    }

    getchar();

    MHD_stop_daemon(daemon);
    return 0;
}
