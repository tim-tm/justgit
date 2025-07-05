#include "main.h"

#define PATH_MAX 4096
#define NOB_IMPLEMENTATION
#include "../nob.h"

#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static const endpoint endpoints[] = {
    {.url = "/",
     .method = "GET",
     .run = endpoint_root_run,
     .iterate_post = NULL},
    {.url = "/user/new",
     .method = "POST",
     .run = endpoint_user_new_run,
     .iterate_post = endpoint_user_new_process}};
static const size_t endpoints_len = sizeof(endpoints) / sizeof(endpoint);

enum MHD_Result iterate_post(void *cls, enum MHD_ValueKind kind,
                             const char *key, const char *filename,
                             const char *content_type,
                             const char *transfer_encoding, const char *data,
                             uint64_t off, size_t size) {
    (void)(kind);
    (void)(off);
    (void)(size);

    endpoint_data *ep_data = cls;
    for (size_t i = 0; i < endpoints_len; i++) {
        // Method check not required, we already know that its POST
        if (strncmp(endpoints[i].url, ep_data->url, MAX_ENDPOINT_INFO_LEN) ==
                0 &&
            endpoints[i].iterate_post != NULL) {
            return endpoints[i].iterate_post(
                ep_data, key, filename, content_type, transfer_encoding, data);
        }
    }

    // just skip if there are no matching endpoints
    return MHD_YES;
}

enum MHD_Result handle_connection(void *cls, struct MHD_Connection *connection,
                                  const char *url, const char *method,
                                  const char *version, const char *upload_data,
                                  size_t *upload_data_size, void **con_cls) {
    (void)(cls);

    if (*con_cls == NULL) {
        endpoint_data *data = malloc(sizeof(endpoint_data));
        if (data == NULL) {
            nob_log(NOB_ERROR, "Failed to allocate memory for connection! This "
                               "should never happen.");
            return send_page_plain(connection, MHD_HTTP_INTERNAL_SERVER_ERROR,
                                   "Running out of memory");
        }
        data->connection = connection;
        data->method = method;
        data->url = url;

        if (strncmp(method, "POST", MAX_ENDPOINT_INFO_LEN) == 0) {
            data->postprocessor = MHD_create_post_processor(
                connection, MAX_POST_SIZE, iterate_post, (void *)data);
            if (data->postprocessor == NULL) {
                nob_log(NOB_ERROR,
                        "Failed to create POST-request processor. Likely due "
                        "to an unsupported encoding or empty data.");
                free(data);
                return send_page_plain(
                    connection, MHD_HTTP_INTERNAL_SERVER_ERROR,
                    "Empty POST data or unsupported encoding");
            }
        }
        *con_cls = (void *)data;
        return MHD_YES;
    }

    endpoint_data *data = (endpoint_data *)*con_cls;
    if (strncmp(method, "POST", MAX_ENDPOINT_INFO_LEN) == 0 &&
        *upload_data_size != 0) {
        MHD_post_process(data->postprocessor, upload_data, *upload_data_size);
        *upload_data_size = 0;
        return MHD_YES;
    }

    nob_log(NOB_INFO, "%s, %s, %s", version, method, url);
    for (size_t i = 0; i < endpoints_len; i++) {
        if (strncmp(endpoints[i].url, url, MAX_ENDPOINT_INFO_LEN) == 0 &&
            strncmp(endpoints[i].method, method, MAX_ENDPOINT_INFO_LEN) == 0) {
            return endpoints[i].run(data);
        }
    }

    return send_page_plain(connection, MHD_HTTP_NOT_FOUND, "Not found");
}

void request_completed(void *cls, struct MHD_Connection *connection,
                       void **con_cls, enum MHD_RequestTerminationCode toe) {
    (void)(cls);
    (void)(connection);
    (void)(toe);

    endpoint_data *data = *con_cls;
    if (data == NULL)
        return;

    if (data->postprocessor)
        MHD_destroy_post_processor(data->postprocessor);

    free(data);
    *con_cls = NULL;
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
                         &handle_connection, NULL, MHD_OPTION_NOTIFY_COMPLETED,
                         request_completed, NULL, MHD_OPTION_END);
    if (NULL == daemon) {
        nob_log(NOB_ERROR,
                "Could not create server. You need elevated privilages "
                "to run on any port below 1024.");
        return 1;
    }
    nob_log(NOB_INFO, "Server up, hit <Enter> to exit.");

    getchar();

    nob_log(NOB_INFO, "Exiting...");
    MHD_stop_daemon(daemon);
    return 0;
}
