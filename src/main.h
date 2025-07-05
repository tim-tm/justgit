#ifndef MAIN_H
#define MAIN_H

#define _GNU_SOURCE
#include <string.h>

// See
//   https://www.gnu.org/software/libmicrohttpd/manual/libmicrohttpd.html
// for reference
#include <microhttpd.h>

#define USAGE_STR "Usage: %s [-p PORT]\n"
#define MAX_ENDPOINT_INFO_LEN 16
#define MAX_POST_SIZE 512
#define MAX_PAGE_SIZE 65536

typedef struct s_arguments {
    unsigned short port;
} arguments;

typedef struct s_endpoint_data {
    struct MHD_Connection *connection;
    const char *method;
    const char *url;
    struct MHD_PostProcessor *postprocessor;
} endpoint_data;

typedef enum MHD_Result (*endpoint_func_run)(endpoint_data *data);
typedef enum MHD_Result (*endpoint_func_post)(const char *key,
                                              const char *filename,
                                              const char *content_type,
                                              const char *transfer_encoding,
                                              const char *data);

typedef struct s_endpoint {
    const char *url;
    const char *method;
    endpoint_func_run run;
    endpoint_func_post iterate_post;
} endpoint;

// defined in utils.c
enum MHD_Result send_page(struct MHD_Connection *connection,
                          unsigned int status_code, const char *message,
                          const char *content_type);
enum MHD_Result send_page_plain(struct MHD_Connection *connection,
                                unsigned int status_code, const char *message);

// endpoint handling functions
// defined in endpoints.c
enum MHD_Result endpoint_root_run(endpoint_data *data);

enum MHD_Result endpoint_repo_new_run(endpoint_data *data);
enum MHD_Result endpoint_repo_new_process(const char *key, const char *filename,
                                          const char *content_type,
                                          const char *transfer_encoding,
                                          const char *data);

#endif // !MAIN_H
