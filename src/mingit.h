#ifndef MINGIT_H
#define MINGIT_H

// See
//   https://www.gnu.org/software/libmicrohttpd/manual/libmicrohttpd.html
// for reference
#include <microhttpd.h>

#define USAGE_STR "Usage: %s [-p PORT]\n"
#define MAX_ENDPOINT_LEN 16

typedef struct s_arguments {
    unsigned short port;
} arguments;

typedef struct s_endpoint_data {
    struct MHD_Connection *connection;
    const char *method;
} endpoint_data;

typedef enum MHD_Result (*endpoint_function)(endpoint_data *data);

typedef struct s_endpoint {
    const char *url;
    endpoint_function run;
} endpoint;

enum MHD_Result endpoint_root(endpoint_data *data);
enum MHD_Result endpoint_repo_new(endpoint_data *data);

#endif // !MINGIT_H
