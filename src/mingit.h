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

typedef enum MHD_Result (*endpoint_function)(struct MHD_Connection *connection);

typedef struct s_endpoint {
    const char *url;
    endpoint_function run;
} endpoint;

enum MHD_Result endpoint_root(struct MHD_Connection *connection);

static const size_t endpoints_len = 1;
static const endpoint endpoints[] = {{.url = "/", endpoint_root}};

#endif // !MINGIT_H
