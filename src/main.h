#ifndef MAIN_H
#define MAIN_H

#define _GNU_SOURCE
#include <string.h>
#include <stdbool.h>

// See
//   https://www.gnu.org/software/libmicrohttpd/manual/libmicrohttpd.html
// for reference
#include <microhttpd.h>
#include <sodium.h>

#define USAGE_STR "Usage: %s [-p PORT]\n"
#define MAX_ENDPOINT_INFO_LEN 16
#define MAX_POST_SIZE 512
#define MAX_PAGE_SIZE 65536
#define MAX_POST_KEY_SIZE 64
#define MAX_POST_DATA_SIZE 448
#define USER_FILE_NAME "justgit-users.bin"
#define REPO_FILE_NAME "justgit-repos.bin"

typedef struct s_arguments {
    unsigned short port;
} arguments;

typedef struct s_basic_auth {
    char *username;
    char *password;
} basic_auth;

typedef struct s_endpoint_data {
    struct MHD_Connection *connection;
    const char *method;
    const char *url;

    struct MHD_PostProcessor *postprocessor;
    bool post_failed;
    const char *post_message;

    basic_auth auth;
} endpoint_data;

typedef enum MHD_Result (*endpoint_func_run)(endpoint_data *data);
typedef enum MHD_Result (*endpoint_func_post)(
    endpoint_data *up_data, const char *key, const char *filename,
    const char *content_type, const char *transfer_encoding, const char *data);
typedef enum MHD_Result (*endpoint_func_auth)(endpoint_data *data);

typedef struct s_endpoint {
    const char *url;
    const char *method;
    endpoint_func_run run;
    endpoint_func_post iterate_post;
    endpoint_func_auth authenticate;
} endpoint;

typedef struct s_user {
    char username[MAX_POST_KEY_SIZE];
    char password_hash[crypto_pwhash_STRBYTES];
} user;

typedef struct s_repo {
    size_t uid;
    char name[MAX_POST_KEY_SIZE];
} repo;

typedef struct s_result {
    bool failed;
    enum MHD_Result status;
} result;

// defined in utils.c
enum MHD_Result send_page(struct MHD_Connection *connection,
                          unsigned int status_code, const char *message,
                          const char *content_type);
enum MHD_Result send_page_plain(struct MHD_Connection *connection,
                                unsigned int status_code, const char *message);

// endpoint handling functions
// defined in endpoints.c
enum MHD_Result endpoint_generic_auth(endpoint_data *data);

enum MHD_Result endpoint_root_run(endpoint_data *data);

enum MHD_Result endpoint_user_new_run(endpoint_data *data);
enum MHD_Result endpoint_user_new_process(endpoint_data *ep_data,
                                          const char *key, const char *filename,
                                          const char *content_type,
                                          const char *transfer_encoding,
                                          const char *data);

enum MHD_Result endpoint_repo_new_run(endpoint_data *data);
enum MHD_Result endpoint_repo_new_process(endpoint_data *ep_data,
                                          const char *key, const char *filename,
                                          const char *content_type,
                                          const char *transfer_encoding,
                                          const char *data);

#endif // !MAIN_H
