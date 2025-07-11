#ifndef MAIN_H
#define MAIN_H

#define _GNU_SOURCE
#include <string.h>
#include <stdbool.h>
#include <pwd.h>
#include <unistd.h>

// See
//   https://www.gnu.org/software/libmicrohttpd/manual/libmicrohttpd.html
// for reference
#include <microhttpd.h>
#include <sodium.h>
#include <git2.h>

#define USAGE_STR "Usage: %s [-p PORT]\n"
#define MAX_ENDPOINT_INFO_LEN 16
#define MAX_POST_SIZE 512
#define MAX_PAGE_SIZE 65536
#define MAX_POST_KEY_SIZE 64
#define MAX_POST_DATA_SIZE 448

// TODO: add paths to arguments
#define WORKING_DIR "/srv/git"
#define DATA_FILE_NAME "/srv/git/justgit-data.bin"
#define GIT_USER_NAME "git"

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
    uint64_t uid;
    char name[MAX_POST_KEY_SIZE];
} repo;

typedef struct s_result {
    bool failed;
    enum MHD_Result status;
} result;

typedef struct s_metadata {
    uint64_t users_count;
    uint64_t repos_count;
} metadata;

// defined in utils.c
enum MHD_Result send_page(struct MHD_Connection *connection,
                          unsigned int status_code, const char *message,
                          const char *content_type);
enum MHD_Result send_page_plain(struct MHD_Connection *connection,
                                unsigned int status_code, const char *message);
int chown_dir(const char *path, uid_t owner, gid_t group);

// endpoint handling functions
// defined in endpoints.c
void endpoints_cleanup(void);

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
