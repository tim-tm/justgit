#include "main.h"

// NOB_IMPLEMENTATION is already defined by main.c
#include "../nob.h"
#include <git2.h>

static user *users = NULL;
static size_t users_cap = 256;
static size_t users_count = 0;

static user current_user = {0};

enum MHD_Result endpoint_root_run(endpoint_data *data) {
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

enum MHD_Result endpoint_user_new_run(endpoint_data *data) {
    if (data->post_failed) {
        return send_page_plain(data->connection, MHD_HTTP_INTERNAL_SERVER_ERROR,
                               "Failed to process POST-data");
    }

    nob_log(NOB_INFO, "Adding user: %s", current_user.username);
    if (users == NULL) {
        FILE *fp = fopen("justgit-users.bin", "rb");
        if (fp == NULL && errno != ENOENT) {
            nob_log(NOB_ERROR,
                    "Failed to add user: Could not open file for reading (%s)",
                    strerror(errno));
            // do not give too much information to the client,
            // preferably don't give them the strerror
            return send_page_plain(data->connection,
                                   MHD_HTTP_INTERNAL_SERVER_ERROR,
                                   "Could not load users");
        }

        if (fp != NULL) {
            fseek(fp, 0, SEEK_END);
            long file_size = ftell(fp);
            users_count = (file_size / sizeof(user));
            // setting users_count = users_cap would mean,
            // that the array will be expanded on the next
            // useradd
            // allocating a bigger array right now will mean
            // less allocations
            users_cap += users_count;
            nob_log(NOB_INFO, "Reading %zu users from file", users_count);
        }

        // users will also be allocated if the error is
        // "No such file or directory"
        users = calloc(users_cap, sizeof(user));
        if (users == NULL) {
            nob_log(NOB_ERROR, "Failed to add user: No more memory for user!");
            return send_page_plain(data->connection,
                                   MHD_HTTP_INTERNAL_SERVER_ERROR,
                                   "No more memory");
        }

        if (fp != NULL) {
            size_t items = fread(users, sizeof(user), users_count, fp);
            if (items != users_count) {
                nob_log(
                    NOB_ERROR,
                    "Failed to add user: Could load all users from disk. User "
                    "count: %zu, read users: %zu",
                    users_count, items);
                return send_page_plain(data->connection,
                                       MHD_HTTP_INTERNAL_SERVER_ERROR,
                                       "Could load users");
            }
            fclose(fp);
        }
    } else if (users_count >= users_cap) {
        users_cap *= 2;
        users = realloc(users, users_cap * sizeof(user));
        if (users == NULL) {
            nob_log(NOB_ERROR, "Failed to add user: No more memory for user!");
            return send_page_plain(data->connection,
                                   MHD_HTTP_INTERNAL_SERVER_ERROR,
                                   "No more memory");
        }
    }

    for (size_t i = 0; i < users_count; i++) {
        if (strncmp(users[i].username, current_user.username,
                    MAX_POST_KEY_SIZE) == 0) {
            nob_log(NOB_ERROR, "Failed to add user: User already exists!");
            return send_page_plain(data->connection, MHD_HTTP_BAD_REQUEST,
                                   "User already exists");
        }
    }
    users[users_count++] = current_user;

    FILE *fp = fopen("justgit-users.bin", "wb");
    if (fp == NULL) {
        nob_log(NOB_ERROR, "Failed to add user: Could not open file (%s)",
                strerror(errno));
        // do not give too much information to the client,
        // preferably don't give them the strerror
        return send_page_plain(data->connection, MHD_HTTP_INTERNAL_SERVER_ERROR,
                               "Could not save user");
    }

    size_t items = fwrite(users, sizeof(user), users_count, fp);
    if (items != users_count) {
        nob_log(NOB_ERROR,
                "Failed to add user: Could not save all users to disk. User "
                "count: %zu, written users: %zu",
                users_count, items);
        return send_page_plain(data->connection, MHD_HTTP_INTERNAL_SERVER_ERROR,
                               "Could not save user");
    }
    fclose(fp);

    return send_page_plain(data->connection, MHD_HTTP_OK, "success");
}

enum MHD_Result endpoint_user_new_process(endpoint_data *ep_data,
                                          const char *key, const char *filename,
                                          const char *content_type,
                                          const char *transfer_encoding,
                                          const char *data) {
    nob_log(NOB_INFO, "Processing post entry: %s, %s, %s, %s, %s", key,
            filename, content_type, transfer_encoding, data);
    if (strncmp(key, "username", MAX_POST_KEY_SIZE) == 0) {
        nob_log(NOB_INFO, "Copying username: %s", data);
        strncpy(current_user.username, data, MAX_POST_KEY_SIZE);
        // TODO: Move user loading from endpoint_user_new_run()
        //       to this place.
        //       Reason: The server should not waste resources
        //               for users that won't be added anyways.
        return MHD_YES;
    } else if (strncmp(key, "password", MAX_POST_KEY_SIZE) == 0) {
        nob_log(NOB_INFO, "Computing hash for: %s", data);
        size_t data_len = strnlen(data, MAX_POST_DATA_SIZE);
        if (crypto_pwhash_str(current_user.password_hash, data, data_len,
                              crypto_pwhash_OPSLIMIT_SENSITIVE,
                              crypto_pwhash_MEMLIMIT_SENSITIVE) != 0) {
            nob_log(NOB_ERROR,
                    "Out of memory while trying to compute hash for user: %s",
                    current_user.username);
            ep_data->post_failed = true;
            return MHD_NO;
        }
        nob_log(NOB_INFO, "Hash computed: %s", current_user.password_hash);
        return MHD_YES;
    }

    ep_data->post_failed = true;
    return MHD_NO;
}
