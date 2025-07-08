#include "main.h"

// NOB_IMPLEMENTATION is already defined by main.c
#include "../nob.h"

#include <dirent.h>

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

int chown_dir(const char *path, uid_t owner, gid_t group) {
    DIR *dir = opendir(path);
    if (dir == NULL) {
        nob_log(NOB_ERROR, "chown_dir: Cannot open directory %s, reason: %s",
                path, strerror(errno));
        return -1;
    }

    char filename[PATH_MAX];
    struct dirent *dp;
    while ((dp = readdir(dir)) != NULL) {
        if (strcmp(dp->d_name, ".") == 0 || strcmp(dp->d_name, "..") == 0)
            continue;

        memset(filename, 0, PATH_MAX);
        snprintf(filename, PATH_MAX, "%s/%s", path, dp->d_name);

        struct stat stbuf;
        if (stat(filename, &stbuf) != 0) {
            nob_log(NOB_ERROR, "chown_dir: Cannot stat file %s, reason: %s",
                    filename, strerror(errno));
            return -1;
        }

        if (chown(filename, owner, group) != 0) {
            nob_log(NOB_ERROR,
                    "chown_dir: Failed to give user with id '%d' permissions "
                    "to access %s.",
                    owner, filename);
            return -1;
        }

        if ((stbuf.st_mode & S_IFMT) == S_IFDIR &&
            chown_dir(filename, owner, group) != 0) {
            nob_log(NOB_ERROR, "chown_dir: Recursive call failed");
            return -1;
        }
    }

    // finally also chown the top-level directory
    if (chown(path, owner, group) != 0) {
        nob_log(NOB_ERROR,
                "chown_dir: Failed to give user with id '%d' permissions "
                "to access %s.",
                owner, path);
        return -1;
    }
    return 0;
}
