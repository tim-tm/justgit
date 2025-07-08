#include "main.h"

// NOB_IMPLEMENTATION is already defined by main.c
#include "../nob.h"

#include <dirent.h>
#include <pwd.h>
#include <unistd.h>

// TODO: heavy refactoring:
//          - users and repos could be merged into a
//            single binary file, that contains a bit of
//            metadata at the start (e.g. users_count, repos_count)
//          - load_users, load_repos can basically be merged
//            into a single, more abstract function,
//            e.g. load_data(ep_data, data_ptr, offset, count, struct_size)
//          - user hashtable would greatly improve performance

static user *users = NULL;
static size_t users_cap = 256;
static size_t users_count = 0;

static repo *repos = NULL;
static size_t repos_cap = 256;
static size_t repos_count = 0;

static user current_user = {0};
static repo current_repo = {0};

static enum MHD_Result load_users(endpoint_data *ep_data) {
    if (users == NULL) {
        FILE *fp = fopen(USER_FILE_NAME, "rb");
        if (fp == NULL && errno != ENOENT) {
            nob_log(NOB_ERROR,
                    "Failed to add user: Could not open file for reading (%s)",
                    strerror(errno));
            // do not give too much information to the client,
            // preferably don't give them the strerror
            ep_data->post_failed = true;
            ep_data->post_message = "Could not load users";
            return MHD_NO;
        }

        if (fp != NULL) {
            fseek(fp, 0, SEEK_END);
            long file_size = ftell(fp);
            // reset to start of fp
            fseek(fp, 0, SEEK_SET);

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
            ep_data->post_failed = true;
            ep_data->post_message = "No more memory";
            fclose(fp);
            return MHD_NO;
        }

        if (fp != NULL) {
            size_t items = fread(users, sizeof(user), users_count, fp);
            if (items != users_count) {
                nob_log(NOB_ERROR,
                        "Failed to add user: Could not load all users from "
                        "disk. User "
                        "count: %zu, read users: %zu",
                        users_count, items);
                ep_data->post_failed = true;
                ep_data->post_message = "Could not load users";
                fclose(fp);
                return MHD_NO;
            }
            fclose(fp);
        }
    }
    ep_data->post_failed = false;
    return MHD_YES;
}

static enum MHD_Result load_repos(endpoint_data *ep_data) {
    if (repos == NULL) {
        FILE *fp = fopen(REPO_FILE_NAME, "rb");
        if (fp == NULL && errno != ENOENT) {
            nob_log(NOB_ERROR,
                    "Failed to add repo: Could not open file for reading (%s)",
                    strerror(errno));
            // do not give too much information to the client,
            // preferably don't give them the strerror
            ep_data->post_failed = true;
            ep_data->post_message = "Could not load repos";
            return MHD_NO;
        }

        if (fp != NULL) {
            fseek(fp, 0, SEEK_END);
            long file_size = ftell(fp);
            // reset to start of fp
            fseek(fp, 0, SEEK_SET);

            repos_count = (file_size / sizeof(repo));
            // setting repos_count = repos_cap would mean,
            // that the array will be expanded on the next
            // repoadd
            // allocating a bigger array right now will mean
            // less allocations
            repos_cap += repos_count;

            nob_log(NOB_INFO, "Reading %zu repos from file", repos_count);
        }

        // repos will also be allocated if the error is
        // "No such file or directory"
        repos = calloc(repos_cap, sizeof(repo));
        if (repos == NULL) {
            nob_log(NOB_ERROR, "Failed to add repo: No more memory for repo!");
            ep_data->post_failed = true;
            ep_data->post_message = "No more memory";
            fclose(fp);
            return MHD_NO;
        }

        if (fp != NULL) {
            size_t items = fread(repos, sizeof(repo), repos_count, fp);
            if (items != repos_count) {
                nob_log(NOB_ERROR,
                        "Failed to add repo: Could not load all repos from "
                        "disk. User "
                        "count: %zu, read repos: %zu",
                        repos_count, items);
                ep_data->post_failed = true;
                ep_data->post_message = "Could not load repos";
                fclose(fp);
                return MHD_NO;
            }
            fclose(fp);
        }
    }
    ep_data->post_failed = false;
    return MHD_YES;
}

static result authenticate(endpoint_data *data) {
    if (data->auth.username == NULL || data->auth.password == NULL)
        return (result){.failed = true,
                        .status = send_page_plain(data->connection,
                                                  MHD_HTTP_UNAUTHORIZED,
                                                  "unauthorized")};

    nob_log(NOB_INFO, "Authorizing: %s", data->auth.username);
    if (load_users(data) == MHD_NO) {
        nob_log(NOB_INFO, "Could not load users: %s", data->post_message);
        return (result){.failed = true,
                        .status = send_page_plain(
                            data->connection, MHD_HTTP_INTERNAL_SERVER_ERROR,
                            "Could not load users")};
    }

    nob_log(NOB_INFO, "users_count=%zu", users_count);

    size_t uid;
    bool found = false;
    for (uid = 0; uid < users_count; uid++) {
        if (strncmp(users[uid].username, data->auth.username,
                    MAX_POST_KEY_SIZE) == 0) {
            nob_log(NOB_INFO, "Found user: uid=%zu", uid);
            current_user = users[uid];
            found = true;
            break;
        }
    }

    if (!found) {
        nob_log(NOB_ERROR, "Could not find user");
        return (result){.failed = true,
                        .status = send_page_plain(data->connection,
                                                  MHD_HTTP_UNAUTHORIZED,
                                                  "Could not find user")};
    }

    nob_log(NOB_INFO, "Checking password...");
    size_t pass_len = strnlen(data->auth.password, MAX_POST_DATA_SIZE);
    if (crypto_pwhash_str_verify(users[uid].password_hash, data->auth.password,
                                 pass_len) != 0) {
        nob_log(NOB_ERROR, "Invalid password");
        return (result){.failed = true,
                        .status = send_page_plain(data->connection,
                                                  MHD_HTTP_UNAUTHORIZED,
                                                  "Invalid password")};
    }
    nob_log(NOB_INFO, "Check passed");
    return (result){.failed = false, .status = MHD_YES};
}

static int chown_dir(const char *path, uid_t owner, gid_t group) {
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

enum MHD_Result endpoint_generic_auth(endpoint_data *data) {
    result res;
    if ((res = authenticate(data)).failed)
        return res.status;
    return MHD_YES;
}

static result append_array(struct MHD_Connection *connection, void *arr,
                           size_t count, size_t cap) {
    if (count >= cap) {
        cap *= 2;
        arr = realloc(arr, cap * sizeof(user));
        if (arr == NULL) {
            nob_log(NOB_ERROR, "Failed to append array: no more memory");
            return (result){.failed = true,
                            .status = send_page_plain(
                                connection, MHD_HTTP_INTERNAL_SERVER_ERROR,
                                "No more memory")};
        }
    }
    return (result){.failed = false, .status = MHD_YES};
}

enum MHD_Result endpoint_root_run(endpoint_data *data) {
    return send_page_plain(data->connection, MHD_HTTP_OK, "success");
}

enum MHD_Result endpoint_user_new_run(endpoint_data *data) {
    if (data->post_failed || current_user.username[0] == '\0' ||
        current_user.password_hash[0] == '\0') {
        return send_page_plain(data->connection, MHD_HTTP_INTERNAL_SERVER_ERROR,
                               data->post_message == NULL ? "Invalid POST-data"
                                                          : data->post_message);
    }

    nob_log(NOB_INFO, "Adding user: %s", current_user.username);
    result res;
    if ((res = append_array(data->connection, users, users_count, users_cap))
            .failed)
        return res.status;
    users[users_count++] = current_user;

    FILE *fp = fopen(USER_FILE_NAME, "wb");
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
        fclose(fp);
        return send_page_plain(data->connection, MHD_HTTP_INTERNAL_SERVER_ERROR,
                               "Could not save user");
    }
    fclose(fp);
    nob_log(NOB_INFO, "User added successfully");

    return send_page_plain(data->connection, MHD_HTTP_OK, "success");
}

enum MHD_Result endpoint_user_new_process(endpoint_data *ep_data,
                                          const char *key, const char *filename,
                                          const char *content_type,
                                          const char *transfer_encoding,
                                          const char *data) {
    (void)(filename);
    (void)(content_type);
    (void)(transfer_encoding);

    if (strncmp(key, "username", MAX_POST_KEY_SIZE) == 0) {
        if (load_users(ep_data) == MHD_NO)
            return MHD_NO;

        for (size_t i = 0; i < users_count; i++) {
            if (strncmp(users[i].username, data, MAX_POST_KEY_SIZE) == 0) {
                nob_log(NOB_ERROR, "Failed to add user: User already exists!");
                ep_data->post_failed = true;
                ep_data->post_message = "User already exists";
                return MHD_NO;
            }
        }

        nob_log(NOB_INFO, "Copying username: %s", data);
        strncpy(current_user.username, data, MAX_POST_KEY_SIZE);
        return MHD_YES;
    } else if (strncmp(key, "password", MAX_POST_KEY_SIZE) == 0) {
        nob_log(NOB_INFO, "Computing hash for password...");
        size_t data_len = strnlen(data, MAX_POST_DATA_SIZE);
        if (crypto_pwhash_str(current_user.password_hash, data, data_len,
                              crypto_pwhash_OPSLIMIT_INTERACTIVE,
                              crypto_pwhash_MEMLIMIT_INTERACTIVE) != 0) {
            nob_log(NOB_ERROR,
                    "Out of memory while trying to compute hash for user: %s",
                    current_user.username);
            ep_data->post_failed = true;
            ep_data->post_message = "No more memory";
            return MHD_NO;
        }
        return MHD_YES;
    }

    ep_data->post_failed = true;
    ep_data->post_message = "Unknown option";
    return MHD_NO;
}

enum MHD_Result endpoint_repo_new_run(endpoint_data *data) {
    if (data->post_failed || current_repo.name[0] == '\0') {
        return send_page_plain(data->connection, MHD_HTTP_INTERNAL_SERVER_ERROR,
                               data->post_message == NULL ? "Invalid POST-data"
                                                          : data->post_message);
    }

    nob_log(NOB_INFO, "Adding repo: %s", current_repo.name);

    // get the "git" user before creating the repository so it
    // is not needed to remove the directory if getting the user fails
    const char *git_user_name = "git";
    nob_log(NOB_INFO, "Getting information for user '%s'", git_user_name);
    struct passwd *git_user_passwd = getpwnam(git_user_name);
    if (git_user_passwd == NULL) {
        nob_log(NOB_ERROR, "Failed to get information for user '%s'.",
                git_user_name);
        return send_page_plain(data->connection, MHD_HTTP_INTERNAL_SERVER_ERROR,
                               "Could not create git repository");
    }

    git_repository *git_repo = NULL;
    const char *reponame = nob_temp_sprintf(
        "%s/%s/%s.git", WORKING_DIR, current_user.username, current_repo.name);
    int err = git_repository_init(&git_repo, reponame, true);
    if (err < 0) {
        const git_error *e = git_error_last();
        nob_log(NOB_ERROR, "Failed to create git-repo at (%s) %d/%d: %s",
                reponame, err, e->klass, e->message);
        return send_page_plain(data->connection, MHD_HTTP_INTERNAL_SERVER_ERROR,
                               "Could not create git repository");
    }
    git_repository_free(git_repo);

    if (chown_dir(reponame, git_user_passwd->pw_uid, git_user_passwd->pw_gid) !=
        0) {
        nob_log(NOB_ERROR, "Failed to give user '%s' permissions to access %s.",
                git_user_name, reponame);
        return send_page_plain(data->connection, MHD_HTTP_INTERNAL_SERVER_ERROR,
                               "Could not create git repository");
    }

    result res;
    if ((res = append_array(data->connection, repos, repos_count, repos_cap))
            .failed)
        return res.status;
    repos[repos_count++] = current_repo;

    FILE *fp = fopen(REPO_FILE_NAME, "wb");
    if (fp == NULL) {
        nob_log(NOB_ERROR, "Failed to add repo: Could not open file (%s)",
                strerror(errno));
        // do not give too much information to the client,
        // preferably don't give them the strerror
        return send_page_plain(data->connection, MHD_HTTP_INTERNAL_SERVER_ERROR,
                               "Could not save repo");
    }

    size_t items = fwrite(repos, sizeof(repo), repos_count, fp);
    if (items != repos_count) {
        nob_log(NOB_ERROR,
                "Failed to add repo: Could not save all repos to disk. Repo "
                "count: %zu, written repos: %zu",
                repos_count, items);
        fclose(fp);
        return send_page_plain(data->connection, MHD_HTTP_INTERNAL_SERVER_ERROR,
                               "Could not save repo");
    }
    fclose(fp);
    nob_log(NOB_INFO, "Repo added successfully");

    return send_page_plain(data->connection, MHD_HTTP_OK, "success");
}

enum MHD_Result endpoint_repo_new_process(endpoint_data *ep_data,
                                          const char *key, const char *filename,
                                          const char *content_type,
                                          const char *transfer_encoding,
                                          const char *data) {
    nob_log(NOB_INFO, "Processing post entry: %s, %s, %s, %s, %s", key,
            filename, content_type, transfer_encoding, data);
    if (strncmp(key, "name", MAX_POST_KEY_SIZE) == 0) {
        if (load_repos(ep_data) == MHD_NO)
            return MHD_NO;

        nob_log(NOB_INFO, "current_user='%s'", current_user.username);
        // FIXME: This is way too slow
        size_t uid;
        bool found = false;
        for (uid = 0; uid < users_count; uid++) {
            // current_user should be defined by endpoint_generic_auth,
            // which is called before this function
            if (strncmp(users[uid].username, current_user.username,
                        MAX_POST_KEY_SIZE) == 0) {
                found = true;
                break;
            }
        }

        // NOTE: This should never happen
        if (!found) {
            ep_data->post_failed = true;
            ep_data->post_message = "Current user not found";
            return MHD_NO;
        }

        for (size_t i = 0; i < repos_count; i++) {
            if (repos[i].uid == uid &&
                strncmp(repos[i].name, data, MAX_POST_KEY_SIZE) == 0) {
                ep_data->post_failed = true;
                ep_data->post_message = "Repo already exists";
                return MHD_NO;
            }
        }

        strncpy(current_repo.name, data, MAX_POST_KEY_SIZE);
        return MHD_YES;
    }

    ep_data->post_failed = true;
    ep_data->post_message = "Unknown option";
    return MHD_NO;
}
