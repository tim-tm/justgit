#include "main.h"

// NOB_IMPLEMENTATION is already defined by main.c
#include "../nob.h"

// TODO: heavy refactoring:
//          - user hashtable would greatly improve performance

static user *users = NULL;
static size_t users_cap = 256;

static repo *repos = NULL;
static size_t repos_cap = 256;

static metadata current_metadata[1];
static user current_user = {0};
static repo current_repo = {0};

static enum MHD_Result load_data(endpoint_data *ep_data) {
    if (users == NULL) {
        FILE *fp = fopen(DATA_FILE_NAME, "rb");
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
            size_t items = fread(current_metadata, sizeof(metadata), 1, fp);
            if (items != 1) {
                nob_log(
                    NOB_ERROR,
                    "Failed to add user: Could not load metadata from disk.");
                ep_data->post_failed = true;
                ep_data->post_message = "Could not load users";
                fclose(fp);
                return MHD_NO;
            }
            nob_log(NOB_INFO, "Reading %zu users from file",
                    current_metadata->users_count);
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
            fseek(fp, sizeof(metadata), SEEK_SET);
            size_t items =
                fread(users, sizeof(user), current_metadata->users_count, fp);
            if (items != current_metadata->users_count) {
                nob_log(NOB_ERROR,
                        "Failed to add user: Could not load all users from "
                        "disk. User "
                        "count: %zu, read users: %zu",
                        current_metadata->users_count, items);
                ep_data->post_failed = true;
                ep_data->post_message = "Could not load users";
                fclose(fp);
                return MHD_NO;
            }

            fseek(fp,
                  sizeof(metadata) +
                      (current_metadata->users_count * sizeof(user)),
                  SEEK_SET);
            items =
                fread(repos, sizeof(repo), current_metadata->repos_count, fp);
            if (items != current_metadata->repos_count) {
                nob_log(NOB_ERROR,
                        "Failed to add repo: Could not load all repos from "
                        "disk. User "
                        "count: %zu, read repos: %zu",
                        current_metadata->repos_count, items);
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
    if (load_data(data) == MHD_NO) {
        nob_log(NOB_INFO, "Could not load users: %s", data->post_message);
        return (result){.failed = true,
                        .status = send_page_plain(
                            data->connection, MHD_HTTP_INTERNAL_SERVER_ERROR,
                            "Could not load users")};
    }

    nob_log(NOB_INFO, "users_count=%zu", current_metadata->users_count);

    size_t uid;
    bool found = false;
    for (uid = 0; uid < current_metadata->users_count; uid++) {
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

static void free_data(void) {
    if (users)
        free(users);
    if (repos)
        free(repos);
}

static result write_data(endpoint_data *data) {
    FILE *fp = fopen(DATA_FILE_NAME, "wb");
    if (fp == NULL) {
        nob_log(NOB_ERROR, "Failed to save data: Could not open file (%s)",
                strerror(errno));
        // do not give too much information to the client,
        // preferably don't give them the strerror
        free_data();
        return (result){.failed = true,
                        .status = send_page_plain(
                            data->connection, MHD_HTTP_INTERNAL_SERVER_ERROR,
                            "Could not save data")};
    }

    size_t items = fwrite(current_metadata, sizeof(metadata), 1, fp);
    if (items != 1) {
        nob_log(NOB_ERROR,
                "Failed to save data: Could not save metadata to disk.");
        fclose(fp);
        free_data();
        return (result){.failed = true,
                        .status = send_page_plain(
                            data->connection, MHD_HTTP_INTERNAL_SERVER_ERROR,
                            "Could not save data")};
    }

    fseek(fp, sizeof(metadata), SEEK_SET);
    items = fwrite(users, sizeof(user), current_metadata->users_count, fp);
    if (items != current_metadata->users_count) {
        nob_log(NOB_ERROR,
                "Failed to save data: Could not save all users to disk. User "
                "count: %zu, written users: %zu",
                current_metadata->users_count, items);
        fclose(fp);
        free_data();
        return (result){.failed = true,
                        .status = send_page_plain(
                            data->connection, MHD_HTTP_INTERNAL_SERVER_ERROR,
                            "Could not save users")};
    }

    fseek(fp, sizeof(metadata) + (current_metadata->users_count * sizeof(user)),
          SEEK_SET);
    items = fwrite(repos, sizeof(repo), current_metadata->repos_count, fp);
    if (items != current_metadata->repos_count) {
        nob_log(NOB_ERROR,
                "Failed to add repo: Could not save all repos to disk. Repo "
                "count: %zu, written repos: %zu",
                current_metadata->repos_count, items);
        fclose(fp);
        free_data();
        return (result){.failed = true,
                        .status = send_page_plain(
                            data->connection, MHD_HTTP_INTERNAL_SERVER_ERROR,
                            "Could not save repos")};
    }
    fclose(fp);
    free_data();
    return (result){.failed = false, .status = MHD_YES};
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

enum MHD_Result endpoint_generic_auth(endpoint_data *data) {
    result res;
    if ((res = authenticate(data)).failed)
        return res.status;
    return MHD_YES;
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
    if ((res = append_array(data->connection, users,
                            current_metadata->users_count, users_cap))
            .failed)
        return res.status;

    users[current_metadata->users_count++] = current_user;

    if ((res = write_data(data)).failed)
        return res.status;

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
        if (load_data(ep_data) == MHD_NO)
            return MHD_NO;

        for (size_t i = 0; i < current_metadata->users_count; i++) {
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
    nob_log(NOB_INFO, "Getting information for user '%s'", GIT_USER_NAME);
    struct passwd *git_user_passwd = getpwnam(GIT_USER_NAME);
    if (git_user_passwd == NULL) {
        nob_log(NOB_ERROR, "Failed to get information for user '%s'.",
                GIT_USER_NAME);
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
                GIT_USER_NAME, reponame);
        return send_page_plain(data->connection, MHD_HTTP_INTERNAL_SERVER_ERROR,
                               "Could not create git repository");
    }

    result res;
    if ((res = append_array(data->connection, repos,
                            current_metadata->repos_count, repos_cap))
            .failed)
        return res.status;

    repos[current_metadata->repos_count++] = current_repo;

    if ((res = write_data(data)).failed)
        return res.status;

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
        if (load_data(ep_data) == MHD_NO)
            return MHD_NO;

        nob_log(NOB_INFO, "current_user='%s'", current_user.username);
        // FIXME: This is way too slow
        size_t uid;
        bool found = false;
        for (uid = 0; uid < current_metadata->users_count; uid++) {
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

        for (size_t i = 0; i < current_metadata->repos_count; i++) {
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
