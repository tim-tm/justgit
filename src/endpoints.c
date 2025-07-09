#include "main.h"

// NOB_IMPLEMENTATION is already defined by main.c
#include "../nob.h"

static user **users = NULL;
static size_t users_cap = 256;

static repo **repos = NULL;
static size_t repos_cap = 256;

static metadata *current_metadata = NULL;
static user *current_user = NULL;
static repo *current_repo = NULL;

static enum MHD_Result load_data(endpoint_data *ep_data) {
    if (current_metadata == NULL && users == NULL && repos == NULL) {
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

        // also allocate memory if the error is
        // "No such file or directory"
        current_metadata = calloc(1, sizeof(metadata));
        if (current_metadata == NULL) {
            nob_log(NOB_ERROR,
                    "Failed to load data: No more memory for metadata!");
            ep_data->post_failed = true;
            ep_data->post_message = "No more memory";
            fclose(fp);
            return MHD_NO;
        }

        users = calloc(users_cap, sizeof(user));
        if (users == NULL) {
            nob_log(NOB_ERROR, "Failed to load data: No more memory for user!");
            ep_data->post_failed = true;
            ep_data->post_message = "No more memory";
            fclose(fp);
            return MHD_NO;
        }

        repos = calloc(repos_cap, sizeof(repo));
        if (repos == NULL) {
            nob_log(NOB_ERROR, "Failed to load data: No more memory for repo!");
            ep_data->post_failed = true;
            ep_data->post_message = "No more memory";
            fclose(fp);
            return MHD_NO;
        }

        if (fp != NULL) {
            nob_log(NOB_INFO, "Reading metadata from file.");
            size_t items = fread(current_metadata, sizeof(metadata), 1, fp);
            if (items != 1) {
                nob_log(
                    NOB_ERROR,
                    "Failed to add user: Could not load metadata from disk.");
                ep_data->post_failed = true;
                ep_data->post_message = "Could not load metadata";
                fclose(fp);
                return MHD_NO;
            }
            nob_log(
                NOB_INFO,
                "(metadata){\n\t.users_count = %zu,\n\t.repos_count = %zu\n}",
                current_metadata->users_count, current_metadata->repos_count);

            nob_log(NOB_INFO, "Trying to read %zu users from file",
                    current_metadata->users_count);
            if (fseek(fp, sizeof(metadata), SEEK_SET) != 0) {
                nob_log(NOB_ERROR, "Failed to load data: %s", strerror(errno));
                ep_data->post_failed = true;
                ep_data->post_message = "Could not load users";
                fclose(fp);
                return MHD_NO;
            }

            if (current_metadata->users_count >= users_cap) {
                users_cap *= 2;
                users = realloc(users, users_cap * sizeof(user));
                if (users == NULL) {
                    nob_log(NOB_ERROR,
                            "Failed to append array: no more memory");
                    ep_data->post_failed = true;
                    ep_data->post_message = "No more memory";
                    fclose(fp);
                    return MHD_NO;
                }
            }

            for (size_t i = 0; i < current_metadata->users_count; i++) {
                users[i] = calloc(1, sizeof(user));
                if (users[i] == NULL) {
                    nob_log(NOB_ERROR,
                            "Failed to load data: No more memory for user!");
                    ep_data->post_failed = true;
                    ep_data->post_message = "No more memory";
                    fclose(fp);
                    return MHD_NO;
                }

                if (fread(users[i], sizeof(user), 1, fp) != 1) {
                    nob_log(NOB_ERROR, "Failed to add user: Could not load all "
                                       "users from disk.");
                    ep_data->post_failed = true;
                    ep_data->post_message = "Could not load users";
                    fclose(fp);
                    return MHD_NO;
                }
            }

            nob_log(NOB_INFO, "Trying to read %zu repos from file",
                    current_metadata->repos_count);
            if (fseek(fp,
                      sizeof(metadata) +
                          (current_metadata->users_count * sizeof(user)),
                      SEEK_SET) != 0) {
                nob_log(NOB_ERROR, "Failed to load data: %s", strerror(errno));
                ep_data->post_failed = true;
                ep_data->post_message = "Could not load repos";
                fclose(fp);
                return MHD_NO;
            }

            if (current_metadata->repos_count >= repos_cap) {
                repos_cap *= 2;
                repos = realloc(repos, repos_cap * sizeof(user));
                if (repos == NULL) {
                    nob_log(NOB_ERROR,
                            "Failed to append array: no more memory");
                    ep_data->post_failed = true;
                    ep_data->post_message = "No more memory";
                    fclose(fp);
                    return MHD_NO;
                }
            }

            for (size_t i = 0; i < current_metadata->repos_count; i++) {
                repos[i] = calloc(1, sizeof(repo));
                if (repos[i] == NULL) {
                    nob_log(NOB_ERROR,
                            "Failed to load data: No more memory for repo!");
                    ep_data->post_failed = true;
                    ep_data->post_message = "No more memory";
                    fclose(fp);
                    return MHD_NO;
                }

                if (fread(repos[i], sizeof(repo), 1, fp) != 1) {
                    nob_log(NOB_ERROR, "Failed to add repo: Could not load all "
                                       "repos from disk.");
                    ep_data->post_failed = true;
                    ep_data->post_message = "Could not load repos";
                    fclose(fp);
                    return MHD_NO;
                }
            }
            fclose(fp);
        }
    }
    ep_data->post_failed = false;
    return MHD_YES;
}

static void free_data(void) {
    if (current_metadata != NULL) {
        free(current_metadata);
    }

    if (users != NULL) {
        for (size_t i = 0; i < users_cap; i++) {
            if (users[i] != NULL) {
                free(users[i]);
            }
        }
        free(users);
    }

    if (repos != NULL) {
        for (size_t i = 0; i < repos_cap; i++) {
            if (repos[i] != NULL) {
                free(repos[i]);
            }
        }
        free(repos);
    }
}

static result write_data(endpoint_data *data) {
    FILE *fp = fopen(DATA_FILE_NAME, "wb");
    if (fp == NULL) {
        nob_log(NOB_ERROR, "Failed to save data: Could not open file (%s)",
                strerror(errno));
        // do not give too much information to the client,
        // preferably don't give them the strerror
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
        return (result){.failed = true,
                        .status = send_page_plain(
                            data->connection, MHD_HTTP_INTERNAL_SERVER_ERROR,
                            "Could not save data")};
    }

    if (fseek(fp, sizeof(metadata), SEEK_SET) != 0) {
        nob_log(NOB_ERROR,
                "Failed to save data: Could not save users to disk.");
        fclose(fp);
        return (result){.failed = true,
                        .status = send_page_plain(
                            data->connection, MHD_HTTP_INTERNAL_SERVER_ERROR,
                            "Could not save data")};
    }

    for (size_t i = 0; i < current_metadata->users_count; i++) {
        if (users[i] == NULL)
            continue;

        if (fwrite(users[i], sizeof(user), 1, fp) != 1) {
            nob_log(NOB_ERROR,
                    "Failed to save data: Could not save all users to disk.");
            fclose(fp);
            return (result){.failed = true,
                            .status =
                                send_page_plain(data->connection,
                                                MHD_HTTP_INTERNAL_SERVER_ERROR,
                                                "Could not save users")};
        }
    }

    if (fseek(fp,
              sizeof(metadata) + (current_metadata->users_count * sizeof(user)),
              SEEK_SET) != 0) {
        nob_log(NOB_ERROR,
                "Failed to save data: Could not save repos to disk.");
        fclose(fp);
        return (result){.failed = true,
                        .status = send_page_plain(
                            data->connection, MHD_HTTP_INTERNAL_SERVER_ERROR,
                            "Could not save data")};
    }

    for (size_t i = 0; i < current_metadata->users_count; i++) {
        if (repos[i] == NULL)
            continue;

        if (fwrite(repos[i], sizeof(repo), 1, fp) != 1) {
            nob_log(NOB_ERROR,
                    "Failed to add repo: Could not save all repos to disk.");
            fclose(fp);
            return (result){.failed = true,
                            .status =
                                send_page_plain(data->connection,
                                                MHD_HTTP_INTERNAL_SERVER_ERROR,
                                                "Could not save repos")};
        }
    }
    fclose(fp);
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

static size_t hash_user(const char *key, size_t len) {
    if (key == NULL)
        return 0;

    // Implementation of Daniel J. Bernstein's djb2-hash
    // (https://theartincode.stanis.me/008-djb2/)

    size_t hash = 5381;
    for (size_t i = 0; i < len - 1; i++) {
        hash = ((hash << 5) + hash) + key[i];
    }
    return hash;
}

static user *get_user(const char *username) {
    if (current_metadata->users_count == 0)
        return NULL;

    size_t len = strnlen(username, MAX_POST_KEY_SIZE);
    size_t hash = hash_user(username, len);
    hash %= current_metadata->users_count;
    nob_log(NOB_INFO, "hash = %zu", hash);

    size_t i = 0;
    while (users[hash] != NULL && i < current_metadata->users_count) {
        nob_log(NOB_INFO, "hash = %zu", hash);
        if (strncmp(users[hash]->username, username, MAX_POST_KEY_SIZE) == 0) {
            return users[hash];
        }

        hash++;
        if (hash >= current_metadata->users_count) {
            hash = 0;
        }
        i++;
    }
    return NULL;
}

static result insert_user(struct MHD_Connection *connection) {
    size_t len = strnlen(current_user->username, MAX_POST_KEY_SIZE);
    size_t hash = hash_user(current_user->username, len);

    current_metadata->users_count++;
    hash %= current_metadata->users_count;
    for (size_t i = 0; i < current_metadata->users_count && users[hash] != NULL;
         i++, hash++) {
        hash %= current_metadata->users_count;
    }

    if (users[hash] != NULL) {
        nob_log(NOB_ERROR, "Hashtable full");
        return (result){
            .failed = true,
            .status = send_page_plain(
                connection, MHD_HTTP_INTERNAL_SERVER_ERROR, "Hashtable full")};
    }
    nob_log(NOB_INFO, "name: %s, pw: %s", current_user->username,
            current_user->password_hash);
    users[hash] = current_user;
    nob_log(NOB_INFO, "name: %s, pw: %s", users[hash]->username,
            users[hash]->password_hash);

    return (result){.failed = false, .status = MHD_YES};
}

static result insert_repo(struct MHD_Connection *connection) {
    size_t len = strnlen(current_repo->name, MAX_POST_KEY_SIZE);
    size_t hash = hash_user(current_repo->name, len);

    hash %= ++current_metadata->repos_count;
    for (size_t i = 0; i < current_metadata->repos_count && repos[hash] != NULL;
         i++, hash++) {
        hash %= current_metadata->repos_count;
    }

    if (repos[hash] != NULL) {
        nob_log(NOB_ERROR, "Hashtable full");
        return (result){
            .failed = true,
            .status = send_page_plain(
                connection, MHD_HTTP_INTERNAL_SERVER_ERROR, "Hashtable full")};
    }
    repos[hash] = current_repo;

    return (result){.failed = false, .status = MHD_YES};
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
    user *u = get_user(data->auth.username);
    if (u == NULL) {
        nob_log(NOB_ERROR, "User with username %s not found",
                data->auth.username);
        return (result){.failed = true,
                        .status = send_page_plain(data->connection,
                                                  MHD_HTTP_UNAUTHORIZED,
                                                  "User not found")};
    }

    // nob_log(NOB_INFO, "Found user: %s, %s", u->username, u->password_hash);
    current_user = u;

    nob_log(NOB_INFO, "Checking password...");
    size_t pass_len = strnlen(data->auth.password, MAX_POST_DATA_SIZE);
    if (crypto_pwhash_str_verify(u->password_hash, data->auth.password,
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
    if (data->post_failed || current_user->username[0] == '\0' ||
        current_user->password_hash[0] == '\0') {
        return send_page_plain(data->connection, MHD_HTTP_INTERNAL_SERVER_ERROR,
                               data->post_message == NULL ? "Invalid POST-data"
                                                          : data->post_message);
    }

    nob_log(NOB_INFO, "Adding user: %s", current_user->username);
    result res;
    if ((res = append_array(data->connection, users,
                            current_metadata->users_count, users_cap))
            .failed)
        return res.status;

    if ((res = insert_user(data->connection)).failed)
        return res.status;

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

        user *u = get_user(data);
        if (u != NULL) {
            nob_log(NOB_ERROR, "Failed to add user: User already exists!");
            ep_data->post_failed = true;
            ep_data->post_message = "User already exists";
            return MHD_NO;
        }

        nob_log(NOB_INFO, "Copying username: %s", data);
        current_user = calloc(1, sizeof(user));
        if (current_user == NULL) {
            nob_log(NOB_ERROR, "Failed to add user: No more memory");
            ep_data->post_failed = true;
            ep_data->post_message = "No more memory";
            return MHD_NO;
        }

        strncpy(current_user->username, data, MAX_POST_KEY_SIZE);
        return MHD_YES;
    } else if (strncmp(key, "password", MAX_POST_KEY_SIZE) == 0) {
        nob_log(NOB_INFO, "Computing hash for password...");
        size_t data_len = strnlen(data, MAX_POST_DATA_SIZE);
        if (crypto_pwhash_str(current_user->password_hash, data, data_len,
                              crypto_pwhash_OPSLIMIT_INTERACTIVE,
                              crypto_pwhash_MEMLIMIT_INTERACTIVE) != 0) {
            nob_log(NOB_ERROR,
                    "Out of memory while trying to compute hash for user: %s",
                    current_user->username);
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
    if (data->post_failed || current_repo->name[0] == '\0') {
        return send_page_plain(data->connection, MHD_HTTP_INTERNAL_SERVER_ERROR,
                               data->post_message == NULL ? "Invalid POST-data"
                                                          : data->post_message);
    }

    nob_log(NOB_INFO, "Adding repo: %s", current_repo->name);

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
    const char *reponame =
        nob_temp_sprintf("%s/%s/%s.git", WORKING_DIR, current_user->username,
                         current_repo->name);
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

    if ((res = insert_repo(data->connection)).failed)
        return res.status;

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

        nob_log(NOB_INFO, "current_user='%s'", current_user->username);
        // FIXME: This is way too slow
        size_t uid;
        bool found = false;
        for (uid = 0; uid < current_metadata->users_count; uid++) {
            // current_user should be defined by endpoint_generic_auth,
            // which is called before this function
            if (strncmp(users[uid]->username, current_user->username,
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
            if (repos[i]->uid == uid &&
                strncmp(repos[i]->name, data, MAX_POST_KEY_SIZE) == 0) {
                ep_data->post_failed = true;
                ep_data->post_message = "Repo already exists";
                return MHD_NO;
            }
        }

        current_repo = calloc(1, sizeof(repo));
        if (current_repo == NULL) {
            nob_log(NOB_ERROR, "Failed to add repo: No more memory");
            ep_data->post_failed = true;
            ep_data->post_message = "No more memory";
            return MHD_NO;
        }

        strncpy(current_repo->name, data, MAX_POST_KEY_SIZE);
        return MHD_YES;
    }

    ep_data->post_failed = true;
    ep_data->post_message = "Unknown option";
    return MHD_NO;
}
