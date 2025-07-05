#define NOB_IMPLEMENTATION
#define NOB_STRIP_PREFIX
#include "nob.h"

int main(int argc, char *argv[])
{
    NOB_GO_REBUILD_URSELF(argc, argv);

    Cmd cmd = {0};
    nob_cc(&cmd);
    nob_cc_flags(&cmd);
    cmd_append(&cmd, "-std=c11");
    cmd_append(&cmd, "-pedantic");
    cmd_append(&cmd, "-Isrc");
    cmd_append(&cmd, "-ggdb2");
    nob_cc_inputs(&cmd, "src/utils.c");
    nob_cc_inputs(&cmd, "src/endpoints.c");
    nob_cc_inputs(&cmd, "src/main.c");
    nob_cc_output(&cmd, "justgit");
    cmd_append(&cmd, "-lmicrohttpd");
    cmd_append(&cmd, "-lgit2");
    cmd_append(&cmd, "-lsodium");
    if (!cmd_run_sync(cmd)) return false;

    nob_log(INFO, "Build finished!");
    return 0;
}
