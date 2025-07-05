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
    nob_cc_inputs(&cmd, "src/mingit.c");
    nob_cc_output(&cmd, "mingit");
    cmd_append(&cmd, "-lmicrohttpd");
    if (!cmd_run_sync(cmd)) return false;

    nob_log(INFO, "Build finished!");
    return 0;
}
