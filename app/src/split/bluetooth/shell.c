
#include <stdlib.h>
#include <zephyr/kernel.h>
#include <shell/shell.h>
#include <zmk/event_manager.h>
#include <zmk/events/position_state_changed.h>

#define HELP_NONE ""

static int cmd_split_status(const struct shell *shell, size_t argc, char **argv) {
    if (argc != 1) {
        return -EINVAL;
    }

    return 0;
};

static int cmd_split_forget(const struct shell *shell, size_t argc, char **argv) {
    if (argc != 1) {
        return -EINVAL;
    }

    return 0;
};

SHELL_STATIC_SUBCMD_SET_CREATE(sub_split, SHELL_CMD(status, NULL, HELP_NONE, cmd_split_status),
                               SHELL_CMD(forget, NULL, HELP_NONE, cmd_split_forget),
                               SHELL_SUBCMD_SET_END /* Array terminated. */
);

SHELL_CMD_REGISTER(key, &sub_split, "Key commands", NULL);