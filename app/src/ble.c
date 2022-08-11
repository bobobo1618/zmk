/*
 * Copyright (c) 2020 The ZMK Contributors
 *
 * SPDX-License-Identifier: MIT
 */

#include <zephyr/device.h>
#include <zephyr/init.h>

#include <errno.h>
#include <math.h>
#include <stdlib.h>
#include <stdio.h>

#include <zephyr/settings/settings.h>
#include <zephyr/bluetooth/bluetooth.h>
#include <zephyr/bluetooth/conn.h>
#include <zephyr/bluetooth/hci.h>
#include <zephyr/bluetooth/uuid.h>
#include <zephyr/bluetooth/gatt.h>
#include <zephyr/bluetooth/hci_err.h>

#if IS_ENABLED(CONFIG_SETTINGS)

#include <zephyr/settings/settings.h>

#endif

#include <zephyr/logging/log.h>

LOG_MODULE_DECLARE(zmk, CONFIG_ZMK_LOG_LEVEL);

#include <zmk/ble.h>
#include <zmk/keys.h>
#include <zmk/split/bluetooth/uuid.h>
#include <zmk/event_manager.h>
#include <zmk/events/ble_active_profile_changed.h>

#if IS_ENABLED(CONFIG_ZMK_BLE_PASSKEY_ENTRY)
#include <zmk/events/keycode_state_changed.h>

#define PASSKEY_DIGITS 6

static struct bt_conn *auth_passkey_entry_conn;
static uint8_t passkey_entries[PASSKEY_DIGITS] = {};
static uint8_t passkey_digit = 0;

#endif /* IS_ENABLED(CONFIG_ZMK_BLE_PASSKEY_ENTRY) */

enum advertising_type {
    ZMK_ADV_NONE,
    ZMK_ADV_DIR,
    ZMK_ADV_CONN,
} advertising_status;

enum dir_adv_caps {
    DIR_ADV_CAPS_ENABLE = BIT(0),
    DIR_ADV_CAPS_USE_RPA = BIT(1),
};

#define CURR_ADV(adv) (adv << 4)

#define ZMK_ADV_CONN_NAME                                                                          \
    BT_LE_ADV_PARAM(BT_LE_ADV_OPT_CONNECTABLE | BT_LE_ADV_OPT_ONE_TIME, BT_GAP_ADV_FAST_INT_MIN_2, \
                    BT_GAP_ADV_FAST_INT_MAX_2, NULL)

static struct zmk_ble_profile profiles[ZMK_BLE_PROFILE_COUNT];
static uint8_t active_profile;

#define DEVICE_NAME CONFIG_BT_DEVICE_NAME
#define DEVICE_NAME_LEN (sizeof(DEVICE_NAME) - 1)

BUILD_ASSERT(DEVICE_NAME_LEN <= 16, "ERROR: BLE device name is too long. Max length: 16");

static const struct bt_data zmk_ble_ad[] = {
    BT_DATA(BT_DATA_NAME_COMPLETE, DEVICE_NAME, DEVICE_NAME_LEN),
    BT_DATA_BYTES(BT_DATA_GAP_APPEARANCE, 0xC1, 0x03),
    BT_DATA_BYTES(BT_DATA_FLAGS, (BT_LE_AD_GENERAL | BT_LE_AD_NO_BREDR)),
    BT_DATA_BYTES(BT_DATA_UUID16_SOME, 0x12, 0x18, /* HID Service */
                  0x0f, 0x18                       /* Battery Service */
                  ),
};

#if IS_ENABLED(CONFIG_ZMK_SPLIT_ROLE_CENTRAL)

static bt_addr_le_t peripheral_addr;

#endif /* IS_ENABLED(CONFIG_ZMK_SPLIT_ROLE_CENTRAL) */

static void raise_profile_changed_event() {
    ZMK_EVENT_RAISE(new_zmk_ble_active_profile_changed((struct zmk_ble_active_profile_changed){
        .index = active_profile, .profile = &profiles[active_profile]}));
}

static void raise_profile_changed_event_callback(struct k_work *work) {
    raise_profile_changed_event();
}

K_WORK_DEFINE(raise_profile_changed_event_work, raise_profile_changed_event_callback);

bool zmk_ble_active_profile_is_open() {
    return !bt_addr_le_cmp(&profiles[active_profile].peer, BT_ADDR_LE_ANY);
}

void set_profile_address(uint8_t index, const bt_addr_le_t *addr) {
    char setting_name[15];
    char addr_str[BT_ADDR_LE_STR_LEN];

    bt_addr_le_to_str(addr, addr_str, sizeof(addr_str));

    memcpy(&profiles[index].peer, addr, sizeof(bt_addr_le_t));
    sprintf(setting_name, "ble/profiles/%d", index);
    LOG_DBG("Setting profile addr for %s to %s", setting_name, addr_str);
    settings_save_one(setting_name, &profiles[index], sizeof(struct zmk_ble_profile));
    k_work_submit(&raise_profile_changed_event_work);
}

static enum dir_adv_caps profile_dir_adv_caps[ZMK_BLE_PROFILE_COUNT];
static bool hd_dir_adv_timed_out = false;

void set_profile_dir_adv_caps(uint8_t index, enum dir_adv_caps caps) {
    char setting_name[19];

    profile_dir_adv_caps[index] = caps;

    sprintf(setting_name, "ble/can_dir_adv/%d", index);

    settings_save_one(setting_name, &caps, sizeof(enum dir_adv_caps));
}

bool zmk_ble_active_profile_is_connected() {
    struct bt_conn *conn;
    struct bt_conn_info;
    bt_addr_le_t *addr = zmk_ble_active_profile_addr();
    if (!bt_addr_le_cmp(addr, BT_ADDR_LE_ANY)) {
        return false;
    } else if ((conn = bt_conn_lookup_addr_le(BT_ID_DEFAULT, addr)) == NULL) {
        return false;
    }

    bool connected = bt_conn_get_security(conn) >= BT_SECURITY_L2;

    bt_conn_unref(conn);

    return connected;
}

#define CHECKED_ADV_STOP()                                                                         \
    err = bt_le_adv_stop();                                                                        \
    advertising_status = ZMK_ADV_NONE;                                                             \
    if (err) {                                                                                     \
        LOG_ERR("Failed to stop advertising (err %d)", err);                                       \
        return err;                                                                                \
    }

#define CHECKED_DIR_ADV()                                                                          \
    addr = zmk_ble_active_profile_addr();                                                          \
    conn = bt_conn_lookup_addr_le(BT_ID_DEFAULT, addr);                                            \
    if (conn != NULL) { /* TODO: Check status of connection */                                     \
        LOG_DBG("Skipping advertising, profile host is already connected");                        \
        bt_conn_unref(conn);                                                                       \
        return 0;                                                                                  \
    }                                                                                              \
    adv_param =                                                                                    \
        hd_dir_adv_timed_out ? *BT_LE_ADV_CONN_DIR_LOW_DUTY(addr) : *BT_LE_ADV_CONN_DIR(addr);      \
    if (profile_dir_adv_caps[active_profile] & DIR_ADV_CAPS_USE_RPA) {                             \
        adv_param.options |= BT_LE_ADV_OPT_DIR_ADDR_RPA;                                           \
    }                                                                                              \
    err = bt_le_adv_start(&adv_param, NULL, 0, NULL, 0);                                           \
    COND_CODE_1(IS_ENABLED(CONFIG_ZMK_PROFILE_MODE_AUTOMATIC), (k_delayed_work_submit(&try_next_profile_work, K_SECONDS(5));), ()) \
    if (err) {                                                                                     \
        LOG_ERR("Advertising failed to start (err %d)", err);                                      \
        return err;                                                                                \
    }                                                                                              \
    hd_dir_adv_timed_out = false;                                                                   \
    advertising_status = ZMK_ADV_DIR;

#define CHECKED_OPEN_ADV()                                                                         \
    err = bt_le_adv_start(ZMK_ADV_CONN_NAME, zmk_ble_ad, ARRAY_SIZE(zmk_ble_ad), NULL, 0);         \
    if (err) {                                                                                     \
        LOG_ERR("Advertising failed to start (err %d)", err);                                      \
        return err;                                                                                \
    }                                                                                              \
    advertising_status = ZMK_ADV_CONN;

int update_advertising() {
    int err = 0;
    bt_addr_le_t *addr;
    struct bt_conn *conn;
    struct bt_le_adv_param adv_param;
    enum advertising_type desired_adv = ZMK_ADV_NONE;

    if (zmk_ble_active_profile_is_open()) {
        desired_adv = ZMK_ADV_CONN;
    } else if (!zmk_ble_active_profile_is_connected()) {
#if IS_ENABLED(CONFIG_ZMK_BLE_DIRECTED_ADVERTISING)
        if (hd_dir_adv_timed_out && IS_ENABLED(CONFIG_ZMK_BLE_PROFILE_MODE_AUTO)) {
            desired_adv = ZMK_ADV_CONN;
        } else {
            desired_adv = (profile_dir_adv_caps[active_profile] & DIR_ADV_CAPS_ENABLE) ? ZMK_ADV_DIR
                                                                                    : ZMK_ADV_CONN;
        }
#else
        desired_adv = ZMK_ADV_CONN;
#endif
    }
    LOG_DBG("advertising from %d to %d", advertising_status, desired_adv);

    switch (desired_adv + CURR_ADV(advertising_status)) {
    case ZMK_ADV_NONE + CURR_ADV(ZMK_ADV_DIR):
    case ZMK_ADV_NONE + CURR_ADV(ZMK_ADV_CONN):
        CHECKED_ADV_STOP();
        break;
    case ZMK_ADV_DIR + CURR_ADV(ZMK_ADV_DIR):
    case ZMK_ADV_DIR + CURR_ADV(ZMK_ADV_CONN):
        CHECKED_ADV_STOP();
        CHECKED_DIR_ADV();
        break;
    case ZMK_ADV_DIR + CURR_ADV(ZMK_ADV_NONE):
        CHECKED_DIR_ADV();
        break;
    case ZMK_ADV_CONN + CURR_ADV(ZMK_ADV_DIR):
        CHECKED_ADV_STOP();
        CHECKED_OPEN_ADV();
        break;
    case ZMK_ADV_CONN + CURR_ADV(ZMK_ADV_NONE):
        CHECKED_OPEN_ADV();
        break;
    }

    return 0;
};

static void update_advertising_callback(struct k_work *work) { update_advertising(); }

K_WORK_DEFINE(update_advertising_work, update_advertising_callback);

int zmk_ble_clear_bonds() {
    LOG_DBG("");

    if (bt_addr_le_cmp(&profiles[active_profile].peer, BT_ADDR_LE_ANY) != 0) {
        LOG_DBG("Unpairing!");
        bt_unpair(BT_ID_DEFAULT, &profiles[active_profile].peer);
    }

    update_advertising();

    return 0;
};

int zmk_ble_active_profile_index() { return active_profile; }

#if IS_ENABLED(CONFIG_SETTINGS)
static void ble_save_profile_work(struct k_work *work) {
    settings_save_one("ble/active_profile", &active_profile, sizeof(active_profile));
}

static struct k_work_delayable ble_save_work;
#endif

static int ble_save_profile() {
#if IS_ENABLED(CONFIG_SETTINGS)
    return k_work_reschedule(&ble_save_work, K_MSEC(CONFIG_ZMK_SETTINGS_SAVE_DEBOUNCE));
#else
    return 0;
#endif
}

int disconnect_for_profile(uint8_t index) {
    struct bt_conn *conn;
    int err = 0;

    if (index >= ZMK_BLE_PROFILE_COUNT) {
        return -ERANGE;
    }

    if (bt_addr_le_cmp(&profiles[index].peer, BT_ADDR_LE_ANY) == 0) {
        return 0;
    }

    if ((conn = bt_conn_lookup_addr_le(BT_ID_DEFAULT, &profiles[index].peer)) == NULL) {
        return 0;
    }

    err = bt_conn_disconnect(conn, BT_HCI_ERR_REMOTE_USER_TERM_CONN);
    bt_conn_unref(conn);

    return err;
}

int zmk_ble_prof_select(uint8_t index) {
    uint8_t prev_index = active_profile;

    if (index >= ZMK_BLE_PROFILE_COUNT) {
        return -ERANGE;
    }

    LOG_DBG("profile %d", index);
    if (active_profile == index) {
        return 0;
    }

    active_profile = index;
    disconnect_for_profile(prev_index);
    ble_save_profile();

    update_advertising();

    raise_profile_changed_event();

    return 0;
};

int zmk_ble_prof_next() {
    LOG_DBG("");
    return zmk_ble_prof_select((active_profile + 1) % ZMK_BLE_PROFILE_COUNT);
};

int zmk_ble_prof_prev() {
    LOG_DBG("");
    return zmk_ble_prof_select((active_profile + ZMK_BLE_PROFILE_COUNT - 1) %
                               ZMK_BLE_PROFILE_COUNT);
};

bt_addr_le_t *zmk_ble_active_profile_addr() { return &profiles[active_profile].peer; }

char *zmk_ble_active_profile_name() { return profiles[active_profile].name; }

#if IS_ENABLED(CONFIG_ZMK_SPLIT_ROLE_CENTRAL)

void zmk_ble_set_peripheral_addr(bt_addr_le_t *addr) {
    memcpy(&peripheral_addr, addr, sizeof(bt_addr_le_t));
    settings_save_one("ble/peripheral_address", addr, sizeof(bt_addr_le_t));
}

#endif /* IS_ENABLED(CONFIG_ZMK_SPLIT_ROLE_CENTRAL) */

#if IS_ENABLED(CONFIG_SETTINGS)

static int ble_profiles_handle_set(const char *name, size_t len, settings_read_cb read_cb,
                                   void *cb_arg) {
    const char *next;

    LOG_DBG("Setting BLE value %s", name);

    if (settings_name_steq(name, "profiles", &next) && next) {
        char *endptr;
        uint8_t idx = strtoul(next, &endptr, 10);
        if (*endptr != '\0') {
            LOG_WRN("Invalid profile index: %s", next);
            return -EINVAL;
        }

        if (len != sizeof(struct zmk_ble_profile)) {
            LOG_ERR("Invalid profile size (got %d expected %d)", len,
                    sizeof(struct zmk_ble_profile));
            return -EINVAL;
        }

        if (idx >= ZMK_BLE_PROFILE_COUNT) {
            LOG_WRN("Profile address for index %d is larger than max of %d", idx,
                    ZMK_BLE_PROFILE_COUNT);
            return -EINVAL;
        }

        int err = read_cb(cb_arg, &profiles[idx], sizeof(struct zmk_ble_profile));
        if (err <= 0) {
            LOG_ERR("Failed to handle profile address from settings (err %d)", err);
            return err;
        }

        char addr_str[BT_ADDR_LE_STR_LEN];
        bt_addr_le_to_str(&profiles[idx].peer, addr_str, sizeof(addr_str));

        LOG_DBG("Loaded %s address for profile %d", addr_str, idx);
    } else if (settings_name_steq(name, "can_dir_adv", &next) && next) {
        char *endptr;
        uint8_t idx = strtoul(next, &endptr, 10);
        if (*endptr != '\0') {
            LOG_WRN("Invalid profile index: %s", next);
            return -EINVAL;
        }

        if (len != sizeof(enum dir_adv_caps)) {
            LOG_ERR("Invalid directed advertising bool size (got %d expected %d)", len,
                    sizeof(enum dir_adv_caps));
            return -EINVAL;
        }

        if (idx >= ZMK_BLE_PROFILE_COUNT) {
            LOG_WRN("Profile can direct advertise for index %d is larger than max of %d", idx,
                    ZMK_BLE_PROFILE_COUNT);
            return -EINVAL;
        }

        int err = read_cb(cb_arg, &profile_dir_adv_caps[idx], sizeof(enum dir_adv_caps));
        if (err <= 0) {
            LOG_ERR("Failed to handle profile can direct advertise from settings (err %d)", err);
            return err;
        }
    } else if (settings_name_steq(name, "active_profile", &next) && !next) {
        if (len != sizeof(active_profile)) {
            return -EINVAL;
        }

        int err = read_cb(cb_arg, &active_profile, sizeof(active_profile));
        if (err <= 0) {
            LOG_ERR("Failed to handle active profile from settings (err %d)", err);
            return err;
        }
    }
#if IS_ENABLED(CONFIG_ZMK_SPLIT_ROLE_CENTRAL)
    else if (settings_name_steq(name, "peripheral_address", &next) && !next) {
        if (len != sizeof(bt_addr_le_t)) {
            return -EINVAL;
        }

        int err = read_cb(cb_arg, &peripheral_addr, sizeof(bt_addr_le_t));
        if (err <= 0) {
            LOG_ERR("Failed to handle peripheral address from settings (err %d)", err);
            return err;
        }
    }
#endif

    return 0;
};

struct settings_handler profiles_handler = {.name = "ble", .h_set = ble_profiles_handle_set};
#endif /* IS_ENABLED(CONFIG_SETTINGS) */

static bool is_conn_active_profile(const struct bt_conn *conn) {
    return bt_addr_le_cmp(bt_conn_get_dst(conn), &profiles[active_profile].peer) == 0;
}

#if IS_ENABLED(CONFIG_ZMK_PROFILE_MODE_AUTOMATIC) || IS_ENABLED(CONFIG_ZMK_BLE_DIRECTED_ADVERTISING)

static int get_profile_for_conn(const struct bt_conn *conn) {
    for (int i = 0; i < ZMK_BLE_PROFILE_COUNT; i++) {
        if (bt_addr_le_cmp(bt_conn_get_dst(conn), &profiles[i].peer) == 0) {
            return i;
        }
    }

    return -EINVAL;
}

#endif


#if IS_ENABLED(CONFIG_ZMK_PROFILE_MODE_AUTOMATIC)

static void try_next_profile(struct k_work *work) {
    zmk_ble_prof_next();
}

static K_DELAYED_WORK_DEFINE(try_next_profile_work, try_next_profile);

static int select_profile_for_conn(const struct bt_conn *conn) {
    int prof_index = get_profile_for_conn(conn);

    if (prof_index >= 0) {
        zmk_ble_prof_select(prof_index);
        return prof_index;
    }

    return -EINVAL;
}

static int select_next_open_profile() {
    for (int i = 0; i < ZMK_BLE_PROFILE_COUNT; i++) {
        if (!bt_addr_le_cmp(&profiles[active_profile].peer, BT_ADDR_LE_ANY)) {
            zmk_ble_prof_select(i);
            return 0;
        }
    }

    return -EINVAL;
}

#endif /* IS_ENABLED(CONFIG_ZMK_PROFILE_MODE_AUTOMATIC) */

static void connected(struct bt_conn *conn, uint8_t err) {
    char addr[BT_ADDR_LE_STR_LEN];
    struct bt_conn_info info;
    LOG_DBG("Connected thread: %p, err: %d", k_current_get(), err);

    bt_conn_get_info(conn, &info);
    bt_addr_le_to_str(bt_conn_get_dst(conn), addr, sizeof(addr));

    if (err == BT_HCI_ERR_ADV_TIMEOUT) {
        LOG_WRN("Advertising timeout to %s", addr);
        hd_dir_adv_timed_out = true;
        k_work_submit(&update_advertising_work);
        return;
    }

    if (info.role != BT_CONN_ROLE_PERIPHERAL) {
        LOG_DBG("SKIPPING FOR ROLE %d %s", info.role, addr);
        return;
    }

    advertising_status = ZMK_ADV_NONE;

    if (err) {
        LOG_WRN("Failed to connect to %s (%u)", addr, err);
        k_work_submit(&update_advertising_work);
        return;
    }

    LOG_DBG("Connected %s", addr);

    if (bt_conn_set_security(conn, BT_SECURITY_L2)) {
        LOG_ERR("Failed to set security");
    }


#if IS_ENABLED(CONFIG_ZMK_PROFILE_MODE_AUTOMATIC)
    k_delayed_work_cancel(&try_next_profile_work);
#endif

    k_work_submit(&update_advertising_work);

    if (is_conn_active_profile(conn)) {
        LOG_DBG("Active profile connected");
        k_work_submit(&raise_profile_changed_event_work);
#if IS_ENABLED(CONFIG_ZMK_PROFILE_MODE_AUTOMATIC)
    } else if (bt_conn_get_security(conn) >= BT_SECURITY_L2) {
        if (select_profile_for_conn(conn) < 0) {
            LOG_ERR("Failed to auto select profile for new connection");
        }
#endif
    }
}

static void disconnected(struct bt_conn *conn, uint8_t reason) {
    char addr[BT_ADDR_LE_STR_LEN];
    struct bt_conn_info info;

    bt_addr_le_to_str(bt_conn_get_dst(conn), addr, sizeof(addr));

    LOG_DBG("Disconnected from %s (reason 0x%02x)", addr, reason);

    bt_conn_get_info(conn, &info);

    if (info.role != BT_CONN_ROLE_PERIPHERAL) {
        LOG_DBG("SKIPPING FOR ROLE %d", info.role);
        return;
    }

    // We need to do this in a work callback, otherwise the advertising update will still see the
    // connection for a profile as active, and not start advertising yet.
    k_work_submit(&update_advertising_work);

    if (is_conn_active_profile(conn)) {
        LOG_DBG("Active profile disconnected");
        k_work_submit(&raise_profile_changed_event_work);
    }
}

static void security_changed(struct bt_conn *conn, bt_security_t level, enum bt_security_err err) {
    char addr[BT_ADDR_LE_STR_LEN];

    bt_addr_le_to_str(bt_conn_get_dst(conn), addr, sizeof(addr));

    if (!err) {
        LOG_DBG("Security changed: %s level %u", addr, level);
    } else {
        LOG_ERR("Security failed: %s level %u err %d", addr, level, err);
    }
}

static void le_param_updated(struct bt_conn *conn, uint16_t interval, uint16_t latency,
                             uint16_t timeout) {
    char addr[BT_ADDR_LE_STR_LEN];

    bt_addr_le_to_str(bt_conn_get_dst(conn), addr, sizeof(addr));

    LOG_DBG("%s: interval %d latency %d timeout %d", addr, interval, latency, timeout);
}

static struct bt_conn_cb conn_callbacks = {
    .connected = connected,
    .disconnected = disconnected,
    .security_changed = security_changed,
    .le_param_updated = le_param_updated,
};

/*
static void auth_passkey_display(struct bt_conn *conn, unsigned int passkey) {
    char addr[BT_ADDR_LE_STR_LEN];

    bt_addr_le_to_str(bt_conn_get_dst(conn), addr, sizeof(addr));

    LOG_DBG("Passkey for %s: %06u", addr, passkey);
}
*/

#if IS_ENABLED(CONFIG_ZMK_BLE_PASSKEY_ENTRY)

static void auth_passkey_entry(struct bt_conn *conn) {
    char addr[BT_ADDR_LE_STR_LEN];

    bt_addr_le_to_str(bt_conn_get_dst(conn), addr, sizeof(addr));

    LOG_DBG("Passkey entry requested for %s", addr);
    passkey_digit = 0;
    auth_passkey_entry_conn = bt_conn_ref(conn);
}

#endif

static void auth_cancel(struct bt_conn *conn) {
    char addr[BT_ADDR_LE_STR_LEN];

    bt_addr_le_to_str(bt_conn_get_dst(conn), addr, sizeof(addr));

#if IS_ENABLED(CONFIG_ZMK_BLE_PASSKEY_ENTRY)
    if (auth_passkey_entry_conn) {
        bt_conn_unref(auth_passkey_entry_conn);
        auth_passkey_entry_conn = NULL;
    }

    passkey_digit = 0;
#endif

    LOG_DBG("Pairing cancelled: %s", addr);
}

static enum bt_security_err auth_pairing_accept(struct bt_conn *conn,
                                                const struct bt_conn_pairing_feat *const feat) {
    struct bt_conn_info info;
    bt_conn_get_info(conn, &info);

    LOG_DBG("role %d, open? %s", info.role, zmk_ble_active_profile_is_open() ? "yes" : "no");
    if (info.role == BT_CONN_ROLE_PERIPHERAL) {
#if IS_ENABLED(CONFIG_ZMK_PROFILE_MODE_AUTOMATIC)
	TODO: Select the profile for the address of the connection
#else
        if(!zmk_ble_active_profile_is_open()) {
            LOG_WRN("Rejecting pairing request to taken profile %d", active_profile);
            return BT_SECURITY_ERR_PAIR_NOT_ALLOWED;
	}
#endif
    }

    return BT_SECURITY_ERR_SUCCESS;
};

#if IS_ENABLED(CONFIG_ZMK_BLE_DIRECTED_ADVERTISING)

static uint8_t read_car_cb(struct bt_conn *conn, uint8_t err, struct bt_gatt_read_params *params,
                           const void *data, uint16_t length) {

    LOG_DBG("");
    bool supported = false;
    if (!err && data && length == 1) {
        const uint8_t *val = data;

        supported = (val[0] == 1);
    }

    LOG_DBG("Supported? %s", supported ? "yes" : "no");

    if (!supported) {
        return BT_GATT_ITER_STOP;
    }

    for (int i = 0; i < ZMK_BLE_PROFILE_COUNT; i++) {
        if (bt_addr_le_cmp(bt_conn_get_dst(conn), &profiles[i].peer) == 0) {
            set_profile_dir_adv_caps(i, DIR_ADV_CAPS_ENABLE | DIR_ADV_CAPS_USE_RPA);
            break;
        }
    }

    return BT_GATT_ITER_STOP;
}

static struct bt_gatt_read_params read_car_params = {
    .func = read_car_cb,
    .by_uuid.uuid = BT_UUID_CENTRAL_ADDR_RES,
    .by_uuid.start_handle = BT_ATT_FIRST_ATTRIBUTE_HANDLE,
    .by_uuid.end_handle = BT_ATT_LAST_ATTRIBUTE_HANDLE,
};
static void determine_direct_advertisability(struct bt_conn *conn, const bt_addr_le_t *peer,
                                             const bt_addr_le_t *remote) {
    int prof_index = get_profile_for_conn(conn);

    if (bt_addr_le_is_rpa(remote)) {
        LOG_DBG("Found private address, start searching GAP for CAR characteristic");
        set_profile_dir_adv_caps(prof_index, 0);
        bt_gatt_read(conn, &read_car_params);
    } else {
        LOG_DBG("Found identity address for peer, settings RPA direct advertisable");

        set_profile_dir_adv_caps(prof_index, DIR_ADV_CAPS_ENABLE);
    }
}
#endif /* IS_ENABLED(CONFIG_ZMK_BLE_DIRECTED_ADVERTISING) */

static void auth_pairing_complete(struct bt_conn *conn, bool bonded) {
    struct bt_conn_info info;
    char addr[BT_ADDR_LE_STR_LEN];

    bt_conn_get_info(conn, &info);

    bt_addr_le_to_str(info.le.dst, addr, sizeof(addr));

    if (info.role != BT_CONN_ROLE_PERIPHERAL) {
        LOG_DBG("SKIPPING FOR ROLE %d", info.role);
        return;
    }

#if IS_ENABLED(CONFIG_ZMK_BLE_PROFILE_MODE_EXPLICIT)
    if (!zmk_ble_active_profile_is_open()) {
        LOG_ERR("Pairing completed but current profile is not open: %s", addr);
        bt_unpair(BT_ID_DEFAULT, info.le.dst);
        return;
    }
#else
    if (select_next_open_profile() < 0) {
        LOG_ERR("Failed to find open profile for new connection");
        return;
    }
#endif

    set_profile_address(active_profile, info.le.dst);
#if IS_ENABLED(CONFIG_ZMK_BLE_DIRECTED_ADVERTISING)
    determine_direct_advertisability(conn, info.le.dst, info.le.remote);
#endif /* IS_ENABLED(CONFIG_ZMK_BLE_DIRECTED_ADVERTISING) */
    update_advertising();
};

static void auth_bond_deleted(uint8_t id, const bt_addr_le_t *peer) {
    char addr[BT_ADDR_LE_STR_LEN];

    if (bt_addr_le_cmp(peer, BT_ADDR_LE_ANY) == 0) {
        LOG_DBG("Skipping clear for any address");
        return;
    }

    bt_addr_le_to_str(peer, addr, sizeof(addr));
    LOG_DBG("Clearing profile for %s", addr);

    for (int i = 0; i < ZMK_BLE_PROFILE_COUNT; i++) {
        if (bt_addr_le_cmp(&profiles[i].peer, BT_ADDR_LE_ANY) == 0) {
            continue;
        }

        if (bt_addr_le_cmp(&profiles[i].peer, peer) == 0) {
            bt_addr_le_to_str(&profiles[i].peer, addr, sizeof(addr));
            LOG_DBG("Clearing profile %d of %s (comp %d", i, addr,
                    bt_addr_le_cmp(&profiles[i].peer, peer));
            set_profile_address(i, BT_ADDR_LE_ANY);
        }
    }
}

static struct bt_conn_auth_cb zmk_ble_auth_cb_display = {
    .pairing_accept = auth_pairing_accept,
// .passkey_display = auth_passkey_display,

#if IS_ENABLED(CONFIG_ZMK_BLE_PASSKEY_ENTRY)
    .passkey_entry = auth_passkey_entry,
#endif
    .cancel = auth_cancel,
};

static struct bt_conn_auth_info_cb zmk_ble_auth_info_cb_display = {
    .pairing_complete = auth_pairing_complete,
    .bond_deleted = auth_bond_deleted,
};

static void zmk_ble_ready(int err) {
    LOG_DBG("ready? %d", err);
    if (err) {
        LOG_ERR("Bluetooth init failed (err %d)", err);
        return;
    }

    update_advertising();
}

static int zmk_ble_init(const struct device *_arg) {
    int err = bt_enable(NULL);

    if (err) {
        LOG_ERR("BLUETOOTH FAILED (%d)", err);
        return err;
    }

#if IS_ENABLED(CONFIG_SETTINGS)
    settings_subsys_init();

    err = settings_register(&profiles_handler);
    if (err) {
        LOG_ERR("Failed to setup the profile settings handler (err %d)", err);
        return err;
    }

    k_work_init_delayable(&ble_save_work, ble_save_profile_work);

    settings_load_subtree("ble");
    settings_load_subtree("bt");

#endif

#if IS_ENABLED(CONFIG_ZMK_BLE_CLEAR_BONDS_ON_START)
    LOG_WRN("Clearing all existing BLE bond information from the keyboard");

    bt_unpair(BT_ID_DEFAULT, NULL);

    for (int i = 0; i < ZMK_BLE_PROFILE_COUNT; i++) {
        char setting_name[15];
        sprintf(setting_name, "ble/profiles/%d", i);

        err = settings_delete(setting_name);
        if (err) {
            LOG_ERR("Failed to delete setting: %d", err);
        }
    }
#endif

    bt_conn_cb_register(&conn_callbacks);
    bt_conn_auth_cb_register(&zmk_ble_auth_cb_display);
    bt_conn_auth_info_cb_register(&zmk_ble_auth_info_cb_display);

    zmk_ble_ready(0);

    return 0;
}

#if IS_ENABLED(CONFIG_ZMK_BLE_PASSKEY_ENTRY)

static bool zmk_ble_numeric_usage_to_value(const zmk_key_t key, const zmk_key_t one,
                                           const zmk_key_t zero, uint32_t *value) {
    if (key < one || key > zero) {
        return false;
    }

    *value = (key == zero) ? 0 : (key - one + 1);
    return true;
}

static int zmk_ble_handle_key_user(struct zmk_keycode_state_changed *event) {
    zmk_key_t key = event->keycode;

    LOG_DBG("key %d", key);

    if (!auth_passkey_entry_conn) {
        LOG_DBG("No connection for passkey entry");
        return ZMK_EV_EVENT_BUBBLE;
    }

    if (!event->state) {
        LOG_DBG("Key released, ignoring");
        return ZMK_EV_EVENT_BUBBLE;
    }

    if (key == HID_USAGE_KEY_KEYBOARD_ESCAPE) {
        bt_conn_auth_cancel(auth_passkey_entry_conn);
        return ZMK_EV_EVENT_HANDLED;
    }

    uint32_t val;
    if (!(zmk_ble_numeric_usage_to_value(key, HID_USAGE_KEY_KEYBOARD_1_AND_EXCLAMATION,
                                         HID_USAGE_KEY_KEYBOARD_0_AND_RIGHT_PARENTHESIS, &val) ||
          zmk_ble_numeric_usage_to_value(key, HID_USAGE_KEY_KEYPAD_1_AND_END,
                                         HID_USAGE_KEY_KEYPAD_0_AND_INSERT, &val))) {
        LOG_DBG("Key not a number, ignoring");
        return ZMK_EV_EVENT_BUBBLE;
    }

    passkey_entries[passkey_digit++] = val;
    LOG_DBG("value entered: %d, digits collected so far: %d", val, passkey_digit);

    if (passkey_digit == PASSKEY_DIGITS) {
        uint32_t passkey = 0;
        for (int i = 0; i < PASSKEY_DIGITS; i++) {
            passkey = (passkey * 10) + passkey_entries[i];
        }

        LOG_DBG("Final passkey: %d", passkey);
        bt_conn_auth_passkey_entry(auth_passkey_entry_conn, passkey);
        bt_conn_unref(auth_passkey_entry_conn);
        auth_passkey_entry_conn = NULL;
    }

    return ZMK_EV_EVENT_HANDLED;
}

static int zmk_ble_listener(const zmk_event_t *eh) {
    struct zmk_keycode_state_changed *kc_state;

    kc_state = as_zmk_keycode_state_changed(eh);

    if (kc_state != NULL) {
        return zmk_ble_handle_key_user(kc_state);
    }

    return 0;
}

ZMK_LISTENER(zmk_ble, zmk_ble_listener);
ZMK_SUBSCRIPTION(zmk_ble, zmk_keycode_state_changed);
#endif /* IS_ENABLED(CONFIG_ZMK_BLE_PASSKEY_ENTRY) */

SYS_INIT(zmk_ble_init, APPLICATION, CONFIG_ZMK_BLE_INIT_PRIORITY);
