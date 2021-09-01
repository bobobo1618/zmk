/*
 * Copyright (c) 2020 The ZMK Contributors
 *
 * SPDX-License-Identifier: MIT
 */

#define DT_DRV_COMPAT zmk_behavior_sensor_rotate_key_press

#include <device.h>
#include <drivers/behavior.h>
#include <logging/log.h>

#include <drivers/sensor.h>
#include <zmk/sensors.h>
#include <zmk/event_manager.h>
#include <zmk/events/keycode_state_changed.h>

LOG_MODULE_DECLARE(zmk, CONFIG_ZMK_LOG_LEVEL);

#if DT_HAS_COMPAT_STATUS_OKAY(DT_DRV_COMPAT)

struct behavior_sensor_rotate_key_press_cfg {
    uint8_t activation_resolution;
};

struct behavior_sensor_rotate_key_press_sensor_data {
    int32_t remainder[ZMK_KEYMAP_SENSORS_LEN];
};

static int behavior_sensor_rotate_key_press_init(const struct device *dev) { return 0; };

static int on_sensor_binding_triggered(struct zmk_behavior_binding *binding,
                                       struct zmk_behavior_binding_event event,
                                       size_t channel_data_size,
                                       const struct zmk_sensor_channel_data *channel_data) {
    const struct device *behavior_dev = device_get_binding(binding->behavior_dev);
    const struct sensor_value *value = &channel_data[0].value;
    const struct behavior_sensor_rotate_key_press_cfg *cfg = behavior_dev->config;
    struct behavior_sensor_rotate_key_press_sensor_data *data = behavior_dev->data;

    uint32_t keycode;

    data->remainder[event.position] += value->val1;

    int8_t triggers = data->remainder[event.position] / cfg->activation_resolution;
    data->remainder[event.position] %= cfg->activation_resolution;

    LOG_DBG("value: %d, remainder: %d triggers: %d inc keycode 0x%02X dec keycode 0x%02X",
            value->val1, data->remainder[event.position], triggers, binding->param1,
            binding->param2);

    if (triggers > 0) {
        keycode = binding->param1;
    } else if (triggers < 0) {
        keycode = binding->param2;
        triggers = -triggers;
    } else {
        return 0;
    }

    LOG_DBG("SEND %d", keycode);

    for (int i = 0; i < triggers; i++) {
        ZMK_EVENT_RAISE(zmk_keycode_state_changed_from_encoded(keycode, true, event.timestamp));

        // TODO: Better way to do this?
        k_msleep(5);

        ZMK_EVENT_RAISE(zmk_keycode_state_changed_from_encoded(keycode, false, event.timestamp));
    }

    return 0;
}

static const struct behavior_driver_api behavior_sensor_rotate_key_press_driver_api = {
    .sensor_binding_triggered = on_sensor_binding_triggered};

#define KP_INST(n)                                                                                 \
    static const struct behavior_sensor_rotate_key_press_cfg                                       \
        behavior_sensor_rotate_key_press_cfg_##n = {                                               \
            .activation_resolution =                                                               \
                (360 / DT_INST_PROP_OR(n, triggers_per_rotation,                                   \
                                       CONFIG_ZMK_ENCODERS_DEFAULT_TRIGGERS_PER_ROTATION))};       \
    static struct behavior_sensor_rotate_key_press_sensor_data                                     \
        behavior_sensor_rotate_key_press_sensor_data_##n;                                          \
    DEVICE_DT_INST_DEFINE(n, behavior_sensor_rotate_key_press_init, NULL,                          \
                          &behavior_sensor_rotate_key_press_sensor_data_##n,                       \
                          &behavior_sensor_rotate_key_press_cfg_##n, APPLICATION,                  \
                          CONFIG_KERNEL_INIT_PRIORITY_DEFAULT,                                     \
                          &behavior_sensor_rotate_key_press_driver_api);

DT_INST_FOREACH_STATUS_OKAY(KP_INST)

#endif /* DT_HAS_COMPAT_STATUS_OKAY(DT_DRV_COMPAT) */
