/*
 * Copyright (c) 2020 The ZMK Contributors
 *
 * SPDX-License-Identifier: MIT
 */

#pragma once

#include <drivers/sensor.h>

#define _SENSOR_CHILD_LEN(node) 1 +
#define ZMK_KEYMAP_SENSORS_NODE DT_INST(0, zmk_keymap_sensors)
// #define ZMK_KEYMAP_SENSORS_FOREACH(fn) DT_FOREACH_CHILD(ZMK_KEYMAP_SENSORS_NODE, fn)
// #define ZMK_KEYMAP_SENSORS_FOREACH(fn) DT_FOREACH_CHILD(ZMK_KEYMAP_SENSORS_NODE, fn)
#define ZMK_KEYMAP_SENSORS_LEN DT_PROP_LEN(ZMK_KEYMAP_SENSORS_NODE, sensors)

// #define ZMK_KEYMAP_SENSORS_LEN (DT_FOREACH_CHILD(ZMK_KEYMAP_SENSORS_NODE, _SENSOR_CHILD_LEN) 0)
#define ZMK_KEYMAP_HAS_SENSORS DT_NODE_HAS_STATUS(ZMK_KEYMAP_SENSORS_NODE, okay)
#define ZMK_KEYMAP_SENSORS_BY_IDX(idx) DT_PHANDLE_BY_IDX(ZMK_KEYMAP_SENSORS_NODE, sensors, idx)

struct zmk_sensor_channel_data {
    enum sensor_channel channel;
    struct sensor_value value;
};
