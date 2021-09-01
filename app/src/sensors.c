/*
 * Copyright (c) 2020 The ZMK Contributors
 *
 * SPDX-License-Identifier: MIT
 */

#include <drivers/sensor.h>
#include <devicetree.h>
#include <init.h>

#include <logging/log.h>

LOG_MODULE_DECLARE(zmk, CONFIG_ZMK_LOG_LEVEL);

#include <zmk/sensors.h>
#include <zmk/event_manager.h>
#include <zmk/events/sensor_event.h>

#if ZMK_KEYMAP_HAS_SENSORS

struct sensors_item_cfg {
    uint8_t sensor_position;
    const struct device *dev;
    struct sensor_trigger trigger;
};

#define _SENSOR_ITEM(node)                                                                         \
    {.dev = COND_CODE_0(DT_NODE_HAS_STATUS(node, okay), (NULL), (DEVICE_DT_GET(node))),            \
     .trigger = {.type = SENSOR_TRIG_DELTA, .chan = SENSOR_CHAN_ROTATION}},
#define SENSOR_ITEM(idx, _i) _SENSOR_ITEM(ZMK_KEYMAP_SENSORS_BY_IDX(idx))

static struct sensors_item_cfg sensors[] = {UTIL_LISTIFY(ZMK_KEYMAP_SENSORS_LEN, SENSOR_ITEM, 0)};

static void zmk_sensors_trigger_handler(const struct device *dev, struct sensor_trigger *trigger) {
    int err;
    struct sensors_item_cfg *item = CONTAINER_OF(trigger, struct sensors_item_cfg, trigger);

    LOG_DBG("sensor %d", item->sensor_position);

    err = sensor_sample_fetch(dev);
    if (err) {
        LOG_WRN("Failed to fetch sample from device %d", err);
        return;
    }

    struct sensor_value value;
    err = sensor_channel_get(dev, item->trigger.chan, &value);

    if (err) {
        LOG_WRN("Failed to get channel data from device %d", err);
        return;
    }

    ZMK_EVENT_RAISE(new_zmk_sensor_event(
        (struct zmk_sensor_event){.sensor_position = item->sensor_position,
                                  .channel_data = {(struct zmk_sensor_channel_data){
                                      .value = value, .channel = item->trigger.chan}},
                                  .timestamp = k_uptime_get()}));
}

static void zmk_sensors_init_item(uint8_t i) {
    LOG_DBG("Init sensor at index %d", i);

    sensors[i].sensor_position = i;

    if (!sensors[i].dev) {
        LOG_DBG("No local device for %d", i);
        return;
    }

    int err = sensor_trigger_set(sensors[i].dev, &sensors[i].trigger, zmk_sensors_trigger_handler);
    if (err) {
        LOG_WRN("Failed to set sensor trigger (%d)", err);
    }
}

#define _SENSOR_INIT(idx, _t) zmk_sensors_init_item(idx);

static int zmk_sensors_init(const struct device *_arg) {
    UTIL_LISTIFY(ZMK_KEYMAP_SENSORS_LEN, _SENSOR_INIT, 0)

    return 0;
}

SYS_INIT(zmk_sensors_init, APPLICATION, CONFIG_APPLICATION_INIT_PRIORITY);

#endif /* ZMK_KEYMAP_HAS_SENSORS */
