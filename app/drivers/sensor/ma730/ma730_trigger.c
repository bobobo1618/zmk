/*
 * Copyright (c) 2020 The ZMK Contributors
 *
 * SPDX-License-Identifier: MIT
 */

#define DT_DRV_COMPAT magalpha_ma730

#include <device.h>
#include <drivers/gpio.h>
#include <sys/util.h>
#include <kernel.h>
#include <drivers/sensor.h>

#include "ma730.h"

// extern struct ma730_data ma730_driver;

#include <logging/log.h>
LOG_MODULE_DECLARE(MA730, CONFIG_SENSOR_LOG_LEVEL);

static inline void setup_int(const struct device *dev, bool enable) {
    struct ma730_data *data = dev->data;
    const struct ma730_config *cfg = dev->config;

    if (gpio_pin_interrupt_configure(cfg->a_spec.port, cfg->a_spec.pin,
                                     enable ? GPIO_INT_EDGE_TO_ACTIVE : GPIO_INT_DISABLE)) {
        LOG_WRN("Unable to set A pin GPIO interrupt");
    }

    /*
    if (gpio_pin_interrupt_configure(cfg->b_spec.port, cfg->b_spec.pin,
                                     enable ? GPIO_INT_EDGE_BOTH : GPIO_INT_DISABLE)) {
        LOG_WRN("Unable to set B pin GPIO interrupt");
    }
    */
}

static void ma730_a_gpio_callback(const struct device *dev, struct gpio_callback *cb,
                                  uint32_t pins) {
    struct ma730_data *drv_data = CONTAINER_OF(cb, struct ma730_data, a_gpio_cb);

    LOG_DBG("");

    setup_int(drv_data->dev, false);

#if defined(CONFIG_MA730_TRIGGER_OWN_THREAD)
    k_sem_give(&drv_data->gpio_sem);
#elif defined(CONFIG_MA730_TRIGGER_GLOBAL_THREAD)
    k_work_submit(&drv_data->work);
#endif
}

/*
static void ma730_b_gpio_callback(const struct device *dev, struct gpio_callback *cb,
                             uint32_t pins) {
struct ma730_data *drv_data = CONTAINER_OF(cb, struct ma730_data, b_gpio_cb);

LOG_DBG("");

setup_int(drv_data->dev, false);

#if defined(CONFIG_MA730_TRIGGER_OWN_THREAD)
k_sem_give(&drv_data->gpio_sem);
#elif defined(CONFIG_MA730_TRIGGER_GLOBAL_THREAD)
k_work_submit(&drv_data->work);
#endif
}
*/

static void ma730_thread_cb(const struct device *dev) {
    struct ma730_data *drv_data = dev->data;

    LOG_DBG("%p", drv_data->handler);
    drv_data->handler(dev, drv_data->trigger);

    // Enable once the wall/spam of interrupts is solved
    setup_int(dev, true);
}

#ifdef CONFIG_MA730_TRIGGER_OWN_THREAD
static void ma730_thread(int dev_ptr, int unused) {
    const struct device *dev = INT_TO_POINTER(dev_ptr);
    struct ma730_data *drv_data = dev->data;

    ARG_UNUSED(unused);

    while (1) {
        k_sem_take(&drv_data->gpio_sem, K_FOREVER);
        ma730_thread_cb(dev);
    }
}
#endif

#ifdef CONFIG_MA730_TRIGGER_GLOBAL_THREAD
static void ma730_work_cb(struct k_work *work) {
    struct ma730_data *drv_data = CONTAINER_OF(work, struct ma730_data, work);

    LOG_DBG("");

    ma730_thread_cb(drv_data->dev);
}
#endif

int ma730_trigger_set(const struct device *dev, const struct sensor_trigger *trig,
                      sensor_trigger_handler_t handler) {
    struct ma730_data *drv_data = dev->data;

    setup_int(dev, false);

    k_msleep(5);

    drv_data->trigger = trig;
    drv_data->handler = handler;

    setup_int(dev, true);

    return 0;
}

int ma730_init_interrupt(const struct device *dev) {
    struct ma730_data *drv_data = dev->data;
    const struct ma730_config *drv_cfg = dev->config;

    drv_data->dev = dev;
    /* setup gpio interrupt */

    gpio_init_callback(&drv_data->a_gpio_cb, ma730_a_gpio_callback, BIT(drv_cfg->a_spec.pin));

    if (gpio_add_callback(drv_cfg->a_spec.port, &drv_data->a_gpio_cb) < 0) {
        LOG_DBG("Failed to set A callback!");
        return -EIO;
    }

    /*
    gpio_init_callback(&drv_data->b_gpio_cb, ma730_b_gpio_callback, BIT(drv_cfg->b_spec.pin));

    if (gpio_add_callback(drv_cfg->b_spec.port, &drv_data->b_gpio_cb) < 0) {
        LOG_DBG("Failed to set B callback!");
        return -EIO;
    }
    */

#if defined(CONFIG_MA730_TRIGGER_OWN_THREAD)
    k_sem_init(&drv_data->gpio_sem, 0, UINT_MAX);

    k_thread_create(&drv_data->thread, drv_data->thread_stack, CONFIG_MA730_THREAD_STACK_SIZE,
                    (k_thread_entry_t)ma730_thread, dev, 0, NULL,
                    K_PRIO_COOP(CONFIG_MA730_THREAD_PRIORITY), 0, K_NO_WAIT);
#elif defined(CONFIG_MA730_TRIGGER_GLOBAL_THREAD)
    k_work_init(&drv_data->work, ma730_work_cb);
#endif

    return 0;
}
