

#define DT_DRV_COMPAT magalpha_ma730

#include <drivers/spi.h>
#include <device.h>
#include <drivers/gpio.h>
#include <sys/util.h>
#include <sys/byteorder.h>
#include <kernel.h>
#include <drivers/sensor.h>
#include <sys/__assert.h>
#include <logging/log.h>

#include "ma730.h"

LOG_MODULE_REGISTER(MA730, CONFIG_SENSOR_LOG_LEVEL);

static int ma730_raw_read(const struct device *dev, uint16_t *value) {
    struct ma730_data *data = dev->data;
    const struct ma730_config *cfg = dev->config;
    const struct spi_config *spi_cfg = &cfg->bus_cfg.spi_cfg->spi_conf;
    uint8_t buffer_tx[2] = {0, 0};
    const struct spi_buf tx_buf = {
        .buf = buffer_tx,
        .len = 2,
    };
    const struct spi_buf_set tx = {.buffers = &tx_buf, .count = 1};
    const struct spi_buf rx_buf = {
        .buf = value,
        .len = 2,
    };
    const struct spi_buf_set rx = {.buffers = &rx_buf, .count = 1};

    if (spi_transceive(data->bus, spi_cfg, &tx, &rx)) {
        return -EIO;
    }

    *value = sys_be16_to_cpu(*value);
    LOG_DBG("MA730 angle value %hu", *value);
    return 0;
}

static int ma730_spi_read_data(const struct device *dev, uint16_t *value) {
    return ma730_raw_read(dev, value);
}

static const struct ma730_transfer_function ma730_spi_transfer_fn = {
    .read_data = ma730_spi_read_data,

};

int ma730_spi_init(const struct device *dev) {
    struct ma730_data *data = dev->data;
    const struct ma730_config *cfg = dev->config;
    const struct ma730_spi_cfg *spi_cfg = cfg->bus_cfg.spi_cfg;

    data->hw_tf = &ma730_spi_transfer_fn;

    if (spi_cfg->cs_gpios_label != NULL) {

        /* handle SPI CS thru GPIO if it is the case */
        data->cs_ctrl.gpio_dev = device_get_binding(spi_cfg->cs_gpios_label);
        if (!data->cs_ctrl.gpio_dev) {
            LOG_ERR("Unable to get GPIO SPI CS device");
            return -ENODEV;
        }
    }

    return 0;
}

static int ma730_sample_fetch(const struct device *dev, enum sensor_channel chan) {
    struct ma730_data *data = dev->data;
    const struct ma730_config *cfg = dev->config;
    uint16_t val;
    int8_t velocity;

    __ASSERT_NO_MSG(chan == SENSOR_CHAN_ALL || chan == SENSOR_CHAN_ROTATION ||
                    chan == SENSOR_CHAN_RPM);
    if (ma730_spi_read_data(dev, &val)) {
        return -EIO;
    }
    data->oldangle = data->angle;
    data->angle = val;

    return 0;
}

static int ma730_channel_get(const struct device *dev, enum sensor_channel chan,
                             struct sensor_value *val) {
    struct ma730_data *data = dev->data;
    const struct ma730_config *cfg = dev->config;

    if (chan != SENSOR_CHAN_ROTATION && chan != SENSOR_CHAN_RPM) {
        return -ENOTSUP;
    } else if (chan == SENSOR_CHAN_ROTATION) {
        int absang = (data->angle / (65536 / 360));
        int absoldang = (data->oldangle / (65536 / 360));
        int delta = absang - absoldang;
        if (delta > 180) {
            delta = -1 * (360 - delta);
        } else if (delta < -180) {
            delta = delta + 360;
        }
        LOG_DBG("Absolute Angle: %d, Delta: %d", absang, delta);
        val->val1 = delta;
    } else {
        // velocity code
    }

    return 0;
}

static const struct sensor_driver_api ma730_driver_api = {
#ifdef CONFIG_MA730_TRIGGER
    .trigger_set = ma730_trigger_set,
#endif
    // .attr_set = ma730_attr_set,
    .sample_fetch = ma730_sample_fetch,
    .channel_get = ma730_channel_get,
};

static int ma730_init_chip(const struct device *dev) {
    struct ma730_data *data = dev->data;
    return 0;
}

static int ma730_init(const struct device *dev) {
    const struct ma730_config *const config = dev->config;
    struct ma730_data *data = dev->data;

    data->bus = device_get_binding(config->bus_name);
    if (!data->bus) {
        LOG_DBG("master not found: %s", log_strdup(config->bus_name));
        return -EINVAL;
    }

    config->bus_init(dev);

    if (ma730_init_chip(dev) < 0) {
        LOG_DBG("failed to initialize chip");
        return -EIO;
    }

    // Fetch an initial angle, to be sure the first delta reported has a baseline old angle.
    ma730_sample_fetch(dev, SENSOR_CHAN_ROTATION);
    data->oldangle = data->angle;

#ifdef CONFIG_MA730_TRIGGER
    if (ma730_init_interrupt(dev) < 0) {
        LOG_DBG("Failed to initialize interrupt!");
        return -EIO;
    }
#endif

    return 0;
}

#define MA730_HAS_CS(n) DT_INST_SPI_DEV_HAS_CS_GPIOS(n)

#define MA730_DATA_SPI_CS(n)                                                                       \
    {                                                                                              \
        .cs_ctrl = {                                                                               \
            .gpio_pin = DT_INST_SPI_DEV_CS_GPIOS_PIN(n),                                           \
            .gpio_dt_flags = DT_INST_SPI_DEV_CS_GPIOS_FLAGS(n),                                    \
        },                                                                                         \
    }

#define MA730_DATA_SPI(n) COND_CODE_1(MA730_HAS_CS(n), (MA730_DATA_SPI_CS(n)), ({}))

#define MA730_SPI_CS_PTR(n) COND_CODE_1(MA730_HAS_CS(n), (&(ma730_data_##n.cs_ctrl)), (NULL))

#define MA730_SPI_CS_LABEL(n)                                                                      \
    COND_CODE_1(MA730_HAS_CS(n), (DT_INST_SPI_DEV_CS_GPIOS_LABEL(n)), (NULL))

#define MA730_SPI_CFG(n)                                                                           \
    (&(struct ma730_spi_cfg){                                                                      \
        .spi_conf =                                                                                \
            {                                                                                      \
                .frequency = DT_INST_PROP(n, spi_max_frequency),                                   \
                .operation =                                                                       \
                    (SPI_WORD_SET(8) | SPI_OP_MODE_MASTER | SPI_MODE_CPOL | SPI_MODE_CPHA),        \
                .slave = DT_INST_REG_ADDR(n),                                                      \
                .cs = MA730_SPI_CS_PTR(n),                                                         \
            },                                                                                     \
        .cs_gpios_label = MA730_SPI_CS_LABEL(n),                                                   \
    })

#define MA730_GPIO_DT_SPEC_GET_BY_IDX(node_id, prop, idx)                                          \
    {                                                                                              \
        .port = DEVICE_DT_GET(DT_GPIO_CTLR_BY_IDX(node_id, prop, idx)),                            \
        .pin = DT_GPIO_PIN_BY_IDX(node_id, prop, idx),                                             \
        .dt_flags = DT_GPIO_FLAGS_BY_IDX(node_id, prop, idx),                                      \
    }

#define MA730_CONFIG_SPI(n)                                                                        \
    {                                                                                              \
        .bus_name = DT_INST_BUS_LABEL(n), .bus_init = ma730_spi_init,                              \
        .bus_cfg = {.spi_cfg = MA730_SPI_CFG(n)},                                                  \
        COND_CODE_0(DT_INST_NODE_HAS_PROP(n, resolution), (1), (DT_INST_PROP(n, resolution)))      \
            COND_CODE_1(CONFIG_MA730_TRIGGER,                                                      \
                        (, MA730_GPIO_DT_SPEC_GET_BY_IDX(DT_DRV_INST(n), a_gpios, 0),              \
                         MA730_GPIO_DT_SPEC_GET_BY_IDX(DT_DRV_INST(n), b_gpios, 0)),               \
                        ())                                                                        \
    }

#define MA730_INST(n)                                                                              \
    static struct ma730_data ma730_data_##n = MA730_DATA_SPI(n);                                   \
    static const struct ma730_config ma730_cfg_##n = MA730_CONFIG_SPI(n);                          \
    DEVICE_DT_INST_DEFINE(n, ma730_init, device_pm_control_nop, &ma730_data_##n, &ma730_cfg_##n,   \
                          POST_KERNEL, CONFIG_SENSOR_INIT_PRIORITY, &ma730_driver_api);

DT_INST_FOREACH_STATUS_OKAY(MA730_INST)
