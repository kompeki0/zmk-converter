#include <errno.h>
#include <stdbool.h>
#include <stdint.h>

#include <zephyr/device.h>
#include <zephyr/drivers/gpio.h>
#include <zephyr/drivers/kscan.h>
#include <zephyr/kernel.h>
#include <zephyr/logging/log.h>
#include <zephyr/sys/util.h>

#if defined(CONFIG_ZMK_BLE_HOGP_SNIFFER_LOG_LEVEL)
LOG_MODULE_REGISTER(kscan_hogp_proxy, CONFIG_ZMK_BLE_HOGP_SNIFFER_LOG_LEVEL);
#else
LOG_MODULE_REGISTER(kscan_hogp_proxy, LOG_LEVEL_INF);
#endif

struct hogp_proxy_kscan_event {
    uint16_t row;
    uint16_t col;
    bool pressed;
};

struct hogp_proxy_kscan_config {
    uint16_t rows;
    uint16_t cols;
    struct gpio_dt_spec buttons[4];
};

struct hogp_proxy_kscan_data {
    const struct device *dev;
    kscan_callback_t callback;
    bool enabled;

    struct k_msgq msgq;
    struct hogp_proxy_kscan_event qbuf[32];
    struct k_work work;
    struct gpio_callback gpio_cbs[4];
    bool btn_pressed[4];
};

static struct hogp_proxy_kscan_data *g_inst;

static void hogp_proxy_gpio_cb(const struct device *port, struct gpio_callback *cb, uint32_t pins) {
    ARG_UNUSED(port);
    ARG_UNUSED(cb);
    ARG_UNUSED(pins);

    if (!g_inst) {
        return;
    }

    const struct hogp_proxy_kscan_config *cfg = g_inst->dev->config;

    for (uint8_t i = 0; i < ARRAY_SIZE(cfg->buttons); i++) {
        int val = gpio_pin_get_dt(&cfg->buttons[i]);
        if (val < 0) {
            continue;
        }

        bool pressed = (val > 0);
        if (pressed == g_inst->btn_pressed[i]) {
            continue;
        }

        g_inst->btn_pressed[i] = pressed;
        (void)zmk_hogp_proxy_kscan_inject(0, (uint16_t)(114 + i), pressed);
    }
}

static void hogp_proxy_kscan_work_handler(struct k_work *work) {
    struct hogp_proxy_kscan_data *data = CONTAINER_OF(work, struct hogp_proxy_kscan_data, work);
    struct hogp_proxy_kscan_event ev;

    while (k_msgq_get(&data->msgq, &ev, K_NO_WAIT) == 0) {
        if (data->enabled && data->callback) {
            data->callback(data->dev, ev.row, ev.col, ev.pressed);
        }
    }
}

static int hogp_proxy_kscan_configure(const struct device *dev, kscan_callback_t callback) {
    struct hogp_proxy_kscan_data *data = dev->data;
    data->callback = callback;
    return 0;
}

static int hogp_proxy_kscan_enable_callback(const struct device *dev) {
    struct hogp_proxy_kscan_data *data = dev->data;
    data->enabled = true;
    return 0;
}

static int hogp_proxy_kscan_disable_callback(const struct device *dev) {
    struct hogp_proxy_kscan_data *data = dev->data;
    data->enabled = false;
    return 0;
}

static const struct kscan_driver_api hogp_proxy_kscan_api = {
    .config = hogp_proxy_kscan_configure,
    .enable_callback = hogp_proxy_kscan_enable_callback,
    .disable_callback = hogp_proxy_kscan_disable_callback,
};

static int hogp_proxy_kscan_init(const struct device *dev) {
    const struct hogp_proxy_kscan_config *cfg = dev->config;
    struct hogp_proxy_kscan_data *data = dev->data;

    if (cfg->rows == 0 || cfg->cols == 0) {
        return -EINVAL;
    }

    data->dev = dev;
    data->callback = NULL;
    data->enabled = false;

    k_msgq_init(&data->msgq, (char *)data->qbuf, sizeof(data->qbuf[0]), ARRAY_SIZE(data->qbuf));
    k_work_init(&data->work, hogp_proxy_kscan_work_handler);

    for (uint8_t i = 0; i < ARRAY_SIZE(cfg->buttons); i++) {
        if (!gpio_is_ready_dt(&cfg->buttons[i])) {
            LOG_ERR("button %u GPIO not ready", i);
            return -ENODEV;
        }

        int err = gpio_pin_configure_dt(&cfg->buttons[i], GPIO_INPUT);
        if (err) {
            LOG_ERR("button %u configure failed (%d)", i, err);
            return err;
        }

        err = gpio_pin_interrupt_configure_dt(&cfg->buttons[i], GPIO_INT_EDGE_BOTH);
        if (err) {
            LOG_ERR("button %u irq config failed (%d)", i, err);
            return err;
        }

        gpio_init_callback(&data->gpio_cbs[i], hogp_proxy_gpio_cb, BIT(cfg->buttons[i].pin));
        err = gpio_add_callback(cfg->buttons[i].port, &data->gpio_cbs[i]);
        if (err) {
            LOG_ERR("button %u add callback failed (%d)", i, err);
            return err;
        }

        int val = gpio_pin_get_dt(&cfg->buttons[i]);
        data->btn_pressed[i] = (val > 0);
    }

    g_inst = data;
    return 0;
}

int zmk_hogp_proxy_kscan_inject(uint16_t row, uint16_t col, bool pressed) {
    if (!g_inst) {
        return -ENODEV;
    }

    struct hogp_proxy_kscan_event ev = {
        .row = row,
        .col = col,
        .pressed = pressed,
    };

    int err = k_msgq_put(&g_inst->msgq, &ev, K_NO_WAIT);
    if (err) {
        /* Drop on overflow; caller can retry if needed. */
        return err;
    }

    k_work_submit(&g_inst->work);
    return 0;
}

/* Single instance, referenced via /chosen zmk,kscan.
 * Avoid DT_PROP(rows/columns) for now: some ZMK/Zephyr setups won't pick up
 * external bindings, causing property macros to be missing at compile-time.
 */
#define HOGP_PROXY_KSCAN_NODE DT_INST(0, zmk_kscan_hogp_proxy)
#define HOGP_PROXY_ROWS 1
#define HOGP_PROXY_COLS 118

BUILD_ASSERT(DT_NUM_INST_STATUS_OKAY(zmk_kscan_hogp_proxy) <= 1,
             "Only one zmk,kscan-hogp-proxy instance is supported");

static const struct hogp_proxy_kscan_config hogp_proxy_kscan_cfg = {
    .rows = HOGP_PROXY_ROWS,
    .cols = HOGP_PROXY_COLS,
    .buttons =
        {
            GPIO_DT_SPEC_GET_BY_IDX(HOGP_PROXY_KSCAN_NODE, input_gpios, 0),
            GPIO_DT_SPEC_GET_BY_IDX(HOGP_PROXY_KSCAN_NODE, input_gpios, 1),
            GPIO_DT_SPEC_GET_BY_IDX(HOGP_PROXY_KSCAN_NODE, input_gpios, 2),
            GPIO_DT_SPEC_GET_BY_IDX(HOGP_PROXY_KSCAN_NODE, input_gpios, 3),
        },
};

static struct hogp_proxy_kscan_data hogp_proxy_kscan_data;

DEVICE_DT_DEFINE(HOGP_PROXY_KSCAN_NODE, hogp_proxy_kscan_init, NULL, &hogp_proxy_kscan_data,
                 &hogp_proxy_kscan_cfg, POST_KERNEL, CONFIG_KERNEL_INIT_PRIORITY_DEFAULT,
                 &hogp_proxy_kscan_api);
