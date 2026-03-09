#include <errno.h>
#include <stdint.h>

#include <zephyr/device.h>
#include <zephyr/input/input.h>
#include <zephyr/logging/log.h>
#include <zephyr/sys/util.h>
#include <zephyr/dt-bindings/input/input-event-codes.h>

LOG_MODULE_DECLARE(ble_hogp_sniffer, CONFIG_ZMK_BLE_HOGP_SNIFFER_LOG_LEVEL);

#define HOGP_POINTER_INPUT_DEVICE DT_NODELABEL(hogp_kscan)

static int report_input_event(const struct device *dev, uint8_t type, uint16_t code, int32_t value,
                              bool sync) {
    int err = input_report(dev, type, code, value, sync, K_NO_WAIT);

    if (err) {
        LOG_WRN("input_report failed type=%u code=%u val=%d sync=%d err=%d", type, code, value,
                sync ? 1 : 0, err);
    }

    return err;
}

int zmk_hogp_proxy_pointer_event(int16_t dx, int16_t dy, int8_t wheel, uint8_t buttons) {
    static uint8_t prev_buttons;
    static bool ready_checked;
    static bool ready;
    const struct device *dev = DEVICE_DT_GET(HOGP_POINTER_INPUT_DEVICE);
    uint8_t btn_changes = 0U;
    uint8_t total_events = 0U;
    uint8_t sent_events = 0U;

    if (!ready_checked) {
        ready = device_is_ready(dev);
        ready_checked = true;
        if (!ready) {
            LOG_WRN("pointer input device not ready");
        }
    }

    if (!ready) {
        return -ENODEV;
    }

    if (IS_ENABLED(CONFIG_ZMK_BLE_HOGP_SNIFFER_POINTER_DEBUG_LOG)) {
        LOG_INF("pointer in dx=%d dy=%d wheel=%d btn=0x%02x", dx, dy, wheel, buttons);
    }

    if (dx != 0) {
        total_events++;
    }
    if (dy != 0) {
        total_events++;
    }
    if (wheel != 0) {
        total_events++;
    }
    for (uint8_t bit = 0U; bit < 5U; bit++) {
        bool prev = (prev_buttons & BIT(bit)) != 0U;
        bool curr = (buttons & BIT(bit)) != 0U;
        if (prev != curr) {
            btn_changes++;
        }
    }
    total_events = (uint8_t)(total_events + btn_changes);

    if (total_events == 0U) {
        return 0;
    }

    if (dx != 0) {
        sent_events++;
        (void)report_input_event(dev, INPUT_EV_REL, INPUT_REL_X, dx, sent_events == total_events);
    }

    if (dy != 0) {
        sent_events++;
        (void)report_input_event(dev, INPUT_EV_REL, INPUT_REL_Y, dy, sent_events == total_events);
    }

    if (wheel != 0) {
        sent_events++;
        (void)report_input_event(dev, INPUT_EV_REL, INPUT_REL_WHEEL, wheel,
                                 sent_events == total_events);
    }

    for (uint8_t bit = 0U; bit < 5U; bit++) {
        bool prev = (prev_buttons & BIT(bit)) != 0U;
        bool curr = (buttons & BIT(bit)) != 0U;

        if (prev == curr) {
            continue;
        }

        sent_events++;
        (void)report_input_event(dev, INPUT_EV_KEY, (uint16_t)(INPUT_BTN_0 + bit), curr ? 1 : 0,
                                 sent_events == total_events);
    }

    prev_buttons = buttons;

    return 0;
}
