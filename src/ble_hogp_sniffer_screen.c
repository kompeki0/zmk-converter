#include <stdio.h>
#include <string.h>

#include <zephyr/kernel.h>
#include <zephyr/sys/util.h>

#include "ble_hogp_sniffer_internal.h"

#if defined(CONFIG_ZMK_BLE_HOGP_SNIFFER_FORWARD_KEY_EVENTS)
static bool char_to_usage(char c, uint8_t *usage, bool *need_shift) {
    *need_shift = false;

    if (c >= 'a' && c <= 'z') {
        *usage = (uint8_t)(0x04 + (c - 'a'));
        return true;
    }
    if (c >= 'A' && c <= 'Z') {
        *usage = (uint8_t)(0x04 + (c - 'A'));
        *need_shift = true;
        return true;
    }
    if (c >= '1' && c <= '9') {
        *usage = (uint8_t)(0x1E + (c - '1'));
        return true;
    }
    if (c == '0') {
        *usage = 0x27;
        return true;
    }
    if (c == ' ') {
        *usage = 0x2C;
        return true;
    }
    if (c == '\n') {
        *usage = 0x28;
        return true;
    }
    if (c == '-') {
        *usage = 0x2D;
        return true;
    }
    if (c == ':') {
        *usage = 0x33;
        *need_shift = true;
        return true;
    }
    if (c == '*') {
        *usage = 0x25;
        *need_shift = true;
        return true;
    }
    if (c == ';') {
        *usage = 0x33;
        return true;
    }
    return false;
}
#endif

void zmk_hogp_sniffer_type_text_line(zmk_hogp_sniffer_emit_usage_cb_t emit_usage, const char *text) {
#if defined(CONFIG_ZMK_BLE_HOGP_SNIFFER_FORWARD_KEY_EVENTS)
    if (!IS_ENABLED(CONFIG_ZMK_BLE_HOGP_SNIFFER_FORWARD_KEY_EVENTS) || !emit_usage) {
        return;
    }

    for (size_t i = 0; text[i] != '\0'; i++) {
        uint8_t usage;
        bool need_shift;

        if (!char_to_usage(text[i], &usage, &need_shift)) {
            continue;
        }

        if (need_shift) {
            emit_usage(0xE1, true);
            k_msleep(1);
        }

        emit_usage(usage, true);
        k_msleep(1);
        emit_usage(usage, false);

        if (need_shift) {
            k_msleep(1);
            emit_usage(0xE1, false);
        }
        k_msleep(2);
    }
    emit_usage(0x28, true);
    k_msleep(1);
    emit_usage(0x28, false);
#else
    ARG_UNUSED(emit_usage);
    ARG_UNUSED(text);
#endif
}

void zmk_hogp_sniffer_screen_log_target_addr(zmk_hogp_sniffer_emit_usage_cb_t emit_usage,
                                             const char *prefix, const bt_addr_le_t *addr) {
#if defined(CONFIG_ZMK_BLE_HOGP_SNIFFER_FORWARD_KEY_EVENTS)
    char line[64];
    char addr_str[BT_ADDR_LE_STR_LEN];

    if (!addr) {
        return;
    }

    bt_addr_le_to_str(addr, addr_str, sizeof(addr_str));
    snprintf(line, sizeof(line), "%s %s", prefix, addr_str);
    zmk_hogp_sniffer_type_text_line(emit_usage, line);
#else
    ARG_UNUSED(emit_usage);
    ARG_UNUSED(prefix);
    ARG_UNUSED(addr);
#endif
}

void zmk_hogp_sniffer_screen_log_target_code(zmk_hogp_sniffer_emit_usage_cb_t emit_usage,
                                             const char *prefix, uint8_t code) {
#if defined(CONFIG_ZMK_BLE_HOGP_SNIFFER_FORWARD_KEY_EVENTS)
    char line[64];

    snprintf(line, sizeof(line), "%s %u", prefix, (uint32_t)code);
    zmk_hogp_sniffer_type_text_line(emit_usage, line);
#else
    ARG_UNUSED(emit_usage);
    ARG_UNUSED(prefix);
    ARG_UNUSED(code);
#endif
}

void zmk_hogp_sniffer_screen_log_target_reason(zmk_hogp_sniffer_emit_usage_cb_t emit_usage,
                                               const char *prefix, uint8_t code,
                                               const char *reason) {
#if defined(CONFIG_ZMK_BLE_HOGP_SNIFFER_FORWARD_KEY_EVENTS)
    char line[96];
    char rs[32];
    size_t j = 0U;

    for (size_t i = 0; reason && reason[i] != '\0' && j + 1U < sizeof(rs); i++) {
        uint8_t c = (uint8_t)reason[i];
        rs[j++] = zmk_hogp_sniffer_is_ascii_alnum(c) ? (char)c : 'x';
    }
    rs[j] = '\0';

    snprintf(line, sizeof(line), "%s %u %s", prefix, (uint32_t)code, rs[0] ? rs : "unknown");
    zmk_hogp_sniffer_type_text_line(emit_usage, line);
#else
    ARG_UNUSED(emit_usage);
    ARG_UNUSED(prefix);
    ARG_UNUSED(code);
    ARG_UNUSED(reason);
#endif
}

void zmk_hogp_sniffer_screen_log_verbose_code(zmk_hogp_sniffer_emit_usage_cb_t emit_usage,
                                              const char *prefix, uint32_t code) {
#if defined(CONFIG_ZMK_BLE_HOGP_SNIFFER_FORWARD_KEY_EVENTS)
    char line[64];

    if (!IS_ENABLED(CONFIG_ZMK_BLE_HOGP_SNIFFER_SCREEN_LOG_VERBOSE)) {
        return;
    }

    snprintf(line, sizeof(line), "%s %u", prefix, code);
    zmk_hogp_sniffer_type_text_line(emit_usage, line);
#else
    ARG_UNUSED(emit_usage);
    ARG_UNUSED(prefix);
    ARG_UNUSED(code);
#endif
}

void zmk_hogp_sniffer_screen_log_verbose_text(zmk_hogp_sniffer_emit_usage_cb_t emit_usage,
                                              const char *text) {
#if defined(CONFIG_ZMK_BLE_HOGP_SNIFFER_FORWARD_KEY_EVENTS)
    if (!IS_ENABLED(CONFIG_ZMK_BLE_HOGP_SNIFFER_SCREEN_LOG_VERBOSE)) {
        return;
    }

    zmk_hogp_sniffer_type_text_line(emit_usage, text);
#else
    ARG_UNUSED(emit_usage);
    ARG_UNUSED(text);
#endif
}
