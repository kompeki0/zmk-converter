#include <errno.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>

#include <zephyr/bluetooth/addr.h>
#include <zephyr/bluetooth/bluetooth.h>
#include <zephyr/bluetooth/conn.h>
#include <zephyr/bluetooth/gatt.h>
#include <zephyr/bluetooth/uuid.h>
#include <zephyr/init.h>
#include <zephyr/kernel.h>
#include <zephyr/logging/log.h>
#include <zephyr/settings/settings.h>
#include <zephyr/sys/byteorder.h>
#include <zephyr/sys/util.h>

#include <zmk/ble.h>
#include <zmk/event_manager.h>
#include <zmk/split/bluetooth/uuid.h>
#include <zmk/usb.h>

#if defined(CONFIG_ZMK_BLE_HOGP_SNIFFER_FORWARD_KEY_EVENTS)
#include <zmk/events/keycode_state_changed.h>
#include <dt-bindings/zmk/keys.h>
#endif

LOG_MODULE_REGISTER(ble_hogp_sniffer, CONFIG_ZMK_BLE_HOGP_SNIFFER_LOG_LEVEL);

#define BOOT_KBD_REPORT_LEN 8
#define MAX_PRESSED_USAGES 14
#define MAX_REPORT_SUBSCRIPTIONS 6
#define MAX_SCAN_CANDIDATES 12
#define MAX_PICKER_DEVICES 16
#define PICKER_NAME_MAX 20
#define CONSUMER_SLOT_BASE 104
#define CONSUMER_SLOT_COUNT 10

static struct bt_conn *default_conn;
static struct bt_gatt_discover_params discover_params;
static struct bt_gatt_subscribe_params subscribe_params[MAX_REPORT_SUBSCRIPTIONS];
static bt_addr_le_t target_addr;
static bool selected_target_valid;
static bool target_any_addr;
static bool target_match_any_type;
static bt_addr_le_t candidate_addrs[MAX_SCAN_CANDIDATES];
struct picker_device {
    bt_addr_le_t addr;
    char name[PICKER_NAME_MAX];
    int8_t rssi;
};
static struct picker_device picker_devices[MAX_PICKER_DEVICES];
static uint8_t picker_device_count;
static uint8_t picker_selected_index;
static struct k_work_delayable sniffer_start_work;
static struct k_work_delayable reconnect_work;
static struct k_work_delayable scan_cycle_work;
static struct k_work_delayable candidate_connect_work;
static struct k_work_delayable picker_probe_timeout_work;
static struct k_work picker_button_work;
K_MSGQ_DEFINE(picker_button_msgq, sizeof(uint8_t), 16, 4);
#if defined(CONFIG_ZMK_BLE_HOGP_SNIFFER_SELFTEST_TYPE_TESTING_ON_BOOT) &&                                \
    defined(CONFIG_ZMK_BLE_HOGP_SNIFFER_FORWARD_KEY_EVENTS)
static struct k_work_delayable selftest_work;
static uint8_t selftest_attempts;
static uint8_t selftest_pos;
static bool selftest_press;
static bool selftest_done;
#endif

static uint16_t hids_start_handle;
static uint16_t hids_end_handle;
static bool scanning;
static bool connecting;
static bool in_candidate_sequence;
static uint8_t candidate_count;
static uint8_t candidate_index;
static bool gatt_discovery_started;
static uint8_t reconnect_fail_count;
static bool host_adv_blocked;
static bool host_connected;
static bool target_hid_verified;
static int64_t next_connect_allowed_ms;
static uint8_t report_sub_count;
static uint16_t pending_report_char_handle;
static uint16_t pending_report_value_handle;
static struct bt_gatt_read_params picker_name_read_params;
static bool picker_name_probe_active;
static uint8_t picker_probe_indices[MAX_PICKER_DEVICES];
static uint8_t picker_probe_count;
static uint8_t picker_probe_pos;
static int picker_probe_current_idx;

static struct bt_uuid_16 hids_uuid = BT_UUID_INIT_16(BT_UUID_HIDS_VAL);
static struct bt_uuid_16 report_uuid = BT_UUID_INIT_16(BT_UUID_HIDS_REPORT_VAL);
static struct bt_uuid_16 ccc_uuid = BT_UUID_INIT_16(BT_UUID_GATT_CCC_VAL);
static struct bt_uuid_16 gap_device_name_uuid = BT_UUID_INIT_16(BT_UUID_GAP_DEVICE_NAME_VAL);
static const struct bt_le_conn_param target_conn_param = {
    .interval_min = 24, /* 30ms */
    .interval_max = 40, /* 50ms */
    .latency = 0,
    .timeout = 800, /* 8s supervision timeout */
};

static uint8_t prev_usages[MAX_PRESSED_USAGES];
static size_t prev_usage_count;
static uint8_t prev_consumer_slots[CONSUMER_SLOT_COUNT];
static size_t prev_consumer_slot_count;

struct persisted_target_addr {
    uint8_t type;
    uint8_t a[6];
};

static bool persisted_target_valid;

static int start_scan(void);
static int connect_to_candidate(const bt_addr_le_t *addr);
static bool try_next_candidate_or_rescan(void);
static bool candidate_list_contains(const bt_addr_le_t *addr);
static void schedule_connect_current_candidate(uint32_t delay_ms);
static int clear_non_target_bonds(void);
static void schedule_scan_restart(void);
static void apply_host_adv_policy(bool target_connected);
static bool should_wait_for_host(void);
static bool host_ready_for_target_scan(void);
static bool ad_contains_hids_uuid(const struct net_buf_simple *ad);
static bool ad_contains_split_service_uuid(const struct net_buf_simple *ad);
static bool picker_name_is_unknown(const char *name);
static void picker_begin_name_probe(void);
static void picker_try_next_name_probe(void);
static uint8_t picker_name_read_cb(struct bt_conn *conn, uint8_t err, struct bt_gatt_read_params *params,
                                   const void *data, uint16_t length);
static void picker_probe_timeout_work_handler(struct k_work *work);
static int resume_report_discovery(struct bt_conn *conn, uint16_t next_start_handle);
static uint8_t discover_report_cb(struct bt_conn *conn, const struct bt_gatt_attr *attr,
                                  struct bt_gatt_discover_params *params);
static void picker_button_work_handler(struct k_work *work);
static int save_persisted_target_addr(const bt_addr_le_t *addr);
static int load_persisted_target_addr(bt_addr_le_t *addr, bool *valid);
static void clear_all_bonds_cb(const struct bt_bond_info *info, void *user_data);
static const char *hci_reason_to_str(uint8_t reason);
static const char *sec_err_to_str(enum bt_security_err err);

#if defined(CONFIG_ZMK_BLE_HOGP_SNIFFER_FORWARD_KEY_EVENTS)
static void emit_usage_state(uint8_t usage, bool pressed);
#endif

int zmk_hogp_proxy_kscan_inject(uint16_t row, uint16_t col, bool pressed);

static bool usage_to_row_col(uint8_t usage, uint16_t *row, uint16_t *col) {
    /* "100%" (ANSI 104) superset mapping for Keyboard/Keypad page (0x07).
     * We map a curated usage list to a dense position index (1 row x N cols).
     *
     * Notes:
     * - Modifiers (0xE0..0xE7) are injected from the modifier bitfield.
     * - Some keys (Intl/JIS) and non-boot consumer/system keys are excluded for now.
     */
    static const uint8_t usage_order[] = {
        /* Top row */
        0x29,                         /* ESC */
        0x3A, 0x3B, 0x3C, 0x3D,        /* F1..F4 */
        0x3E, 0x3F, 0x40, 0x41,        /* F5..F8 */
        0x42, 0x43, 0x44, 0x45,        /* F9..F12 */
        0x46, 0x47, 0x48,              /* PRINT_SCREEN, SCROLL_LOCK, PAUSE */

        /* Alnum block */
        0x35,                         /* GRAVE */
        0x1E, 0x1F, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, /* 1..0 */
        0x2D, 0x2E, 0x2A,              /* -, =, BACKSPACE */

        0x2B,                         /* TAB */
        0x14, 0x1A, 0x08, 0x15, 0x17, 0x1C, 0x18, 0x0C, 0x12, 0x13, /* Q..P */
        0x2F, 0x30, 0x31,              /* [, ], \ */

        0x39,                         /* CAPS_LOCK */
        0x04, 0x16, 0x07, 0x09, 0x0A, 0x0B, 0x0D, 0x0E, 0x0F,       /* A..L */
        0x33, 0x34, 0x28,              /* ;, ', ENTER */

        0xE1,                         /* LSHIFT */
        0x1D, 0x1B, 0x06, 0x19, 0x05, 0x11, 0x10, 0x36, 0x37, 0x38, /* Z.. / */
        0xE5,                         /* RSHIFT */

        0xE0, 0xE3, 0xE2, 0x2C, 0xE6, 0xE7, 0x65, 0xE4, /* LCTRL, LGUI, LALT, SPACE, RALT, RGUI, APP, RCTRL */

        /* Navigation cluster */
        0x49, 0x4A, 0x4B,              /* INSERT, HOME, PAGE_UP */
        0x4C, 0x4D, 0x4E,              /* DELETE, END, PAGE_DOWN */
        0x52, 0x50, 0x51, 0x4F,        /* UP, LEFT, DOWN, RIGHT */

        /* Numpad */
        0x53, 0x54, 0x55, 0x56,        /* NUM_LOCK, KP /, KP *, KP - */
        0x5F, 0x60, 0x61, 0x57,        /* KP7, KP8, KP9, KP+ */
        0x5C, 0x5D, 0x5E,              /* KP4, KP5, KP6 */
        0x59, 0x5A, 0x5B, 0x58,        /* KP1, KP2, KP3, KP_ENTER */
        0x62, 0x63,                    /* KP0, KP. */
    };

    for (uint16_t i = 0; i < (uint16_t)ARRAY_SIZE(usage_order); i++) {
        if (usage_order[i] == usage) {
            *row = 0;
            *col = i;
            return true;
        }
    }

    return false;
}

#if defined(CONFIG_ZMK_BLE_HOGP_SNIFFER_SELFTEST_TYPE_TESTING_ON_BOOT) &&                                \
    defined(CONFIG_ZMK_BLE_HOGP_SNIFFER_FORWARD_KEY_EVENTS)
static const uint8_t selftest_usages[] = {
    0x17, /* t */
    0x08, /* e */
    0x16, /* s */
    0x17, /* t */
    0x0c, /* i */
    0x11, /* n */
    0x0a, /* g */
};

static void selftest_work_handler(struct k_work *work) {
    ARG_UNUSED(work);

    if (!IS_ENABLED(CONFIG_ZMK_BLE_HOGP_SNIFFER_SELFTEST_TYPE_TESTING_ON_BOOT) || selftest_done) {
        return;
    }

    /* For the USB connectivity test, only run when HID is ready. */
    if (!zmk_usb_is_hid_ready()) {
        if (selftest_attempts++ < 30) {
            k_work_schedule(&selftest_work, K_MSEC(500));
        }
        return;
    }

    if (selftest_pos >= ARRAY_SIZE(selftest_usages)) {
        selftest_done = true;
        return;
    }

    uint8_t usage = selftest_usages[selftest_pos];

    if (!selftest_press) {
        emit_usage_state(usage, true);
        selftest_press = true;
        k_work_schedule(&selftest_work, K_MSEC(20));
        return;
    }

    emit_usage_state(usage, false);
    selftest_press = false;
    selftest_pos++;
    k_work_schedule(&selftest_work, K_MSEC(60));
}
#endif

static bool usage_exists(const uint8_t *usages, size_t count, uint8_t usage) {
    for (size_t i = 0; i < count; i++) {
        if (usages[i] == usage) {
            return true;
        }
    }

    return false;
}

static const char *hci_reason_to_str(uint8_t reason) {
    switch (reason) {
#ifdef BT_HCI_ERR_UNKNOWN_CONN_ID
    case BT_HCI_ERR_UNKNOWN_CONN_ID:
        return "unknown_conn_id";
#endif
#ifdef BT_HCI_ERR_AUTH_FAIL
    case BT_HCI_ERR_AUTH_FAIL:
        return "auth_fail";
#endif
#ifdef BT_HCI_ERR_PIN_OR_KEY_MISSING
    case BT_HCI_ERR_PIN_OR_KEY_MISSING:
        return "pin_or_key_missing";
#endif
#ifdef BT_HCI_ERR_CONN_TIMEOUT
    case BT_HCI_ERR_CONN_TIMEOUT:
        return "conn_timeout";
#endif
#ifdef BT_HCI_ERR_CONN_LIMIT_EXCEEDED
    case BT_HCI_ERR_CONN_LIMIT_EXCEEDED:
        return "conn_limit_exceeded";
#endif
#ifdef BT_HCI_ERR_CONN_FAIL_TO_ESTAB
    case BT_HCI_ERR_CONN_FAIL_TO_ESTAB:
        return "conn_fail_to_estab";
#endif
#ifdef BT_HCI_ERR_REMOTE_USER_TERM_CONN
    case BT_HCI_ERR_REMOTE_USER_TERM_CONN:
        return "remote_user_term";
#endif
#ifdef BT_HCI_ERR_REMOTE_LOW_RESOURCES
    case BT_HCI_ERR_REMOTE_LOW_RESOURCES:
        return "remote_low_resources";
#endif
#ifdef BT_HCI_ERR_REMOTE_POWER_OFF
    case BT_HCI_ERR_REMOTE_POWER_OFF:
        return "remote_power_off";
#endif
#ifdef BT_HCI_ERR_UNSUPP_REMOTE_FEATURE
    case BT_HCI_ERR_UNSUPP_REMOTE_FEATURE:
        return "unsupported_remote_feature";
#endif
#ifdef BT_HCI_ERR_PAIRING_NOT_SUPPORTED
    case BT_HCI_ERR_PAIRING_NOT_SUPPORTED:
        return "pairing_not_supported";
#endif
#ifdef BT_HCI_ERR_UNACCEPT_CONN_PARAM
    case BT_HCI_ERR_UNACCEPT_CONN_PARAM:
        return "unacceptable_conn_param";
#endif
#ifdef BT_HCI_ERR_ADV_TIMEOUT
    case BT_HCI_ERR_ADV_TIMEOUT:
        return "adv_timeout";
#endif
#ifdef BT_HCI_ERR_TERM_DUE_TO_MIC_FAIL
    case BT_HCI_ERR_TERM_DUE_TO_MIC_FAIL:
        return "mic_fail";
#endif
    default:
        return "unknown";
    }
}

static const char *sec_err_to_str(enum bt_security_err err) {
    switch (err) {
#ifdef BT_SECURITY_ERR_SUCCESS
    case BT_SECURITY_ERR_SUCCESS:
        return "success";
#endif
#ifdef BT_SECURITY_ERR_AUTH_FAIL
    case BT_SECURITY_ERR_AUTH_FAIL:
        return "auth_fail";
#endif
#ifdef BT_SECURITY_ERR_PIN_OR_KEY_MISSING
    case BT_SECURITY_ERR_PIN_OR_KEY_MISSING:
        return "pin_or_key_missing";
#endif
#ifdef BT_SECURITY_ERR_OOB_NOT_AVAILABLE
    case BT_SECURITY_ERR_OOB_NOT_AVAILABLE:
        return "oob_not_available";
#endif
#ifdef BT_SECURITY_ERR_AUTH_REQUIREMENT
    case BT_SECURITY_ERR_AUTH_REQUIREMENT:
        return "auth_requirement";
#endif
#ifdef BT_SECURITY_ERR_PAIR_NOT_SUPPORTED
    case BT_SECURITY_ERR_PAIR_NOT_SUPPORTED:
        return "pair_not_supported";
#endif
#ifdef BT_SECURITY_ERR_PAIR_NOT_ALLOWED
    case BT_SECURITY_ERR_PAIR_NOT_ALLOWED:
        return "pair_not_allowed";
#endif
#ifdef BT_SECURITY_ERR_INVALID_PARAM
    case BT_SECURITY_ERR_INVALID_PARAM:
        return "invalid_param";
#endif
#ifdef BT_SECURITY_ERR_UNSPECIFIED
    case BT_SECURITY_ERR_UNSPECIFIED:
        return "unspecified";
#endif
#ifdef BT_SECURITY_ERR_CONFIRM_VALUE_FAILED
    case BT_SECURITY_ERR_CONFIRM_VALUE_FAILED:
        return "confirm_value_failed";
#endif
#ifdef BT_SECURITY_ERR_PAIRING_IN_PROGRESS
    case BT_SECURITY_ERR_PAIRING_IN_PROGRESS:
        return "pairing_in_progress";
#endif
#ifdef BT_SECURITY_ERR_CROSS_TRANSP_NOT_ALLOWED
    case BT_SECURITY_ERR_CROSS_TRANSP_NOT_ALLOWED:
        return "cross_transport_not_allowed";
#endif
    default:
        return "unknown";
    }
}

static void append_usage_unique(uint8_t *usages, size_t *count, uint8_t usage) {
    if (usage == 0 || *count >= MAX_PRESSED_USAGES || usage_exists(usages, *count, usage)) {
        return;
    }

    usages[(*count)++] = usage;
}

static void build_usage_set_from_boot_report(const uint8_t *report, size_t report_len, uint8_t *usages,
                                             size_t *count) {
    uint8_t modifiers;

    *count = 0;
    if (report_len < BOOT_KBD_REPORT_LEN) {
        return;
    }

    modifiers = report[0];
    for (uint8_t bit = 0; bit < 8; bit++) {
        if (modifiers & BIT(bit)) {
            append_usage_unique(usages, count, (uint8_t)(0xE0 + bit));
        }
    }

    for (size_t i = 2; i < BOOT_KBD_REPORT_LEN; i++) {
        uint8_t usage = report[i];

        if (usage == 0x01 || usage == 0x02 || usage == 0x03) {
            continue;
        }

        append_usage_unique(usages, count, usage);
    }
}

static bool slot_exists(const uint8_t *slots, size_t count, uint8_t slot) {
    for (size_t i = 0; i < count; i++) {
        if (slots[i] == slot) {
            return true;
        }
    }
    return false;
}

static void append_slot_unique(uint8_t *slots, size_t *count, uint8_t slot) {
    if (*count >= CONSUMER_SLOT_COUNT || slot_exists(slots, *count, slot)) {
        return;
    }
    slots[(*count)++] = slot;
}

static int consumer_usage_to_slot(uint16_t usage) {
    switch (usage) {
    case 0x00EA: /* Volume Down */
        return 0;
    case 0x00E9: /* Volume Up */
        return 1;
    case 0x00E2: /* Mute */
        return 2;
    case 0x00B6: /* Scan Previous Track */
        return 3;
    case 0x00CD: /* Play/Pause */
        return 4;
    case 0x00B5: /* Scan Next Track */
        return 5;
    case 0x00B7: /* Stop */
        return 6;
    case 0x006F: /* Brightness Increment */
        return 7;
    case 0x0070: /* Brightness Decrement */
        return 8;
    case 0x00F8: /* Mic Mute (commonly used by PC keyboards) */
        return 9;
    default:
        return -ENOENT;
    }
}

static void build_consumer_slots_from_12byte_report(const uint8_t *report, size_t report_len,
                                                    uint8_t *slots, size_t *count) {
    *count = 0;
    if (report_len != 12U) {
        return;
    }

    /* Format seen on target: 12-byte array of 16-bit consumer usages. */
    for (uint8_t i = 0; i < 6U; i++) {
        uint16_t usage = sys_get_le16(&report[i * 2U]);
        int slot;

        if (usage == 0U) {
            continue;
        }

        slot = consumer_usage_to_slot(usage);
        if (slot >= 0) {
            append_slot_unique(slots, count, (uint8_t)slot);
        } else {
            LOG_DBG("Unsupported consumer usage 0x%04x", usage);
        }
    }
}

#if defined(CONFIG_ZMK_BLE_HOGP_SNIFFER_FORWARD_KEY_EVENTS)
static void emit_usage_state(uint8_t usage, bool pressed) {
    int err = raise_zmk_keycode_state_changed_from_encoded(usage, pressed, k_uptime_get());

    if (err) {
        LOG_WRN("Failed to emit usage 0x%02x (%s), err=%d", usage, pressed ? "down" : "up", err);
    } else {
        LOG_DBG("Usage 0x%02x %s", usage, pressed ? "down" : "up");
    }
}
#endif

static bool is_ascii_alnum(uint8_t c) {
    return ((c >= '0' && c <= '9') || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z'));
}

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
        *usage = SPACE;
        return true;
    }
    if (c == '\n') {
        *usage = ENTER;
        return true;
    }
    if (c == '-') {
        *usage = MINUS;
        return true;
    }
    if (c == ':') {
        *usage = SEMI;
        *need_shift = true;
        return true;
    }
    if (c == '*') {
        *usage = N8;
        *need_shift = true;
        return true;
    }
    if (c == ';') {
        *usage = SEMI;
        return true;
    }
    return false;
}

static void type_text_line(const char *text) {
    if (!IS_ENABLED(CONFIG_ZMK_BLE_HOGP_SNIFFER_FORWARD_KEY_EVENTS)) {
        return;
    }

    for (size_t i = 0; text[i] != '\0'; i++) {
        uint8_t usage;
        bool need_shift;

        if (!char_to_usage(text[i], &usage, &need_shift)) {
            continue;
        }

        if (need_shift) {
            emit_usage_state(LSHIFT, true);
            k_msleep(1);
        }

        emit_usage_state(usage, true);
        k_msleep(1);
        emit_usage_state(usage, false);

        if (need_shift) {
            k_msleep(1);
            emit_usage_state(LSHIFT, false);
        }
        k_msleep(2);
    }
    emit_usage_state(ENTER, true);
    k_msleep(1);
    emit_usage_state(ENTER, false);
}
#endif

struct ad_name_ctx {
    char *out;
    size_t cap;
    size_t len;
    bool found;
};

static bool ad_parse_name_cb(struct bt_data *data, void *user_data) {
    struct ad_name_ctx *ctx = user_data;

    if (ctx->found) {
        return false;
    }

    if (data->type != BT_DATA_NAME_COMPLETE && data->type != BT_DATA_NAME_SHORTENED) {
        return true;
    }

    for (size_t i = 0; i < data->data_len && ctx->len + 1 < ctx->cap; i++) {
        uint8_t c = data->data[i];
        if (is_ascii_alnum(c)) {
            ctx->out[ctx->len++] = (char)c;
        } else {
            /* Keep length/shape of name while avoiding unsupported glyphs. */
            ctx->out[ctx->len++] = 'x';
        }
    }
    ctx->out[ctx->len] = '\0';
    ctx->found = (ctx->len > 0);
    return false;
}

static bool extract_alnum_name(const struct net_buf_simple *ad, char *out, size_t out_len) {
    struct net_buf_simple ad_copy = *ad;
    struct ad_name_ctx ctx = {.out = out, .cap = out_len, .len = 0, .found = false};

    if (out_len == 0U) {
        return false;
    }
    out[0] = '\0';
    bt_data_parse(&ad_copy, ad_parse_name_cb, &ctx);
    return ctx.found;
}

static int picker_find_index_by_addr(const bt_addr_le_t *addr) {
    for (uint8_t i = 0; i < picker_device_count; i++) {
        if (picker_devices[i].addr.type == addr->type &&
            bt_addr_eq(&picker_devices[i].addr.a, &addr->a)) {
            return i;
        }
    }
    return -ENOENT;
}

static bool picker_name_is_unknown(const char *name) {
    return (name == NULL || name[0] == '\0' || strncmp(name, "UNK", 3) == 0);
}

static uint8_t picker_item_count(void) { return (uint8_t)(picker_device_count + 2U); }

static void picker_announce_current(const char *prefix) {
    char buf[48];
    uint8_t items = picker_item_count();

    if (picker_selected_index >= items) {
        picker_selected_index = 0;
    }

    if (picker_selected_index == 0U) {
        snprintf(buf, sizeof(buf), "%s 0 RESETALL", prefix);
        LOG_INF("%s", buf);
#if defined(CONFIG_ZMK_BLE_HOGP_SNIFFER_FORWARD_KEY_EVENTS)
        type_text_line(buf);
#endif
        return;
    }

    if (picker_selected_index == 1U) {
        snprintf(buf, sizeof(buf), "%s 1 OTHER", prefix);
        LOG_INF("%s", buf);
#if defined(CONFIG_ZMK_BLE_HOGP_SNIFFER_FORWARD_KEY_EVENTS)
        type_text_line(buf);
#endif
        return;
    }

    snprintf(buf, sizeof(buf), "%s %u %s", prefix, (uint32_t)picker_selected_index,
             picker_devices[picker_selected_index - 2U].name);
    LOG_INF("%s", buf);
#if defined(CONFIG_ZMK_BLE_HOGP_SNIFFER_FORWARD_KEY_EVENTS)
    type_text_line(buf);
#endif
}

#if defined(CONFIG_ZMK_BLE_HOGP_SNIFFER_FORWARD_KEY_EVENTS)
static void screen_log_target_addr(const char *prefix, const bt_addr_le_t *addr) {
    char line[64];
    char addr_str[BT_ADDR_LE_STR_LEN];

    if (!addr) {
        return;
    }

    bt_addr_le_to_str(addr, addr_str, sizeof(addr_str));
    snprintf(line, sizeof(line), "%s %s", prefix, addr_str);
    type_text_line(line);
}

static void screen_log_target_code(const char *prefix, uint8_t code) {
    char line[64];
    snprintf(line, sizeof(line), "%s %u", prefix, (uint32_t)code);
    type_text_line(line);
}

static void screen_log_verbose_code(const char *prefix, uint32_t code) {
    char line[64];
    if (!IS_ENABLED(CONFIG_ZMK_BLE_HOGP_SNIFFER_SCREEN_LOG_VERBOSE)) {
        return;
    }
    snprintf(line, sizeof(line), "%s %u", prefix, code);
    type_text_line(line);
}

static void screen_log_verbose_text(const char *text) {
    if (!IS_ENABLED(CONFIG_ZMK_BLE_HOGP_SNIFFER_SCREEN_LOG_VERBOSE)) {
        return;
    }
    type_text_line(text);
}
#endif

static void picker_add_or_update(const bt_addr_le_t *addr, const char *name, int8_t rssi) {
    char fallback[PICKER_NAME_MAX];
    const char *use_name = name;
    int idx = picker_find_index_by_addr(addr);

    if (!name || name[0] == '\0') {
        snprintf(fallback, sizeof(fallback), "UNK%02X%02X%02X", addr->a.val[2], addr->a.val[1],
                 addr->a.val[0]);
        use_name = fallback;
    }

    if (idx >= 0) {
        picker_devices[idx].rssi = rssi;
        if (picker_devices[idx].name[0] == '\0' && use_name[0] != '\0') {
            strncpy(picker_devices[idx].name, use_name, sizeof(picker_devices[idx].name) - 1);
            picker_devices[idx].name[sizeof(picker_devices[idx].name) - 1] = '\0';
        }
        return;
    }

    if (picker_device_count >= MAX_PICKER_DEVICES) {
        return;
    }

    bt_addr_le_copy(&picker_devices[picker_device_count].addr, addr);
    picker_devices[picker_device_count].rssi = rssi;
    strncpy(picker_devices[picker_device_count].name, use_name,
            sizeof(picker_devices[picker_device_count].name) - 1);
    picker_devices[picker_device_count].name[sizeof(picker_devices[picker_device_count].name) - 1] =
        '\0';
    LOG_INF("Found candidate %u: %s (rssi=%d)", (uint8_t)(picker_device_count + 1U),
            picker_devices[picker_device_count].name, rssi);
    picker_device_count++;
}

static void picker_try_next_name_probe(void) {
    if (!picker_name_probe_active) {
        return;
    }

    while (picker_probe_pos < picker_probe_count) {
        int idx = (int)picker_probe_indices[picker_probe_pos++];

        if (idx < 0 || idx >= picker_device_count) {
            continue;
        }

        picker_probe_current_idx = idx;
        bt_addr_le_copy(&target_addr, &picker_devices[idx].addr);
        selected_target_valid = true;
        target_any_addr = false;
        target_match_any_type = true;
        target_hid_verified = false;
        reconnect_fail_count = 0;
        in_candidate_sequence = false;
        candidate_count = 0;
        candidate_index = 0;
        memset(candidate_addrs, 0, sizeof(candidate_addrs));

        if (scanning) {
            int serr = bt_le_scan_stop();
            if (serr && serr != -EALREADY) {
                LOG_WRN("Scan stop before probe failed (%d)", serr);
            }
            scanning = false;
        }

        LOG_INF("name probe connect %u/%u", picker_probe_pos, picker_probe_count);
        if (connect_to_candidate(&target_addr)) {
            picker_try_next_name_probe();
        }
        return;
    }

    picker_name_probe_active = false;
    picker_probe_count = 0;
    picker_probe_pos = 0;
    picker_probe_current_idx = -1;
    selected_target_valid = false;
    target_hid_verified = false;
    picker_selected_index = 1U;
    picker_announce_current("other done");
    (void)start_scan();
}

static void picker_begin_name_probe(void) {
    picker_probe_count = 0;
    picker_probe_pos = 0;
    picker_probe_current_idx = -1;

    for (uint8_t i = 0; i < picker_device_count && picker_probe_count < MAX_PICKER_DEVICES; i++) {
        if (picker_name_is_unknown(picker_devices[i].name)) {
            picker_probe_indices[picker_probe_count++] = i;
        }
    }

    if (picker_probe_count == 0U) {
        picker_announce_current("other none");
        return;
    }

    picker_name_probe_active = true;
    picker_announce_current("other probe");
    picker_try_next_name_probe();
}

static int settings_set_target_addr(const char *name, size_t len_rd, settings_read_cb read_cb,
                                    void *cb_arg) {
    struct persisted_target_addr raw;
    int len;

    if (strcmp(name, "target_addr") != 0) {
        return -ENOENT;
    }

    if (len_rd != sizeof(raw)) {
        return -EINVAL;
    }

    len = read_cb(cb_arg, &raw, sizeof(raw));
    if (len != sizeof(raw)) {
        return -EIO;
    }

    if (raw.type != BT_ADDR_LE_PUBLIC && raw.type != BT_ADDR_LE_RANDOM) {
        persisted_target_valid = false;
        return -EINVAL;
    }

    target_addr.type = raw.type;
    memcpy(target_addr.a.val, raw.a, sizeof(raw.a));
    persisted_target_valid = true;
    return 0;
}

static int settings_commit_target_addr(void) { return 0; }

SETTINGS_STATIC_HANDLER_DEFINE(ble_hogp_sniffer, "ble_hogp_sniffer", NULL, settings_set_target_addr,
                               settings_commit_target_addr, NULL);

static int save_persisted_target_addr(const bt_addr_le_t *addr) {
    struct persisted_target_addr raw;

    if (!addr) {
        return -EINVAL;
    }

    raw.type = addr->type;
    memcpy(raw.a, addr->a.val, sizeof(raw.a));
    return settings_save_one("ble_hogp_sniffer/target_addr", &raw, sizeof(raw));
}

static int load_persisted_target_addr(bt_addr_le_t *addr, bool *valid) {
    int err;

    if (!addr || !valid) {
        return -EINVAL;
    }

    persisted_target_valid = false;
    err = settings_load_subtree("ble_hogp_sniffer");
    if (err) {
        *valid = false;
        return err;
    }

    *valid = persisted_target_valid;
    if (*valid) {
        *addr = target_addr;
    }
    return 0;
}

static void clear_all_bonds_cb(const struct bt_bond_info *info, void *user_data) {
    char addr_str[BT_ADDR_LE_STR_LEN];
    int err;
    ARG_UNUSED(user_data);

    err = bt_unpair(BT_ID_DEFAULT, &info->addr);
    bt_addr_le_to_str(&info->addr, addr_str, sizeof(addr_str));
    if (err) {
        LOG_WRN("Failed to clear bond %s (%d)", addr_str, err);
    } else {
        LOG_INF("Cleared bond: %s", addr_str);
    }
}

static void process_boot_report(const uint8_t *report, size_t report_len) {
    uint8_t curr_usages[MAX_PRESSED_USAGES];
    size_t curr_usage_count = 0;

    build_usage_set_from_boot_report(report, report_len, curr_usages, &curr_usage_count);

#if defined(CONFIG_ZMK_BLE_HOGP_SNIFFER_FORWARD_KEY_EVENTS)
    if (IS_ENABLED(CONFIG_ZMK_BLE_HOGP_SNIFFER_FORWARD_KEY_EVENTS) &&
        !IS_ENABLED(CONFIG_ZMK_BLE_HOGP_SNIFFER_EMIT_POSITION_EVENTS)) {
        for (size_t i = 0; i < prev_usage_count; i++) {
            if (!usage_exists(curr_usages, curr_usage_count, prev_usages[i])) {
                emit_usage_state(prev_usages[i], false);
            }
        }

        for (size_t i = 0; i < curr_usage_count; i++) {
            if (!usage_exists(prev_usages, prev_usage_count, curr_usages[i])) {
                emit_usage_state(curr_usages[i], true);
            }
        }
    }
#endif

#if defined(CONFIG_ZMK_BLE_HOGP_SNIFFER_EMIT_POSITION_EVENTS)
    if (IS_ENABLED(CONFIG_ZMK_BLE_HOGP_SNIFFER_EMIT_POSITION_EVENTS)) {
        for (size_t i = 0; i < prev_usage_count; i++) {
            if (!usage_exists(curr_usages, curr_usage_count, prev_usages[i])) {
                uint16_t row, col;
                if (usage_to_row_col(prev_usages[i], &row, &col)) {
                    (void)zmk_hogp_proxy_kscan_inject(row, col, false);
                }
            }
        }

        for (size_t i = 0; i < curr_usage_count; i++) {
            if (!usage_exists(prev_usages, prev_usage_count, curr_usages[i])) {
                uint16_t row, col;
                if (usage_to_row_col(curr_usages[i], &row, &col)) {
                    (void)zmk_hogp_proxy_kscan_inject(row, col, true);
                }
            }
        }
    }
#endif

    prev_usage_count = curr_usage_count;
    memcpy(prev_usages, curr_usages, curr_usage_count);
}

static void process_nkro12_report(const uint8_t *report, size_t report_len) {
    uint8_t curr_slots[CONSUMER_SLOT_COUNT];
    size_t curr_slot_count = 0;

    build_consumer_slots_from_12byte_report(report, report_len, curr_slots, &curr_slot_count);

    for (size_t i = 0; i < prev_consumer_slot_count; i++) {
        if (!slot_exists(curr_slots, curr_slot_count, prev_consumer_slots[i])) {
            (void)zmk_hogp_proxy_kscan_inject(0, (uint16_t)(CONSUMER_SLOT_BASE + prev_consumer_slots[i]),
                                              false);
        }
    }

    for (size_t i = 0; i < curr_slot_count; i++) {
        if (!slot_exists(prev_consumer_slots, prev_consumer_slot_count, curr_slots[i])) {
            (void)zmk_hogp_proxy_kscan_inject(0, (uint16_t)(CONSUMER_SLOT_BASE + curr_slots[i]), true);
        }
    }

    prev_consumer_slot_count = curr_slot_count;
    memcpy(prev_consumer_slots, curr_slots, curr_slot_count);
}

#if defined(CONFIG_ZMK_BLE_HOGP_SNIFFER_CLEAR_NON_TARGET_BONDS_ON_START)
struct clear_bonds_ctx {
    bt_addr_le_t keep;
};

static void clear_non_target_bonds_cb(const struct bt_bond_info *info, void *user_data) {
    struct clear_bonds_ctx *ctx = user_data;
    int err;
    char addr_str[BT_ADDR_LE_STR_LEN];
    bool is_target = (info->addr.type == ctx->keep.type && bt_addr_eq(&info->addr.a, &ctx->keep.a));

    if (is_target && !IS_ENABLED(CONFIG_ZMK_BLE_HOGP_SNIFFER_CLEAR_TARGET_BOND_ON_START)) {
        bt_addr_le_to_str(&info->addr, addr_str, sizeof(addr_str));
        LOG_INF("Keeping bond: %s", addr_str);
        return;
    }

    err = bt_unpair(BT_ID_DEFAULT, &info->addr);
    bt_addr_le_to_str(&info->addr, addr_str, sizeof(addr_str));
    if (err) {
        LOG_WRN("Failed to clear bond %s (%d)", addr_str, err);
    } else {
        LOG_INF("Cleared bond: %s", addr_str);
    }
}
#endif

static int clear_non_target_bonds(void) {
#if defined(CONFIG_ZMK_BLE_HOGP_SNIFFER_CLEAR_NON_TARGET_BONDS_ON_START)
    if (IS_ENABLED(CONFIG_ZMK_BLE_HOGP_SNIFFER_CLEAR_NON_TARGET_BONDS_ON_START)) {
        if (!selected_target_valid) {
            return 0;
        }
        struct clear_bonds_ctx ctx = {
            .keep = target_addr,
        };

        bt_foreach_bond(BT_ID_DEFAULT, clear_non_target_bonds_cb, &ctx);
    }
#endif
    return 0;
}

static int resume_report_discovery(struct bt_conn *conn, uint16_t next_start_handle) {
    discover_params.uuid = &report_uuid.uuid;
    discover_params.start_handle = next_start_handle;
    discover_params.end_handle = hids_end_handle;
    discover_params.type = BT_GATT_DISCOVER_CHARACTERISTIC;
    discover_params.func = discover_report_cb;
    return bt_gatt_discover(conn, &discover_params);
}

static uint8_t notify_cb(struct bt_conn *conn, struct bt_gatt_subscribe_params *params,
                         const void *data, uint16_t length) {
    ARG_UNUSED(conn);
    uint8_t sub_idx = 0xFF;

    for (uint8_t i = 0; i < report_sub_count; i++) {
        if (params == &subscribe_params[i]) {
            sub_idx = i;
            break;
        }
    }

    if (!data) {
        LOG_INF("Notification stopped (sub=%u, vh=0x%04x)", sub_idx, params->value_handle);
        return BT_GATT_ITER_STOP;
    }

    LOG_INF("HID Input notify: sub=%u vh=0x%04x len=%u", sub_idx, params->value_handle, length);
    LOG_HEXDUMP_INF(data, length, "HID Input");

    /* First real input means candidate-connect phase succeeded. */
    in_candidate_sequence = false;
    candidate_count = 0;
    candidate_index = 0;

    if (length == BOOT_KBD_REPORT_LEN) {
        process_boot_report(data, length);
    } else if (length == 12U) {
        process_nkro12_report(data, length);
    } else {
        LOG_DBG("Unsupported report format for key mapper (len=%u, sub=%u)", length, sub_idx);
    }
    return BT_GATT_ITER_CONTINUE;
}

static uint8_t discover_ccc_cb(struct bt_conn *conn, const struct bt_gatt_attr *attr,
                               struct bt_gatt_discover_params *params) {
    int err;
    ARG_UNUSED(params);

    if (!attr) {
        LOG_WRN("CCC descriptor not found for value handle 0x%04x", pending_report_value_handle);
        err = resume_report_discovery(conn, (uint16_t)(pending_report_char_handle + 1U));
        if (err) {
            LOG_ERR("Resume report discovery failed (%d)", err);
        }
        return BT_GATT_ITER_STOP;
    }

    if (bt_uuid_cmp(attr->uuid, &ccc_uuid.uuid) != 0) {
        return BT_GATT_ITER_CONTINUE;
    }

    if (report_sub_count >= MAX_REPORT_SUBSCRIPTIONS) {
        LOG_WRN("Reached max report subscriptions (%u), skip vh=0x%04x", MAX_REPORT_SUBSCRIPTIONS,
                pending_report_value_handle);
    } else {
        struct bt_gatt_subscribe_params *sub = &subscribe_params[report_sub_count];

        memset(sub, 0, sizeof(*sub));
        sub->notify = notify_cb;
        sub->value = BT_GATT_CCC_NOTIFY;
        sub->value_handle = pending_report_value_handle;
        sub->ccc_handle = attr->handle;

        err = bt_gatt_subscribe(conn, sub);
        if (err) {
            LOG_ERR("bt_gatt_subscribe failed for vh=0x%04x (%d)", pending_report_value_handle, err);
#if defined(CONFIG_ZMK_BLE_HOGP_SNIFFER_FORWARD_KEY_EVENTS)
            screen_log_verbose_code("sub err", (uint32_t)(-err));
#endif
        } else {
            reconnect_fail_count = 0;
            target_hid_verified = true;
            report_sub_count++;
            LOG_INF("Subscribed Input Report #%u (vh=0x%04x ccc=0x%04x)", report_sub_count,
                    pending_report_value_handle, attr->handle);
#if defined(CONFIG_ZMK_BLE_HOGP_SNIFFER_FORWARD_KEY_EVENTS)
            screen_log_verbose_code("sub ok", report_sub_count);
#endif
        }
    }

    err = resume_report_discovery(conn, (uint16_t)(pending_report_char_handle + 1U));
    if (err) {
        LOG_ERR("Resume report discovery failed (%d)", err);
    }

    return BT_GATT_ITER_STOP;
}

static uint8_t discover_report_cb(struct bt_conn *conn, const struct bt_gatt_attr *attr,
                                  struct bt_gatt_discover_params *params) {
    int err;
    const struct bt_gatt_chrc *chrc;
    ARG_UNUSED(params);

    if (!attr) {
        if (report_sub_count == 0) {
            LOG_ERR("No notifiable Input Report characteristic subscribed");
#if defined(CONFIG_ZMK_BLE_HOGP_SNIFFER_FORWARD_KEY_EVENTS)
            screen_log_verbose_text("no report sub");
#endif
        } else {
            LOG_INF("Report discovery complete (subscriptions=%u)", report_sub_count);
#if defined(CONFIG_ZMK_BLE_HOGP_SNIFFER_FORWARD_KEY_EVENTS)
            type_text_line("target ready");
            screen_log_verbose_code("sub total", report_sub_count);
#endif
        }
        return BT_GATT_ITER_STOP;
    }

    chrc = attr->user_data;
    if (!(chrc->properties & BT_GATT_CHRC_NOTIFY)) {
        return BT_GATT_ITER_CONTINUE;
    }

    pending_report_char_handle = attr->handle;
    pending_report_value_handle = chrc->value_handle;
    LOG_INF("Found notifiable Input Report char vh=0x%04x", chrc->value_handle);

    discover_params.uuid = &ccc_uuid.uuid;
    discover_params.start_handle = (uint16_t)(chrc->value_handle + 1U);
    discover_params.end_handle = hids_end_handle;
    discover_params.type = BT_GATT_DISCOVER_DESCRIPTOR;
    discover_params.func = discover_ccc_cb;

    err = bt_gatt_discover(conn, &discover_params);
    if (err) {
        LOG_ERR("CCC discovery failed (%d)", err);
    } else {
        LOG_INF("Discovering CCC descriptor for vh=0x%04x", chrc->value_handle);
    }

    return BT_GATT_ITER_STOP;
}

static uint8_t discover_hids_cb(struct bt_conn *conn, const struct bt_gatt_attr *attr,
                                struct bt_gatt_discover_params *params) {
    int err;
    const struct bt_gatt_service_val *svc;
    ARG_UNUSED(params);

    if (!attr) {
        LOG_ERR("HID service not found");
        return BT_GATT_ITER_STOP;
    }

    svc = attr->user_data;
    hids_start_handle = attr->handle;
    hids_end_handle = svc->end_handle;

    report_sub_count = 0;
    pending_report_char_handle = 0;
    pending_report_value_handle = 0;
    memset(subscribe_params, 0, sizeof(subscribe_params));

    err = resume_report_discovery(conn, (uint16_t)(hids_start_handle + 1U));
    if (err) {
        LOG_ERR("Report characteristic discovery failed (%d)", err);
#if defined(CONFIG_ZMK_BLE_HOGP_SNIFFER_FORWARD_KEY_EVENTS)
        screen_log_verbose_code("report disc err", (uint32_t)(-err));
#endif
    } else {
        LOG_INF("HID service found, discovering Input Report characteristics");
#if defined(CONFIG_ZMK_BLE_HOGP_SNIFFER_FORWARD_KEY_EVENTS)
        screen_log_verbose_text("hids found");
#endif
    }

    return BT_GATT_ITER_STOP;
}

static int discover_hids(struct bt_conn *conn) {
    discover_params.uuid = &hids_uuid.uuid;
    discover_params.start_handle = BT_ATT_FIRST_ATTRIBUTE_HANDLE;
    discover_params.end_handle = BT_ATT_LAST_ATTRIBUTE_HANDLE;
    discover_params.type = BT_GATT_DISCOVER_PRIMARY;
    discover_params.func = discover_hids_cb;

    return bt_gatt_discover(conn, &discover_params);
}

static void connected_cb(struct bt_conn *conn, uint8_t err) {
    int derr;
    bt_security_t wanted_sec = (bt_security_t)CONFIG_ZMK_BLE_HOGP_SNIFFER_SECURITY_LEVEL;
    const bt_addr_le_t *peer = bt_conn_get_dst(conn);
    struct bt_conn_info info = {0};
    bool is_peripheral = (bt_conn_get_info(conn, &info) == 0 && info.role == BT_CONN_ROLE_PERIPHERAL);

    if (conn != default_conn) {
        if (!err && is_peripheral) {
            host_connected = true;
            LOG_INF("Host PC connected");
            if (should_wait_for_host()) {
                (void)start_scan();
            }
        }
        return;
    }

    connecting = false;

    if (err) {
        LOG_ERR("Connection failed (err 0x%02x: %s)", err, hci_reason_to_str(err));
        if (err == BT_HCI_ERR_CONN_FAIL_TO_ESTAB || err == BT_HCI_ERR_UNKNOWN_CONN_ID) {
            next_connect_allowed_ms = k_uptime_get() + 5000;
        }
#if defined(CONFIG_ZMK_BLE_HOGP_SNIFFER_FORWARD_KEY_EVENTS)
        screen_log_target_code("target connect err", err);
#endif
        bt_conn_unref(default_conn);
        default_conn = NULL;
        if (reconnect_fail_count < UINT8_MAX) {
            reconnect_fail_count++;
        }
        if (picker_name_probe_active) {
            picker_try_next_name_probe();
            return;
        }
        (void)try_next_candidate_or_rescan();
        return;
    }

    LOG_INF("Connected to target");
#if defined(CONFIG_ZMK_BLE_HOGP_SNIFFER_FORWARD_KEY_EVENTS)
    screen_log_target_addr("target connected", peer);
    screen_log_verbose_text("conn ok");
#endif
    if (picker_name_probe_active) {
        memset(&picker_name_read_params, 0, sizeof(picker_name_read_params));
        picker_name_read_params.func = picker_name_read_cb;
        picker_name_read_params.handle_count = 0U;
        picker_name_read_params.by_uuid.start_handle = 0x0001U;
        picker_name_read_params.by_uuid.end_handle = 0xFFFFU;
        picker_name_read_params.by_uuid.uuid = &gap_device_name_uuid.uuid;

        derr = bt_gatt_read(conn, &picker_name_read_params);
        if (derr) {
            LOG_WRN("name probe bt_gatt_read failed (%d)", derr);
            (void)bt_conn_disconnect(default_conn, BT_HCI_ERR_REMOTE_USER_TERM_CONN);
        } else {
            k_work_schedule(&picker_probe_timeout_work, K_MSEC(1500));
        }
        return;
    }

    if (peer) {
        target_addr = *peer;
        selected_target_valid = true;
        target_any_addr = false;
        int serr = save_persisted_target_addr(peer);
        if (serr) {
            LOG_WRN("Failed to persist target addr (%d)", serr);
        } else {
            LOG_INF("Persisted target addr");
        }
    }
    gatt_discovery_started = false;
    apply_host_adv_policy(true);

    derr = bt_conn_le_param_update(conn, &target_conn_param);
    if (derr && derr != -EALREADY) {
        LOG_WRN("bt_conn_le_param_update request failed (%d)", derr);
    } else {
        LOG_INF("Requested stable conn params (30-50ms, lat=0, timeout=8s)");
    }

    LOG_INF("Requesting security L%u", (uint32_t)wanted_sec);
    derr = bt_conn_set_security(conn, wanted_sec);
    if (derr == -EALREADY) {
        LOG_INF("Security already satisfied (L%u)", (uint32_t)wanted_sec);
        gatt_discovery_started = true;
        derr = discover_hids(conn);
        if (derr) {
            LOG_ERR("HID discovery start failed (%d)", derr);
        }
        return;
    }

    if (derr == 0) {
        /* Wait for security_changed callback, then start discovery. */
#if defined(CONFIG_ZMK_BLE_HOGP_SNIFFER_FORWARD_KEY_EVENTS)
        screen_log_verbose_text("wait sec");
#endif
        return;
    }

    /* Some stacks can transiently fail set_security (e.g. -ENOMEM). Do not
     * bounce the link immediately; fallback to discovery and let security
     * progress in parallel if possible.
     */
    LOG_WRN("bt_conn_set_security failed (%d), fallback to discovery", derr);
    if (!gatt_discovery_started) {
        gatt_discovery_started = true;
        derr = discover_hids(conn);
        if (derr) {
            LOG_ERR("HID discovery start failed (%d)", derr);
        }
    }
}

static void disconnected_cb(struct bt_conn *conn, uint8_t reason) {
    const bt_addr_le_t *peer = bt_conn_get_dst(conn);
    struct bt_conn_info info = {0};
    bool is_peripheral = (bt_conn_get_info(conn, &info) == 0 && info.role == BT_CONN_ROLE_PERIPHERAL);

    if (conn != default_conn) {
    if (is_peripheral) {
        host_connected = false;
        LOG_INF("Host PC disconnected (reason 0x%02x)", reason);
#if defined(CONFIG_ZMK_BLE_HOGP_SNIFFER_FORWARD_KEY_EVENTS)
        screen_log_verbose_code("host disc", reason);
#endif
    }
        return;
    }

    LOG_INF("Disconnected (reason 0x%02x: %s)", reason, hci_reason_to_str(reason));
    if (reason == BT_HCI_ERR_CONN_FAIL_TO_ESTAB || reason == BT_HCI_ERR_REMOTE_USER_TERM_CONN ||
        reason == BT_HCI_ERR_CONN_TIMEOUT) {
        next_connect_allowed_ms = k_uptime_get() + 5000;
    }
#if defined(CONFIG_ZMK_BLE_HOGP_SNIFFER_FORWARD_KEY_EVENTS)
    screen_log_target_addr("target disconnected", peer);
    screen_log_target_code("target disc reason", reason);
    screen_log_verbose_text("reconnect");
#endif

    bt_conn_unref(default_conn);
    default_conn = NULL;

    for (size_t i = 0; i < prev_consumer_slot_count; i++) {
        (void)zmk_hogp_proxy_kscan_inject(0, (uint16_t)(CONSUMER_SLOT_BASE + prev_consumer_slots[i]),
                                          false);
    }

    memset(subscribe_params, 0, sizeof(subscribe_params));
    report_sub_count = 0;
    pending_report_char_handle = 0;
    pending_report_value_handle = 0;
    prev_consumer_slot_count = 0;
    memset(prev_consumer_slots, 0, sizeof(prev_consumer_slots));

#if defined(CONFIG_ZMK_BLE_HOGP_SNIFFER_FORWARD_KEY_EVENTS)
    if (IS_ENABLED(CONFIG_ZMK_BLE_HOGP_SNIFFER_FORWARD_KEY_EVENTS)) {
        for (size_t i = 0; i < prev_usage_count; i++) {
            emit_usage_state(prev_usages[i], false);
        }
    }
#endif
    prev_usage_count = 0;
    apply_host_adv_policy(should_wait_for_host() ? true : false);

    if (reconnect_fail_count < UINT8_MAX) {
        reconnect_fail_count++;
    }

    if (picker_name_probe_active) {
        k_work_cancel_delayable(&picker_probe_timeout_work);
        picker_try_next_name_probe();
        return;
    }

    (void)try_next_candidate_or_rescan();
}

static void security_changed_cb(struct bt_conn *conn, bt_security_t level, enum bt_security_err err) {
    int derr;
    bt_security_t wanted_sec = (bt_security_t)CONFIG_ZMK_BLE_HOGP_SNIFFER_SECURITY_LEVEL;

    if (conn != default_conn) {
        return;
    }

    if (err) {
        LOG_WRN("Security changed failed (level %u, err %d: %s)", (uint32_t)level, (int)err,
                sec_err_to_str(err));
#if defined(CONFIG_ZMK_BLE_HOGP_SNIFFER_FORWARD_KEY_EVENTS)
        screen_log_verbose_code("sec err", (uint32_t)err);
#endif
        return;
    }

    if (level < wanted_sec || gatt_discovery_started) {
        if (level < wanted_sec) {
            LOG_WRN("Security level insufficient: got L%u want L%u", (uint32_t)level,
                    (uint32_t)wanted_sec);
        }
        return;
    }

    gatt_discovery_started = true;
    derr = discover_hids(conn);
    if (derr) {
        LOG_ERR("HID discovery start failed (%d)", derr);
#if defined(CONFIG_ZMK_BLE_HOGP_SNIFFER_FORWARD_KEY_EVENTS)
        screen_log_verbose_code("disc err", (uint32_t)derr);
#endif
    } else {
#if defined(CONFIG_ZMK_BLE_HOGP_SNIFFER_FORWARD_KEY_EVENTS)
        screen_log_verbose_text("disc hids");
#endif
    }
}

static void pairing_complete_cb(struct bt_conn *conn, bool bonded) {
    ARG_UNUSED(conn);
    LOG_INF("Pairing complete (bonded=%u)", bonded ? 1U : 0U);
}

static void pairing_failed_cb(struct bt_conn *conn, enum bt_security_err reason) {
    ARG_UNUSED(conn);
    LOG_WRN("Pairing failed (reason=%d: %s)", (int)reason, sec_err_to_str(reason));
}

#if defined(CONFIG_BT_SMP)
static struct bt_conn_auth_info_cb auth_info_cb = {
    .pairing_complete = pairing_complete_cb,
    .pairing_failed = pairing_failed_cb,
};
#endif

BT_CONN_CB_DEFINE(conn_callbacks) = {
    .connected = connected_cb,
    .disconnected = disconnected_cb,
    .security_changed = security_changed_cb,
};

static bool ad_find_hids_uuid_cb(struct bt_data *data, void *user_data) {
    bool *found = user_data;

    if (*found) {
        return false;
    }

    if (data->type != BT_DATA_UUID16_SOME && data->type != BT_DATA_UUID16_ALL) {
        return true;
    }

    for (size_t i = 0; i + 1 < data->data_len; i += 2) {
        uint16_t uuid16 = sys_get_le16(&data->data[i]);
        if (uuid16 == BT_UUID_HIDS_VAL) {
            *found = true;
            return false;
        }
    }

    return true;
}

static bool ad_contains_hids_uuid(const struct net_buf_simple *ad) {
    struct net_buf_simple ad_copy = *ad;
    bool found = false;

    bt_data_parse(&ad_copy, ad_find_hids_uuid_cb, &found);
    return found;
}

static bool ad_find_split_uuid_cb(struct bt_data *data, void *user_data) {
    bool *found = user_data;
    static const uint8_t split_uuid_le[16] = {ZMK_SPLIT_BT_SERVICE_UUID};

    if (*found) {
        return false;
    }

    if (data->type != BT_DATA_UUID128_SOME && data->type != BT_DATA_UUID128_ALL) {
        return true;
    }

    for (size_t i = 0; i + 15U < data->data_len; i += 16U) {
        if (memcmp(&data->data[i], split_uuid_le, 16U) == 0) {
            *found = true;
            return false;
        }
    }

    return true;
}

static bool ad_contains_split_service_uuid(const struct net_buf_simple *ad) {
    struct net_buf_simple ad_copy = *ad;
    bool found = false;

    bt_data_parse(&ad_copy, ad_find_split_uuid_cb, &found);
    return found;
}

static void scan_cb(const bt_addr_le_t *addr, int8_t rssi, uint8_t adv_type,
                    struct net_buf_simple *ad) {
    char addr_str[BT_ADDR_LE_STR_LEN];
    char name[PICKER_NAME_MAX];

    if (IS_ENABLED(CONFIG_ZMK_BLE_HOGP_SNIFFER_LOG_SCAN_EVENTS)) {
        bt_addr_le_to_str(addr, addr_str, sizeof(addr_str));
        LOG_INF("ADV: %s type=%u rssi=%d", addr_str, adv_type, rssi);
    }

    if (default_conn || connecting) {
        return;
    }

    if (IS_ENABLED(CONFIG_ZMK_BLE_HOGP_SNIFFER_REJECT_SPLIT_UUID_IN_ADV) &&
        ad_contains_split_service_uuid(ad)) {
        LOG_DBG("Seen with split UUID in AD type=%u, skip", adv_type);
        return;
    }

    if (IS_ENABLED(CONFIG_ZMK_BLE_HOGP_SNIFFER_REQUIRE_HIDS_IN_ADV) &&
        !ad_contains_hids_uuid(ad)) {
        LOG_DBG("Seen without HIDS UUID in AD type=%u, skip", adv_type);
        return;
    }

    if (IS_ENABLED(CONFIG_ZMK_BLE_HOGP_SNIFFER_BUTTON_SELECTOR) && !selected_target_valid) {
        (void)extract_alnum_name(ad, name, sizeof(name));
        picker_add_or_update(addr, name, rssi);
        return;
    }

    if (!target_any_addr) {
        if (target_match_any_type) {
            if (!bt_addr_eq(&addr->a, &target_addr.a)) {
                return;
            }
        } else {
            if (addr->type != target_addr.type) {
                return;
            }

            if (!bt_addr_eq(&addr->a, &target_addr.a)) {
                return;
            }
        }
    }

    if (candidate_list_contains(addr)) {
        return;
    }

    if (candidate_count < MAX_SCAN_CANDIDATES) {
        bt_addr_le_copy(&candidate_addrs[candidate_count], addr);
        candidate_count++;
        LOG_INF("Target candidate #%u found in scan cycle (rssi=%d type=%u)", candidate_count, rssi,
                adv_type);
#if defined(CONFIG_ZMK_BLE_HOGP_SNIFFER_FORWARD_KEY_EVENTS)
        screen_log_verbose_code("cand", candidate_count);
#endif
    } else {
        LOG_DBG("Candidate list full, dropping additional match");
    }
}

static bool candidate_list_contains(const bt_addr_le_t *addr) {
    for (uint8_t i = 0; i < candidate_count; i++) {
        if (candidate_addrs[i].type == addr->type && bt_addr_eq(&candidate_addrs[i].a, &addr->a)) {
            return true;
        }
    }
    return false;
}

static int start_scan(void) {
    int err;
    struct bt_le_scan_param scan_param = {
        .type = BT_LE_SCAN_TYPE_ACTIVE,
        .options = IS_ENABLED(CONFIG_ZMK_BLE_HOGP_SNIFFER_SCAN_FILTER_DUPLICATE)
                       ? BT_LE_SCAN_OPT_FILTER_DUPLICATE
                       : BT_LE_SCAN_OPT_NONE,
        .interval = BT_GAP_SCAN_FAST_INTERVAL,
        .window = BT_GAP_SCAN_FAST_WINDOW,
    };

    if (scanning || default_conn || connecting) {
        return 0;
    }

    if (!host_ready_for_target_scan()) {
        LOG_INF("Waiting host PC connection before target scan");
#if defined(CONFIG_ZMK_BLE_HOGP_SNIFFER_FORWARD_KEY_EVENTS)
        screen_log_verbose_text("wait host pc");
#endif
        return 0;
    }

    in_candidate_sequence = false;
    candidate_count = 0;
    candidate_index = 0;
    memset(candidate_addrs, 0, sizeof(candidate_addrs));

    err = bt_le_scan_start(&scan_param, scan_cb);
    if (err) {
        LOG_ERR("bt_le_scan_start failed (%d)", err);
        return err;
    }

    scanning = true;
    k_work_schedule(&scan_cycle_work, K_MSEC(CONFIG_ZMK_BLE_HOGP_SNIFFER_SCAN_CYCLE_MS));
    LOG_INF("Scanning started (cycle=%d ms, dup_filter=%u)",
            CONFIG_ZMK_BLE_HOGP_SNIFFER_SCAN_CYCLE_MS,
            IS_ENABLED(CONFIG_ZMK_BLE_HOGP_SNIFFER_SCAN_FILTER_DUPLICATE) ? 1U : 0U);
#if defined(CONFIG_ZMK_BLE_HOGP_SNIFFER_FORWARD_KEY_EVENTS)
    screen_log_verbose_text("scan start");
#endif
    return 0;
}

static int connect_to_candidate(const bt_addr_le_t *addr) {
    int err;
    int64_t now = k_uptime_get();

    if (now < next_connect_allowed_ms) {
        LOG_WRN("Connect throttled for %lld ms", (long long)(next_connect_allowed_ms - now));
        return -EAGAIN;
    }

    connecting = true;
#if defined(CONFIG_ZMK_BLE_HOGP_SNIFFER_FORWARD_KEY_EVENTS)
    screen_log_verbose_text("connect try");
#endif
    err = bt_conn_le_create(addr, BT_CONN_LE_CREATE_CONN, BT_LE_CONN_PARAM_DEFAULT, &default_conn);
    if (err) {
        connecting = false;
        default_conn = NULL;
        LOG_ERR("bt_conn_le_create failed (%d)", err);
        return err;
    }

    return 0;
}

static uint8_t picker_name_read_cb(struct bt_conn *conn, uint8_t err, struct bt_gatt_read_params *params,
                                   const void *data, uint16_t length) {
    ARG_UNUSED(params);

    if (!picker_name_probe_active || conn != default_conn) {
        return BT_GATT_ITER_STOP;
    }

    if (!err && data && length > 0 && picker_probe_current_idx >= 0 &&
        picker_probe_current_idx < picker_device_count) {
        char name[PICKER_NAME_MAX];
        size_t n = MIN((size_t)length, sizeof(name) - 1U);

        memcpy(name, data, n);
        name[n] = '\0';
        for (size_t i = 0; i < n; i++) {
            uint8_t c = (uint8_t)name[i];
            if (!is_ascii_alnum(c)) {
                name[i] = 'x';
            }
        }

        if (name[0] != '\0') {
            strncpy(picker_devices[picker_probe_current_idx].name, name,
                    sizeof(picker_devices[picker_probe_current_idx].name) - 1U);
            picker_devices[picker_probe_current_idx].name
                [sizeof(picker_devices[picker_probe_current_idx].name) - 1U] = '\0';
            LOG_INF("name probe ok: %s", picker_devices[picker_probe_current_idx].name);
        }
    } else {
        LOG_WRN("name probe read failed (%u)", err);
    }

    if (default_conn) {
        (void)bt_conn_disconnect(default_conn, BT_HCI_ERR_REMOTE_USER_TERM_CONN);
    }
    return BT_GATT_ITER_STOP;
}

static void picker_probe_timeout_work_handler(struct k_work *work) {
    ARG_UNUSED(work);

    if (!picker_name_probe_active) {
        return;
    }

    if (default_conn) {
        LOG_WRN("name probe timeout");
        (void)bt_conn_disconnect(default_conn, BT_HCI_ERR_REMOTE_USER_TERM_CONN);
    }
}

static void candidate_connect_work_handler(struct k_work *work) {
    int err;
    ARG_UNUSED(work);

    if (!in_candidate_sequence || default_conn || connecting || candidate_index >= candidate_count) {
        return;
    }

    LOG_INF("Trying candidate %u/%u", (uint8_t)(candidate_index + 1U), candidate_count);
#if defined(CONFIG_ZMK_BLE_HOGP_SNIFFER_FORWARD_KEY_EVENTS)
    screen_log_verbose_code("try idx", (uint32_t)(candidate_index + 1U));
#endif
    err = connect_to_candidate(&candidate_addrs[candidate_index]);
    if (err) {
        if (reconnect_fail_count < UINT8_MAX) {
            reconnect_fail_count++;
        }
        (void)try_next_candidate_or_rescan();
    }
}

static void schedule_connect_current_candidate(uint32_t delay_ms) {
    k_work_schedule(&candidate_connect_work, K_MSEC(delay_ms));
}

static bool try_next_candidate_or_rescan(void) {
    if (IS_ENABLED(CONFIG_ZMK_BLE_HOGP_SNIFFER_BUTTON_SELECTOR) && !selected_target_valid) {
        in_candidate_sequence = false;
        candidate_count = 0;
        candidate_index = 0;
        schedule_scan_restart();
        return false;
    }

    if (IS_ENABLED(CONFIG_ZMK_BLE_HOGP_SNIFFER_SINGLE_TARGET_ONLY) && target_hid_verified) {
        LOG_INF("Single-target mode: retry target only after %d ms",
                CONFIG_ZMK_BLE_HOGP_SNIFFER_NEXT_CONNECT_DELAY_MS);
        in_candidate_sequence = true;
        candidate_count = 1;
        candidate_index = 0;
        bt_addr_le_copy(&candidate_addrs[0], &target_addr);
        schedule_connect_current_candidate(CONFIG_ZMK_BLE_HOGP_SNIFFER_NEXT_CONNECT_DELAY_MS);
        return true;
    }

    if (in_candidate_sequence && (candidate_index + 1U) < candidate_count) {
        candidate_index++;
        LOG_INF("Queue next candidate %u/%u after %d ms", (uint8_t)(candidate_index + 1U),
                candidate_count, CONFIG_ZMK_BLE_HOGP_SNIFFER_NEXT_CONNECT_DELAY_MS);
        schedule_connect_current_candidate(CONFIG_ZMK_BLE_HOGP_SNIFFER_NEXT_CONNECT_DELAY_MS);
        return true;
    }

    in_candidate_sequence = false;
    candidate_count = 0;
    candidate_index = 0;
    schedule_scan_restart();
    return false;
}

static void scan_cycle_work_handler(struct k_work *work) {
    int err;
    ARG_UNUSED(work);

    if (!scanning || connecting || default_conn) {
        return;
    }

    if (IS_ENABLED(CONFIG_ZMK_BLE_HOGP_SNIFFER_BUTTON_SELECTOR) && !selected_target_valid) {
        LOG_INF("Picker scan running: devices=%u selected=%u", picker_device_count,
                (uint8_t)(picker_selected_index + 1U));
        k_work_schedule(&scan_cycle_work, K_MSEC(CONFIG_ZMK_BLE_HOGP_SNIFFER_SCAN_CYCLE_MS));
        return;
    }

    err = bt_le_scan_stop();
    if (err && err != -EALREADY) {
        LOG_ERR("Scan stop failed (%d)", err);
        schedule_scan_restart();
        return;
    }
    scanning = false;

    if (candidate_count == 0U) {
        LOG_DBG("Scan cycle ended without target candidate");
        err = start_scan();
        if (err) {
            schedule_scan_restart();
        }
        return;
    }

    in_candidate_sequence = true;
    candidate_index = 0;

    LOG_INF("Scan cycle ended, trying candidate 1/%u", candidate_count);
    schedule_connect_current_candidate(0U);
}

static void reconnect_work_handler(struct k_work *work) {
    ARG_UNUSED(work);
    (void)start_scan();
}

static void schedule_scan_restart(void) {
    uint32_t delay_ms;

    if (reconnect_fail_count == 0) {
        delay_ms = 200U;
    } else if (reconnect_fail_count == 1) {
        delay_ms = 500U;
    } else if (reconnect_fail_count == 2) {
        delay_ms = 1000U;
    } else if (reconnect_fail_count == 3) {
        delay_ms = 2000U;
    } else {
        delay_ms = 4000U;
    }

    LOG_INF("Restart scan in %u ms (fail=%u)", delay_ms, reconnect_fail_count);
    k_work_schedule(&reconnect_work, K_MSEC(delay_ms));
}

static bool should_wait_for_host(void) {
    return IS_ENABLED(CONFIG_ZMK_BLE_HOGP_SNIFFER_WAIT_FOR_HOST_BEFORE_TARGET_SCAN);
}

static bool host_ready_for_target_scan(void) {
    return !should_wait_for_host() || host_connected;
}

static void apply_host_adv_policy(bool target_connected) {
#if defined(CONFIG_ZMK_BLE_HOGP_SNIFFER_BLOCK_HOST_ADV_UNTIL_TARGET_CONNECTED)
    if (!IS_ENABLED(CONFIG_ZMK_BLE_HOGP_SNIFFER_BLOCK_HOST_ADV_UNTIL_TARGET_CONNECTED)) {
        return;
    }

    if (!target_connected) {
        if (!host_adv_blocked) {
            int err = bt_le_adv_stop();
            if (err && err != -EALREADY) {
                LOG_WRN("Failed to stop host advertising (%d)", err);
            } else {
                host_adv_blocked = true;
                LOG_INF("Host BLE advertising blocked until target connects");
            }
        }
        return;
    }

    if (host_adv_blocked) {
        /* Nudge ZMK to re-run its default advertising state machine. */
        int err = zmk_ble_set_device_name((char *)CONFIG_BT_DEVICE_NAME);
        if (err) {
            LOG_WRN("Failed to resume host advertising (%d)", err);
        } else {
            host_adv_blocked = false;
            LOG_INF("Host BLE advertising resumed");
        }
    }
#else
    ARG_UNUSED(target_connected);
#endif
}

static void picker_button_work_handler(struct k_work *work) {
    uint8_t ev;
    uint8_t items;
    ARG_UNUSED(work);

    while (k_msgq_get(&picker_button_msgq, &ev, K_NO_WAIT) == 0) {
        uint8_t idx = (uint8_t)(ev & 0x7F);
        bool pressed = (ev & 0x80U) != 0U;

        if (!pressed) {
            continue;
        }

        items = picker_item_count();
        if (picker_selected_index >= items) {
            picker_selected_index = 0;
        }

        switch (idx) {
        case 0: /* Up */
            if (items > 0U) {
                if (picker_selected_index == 0U) {
                    picker_selected_index = (uint8_t)(items - 1U);
                } else {
                    picker_selected_index--;
                }
            }
            picker_announce_current("sel");
            break;

        case 1: /* Down */
            if (items > 0U) {
                picker_selected_index = (uint8_t)((picker_selected_index + 1U) % items);
            }
            picker_announce_current("sel");
            break;

        case 2: /* OK */
            if (picker_selected_index == 0U) {
                LOG_INF("Running full connection reset");
                bt_foreach_bond(BT_ID_DEFAULT, clear_all_bonds_cb, NULL);
                (void)settings_delete("ble_hogp_sniffer/target_addr");

                picker_name_probe_active = false;
                picker_probe_count = 0;
                picker_probe_pos = 0;
                picker_probe_current_idx = -1;
                k_work_cancel_delayable(&picker_probe_timeout_work);
                selected_target_valid = false;
                target_any_addr = false;
                target_hid_verified = false;
                reconnect_fail_count = 0;
                in_candidate_sequence = false;
                candidate_count = 0;
                candidate_index = 0;
                picker_device_count = 0;
                picker_selected_index = 0;
                memset(candidate_addrs, 0, sizeof(candidate_addrs));

                if (default_conn) {
                    (void)bt_conn_disconnect(default_conn, BT_HCI_ERR_REMOTE_USER_TERM_CONN);
                } else {
                    apply_host_adv_policy(should_wait_for_host() ? true : false);
                    (void)start_scan();
                }
                picker_announce_current("reset");
                break;
            }

            if (picker_selected_index == 1U) {
                if (default_conn || connecting) {
                    picker_announce_current("busy");
                    break;
                }
                picker_begin_name_probe();
                break;
            }

            if (default_conn || connecting) {
                picker_announce_current("busy");
                break;
            }

            bt_addr_le_copy(&target_addr, &picker_devices[picker_selected_index - 2U].addr);
            selected_target_valid = true;
            target_any_addr = false;
            target_match_any_type = true;
            target_hid_verified = false;
            reconnect_fail_count = 0;
            in_candidate_sequence = false;
            candidate_count = 0;
            candidate_index = 0;
            memset(candidate_addrs, 0, sizeof(candidate_addrs));

            picker_announce_current("connect");
            apply_host_adv_policy(should_wait_for_host() ? true : false);
            (void)start_scan();
            break;

        case 3: /* Back */
            picker_name_probe_active = false;
            picker_probe_count = 0;
            picker_probe_pos = 0;
            picker_probe_current_idx = -1;
            k_work_cancel_delayable(&picker_probe_timeout_work);
            selected_target_valid = false;
            target_hid_verified = false;
            in_candidate_sequence = false;
            candidate_count = 0;
            candidate_index = 0;
            picker_selected_index = 0;
            memset(candidate_addrs, 0, sizeof(candidate_addrs));
            picker_announce_current("back");
            if (default_conn) {
                (void)bt_conn_disconnect(default_conn, BT_HCI_ERR_REMOTE_USER_TERM_CONN);
            } else {
                apply_host_adv_policy(should_wait_for_host() ? true : false);
                (void)start_scan();
            }
            break;

        default:
            break;
        }
    }
}

int zmk_hogp_sniffer_button_event(uint8_t idx, bool pressed) {
    uint8_t ev;
    int err;

    if (!IS_ENABLED(CONFIG_ZMK_BLE_HOGP_SNIFFER_BUTTON_SELECTOR)) {
        return -ENOTSUP;
    }

    if (idx > 3U) {
        return -EINVAL;
    }

    ev = (uint8_t)(idx | (pressed ? 0x80U : 0x00U));
    err = k_msgq_put(&picker_button_msgq, &ev, K_NO_WAIT);
    if (err) {
        return err;
    }

    k_work_submit(&picker_button_work);
    return 0;
}

static int parse_target_addr(void) {
    int err;
    const bool target_is_public = IS_ENABLED(CONFIG_ZMK_BLE_HOGP_SNIFFER_TARGET_ADDR_TYPE_PUBLIC);
    bt_addr_t addr;

    target_match_any_type = false;

    if (CONFIG_ZMK_BLE_HOGP_SNIFFER_TARGET_MAC[0] == '\0') {
        target_any_addr = true;
        selected_target_valid = true;
        memset(&target_addr, 0, sizeof(target_addr));
        LOG_INF("Target MAC empty: any-address connect mode enabled");
        return 0;
    }

    err = bt_addr_from_str(CONFIG_ZMK_BLE_HOGP_SNIFFER_TARGET_MAC, &addr);
    if (err) {
        LOG_ERR("Invalid target MAC: %s", CONFIG_ZMK_BLE_HOGP_SNIFFER_TARGET_MAC);
        return err;
    }

    target_any_addr = false;
    selected_target_valid = true;
    target_addr.type = target_is_public ? BT_ADDR_LE_PUBLIC : BT_ADDR_LE_RANDOM;
    bt_addr_copy(&target_addr.a, &addr);

    LOG_INF("Target MAC: %s (%s)", CONFIG_ZMK_BLE_HOGP_SNIFFER_TARGET_MAC,
            target_is_public ? "public" : "random");
    return 0;
}

static int ble_hogp_sniffer_init(void) {
    int err;

    printk("[hogp] init called\r\n");
    LOG_INF("BLE HOGP sniffer init");

#if defined(CONFIG_ZMK_BLE_HOGP_SNIFFER_SELFTEST_TYPE_TESTING_ON_BOOT) &&                                \
    defined(CONFIG_ZMK_BLE_HOGP_SNIFFER_FORWARD_KEY_EVENTS)
    if (IS_ENABLED(CONFIG_ZMK_BLE_HOGP_SNIFFER_SELFTEST_TYPE_TESTING_ON_BOOT) && !selftest_done &&
        selftest_attempts == 0 && selftest_pos == 0) {
        k_work_init_delayable(&selftest_work, selftest_work_handler);
        k_work_schedule(&selftest_work, K_SECONDS(5));
        LOG_INF("Selftest scheduled (from init)");
    }
#endif

    err = bt_enable(NULL);
    if (err && err != -EALREADY) {
        LOG_ERR("bt_enable failed (%d)", err);
        return err;
    }

#if defined(CONFIG_BT_SMP)
    err = bt_conn_auth_info_cb_register(&auth_info_cb);
    if (err && err != -EALREADY) {
        LOG_WRN("bt_conn_auth_info_cb_register failed (%d)", err);
    }
#endif

    /* Ensure host advertising state machine is nudged at boot. */
    (void)zmk_ble_set_device_name((char *)CONFIG_BT_DEVICE_NAME);

    target_any_addr = false;
    if (IS_ENABLED(CONFIG_ZMK_BLE_HOGP_SNIFFER_BUTTON_SELECTOR)) {
        bool loaded = false;
        int lerr = load_persisted_target_addr(&target_addr, &loaded);
        if (lerr) {
            LOG_WRN("Persisted target load failed (%d)", lerr);
        }
        selected_target_valid = loaded;
        picker_device_count = 0;
        picker_selected_index = 0;
        if (loaded) {
            target_any_addr = false;
            target_match_any_type = true;
            LOG_INF("Button selector mode: restored last target");
        } else {
            memset(&target_addr, 0, sizeof(target_addr));
            LOG_INF("Button selector mode enabled (Up/Down/OK/Back)");
        }
    } else {
        err = parse_target_addr();
        if (err) {
            return err;
        }
        selected_target_valid = true;
    }

    prev_consumer_slot_count = 0;
    memset(prev_consumer_slots, 0, sizeof(prev_consumer_slots));
    target_hid_verified = false;
    next_connect_allowed_ms = 0;
    picker_name_probe_active = false;
    picker_probe_count = 0;
    picker_probe_pos = 0;
    picker_probe_current_idx = -1;

    (void)clear_non_target_bonds();
    apply_host_adv_policy(should_wait_for_host() ? true : false);

    err = start_scan();
    if (err) {
        printk("[hogp] start_scan failed: %d\r\n", err);
    } else {
        printk("[hogp] scan start requested\r\n");
    }

    return err;
}

static void sniffer_start_work_handler(struct k_work *work) {
    ARG_UNUSED(work);
    (void)ble_hogp_sniffer_init();
}

static int ble_hogp_sniffer_schedule_init(void) {
    printk("[hogp] schedule init\r\n");
    k_work_init_delayable(&reconnect_work, reconnect_work_handler);
    k_work_init_delayable(&scan_cycle_work, scan_cycle_work_handler);
    k_work_init_delayable(&candidate_connect_work, candidate_connect_work_handler);
    k_work_init_delayable(&picker_probe_timeout_work, picker_probe_timeout_work_handler);
    k_work_init(&picker_button_work, picker_button_work_handler);
    k_work_init_delayable(&sniffer_start_work, sniffer_start_work_handler);
    k_work_schedule(&sniffer_start_work, K_SECONDS(3));
    return 0;
}

SYS_INIT(ble_hogp_sniffer_schedule_init, APPLICATION, CONFIG_APPLICATION_INIT_PRIORITY);
