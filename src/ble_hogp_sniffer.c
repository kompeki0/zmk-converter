#include <errno.h>
#include <stdbool.h>
#include <stddef.h>
#include <string.h>

#include <zephyr/bluetooth/addr.h>
#include <zephyr/bluetooth/bluetooth.h>
#include <zephyr/bluetooth/conn.h>
#include <zephyr/bluetooth/gatt.h>
#include <zephyr/bluetooth/uuid.h>
#include <zephyr/init.h>
#include <zephyr/kernel.h>
#include <zephyr/logging/log.h>
#include <zephyr/sys/byteorder.h>
#include <zephyr/sys/util.h>

#include <zmk/ble.h>
#include <zmk/event_manager.h>
#include <zmk/split/bluetooth/uuid.h>
#include <zmk/usb.h>

#if defined(CONFIG_ZMK_BLE_HOGP_SNIFFER_FORWARD_KEY_EVENTS)
#include <zmk/events/keycode_state_changed.h>
#endif

LOG_MODULE_REGISTER(ble_hogp_sniffer, CONFIG_ZMK_BLE_HOGP_SNIFFER_LOG_LEVEL);

#define BOOT_KBD_REPORT_LEN 8
#define MAX_PRESSED_USAGES 14
#define MAX_REPORT_SUBSCRIPTIONS 6
#define MAX_SCAN_CANDIDATES 12
#define CONSUMER_SLOT_BASE 104
#define CONSUMER_SLOT_COUNT 8
#define CONSUMER_BITS_12B 88

static struct bt_conn *default_conn;
static struct bt_gatt_discover_params discover_params;
static struct bt_gatt_subscribe_params subscribe_params[MAX_REPORT_SUBSCRIPTIONS];
static bt_addr_le_t target_addr;
static bt_addr_le_t candidate_addrs[MAX_SCAN_CANDIDATES];
static struct k_work_delayable sniffer_start_work;
static struct k_work_delayable reconnect_work;
static struct k_work_delayable scan_cycle_work;
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
static uint8_t report_sub_count;
static uint16_t pending_report_char_handle;
static uint16_t pending_report_value_handle;

static struct bt_uuid_16 hids_uuid = BT_UUID_INIT_16(BT_UUID_HIDS_VAL);
static struct bt_uuid_16 report_uuid = BT_UUID_INIT_16(BT_UUID_HIDS_REPORT_VAL);
static struct bt_uuid_16 ccc_uuid = BT_UUID_INIT_16(BT_UUID_GATT_CCC_VAL);

static uint8_t prev_usages[MAX_PRESSED_USAGES];
static size_t prev_usage_count;
static uint8_t prev_consumer_slots[CONSUMER_SLOT_COUNT];
static size_t prev_consumer_slot_count;
static int8_t consumer_bit_to_slot[CONSUMER_BITS_12B];

static int start_scan(void);
static int connect_to_candidate(const bt_addr_le_t *addr);
static bool try_next_candidate_or_rescan(void);
static int clear_non_target_bonds(void);
static void schedule_scan_restart(void);
static void apply_host_adv_policy(bool target_connected);
static bool ad_contains_hids_uuid(const struct net_buf_simple *ad);
static bool ad_contains_split_service_uuid(const struct net_buf_simple *ad);
static int resume_report_discovery(struct bt_conn *conn, uint16_t next_start_handle);
static uint8_t discover_report_cb(struct bt_conn *conn, const struct bt_gatt_attr *attr,
                                  struct bt_gatt_discover_params *params);

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

static int allocate_consumer_slot_for_bit(uint8_t bit_index) {
    if (bit_index >= CONSUMER_BITS_12B) {
        return -EINVAL;
    }

    if (consumer_bit_to_slot[bit_index] >= 0) {
        return consumer_bit_to_slot[bit_index];
    }

    bool used[CONSUMER_SLOT_COUNT] = {0};
    for (uint8_t i = 0; i < CONSUMER_BITS_12B; i++) {
        if (consumer_bit_to_slot[i] >= 0 && consumer_bit_to_slot[i] < CONSUMER_SLOT_COUNT) {
            used[(uint8_t)consumer_bit_to_slot[i]] = true;
        }
    }

    for (uint8_t slot = 0; slot < CONSUMER_SLOT_COUNT; slot++) {
        if (!used[slot]) {
            consumer_bit_to_slot[bit_index] = (int8_t)slot;
            LOG_INF("Mapped consumer bit %u -> slot %u (position %u)", bit_index, slot,
                    (uint16_t)(CONSUMER_SLOT_BASE + slot));
            return slot;
        }
    }

    return -ENOMEM;
}

static void build_consumer_slots_from_12byte_report(const uint8_t *report, size_t report_len,
                                                    uint8_t *slots, size_t *count) {
    *count = 0;
    if (report_len != 12U) {
        return;
    }

    for (uint8_t byte_idx = 1; byte_idx < 12U; byte_idx++) {
        uint8_t b = report[byte_idx];
        if (b == 0U) {
            continue;
        }

        for (uint8_t bit = 0; bit < 8U; bit++) {
            if (!(b & BIT(bit))) {
                continue;
            }

            uint8_t bit_index = (uint8_t)(((byte_idx - 1U) * 8U) + bit);
            int slot = allocate_consumer_slot_for_bit(bit_index);
            if (slot >= 0) {
                append_slot_unique(slots, count, (uint8_t)slot);
            }
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
        } else {
            reconnect_fail_count = 0;
            report_sub_count++;
            LOG_INF("Subscribed Input Report #%u (vh=0x%04x ccc=0x%04x)", report_sub_count,
                    pending_report_value_handle, attr->handle);
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
        } else {
            LOG_INF("Report discovery complete (subscriptions=%u)", report_sub_count);
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
    } else {
        LOG_INF("HID service found, discovering Input Report characteristics");
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

    if (conn != default_conn) {
        return;
    }

    connecting = false;

    if (err) {
        LOG_ERR("Connection failed (err 0x%02x)", err);
        bt_conn_unref(default_conn);
        default_conn = NULL;
        if (reconnect_fail_count < UINT8_MAX) {
            reconnect_fail_count++;
        }
        (void)try_next_candidate_or_rescan();
        return;
    }

    LOG_INF("Connected to target");
    gatt_discovery_started = false;
    apply_host_adv_policy(true);
    derr = bt_conn_set_security(conn, BT_SECURITY_L2);
    if (derr == -EALREADY) {
        gatt_discovery_started = true;
        derr = discover_hids(conn);
        if (derr) {
            LOG_ERR("HID discovery start failed (%d)", derr);
        }
        return;
    }

    if (derr == 0) {
        /* Wait for security_changed callback, then start discovery. */
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
    if (conn != default_conn) {
        return;
    }

    LOG_INF("Disconnected (reason 0x%02x)", reason);

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
    apply_host_adv_policy(false);

    if (reconnect_fail_count < UINT8_MAX) {
        reconnect_fail_count++;
    }
    (void)try_next_candidate_or_rescan();
}

static void security_changed_cb(struct bt_conn *conn, bt_security_t level, enum bt_security_err err) {
    int derr;

    if (conn != default_conn) {
        return;
    }

    if (err) {
        LOG_WRN("Security changed failed (level %u, err %d)", level, err);
        return;
    }

    if (level < BT_SECURITY_L2 || gatt_discovery_started) {
        return;
    }

    gatt_discovery_started = true;
    derr = discover_hids(conn);
    if (derr) {
        LOG_ERR("HID discovery start failed (%d)", derr);
    }
}

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

    if (IS_ENABLED(CONFIG_ZMK_BLE_HOGP_SNIFFER_LOG_SCAN_EVENTS)) {
        bt_addr_le_to_str(addr, addr_str, sizeof(addr_str));
        LOG_INF("ADV: %s type=%u rssi=%d", addr_str, adv_type, rssi);
    }

    if (default_conn || connecting) {
        return;
    }

    if (addr->type != target_addr.type) {
        return;
    }

    if (!bt_addr_eq(&addr->a, &target_addr.a)) {
        return;
    }

    if (IS_ENABLED(CONFIG_ZMK_BLE_HOGP_SNIFFER_REJECT_SPLIT_UUID_IN_ADV) &&
        ad_contains_split_service_uuid(ad)) {
        LOG_DBG("Target seen with split UUID in AD type=%u, skip", adv_type);
        return;
    }

    if (IS_ENABLED(CONFIG_ZMK_BLE_HOGP_SNIFFER_REQUIRE_HIDS_IN_ADV) &&
        !ad_contains_hids_uuid(ad)) {
        LOG_DBG("Target seen without HIDS UUID in AD type=%u, skip", adv_type);
        return;
    }

    if (candidate_count < MAX_SCAN_CANDIDATES) {
        bt_addr_le_copy(&candidate_addrs[candidate_count], addr);
        candidate_count++;
        LOG_INF("Target candidate #%u found in scan cycle (rssi=%d type=%u)", candidate_count, rssi,
                adv_type);
    } else {
        LOG_DBG("Candidate list full, dropping additional match");
    }
}

static int start_scan(void) {
    int err;
    static const struct bt_le_scan_param scan_param = {
        .type = BT_LE_SCAN_TYPE_ACTIVE,
        .options = BT_LE_SCAN_OPT_NONE,
        .interval = BT_GAP_SCAN_FAST_INTERVAL,
        .window = BT_GAP_SCAN_FAST_WINDOW,
    };

    if (scanning || default_conn || connecting) {
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
    LOG_INF("Scanning started (cycle=%d ms)", CONFIG_ZMK_BLE_HOGP_SNIFFER_SCAN_CYCLE_MS);
    return 0;
}

static int connect_to_candidate(const bt_addr_le_t *addr) {
    int err;

    connecting = true;
    err = bt_conn_le_create(addr, BT_CONN_LE_CREATE_CONN, BT_LE_CONN_PARAM_DEFAULT, &default_conn);
    if (err) {
        connecting = false;
        default_conn = NULL;
        LOG_ERR("bt_conn_le_create failed (%d)", err);
        return err;
    }

    return 0;
}

static bool try_next_candidate_or_rescan(void) {
    int err;

    if (in_candidate_sequence && (candidate_index + 1U) < candidate_count) {
        candidate_index++;
        LOG_INF("Trying next candidate %u/%u", (uint8_t)(candidate_index + 1U), candidate_count);
        err = connect_to_candidate(&candidate_addrs[candidate_index]);
        if (!err) {
            return true;
        }
        /* Fallthrough to rescan if immediate create failed. */
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

    err = bt_le_scan_stop();
    if (err && err != -EALREADY) {
        LOG_ERR("Scan stop failed (%d)", err);
        schedule_scan_restart();
        return;
    }
    scanning = false;

    if (candidate_count == 0U) {
        LOG_DBG("Scan cycle ended without target candidate");
        schedule_scan_restart();
        return;
    }

    in_candidate_sequence = true;
    candidate_index = 0;

    LOG_INF("Scan cycle ended, trying candidate 1/%u", candidate_count);
    err = connect_to_candidate(&candidate_addrs[candidate_index]);
    if (err) {
        if (reconnect_fail_count < UINT8_MAX) {
            reconnect_fail_count++;
        }
        (void)try_next_candidate_or_rescan();
    }
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

static int parse_target_addr(void) {
    int err;
    const bool target_is_public = IS_ENABLED(CONFIG_ZMK_BLE_HOGP_SNIFFER_TARGET_ADDR_TYPE_PUBLIC);
    bt_addr_t addr;

    err = bt_addr_from_str(CONFIG_ZMK_BLE_HOGP_SNIFFER_TARGET_MAC, &addr);
    if (err) {
        LOG_ERR("Invalid target MAC: %s", CONFIG_ZMK_BLE_HOGP_SNIFFER_TARGET_MAC);
        return err;
    }

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

    err = parse_target_addr();
    if (err) {
        return err;
    }

    memset(consumer_bit_to_slot, -1, sizeof(consumer_bit_to_slot));
    prev_consumer_slot_count = 0;
    memset(prev_consumer_slots, 0, sizeof(prev_consumer_slots));

    (void)clear_non_target_bonds();
    apply_host_adv_policy(false);

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
    k_work_init_delayable(&sniffer_start_work, sniffer_start_work_handler);
    k_work_schedule(&sniffer_start_work, K_SECONDS(3));
    return 0;
}

SYS_INIT(ble_hogp_sniffer_schedule_init, APPLICATION, CONFIG_APPLICATION_INIT_PRIORITY);
