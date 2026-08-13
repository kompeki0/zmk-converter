#include <errno.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>

#include <zephyr/bluetooth/addr.h>
#include <zephyr/bluetooth/bluetooth.h>
#include <zephyr/bluetooth/conn.h>
#include <zephyr/bluetooth/gap.h>
#include <zephyr/bluetooth/gatt.h>
#include <zephyr/bluetooth/uuid.h>
#include <zephyr/init.h>
#include <zephyr/kernel.h>
#include <zephyr/logging/log.h>
#include <zephyr/settings/settings.h>
#include <zephyr/sys/atomic.h>
#include <zephyr/sys/byteorder.h>
#include <zephyr/sys/util.h>

#if defined(CONFIG_ZMK_BLE)
#include <zmk/ble.h>
#endif
#include <zmk/event_manager.h>
#include <zmk/split/bluetooth/uuid.h>
#include <zmk/usb.h>

#include "ble_hogp_sniffer_internal.h"
#include "hid_report_parser.h"

#if defined(CONFIG_ZMK_BLE_HOGP_SNIFFER_FORWARD_KEY_EVENTS)
#include <zmk/events/keycode_state_changed.h>
#endif

LOG_MODULE_REGISTER(ble_hogp_sniffer, CONFIG_ZMK_BLE_HOGP_SNIFFER_LOG_LEVEL);

#define BOOT_KBD_REPORT_LEN 8
#define POINTER_EXT_REPORT_LEN 9
#define MAX_PRESSED_USAGES HOGP_HID_MAX_KEY_USAGES
#define MAX_REPORT_SUBSCRIPTIONS 12
#define MAX_HIDS_CHARACTERISTICS 24
#define MAX_REPORT_MAP_SIZE 512
#define MAX_SCAN_CANDIDATES 12
#define MAX_PICKER_DEVICES 16
#define PICKER_NAME_MAX 20
#define CONSUMER_SLOT_BASE 104
#define CONSUMER_SLOT_COUNT 52
#define POINTER_SLOT_BASE 118
#define POINTER_BUTTON_SLOT_COUNT 5
#define POINTER_AXIS_LEFT_SLOT 123
#define POINTER_AXIS_RIGHT_SLOT 124
#define POINTER_AXIS_UP_SLOT 125
#define POINTER_AXIS_DOWN_SLOT 126
#define POINTER_WHEEL_UP_SLOT 127
#define POINTER_WHEEL_DOWN_SLOT 128
#define POINTER_HWHEEL_LEFT_SLOT 129
#define POINTER_HWHEEL_RIGHT_SLOT 130
#define TARGET_NAME_MAX PICKER_NAME_MAX
#define MAX_ACTIVE_TARGETS 3
#define MAX_REGISTERED_TARGETS 8
#define TARGET_REGISTRY_VERSION 1

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
static struct k_work_delayable security_disconnect_work;
static struct k_work_delayable hid_discovery_work;
static struct k_work_delayable gatt_stage_work;
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

static bool scanning;
static bool connecting;
static bool in_candidate_sequence;
static uint8_t candidate_count;
static uint8_t candidate_index;
static uint8_t reconnect_fail_count;
#if defined(CONFIG_ZMK_BLE_HOGP_SNIFFER_BLOCK_HOST_ADV_UNTIL_TARGET_CONNECTED)
static bool host_adv_blocked;
#endif
static bool host_connected;
static int64_t next_connect_allowed_ms;
static bool sec_policy_cycle_active;
static uint8_t sec_policy_try_idx;
static int64_t last_sec_policy_step_ms;
static bool screen_typing_enabled;
static bool picker_menu_active;
static bool input_passthrough_enabled;
static struct bt_gatt_read_params picker_name_read_params;
static bool picker_name_probe_active;
static bt_addr_le_t picker_unknown_addrs[MAX_PICKER_DEVICES];
static uint8_t picker_unknown_count;
static uint8_t picker_probe_count;
static uint8_t picker_probe_pos;
static bt_addr_le_t picker_probe_addr;
static bool picker_probe_addr_valid;
static uint8_t pending_disconnect_reason;
static struct bt_conn *pending_disconnect_conn;

enum hogp_gatt_stage {
    HOGP_GATT_STAGE_NONE,
    HOGP_GATT_STAGE_DISCOVER_CHARACTERISTICS,
    HOGP_GATT_STAGE_READ_REPORT_MAP,
    HOGP_GATT_STAGE_DISCOVER_NEXT_INPUT,
    HOGP_GATT_STAGE_READ_REPORT_REFERENCE,
    HOGP_GATT_STAGE_SUBSCRIBE_INPUT,
};

static enum hogp_gatt_stage pending_gatt_stage;
static bool pending_sub_report_ref_valid;
static uint8_t pending_sub_report_id;
static uint8_t pending_sub_report_type;
static bool pending_sub_boot_keyboard;
static uint8_t position_hold_counts[168];

static struct bt_uuid_16 hids_uuid = BT_UUID_INIT_16(BT_UUID_HIDS_VAL);
static struct bt_uuid_16 report_ref_uuid = BT_UUID_INIT_16(0x2908);
static struct bt_uuid_16 ccc_uuid = BT_UUID_INIT_16(BT_UUID_GATT_CCC_VAL);
static struct bt_uuid_16 gap_device_name_uuid = BT_UUID_INIT_16(BT_UUID_GAP_DEVICE_NAME_VAL);
static const struct bt_le_conn_param target_conn_param = {
    /* Start with broadly supported HID-friendly parameters. Forcing the
     * previous 7.5-11.25 ms interval made some keyboards time out while their
     * relatively slow GATT database was being enumerated. The peripheral may
     * still request its preferred power-saving parameters after connecting.
     */
    .interval_min = 24, /* 30ms, Zephyr recommended initial minimum */
    .interval_max = 40, /* 50ms, Zephyr recommended initial maximum */
    .latency = 0,
    .timeout = 3200, /* 32s supervision timeout */
};

struct hids_characteristic {
    uint16_t uuid16;
    uint16_t declaration_handle;
    uint16_t value_handle;
    uint16_t end_handle;
    uint8_t properties;
};

struct hogp_report_meta {
    uint8_t report_id;
    uint8_t report_type;
    bool report_ref_valid;
    bool boot_keyboard;
};

struct hogp_target_state {
    struct bt_conn *conn;
    struct bt_gatt_discover_params hids_service_discover_params;
    struct bt_gatt_discover_params hids_characteristic_discover_params;
    struct bt_gatt_discover_params report_descriptor_discover_params[2];
    struct bt_gatt_read_params report_map_read_params;
    struct bt_gatt_read_params report_ref_read_params;
    struct bt_gatt_subscribe_params subscribe_params[MAX_REPORT_SUBSCRIPTIONS];
    struct hogp_report_meta report_meta[MAX_REPORT_SUBSCRIPTIONS];
    struct hids_characteristic hids_characteristics[MAX_HIDS_CHARACTERISTICS];
    struct hogp_hid_parser hid_parser;
    uint8_t report_map[MAX_REPORT_MAP_SIZE];
    bt_addr_le_t addr;
    bool selected_valid;
    bool any_addr;
    bool match_any_type;
    char name[TARGET_NAME_MAX];
    bool name_valid;
    uint8_t sec_level_hint;
    bool sec_hint_valid;
    uint16_t hids_start_handle;
    uint16_t hids_end_handle;
    bool gatt_discovery_started;
    bool hid_verified;
    uint8_t report_sub_count;
    uint8_t hids_characteristic_count;
    uint8_t pending_hids_characteristic;
    uint8_t report_descriptor_discover_slot;
    uint16_t report_map_len;
    uint16_t pending_report_ref_handle;
    uint16_t pending_ccc_handle;
    uint8_t pending_report_properties;
    bool report_map_valid;
    bool report_map_overflow;
    uint16_t pending_report_char_handle;
    uint16_t pending_report_value_handle;
    bool ready_announced;
    bool security_failure_latched;
    uint8_t prev_usages[MAX_PRESSED_USAGES];
    size_t prev_usage_count;
    uint8_t prev_consumer_slots[CONSUMER_SLOT_COUNT];
    size_t prev_consumer_slot_count;
    uint8_t pointer_buttons;
    uint8_t report_format_hint[MAX_REPORT_SUBSCRIPTIONS];
    uint8_t report_key_usages[MAX_REPORT_SUBSCRIPTIONS][MAX_PRESSED_USAGES];
    uint8_t report_key_usage_count[MAX_REPORT_SUBSCRIPTIONS];
    uint8_t report_consumer_slots[MAX_REPORT_SUBSCRIPTIONS][CONSUMER_SLOT_COUNT];
    uint8_t report_consumer_slot_count[MAX_REPORT_SUBSCRIPTIONS];
};

static struct hogp_target_state target_slots[MAX_ACTIVE_TARGETS];
static struct hogp_target_state *active_target_ptr = &target_slots[0];
#define active_target (*active_target_ptr)

#define default_conn active_target.conn
#define subscribe_params active_target.subscribe_params
#define report_meta active_target.report_meta
#define target_addr active_target.addr
#define selected_target_valid active_target.selected_valid
#define target_any_addr active_target.any_addr
#define target_match_any_type active_target.match_any_type
#define target_name active_target.name
#define target_name_valid active_target.name_valid
#define target_sec_level_hint active_target.sec_level_hint
#define target_sec_hint_valid active_target.sec_hint_valid
#define hids_start_handle active_target.hids_start_handle
#define hids_end_handle active_target.hids_end_handle
#define gatt_discovery_started active_target.gatt_discovery_started
#define target_hid_verified active_target.hid_verified
#define report_sub_count active_target.report_sub_count
#define hids_characteristic_count active_target.hids_characteristic_count
#define pending_hids_characteristic active_target.pending_hids_characteristic
#define report_map_len active_target.report_map_len
#define pending_report_ref_handle active_target.pending_report_ref_handle
#define pending_ccc_handle active_target.pending_ccc_handle
#define pending_report_properties active_target.pending_report_properties
#define report_map_valid active_target.report_map_valid
#define report_map_overflow active_target.report_map_overflow
#define pending_report_char_handle active_target.pending_report_char_handle
#define pending_report_value_handle active_target.pending_report_value_handle
#define target_ready_announced active_target.ready_announced
#define security_failure_latched active_target.security_failure_latched
#define prev_usages active_target.prev_usages
#define prev_usage_count active_target.prev_usage_count
#define prev_consumer_slots active_target.prev_consumer_slots
#define prev_consumer_slot_count active_target.prev_consumer_slot_count
#define prev_pointer_buttons active_target.pointer_buttons
#define report_format_hint active_target.report_format_hint

struct persisted_target_addr {
    uint8_t type;
    uint8_t a[6];
};

struct persisted_target_meta {
    uint8_t sec_level_hint;
    uint8_t has_name;
    char name[TARGET_NAME_MAX];
};

struct persisted_registered_target {
    uint8_t type;
    uint8_t a[6];
    char name[TARGET_NAME_MAX];
};

struct persisted_target_registry {
    uint8_t version;
    uint8_t count;
    struct persisted_registered_target targets[MAX_REGISTERED_TARGETS];
};

static bool persisted_target_valid;
static bool persisted_target_meta_valid;
static struct persisted_target_registry target_registry;

static int start_scan(void);
static int connect_to_candidate(const bt_addr_le_t *addr);
static bool try_next_candidate_or_rescan(void);
static bool candidate_list_contains(const bt_addr_le_t *addr);
static void candidate_same_addr_progress(uint8_t idx, uint8_t *rank, uint8_t *total);
static void schedule_connect_current_candidate(uint32_t delay_ms);
static int clear_non_target_bonds(void);
static void schedule_scan_restart(void);
static void apply_host_adv_policy(bool target_connected);
static bool should_wait_for_host(void);
static bool host_ready_for_target_scan(void);
static bool ad_contains_hids_uuid(const struct net_buf_simple *ad);
static bool ad_contains_split_service_uuid(const struct net_buf_simple *ad);
static int picker_unknown_find_index_by_addr(const bt_addr_le_t *addr);
static void picker_unknown_remove_by_addr(const bt_addr_le_t *addr);
static void picker_try_next_name_probe(void);
static uint8_t picker_name_read_cb(struct bt_conn *conn, uint8_t err, struct bt_gatt_read_params *params,
                                   const void *data, uint16_t length);
static void picker_probe_timeout_work_handler(struct k_work *work);
static uint8_t discover_hids_characteristic_cb(struct bt_conn *conn, const struct bt_gatt_attr *attr,
                                               struct bt_gatt_discover_params *params);
static void discover_next_input_report(struct bt_conn *conn);
static void picker_button_work_handler(struct k_work *work);
static void security_disconnect_work_handler(struct k_work *work);
static void hid_discovery_work_handler(struct k_work *work);
static void schedule_hid_discovery(uint32_t delay_ms);
static void gatt_stage_work_handler(struct k_work *work);
static void schedule_gatt_stage(enum hogp_gatt_stage stage, uint32_t delay_ms);
static int start_hids_characteristic_discovery(struct bt_conn *conn);
static void finish_hids_characteristic_discovery(struct bt_conn *conn, const char *reason);
static int start_report_map_read(struct bt_conn *conn);
static int start_report_reference_read(struct bt_conn *conn);
static int start_pending_subscription(struct bt_conn *conn);
static void select_boot_protocol_if_needed(struct bt_conn *conn);
static int discover_hids(struct bt_conn *conn);
static int save_persisted_target_addr(const bt_addr_le_t *addr);
static int load_persisted_target_addr(bt_addr_le_t *addr, bool *valid);
static int save_persisted_target_meta(uint8_t sec_level_hint, const char *name, bool has_name);
static int load_persisted_target_meta(uint8_t *sec_level_hint, char *name, bool *has_name,
                                      bool *valid);
static void step_security_policy_on_failure(int reason_code, const char *tag);
static void schedule_security_disconnect(uint8_t reason, uint32_t delay_ms);
static void clear_default_conn_ref(void);
static struct hogp_target_state *find_target_slot_by_conn(struct bt_conn *conn);
static struct hogp_target_state *find_free_target_slot(void);
static uint8_t target_slot_number(const struct hogp_target_state *target);
static void release_all_target_inputs(void);
static int target_registry_find(const bt_addr_le_t *addr);
static int target_registry_add(const bt_addr_le_t *addr, const char *name);
static int target_registry_remove(const bt_addr_le_t *addr);

#if defined(CONFIG_BT_SMP)
static struct bt_conn_auth_cb auth_cb;
#endif

#if defined(CONFIG_ZMK_BLE_HOGP_SNIFFER_FORWARD_KEY_EVENTS)
static void emit_usage_state(uint8_t usage, bool pressed);
static void screen_emit_usage_state(uint8_t usage, bool pressed);
#endif

int zmk_hogp_proxy_kscan_inject(uint16_t row, uint16_t col, bool pressed);
static int inject_held_position(uint16_t row, uint16_t col, bool pressed);
__attribute__((weak)) int zmk_hogp_proxy_pointer_event(int16_t dx, int16_t dy, int8_t wheel,
                                                       uint8_t buttons) {
    ARG_UNUSED(dx);
    ARG_UNUSED(dy);
    ARG_UNUSED(wheel);
    ARG_UNUSED(buttons);
    return -ENOTSUP;
}
__attribute__((weak)) int zmk_hogp_proxy_pointer_event_ex(int16_t dx, int16_t dy, int16_t hwheel,
                                                          int16_t wheel, uint8_t buttons) {
    ARG_UNUSED(dx);
    ARG_UNUSED(dy);
    ARG_UNUSED(hwheel);
    ARG_UNUSED(wheel);
    ARG_UNUSED(buttons);
    return -ENOTSUP;
}

static int inject_held_position(uint16_t row, uint16_t col, bool pressed) {
    if (row != 0U || col >= ARRAY_SIZE(position_hold_counts)) {
        return zmk_hogp_proxy_kscan_inject(row, col, pressed);
    }

    if (pressed) {
        if (position_hold_counts[col] == UINT8_MAX) {
            return -EOVERFLOW;
        }
        position_hold_counts[col]++;
        if (position_hold_counts[col] > 1U) {
            return 0;
        }
    } else {
        if (position_hold_counts[col] == 0U) {
            return 0;
        }
        position_hold_counts[col]--;
        if (position_hold_counts[col] > 0U) {
            return 0;
        }
    }

    return zmk_hogp_proxy_kscan_inject(row, col, pressed);
}

static void clear_default_conn_ref(void) {
    if (default_conn) {
        bt_conn_unref(default_conn);
        default_conn = NULL;
    }
}

static struct hogp_target_state *find_target_slot_by_conn(struct bt_conn *conn) {
    if (!conn) {
        return NULL;
    }
    for (uint8_t i = 0U; i < MAX_ACTIVE_TARGETS; i++) {
        if (target_slots[i].conn == conn) {
            return &target_slots[i];
        }
    }
    return NULL;
}

static struct hogp_target_state *find_free_target_slot(void) {
    for (uint8_t i = 0U; i < MAX_ACTIVE_TARGETS; i++) {
        if (!target_slots[i].conn) {
            return &target_slots[i];
        }
    }
    return NULL;
}

static uint8_t target_slot_number(const struct hogp_target_state *target) {
    if (!target || target < &target_slots[0] || target >= &target_slots[MAX_ACTIVE_TARGETS]) {
        return 0U;
    }
    return (uint8_t)(target - &target_slots[0] + 1U);
}

static void security_disconnect_work_handler(struct k_work *work) {
    struct bt_conn *conn = pending_disconnect_conn;
    ARG_UNUSED(work);

    pending_disconnect_conn = NULL;
    if (conn) {
        (void)bt_conn_disconnect(conn, pending_disconnect_reason);
        bt_conn_unref(conn);
    }
}

static void schedule_security_disconnect(uint8_t reason, uint32_t delay_ms) {
    if (pending_disconnect_conn) {
        bt_conn_unref(pending_disconnect_conn);
        pending_disconnect_conn = NULL;
    }
    pending_disconnect_reason = reason;
    if (default_conn) {
        pending_disconnect_conn = bt_conn_ref(default_conn);
    }
    k_work_schedule(&security_disconnect_work, K_MSEC(delay_ms));
}

static void hid_discovery_work_handler(struct k_work *work) {
    int err;
    ARG_UNUSED(work);

    if (!default_conn || !gatt_discovery_started) {
        return;
    }

    LOG_INF("Starting HID discovery after security settle");
    err = discover_hids(default_conn);
    if (err == -ENOMEM || err == -EAGAIN) {
        LOG_WRN("HID discovery temporarily busy (%d), retrying", err);
        k_work_reschedule(&hid_discovery_work, K_MSEC(100));
        return;
    }
    if (err) {
        gatt_discovery_started = false;
        LOG_ERR("HID discovery start failed (%d)", err);
    }
}

static void schedule_hid_discovery(uint32_t delay_ms) {
    gatt_discovery_started = true;
    k_work_reschedule(&hid_discovery_work, K_MSEC(delay_ms));
    LOG_INF("HID discovery scheduled in %u ms", delay_ms);
}

static const char *gatt_stage_name(enum hogp_gatt_stage stage) {
    switch (stage) {
    case HOGP_GATT_STAGE_DISCOVER_CHARACTERISTICS:
        return "characteristics";
    case HOGP_GATT_STAGE_READ_REPORT_MAP:
        return "report-map";
    case HOGP_GATT_STAGE_DISCOVER_NEXT_INPUT:
        return "input-descriptors";
    case HOGP_GATT_STAGE_READ_REPORT_REFERENCE:
        return "report-reference";
    case HOGP_GATT_STAGE_SUBSCRIBE_INPUT:
        return "subscribe";
    default:
        return "none";
    }
}

static void schedule_gatt_stage(enum hogp_gatt_stage stage, uint32_t delay_ms) {
    pending_gatt_stage = stage;
    k_work_reschedule(&gatt_stage_work, K_MSEC(delay_ms));
    LOG_INF("GATT stage scheduled: %s in %u ms", gatt_stage_name(stage), delay_ms);
}

static void gatt_stage_work_handler(struct k_work *work) {
    enum hogp_gatt_stage stage = pending_gatt_stage;
    int err = 0;
    ARG_UNUSED(work);

    if (!default_conn || !gatt_discovery_started || stage == HOGP_GATT_STAGE_NONE) {
        return;
    }

    pending_gatt_stage = HOGP_GATT_STAGE_NONE;
    LOG_INF("Starting GATT stage: %s", gatt_stage_name(stage));

    switch (stage) {
    case HOGP_GATT_STAGE_DISCOVER_CHARACTERISTICS:
        err = start_hids_characteristic_discovery(default_conn);
        break;
    case HOGP_GATT_STAGE_READ_REPORT_MAP:
        select_boot_protocol_if_needed(default_conn);
        err = start_report_map_read(default_conn);
        break;
    case HOGP_GATT_STAGE_DISCOVER_NEXT_INPUT:
        discover_next_input_report(default_conn);
        break;
    case HOGP_GATT_STAGE_READ_REPORT_REFERENCE:
        err = start_report_reference_read(default_conn);
        break;
    case HOGP_GATT_STAGE_SUBSCRIBE_INPUT:
        err = start_pending_subscription(default_conn);
        break;
    default:
        return;
    }

    if (err == -ENOMEM || err == -EAGAIN) {
        LOG_WRN("GATT stage %s temporarily busy (%d), retrying", gatt_stage_name(stage), err);
        schedule_gatt_stage(stage, 50U);
    } else if (err) {
        LOG_ERR("GATT stage %s failed (%d)", gatt_stage_name(stage), err);
        gatt_discovery_started = false;
        schedule_security_disconnect(BT_HCI_ERR_REMOTE_USER_TERM_CONN, 100U);
    }
}

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

    /* Keep ISO/JIS/IME usages in their dedicated block (131..143),
     * separate from consumer slots (104..113).
     * Reserve tail slots (156..167) for extended function keys (F13..F24).
     */
    switch (usage) {
    case 0x68: /* F13 */
        *row = 0;
        *col = 156;
        return true;
    case 0x69: /* F14 */
        *row = 0;
        *col = 157;
        return true;
    case 0x6A: /* F15 */
        *row = 0;
        *col = 158;
        return true;
    case 0x6B: /* F16 */
        *row = 0;
        *col = 159;
        return true;
    case 0x6C: /* F17 */
        *row = 0;
        *col = 160;
        return true;
    case 0x6D: /* F18 */
        *row = 0;
        *col = 161;
        return true;
    case 0x6E: /* F19 */
        *row = 0;
        *col = 162;
        return true;
    case 0x6F: /* F20 */
        *row = 0;
        *col = 163;
        return true;
    case 0x70: /* F21 */
        *row = 0;
        *col = 164;
        return true;
    case 0x71: /* F22 */
        *row = 0;
        *col = 165;
        return true;
    case 0x72: /* F23 */
        *row = 0;
        *col = 166;
        return true;
    case 0x73: /* F24 */
        *row = 0;
        *col = 167;
        return true;
    case 0x64: /* NON_US_BACKSLASH */
        *row = 0;
        *col = 131;
        return true;
    case 0x87: /* INT_RO / International 1 */
        *row = 0;
        *col = 132;
        return true;
    case 0x88: /* INT_KANA */
        *row = 0;
        *col = 133;
        return true;
    case 0x89: /* INT_YEN / International 3 */
        *row = 0;
        *col = 134;
        return true;
    case 0x8A: /* INT_HENKAN */
        *row = 0;
        *col = 135;
        return true;
    case 0x8B: /* INT_MUHENKAN */
        *row = 0;
        *col = 136;
        return true;
    case 0x8C: /* INT_KPJPCOMMA / International 6 */
        *row = 0;
        *col = 137;
        return true;
    case 0x90: /* LANG1 */
        *row = 0;
        *col = 138;
        return true;
    case 0x91: /* LANG2 */
        *row = 0;
        *col = 139;
        return true;
    case 0x92: /* LANG3 */
        *row = 0;
        *col = 140;
        return true;
    case 0x93: /* LANG4 */
        *row = 0;
        *col = 141;
        return true;
    case 0x94: /* LANG5 */
        *row = 0;
        *col = 142;
        return true;
    case 0x95: /* LANG6 */
        *row = 0;
        *col = 143;
        return true;
    default:
        break;
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

static bt_security_t get_desired_security_level(void) {
    bt_security_t configured = (bt_security_t)CONFIG_ZMK_BLE_HOGP_SNIFFER_SECURITY_LEVEL;

    if (sec_policy_cycle_active) {
        bt_security_t level = zmk_hogp_sniffer_sec_policy_level_for_idx(sec_policy_try_idx);
        if (level < configured) {
            return configured;
        }
        return level;
    }

    /* A previously negotiated level is not a required minimum. Starting a new
     * pairing at that level can lock a Just Works device into an unnecessary
     * L3 retry loop. The configured level is the minimum; SMP may still
     * negotiate a higher level when the peer requires it.
     */
    return configured;
}

static void step_security_policy_on_failure(int reason_code, const char *tag) {
    int64_t now = k_uptime_get();
    bt_security_t prev_level = get_desired_security_level();
    bt_security_t next_level;
    bt_security_t configured = (bt_security_t)CONFIG_ZMK_BLE_HOGP_SNIFFER_SECURITY_LEVEL;
    bool auth_requirement = false;

    /* Pairing callbacks and security_changed can report the same failure. */
    if ((now - last_sec_policy_step_ms) < 500) {
        return;
    }
    last_sec_policy_step_ms = now;

    if (reason_code == 4) {
        auth_requirement = true;
    }
#ifdef BT_SECURITY_ERR_AUTH_REQUIREMENT
    if (reason_code == (int)BT_SECURITY_ERR_AUTH_REQUIREMENT) {
        auth_requirement = true;
    }
#endif

    /* Some targets reject L1 and require encrypted/authenticated links. */
    if (auth_requirement) {
        sec_policy_cycle_active = true;
        if (prev_level <= BT_SECURITY_L1) {
            sec_policy_try_idx = 1U; /* raise to L2 */
        } else if (prev_level == BT_SECURITY_L2) {
            sec_policy_try_idx = 0U; /* peer may require MITM: try L3 */
        } else {
            sec_policy_try_idx = 1U; /* L3 rejected: fall back to L2 */
        }
    } else if (!sec_policy_cycle_active) {
        sec_policy_cycle_active = true;
        if (prev_level >= BT_SECURITY_L3) {
            sec_policy_try_idx = 1U; /* L3 failed -> try L2 */
        } else if (prev_level == BT_SECURITY_L2) {
            sec_policy_try_idx = 2U; /* L2 failed -> try L1 */
        } else {
            sec_policy_try_idx = 2U; /* already low -> keep L1 */
        }
    } else if (sec_policy_try_idx < 2U) {
        sec_policy_try_idx++;
    }

    next_level = get_desired_security_level();

    /* Never drop below configured minimum security level. */
    if (next_level < configured) {
        if (configured >= BT_SECURITY_L3) {
            sec_policy_try_idx = 0U; /* L3 */
        } else if (configured == BT_SECURITY_L2) {
            sec_policy_try_idx = 1U; /* L2 */
        } else {
            sec_policy_try_idx = 2U; /* L1 */
        }
        next_level = get_desired_security_level();
    }

    next_connect_allowed_ms = now + (int64_t)(2500U * (uint32_t)(sec_policy_try_idx + 1U));
    LOG_WRN("%s: security policy L%u -> L%u (step %u/3), cooldown=%lldms", tag,
            (uint32_t)prev_level, (uint32_t)next_level, (uint32_t)(sec_policy_try_idx + 1U),
            (long long)(next_connect_allowed_ms - now));
#if defined(CONFIG_ZMK_BLE_HOGP_SNIFFER_FORWARD_KEY_EVENTS)
    if (next_level != prev_level) {
        zmk_hogp_sniffer_screen_log_target_reason(screen_emit_usage_state, "sec policy",
                                                  (uint8_t)next_level, "next security level");
    }
#endif
    ARG_UNUSED(reason_code);
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
    case 0x0224: /* AC Back */
        return 40;
    case 0x0225: /* AC Forward */
        return 41;
    case 0x0227: /* AC Refresh */
        return 42;
    case 0x0226: /* AC Stop */
        return 43;
    case 0x0223: /* AC Home */
        return 44;
    case 0x0221: /* AC Search */
        return 45;
    case 0x022A: /* AC Bookmarks */
        return 46;
    case 0x0196: /* AL Internet Browser */
        return 47;
    case 0x018A: /* AL Email Reader */
        return 48;
    case 0x0192: /* AL Calculator */
        return 49;
    case 0x022D: /* AC Zoom In */
        return 50;
    case 0x022E: /* AC Zoom Out */
        return 51;
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

static void screen_emit_usage_state(uint8_t usage, bool pressed) {
    if (!screen_typing_enabled) {
        return;
    }

    emit_usage_state(usage, pressed);
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
        if (zmk_hogp_sniffer_is_ascii_alnum(c)) {
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

static int picker_unknown_find_index_by_addr(const bt_addr_le_t *addr) {
    for (uint8_t i = 0; i < picker_unknown_count; i++) {
        if (picker_unknown_addrs[i].type == addr->type &&
            bt_addr_eq(&picker_unknown_addrs[i].a, &addr->a)) {
            return i;
        }
    }
    return -ENOENT;
}

static void picker_unknown_remove_by_addr(const bt_addr_le_t *addr) {
    int idx = picker_unknown_find_index_by_addr(addr);

    if (idx < 0) {
        return;
    }

    for (uint8_t i = (uint8_t)idx; i + 1U < picker_unknown_count; i++) {
        picker_unknown_addrs[i] = picker_unknown_addrs[i + 1U];
    }
    picker_unknown_count--;
}

static uint8_t picker_item_count(void) { return picker_device_count; }

struct picker_bond_lookup_ctx {
    const bt_addr_le_t *addr;
    bool found;
};

static void picker_bond_lookup_cb(const struct bt_bond_info *info, void *user_data) {
    struct picker_bond_lookup_ctx *ctx = user_data;

    if (info->addr.type == ctx->addr->type && bt_addr_eq(&info->addr.a, &ctx->addr->a)) {
        ctx->found = true;
    }
}

static bool picker_device_is_bonded(const bt_addr_le_t *addr) {
    struct picker_bond_lookup_ctx ctx = {.addr = addr, .found = false};
    bt_foreach_bond(BT_ID_DEFAULT, picker_bond_lookup_cb, &ctx);
    return ctx.found;
}

static bool picker_device_is_connected(const bt_addr_le_t *addr) {
    for (uint8_t i = 0U; i < MAX_ACTIVE_TARGETS; i++) {
        if (target_slots[i].conn && target_slots[i].addr.type == addr->type &&
            bt_addr_eq(&target_slots[i].addr.a, &addr->a)) {
            struct bt_conn_info info;
            if (bt_conn_get_info(target_slots[i].conn, &info) == 0 &&
                info.state == BT_CONN_STATE_CONNECTED) {
                return true;
            }
        }
    }
    struct bt_conn *conn = bt_conn_lookup_addr_le(BT_ID_DEFAULT, addr);

    if (!conn) {
        return false;
    }
    struct bt_conn_info info;
    bool connected = bt_conn_get_info(conn, &info) == 0 && info.state == BT_CONN_STATE_CONNECTED;
    bt_conn_unref(conn);
    return connected;
}

static void picker_print_list(void) {
    char line[64];

    LOG_INF("Device list (%u): [>] selected [C] connected [R] registered [B] bonded",
            picker_device_count);
#if defined(CONFIG_ZMK_BLE_HOGP_SNIFFER_FORWARD_KEY_EVENTS)
    zmk_hogp_sniffer_type_text_line(screen_emit_usage_state, "DEVICE LIST");
#endif
    if (picker_device_count == 0U) {
        LOG_INF("  (no devices; put a device in pairing mode and press D0)");
#if defined(CONFIG_ZMK_BLE_HOGP_SNIFFER_FORWARD_KEY_EVENTS)
        zmk_hogp_sniffer_type_text_line(screen_emit_usage_state, "NO DEVICES");
#endif
        return;
    }

    for (uint8_t i = 0U; i < picker_device_count; i++) {
        bool connected = picker_device_is_connected(&picker_devices[i].addr);
        bool registered = target_registry_find(&picker_devices[i].addr) >= 0;
        bool bonded = picker_device_is_bonded(&picker_devices[i].addr);
        snprintf(line, sizeof(line), "%c%u [%c%c%c] %s RSSI%d",
                 i == picker_selected_index ? '>' : ' ', (uint32_t)(i + 1U),
                 connected ? 'C' : '-', registered ? 'R' : '-', bonded ? 'B' : '-',
                 picker_devices[i].name, picker_devices[i].rssi);
        LOG_INF("%s", line);
#if defined(CONFIG_ZMK_BLE_HOGP_SNIFFER_FORWARD_KEY_EVENTS)
        zmk_hogp_sniffer_type_text_line(screen_emit_usage_state, line);
#endif
    }
}

static void picker_announce_current(const char *prefix) {
    char buf[48];
    uint8_t items = picker_item_count();

    if (picker_selected_index >= items) {
        picker_selected_index = 0;
    }

    if (items == 0U) {
        snprintf(buf, sizeof(buf), "%s NO DEVICE", prefix);
    } else {
        snprintf(buf, sizeof(buf), "%s %u %s", prefix, (uint32_t)(picker_selected_index + 1U),
                 picker_devices[picker_selected_index].name);
    }
    LOG_INF("%s", buf);
#if defined(CONFIG_ZMK_BLE_HOGP_SNIFFER_FORWARD_KEY_EVENTS)
    zmk_hogp_sniffer_type_text_line(screen_emit_usage_state, buf);
#endif
}

static void picker_add_or_update(const bt_addr_le_t *addr, const char *name, int8_t rssi) {
    int idx = picker_find_index_by_addr(addr);

    if (!name || name[0] == '\0') {
        return;
    }

    if (idx >= 0) {
        picker_devices[idx].rssi = rssi;
        strncpy(picker_devices[idx].name, name, sizeof(picker_devices[idx].name) - 1);
        picker_devices[idx].name[sizeof(picker_devices[idx].name) - 1] = '\0';
        picker_unknown_remove_by_addr(addr);
        return;
    }

    if (picker_device_count >= MAX_PICKER_DEVICES) {
        return;
    }

    bt_addr_le_copy(&picker_devices[picker_device_count].addr, addr);
    picker_devices[picker_device_count].rssi = rssi;
    strncpy(picker_devices[picker_device_count].name, name,
            sizeof(picker_devices[picker_device_count].name) - 1);
    picker_devices[picker_device_count].name[sizeof(picker_devices[picker_device_count].name) - 1] =
        '\0';
    LOG_INF("Found candidate %u: %s (rssi=%d)", (uint8_t)(picker_device_count + 1U),
            picker_devices[picker_device_count].name, rssi);
    picker_device_count++;
    picker_unknown_remove_by_addr(addr);
}

static void picker_load_saved_and_connected_devices(void) {
    for (uint8_t i = 0U; i < target_registry.count; i++) {
        bt_addr_le_t addr = {.type = target_registry.targets[i].type};
        memcpy(addr.a.val, target_registry.targets[i].a, sizeof(addr.a.val));
        picker_add_or_update(&addr,
                             target_registry.targets[i].name[0] != '\0'
                                 ? target_registry.targets[i].name
                                 : "REGISTERED",
                             INT8_MIN);
    }
    for (uint8_t i = 0U; i < MAX_ACTIVE_TARGETS; i++) {
        if (!target_slots[i].conn) {
            continue;
        }
        picker_add_or_update(&target_slots[i].addr,
                             target_slots[i].name_valid ? target_slots[i].name : "CONNECTED", 0);
    }
}

static void picker_try_next_name_probe(void) {
    if (!picker_name_probe_active) {
        return;
    }

    while (picker_probe_pos < picker_probe_count) {
        bt_addr_le_copy(&target_addr, &picker_unknown_addrs[picker_probe_pos]);
        bt_addr_le_copy(&picker_probe_addr, &picker_unknown_addrs[picker_probe_pos]);
        picker_probe_addr_valid = true;
        picker_probe_pos++;
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
    picker_probe_addr_valid = false;
    selected_target_valid = false;
    target_hid_verified = false;
    picker_selected_index = 1U;
    picker_announce_current("other done");
    (void)start_scan();
}

static int settings_set_target_addr(const char *name, size_t len_rd, settings_read_cb read_cb,
                                    void *cb_arg) {
    struct persisted_target_addr raw;
    struct persisted_target_meta meta;
    int len;

    if (strcmp(name, "target_addr") == 0) {
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

    if (strcmp(name, "target_meta") == 0) {
        if (len_rd != sizeof(meta)) {
            return -EINVAL;
        }

        len = read_cb(cb_arg, &meta, sizeof(meta));
        if (len != sizeof(meta)) {
            return -EIO;
        }

        target_sec_level_hint = meta.sec_level_hint;
        target_sec_hint_valid =
            (target_sec_level_hint >= BT_SECURITY_L1 && target_sec_level_hint <= BT_SECURITY_L4);
        target_name_valid = false;
        if (meta.has_name) {
            strncpy(target_name, meta.name, sizeof(target_name) - 1U);
            target_name[sizeof(target_name) - 1U] = '\0';
            target_name_valid = (target_name[0] != '\0');
        }
        persisted_target_meta_valid = true;
        return 0;
    }

    if (strcmp(name, "devices") == 0) {
        if (len_rd != sizeof(target_registry)) {
            /* Treat stale/older registry layouts as empty. Bond data remains
             * intact and a successful HID discovery will rebuild this list.
             */
            memset(&target_registry, 0, sizeof(target_registry));
            LOG_WRN("Ignoring incompatible target registry (size=%u)",
                    (uint32_t)len_rd);
            return 0;
        }
        len = read_cb(cb_arg, &target_registry, sizeof(target_registry));
        if (len != sizeof(target_registry) ||
            target_registry.version != TARGET_REGISTRY_VERSION ||
            target_registry.count > MAX_REGISTERED_TARGETS) {
            memset(&target_registry, 0, sizeof(target_registry));
            LOG_WRN("Ignoring invalid target registry");
            return 0;
        }
        return 0;
    }

    return -ENOENT;
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

static int save_persisted_target_meta(uint8_t sec_level_hint, const char *name, bool has_name) {
    struct persisted_target_meta meta = {0};

    meta.sec_level_hint = sec_level_hint;
    meta.has_name = has_name ? 1U : 0U;
    if (has_name && name) {
        strncpy(meta.name, name, sizeof(meta.name) - 1U);
        meta.name[sizeof(meta.name) - 1U] = '\0';
    }

    return settings_save_one("ble_hogp_sniffer/target_meta", &meta, sizeof(meta));
}

static int target_registry_save(void) {
    target_registry.version = TARGET_REGISTRY_VERSION;
    return settings_save_one("ble_hogp_sniffer/devices", &target_registry,
                             sizeof(target_registry));
}

static int target_registry_find(const bt_addr_le_t *addr) {
    for (uint8_t i = 0U; i < target_registry.count; i++) {
        if (target_registry.targets[i].type == addr->type &&
            memcmp(target_registry.targets[i].a, addr->a.val,
                   sizeof(target_registry.targets[i].a)) == 0) {
            return i;
        }
    }
    return -ENOENT;
}

static int target_registry_add(const bt_addr_le_t *addr, const char *name) {
    int index = target_registry_find(addr);

    if (index < 0) {
        if (target_registry.count >= MAX_REGISTERED_TARGETS) {
            return -ENOMEM;
        }
        index = target_registry.count++;
    }

    struct persisted_registered_target *entry = &target_registry.targets[index];
    memset(entry, 0, sizeof(*entry));
    entry->type = addr->type;
    memcpy(entry->a, addr->a.val, sizeof(entry->a));
    if (name) {
        strncpy(entry->name, name, sizeof(entry->name) - 1U);
    }
    return target_registry_save();
}

static int target_registry_remove(const bt_addr_le_t *addr) {
    int index = target_registry_find(addr);

    if (index < 0) {
        return index;
    }
    for (uint8_t i = (uint8_t)index; i + 1U < target_registry.count; i++) {
        target_registry.targets[i] = target_registry.targets[i + 1U];
    }
    target_registry.count--;
    memset(&target_registry.targets[target_registry.count], 0,
           sizeof(target_registry.targets[target_registry.count]));
    return target_registry_save();
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

static int load_persisted_target_meta(uint8_t *sec_level_hint, char *name, bool *has_name,
                                      bool *valid) {
    int err;

    if (!sec_level_hint || !name || !has_name || !valid) {
        return -EINVAL;
    }

    persisted_target_meta_valid = false;
    err = settings_load_subtree("ble_hogp_sniffer");
    if (err) {
        *valid = false;
        return err;
    }

    if (persisted_target_meta_valid) {
        *sec_level_hint = target_sec_level_hint;
        *has_name = target_name_valid;
        if (target_name_valid) {
            strncpy(name, target_name, TARGET_NAME_MAX - 1U);
            name[TARGET_NAME_MAX - 1U] = '\0';
        } else {
            name[0] = '\0';
        }
    }
    *valid = persisted_target_meta_valid && target_sec_hint_valid;
    return 0;
}

static uint8_t aggregate_pointer_buttons(uint8_t current_buttons) {
    uint8_t buttons = current_buttons;

    for (uint8_t i = 0U; i < MAX_ACTIVE_TARGETS; i++) {
        if (&target_slots[i] != active_target_ptr && target_slots[i].conn) {
            buttons |= target_slots[i].pointer_buttons;
        }
    }
    return buttons;
}

static void process_keyboard_usage_set(const uint8_t *curr_usages, size_t curr_usage_count) {
    uint8_t next_pointer_buttons = prev_pointer_buttons;
    bool pointer_buttons_changed = false;

    for (size_t i = 0; i < prev_usage_count; i++) {
        if (!usage_exists(curr_usages, curr_usage_count, prev_usages[i])) {
            uint8_t usage = prev_usages[i];
            uint8_t mapped = 0U;

            if ((uint8_t)CONFIG_ZMK_BLE_HOGP_SNIFFER_KEY_USAGE_MOUSE_BTN1 == usage) {
                mapped = BIT(0);
            } else if ((uint8_t)CONFIG_ZMK_BLE_HOGP_SNIFFER_KEY_USAGE_MOUSE_BTN2 == usage) {
                mapped = BIT(1);
            } else if ((uint8_t)CONFIG_ZMK_BLE_HOGP_SNIFFER_KEY_USAGE_MOUSE_BTN3 == usage) {
                mapped = BIT(2);
            } else if ((uint8_t)CONFIG_ZMK_BLE_HOGP_SNIFFER_KEY_USAGE_MOUSE_BTN4 == usage) {
                mapped = BIT(3);
            } else if ((uint8_t)CONFIG_ZMK_BLE_HOGP_SNIFFER_KEY_USAGE_MOUSE_BTN5 == usage) {
                mapped = BIT(4);
            }

            if (mapped) {
                next_pointer_buttons &= (uint8_t)~mapped;
                pointer_buttons_changed = true;
            }
        }
    }

    for (size_t i = 0; i < curr_usage_count; i++) {
        if (!usage_exists(prev_usages, prev_usage_count, curr_usages[i])) {
            uint8_t usage = curr_usages[i];
            uint8_t mapped = 0U;

            if ((uint8_t)CONFIG_ZMK_BLE_HOGP_SNIFFER_KEY_USAGE_MOUSE_BTN1 == usage) {
                mapped = BIT(0);
            } else if ((uint8_t)CONFIG_ZMK_BLE_HOGP_SNIFFER_KEY_USAGE_MOUSE_BTN2 == usage) {
                mapped = BIT(1);
            } else if ((uint8_t)CONFIG_ZMK_BLE_HOGP_SNIFFER_KEY_USAGE_MOUSE_BTN3 == usage) {
                mapped = BIT(2);
            } else if ((uint8_t)CONFIG_ZMK_BLE_HOGP_SNIFFER_KEY_USAGE_MOUSE_BTN4 == usage) {
                mapped = BIT(3);
            } else if ((uint8_t)CONFIG_ZMK_BLE_HOGP_SNIFFER_KEY_USAGE_MOUSE_BTN5 == usage) {
                mapped = BIT(4);
            }

            if (mapped) {
                next_pointer_buttons |= mapped;
                pointer_buttons_changed = true;
            }
        }
    }

    if (pointer_buttons_changed) {
        if (IS_ENABLED(CONFIG_ZMK_BLE_HOGP_SNIFFER_POINTER_USE_INPUT_LISTENER)) {
            int err = zmk_hogp_proxy_pointer_event_ex(
                0, 0, 0, 0, aggregate_pointer_buttons(next_pointer_buttons));
            if (err && IS_ENABLED(CONFIG_ZMK_BLE_HOGP_SNIFFER_POINTER_DEBUG_LOG)) {
                LOG_WRN("kbd->pointer route failed (%d)", err);
            }
        } else {
            for (uint8_t bit = 0; bit < POINTER_BUTTON_SLOT_COUNT; bit++) {
                bool prev = (prev_pointer_buttons & BIT(bit)) != 0U;
                bool curr = (next_pointer_buttons & BIT(bit)) != 0U;
                if (prev != curr) {
                    (void)inject_held_position(0, (uint16_t)(POINTER_SLOT_BASE + bit), curr);
                }
            }
        }
        prev_pointer_buttons = next_pointer_buttons;
    }

#if defined(CONFIG_ZMK_BLE_HOGP_SNIFFER_FORWARD_KEY_EVENTS)
    if (IS_ENABLED(CONFIG_ZMK_BLE_HOGP_SNIFFER_FORWARD_KEY_EVENTS) &&
        !IS_ENABLED(CONFIG_ZMK_BLE_HOGP_SNIFFER_EMIT_POSITION_EVENTS)) {
        for (size_t i = 0; i < prev_usage_count; i++) {
            if (!usage_exists(curr_usages, curr_usage_count, prev_usages[i])) {
                if (prev_usages[i] == (uint8_t)CONFIG_ZMK_BLE_HOGP_SNIFFER_KEY_USAGE_MOUSE_BTN1 ||
                    prev_usages[i] == (uint8_t)CONFIG_ZMK_BLE_HOGP_SNIFFER_KEY_USAGE_MOUSE_BTN2 ||
                    prev_usages[i] == (uint8_t)CONFIG_ZMK_BLE_HOGP_SNIFFER_KEY_USAGE_MOUSE_BTN3 ||
                    prev_usages[i] == (uint8_t)CONFIG_ZMK_BLE_HOGP_SNIFFER_KEY_USAGE_MOUSE_BTN4 ||
                    prev_usages[i] == (uint8_t)CONFIG_ZMK_BLE_HOGP_SNIFFER_KEY_USAGE_MOUSE_BTN5) {
                    continue;
                }
                emit_usage_state(prev_usages[i], false);
            }
        }

        for (size_t i = 0; i < curr_usage_count; i++) {
            if (!usage_exists(prev_usages, prev_usage_count, curr_usages[i])) {
                if (curr_usages[i] == (uint8_t)CONFIG_ZMK_BLE_HOGP_SNIFFER_KEY_USAGE_MOUSE_BTN1 ||
                    curr_usages[i] == (uint8_t)CONFIG_ZMK_BLE_HOGP_SNIFFER_KEY_USAGE_MOUSE_BTN2 ||
                    curr_usages[i] == (uint8_t)CONFIG_ZMK_BLE_HOGP_SNIFFER_KEY_USAGE_MOUSE_BTN3 ||
                    curr_usages[i] == (uint8_t)CONFIG_ZMK_BLE_HOGP_SNIFFER_KEY_USAGE_MOUSE_BTN4 ||
                    curr_usages[i] == (uint8_t)CONFIG_ZMK_BLE_HOGP_SNIFFER_KEY_USAGE_MOUSE_BTN5) {
                    continue;
                }
                emit_usage_state(curr_usages[i], true);
            }
        }
    }
#endif

#if defined(CONFIG_ZMK_BLE_HOGP_SNIFFER_EMIT_POSITION_EVENTS)
    if (IS_ENABLED(CONFIG_ZMK_BLE_HOGP_SNIFFER_EMIT_POSITION_EVENTS)) {
        for (size_t i = 0; i < prev_usage_count; i++) {
            if (!usage_exists(curr_usages, curr_usage_count, prev_usages[i])) {
                if (prev_usages[i] == (uint8_t)CONFIG_ZMK_BLE_HOGP_SNIFFER_KEY_USAGE_MOUSE_BTN1 ||
                    prev_usages[i] == (uint8_t)CONFIG_ZMK_BLE_HOGP_SNIFFER_KEY_USAGE_MOUSE_BTN2 ||
                    prev_usages[i] == (uint8_t)CONFIG_ZMK_BLE_HOGP_SNIFFER_KEY_USAGE_MOUSE_BTN3 ||
                    prev_usages[i] == (uint8_t)CONFIG_ZMK_BLE_HOGP_SNIFFER_KEY_USAGE_MOUSE_BTN4 ||
                    prev_usages[i] == (uint8_t)CONFIG_ZMK_BLE_HOGP_SNIFFER_KEY_USAGE_MOUSE_BTN5) {
                    continue;
                }
                uint16_t row, col;
                if (usage_to_row_col(prev_usages[i], &row, &col)) {
                    (void)inject_held_position(row, col, false);
                }
            }
        }

        for (size_t i = 0; i < curr_usage_count; i++) {
            if (!usage_exists(prev_usages, prev_usage_count, curr_usages[i])) {
                if (curr_usages[i] == (uint8_t)CONFIG_ZMK_BLE_HOGP_SNIFFER_KEY_USAGE_MOUSE_BTN1 ||
                    curr_usages[i] == (uint8_t)CONFIG_ZMK_BLE_HOGP_SNIFFER_KEY_USAGE_MOUSE_BTN2 ||
                    curr_usages[i] == (uint8_t)CONFIG_ZMK_BLE_HOGP_SNIFFER_KEY_USAGE_MOUSE_BTN3 ||
                    curr_usages[i] == (uint8_t)CONFIG_ZMK_BLE_HOGP_SNIFFER_KEY_USAGE_MOUSE_BTN4 ||
                    curr_usages[i] == (uint8_t)CONFIG_ZMK_BLE_HOGP_SNIFFER_KEY_USAGE_MOUSE_BTN5) {
                    continue;
                }
                uint16_t row, col;
                if (usage_to_row_col(curr_usages[i], &row, &col)) {
                    (void)inject_held_position(row, col, true);
                }
            }
        }
    }
#endif

    prev_usage_count = curr_usage_count;
    if (curr_usage_count > 0U) {
        memcpy(prev_usages, curr_usages, curr_usage_count);
    }
}

static void process_boot_report(const uint8_t *report, size_t report_len) {
    uint8_t curr_usages[MAX_PRESSED_USAGES];
    size_t curr_usage_count = 0;

    build_usage_set_from_boot_report(report, report_len, curr_usages, &curr_usage_count);
    process_keyboard_usage_set(curr_usages, curr_usage_count);
}

static void process_consumer_slot_set(const uint8_t *curr_slots, size_t curr_slot_count) {
    for (size_t i = 0; i < prev_consumer_slot_count; i++) {
        if (!slot_exists(curr_slots, curr_slot_count, prev_consumer_slots[i])) {
            (void)inject_held_position(0,
                                       (uint16_t)(CONSUMER_SLOT_BASE + prev_consumer_slots[i]),
                                       false);
        }
    }

    for (size_t i = 0; i < curr_slot_count; i++) {
        if (!slot_exists(prev_consumer_slots, prev_consumer_slot_count, curr_slots[i])) {
            (void)inject_held_position(0, (uint16_t)(CONSUMER_SLOT_BASE + curr_slots[i]), true);
        }
    }

    prev_consumer_slot_count = curr_slot_count;
    if (curr_slot_count > 0U) {
        memcpy(prev_consumer_slots, curr_slots, curr_slot_count);
    }
}

static void process_consumer_usage_set(const uint16_t *usages, size_t usage_count) {
    uint8_t curr_slots[CONSUMER_SLOT_COUNT];
    size_t curr_slot_count = 0;

    for (size_t i = 0; i < usage_count; i++) {
        int slot = consumer_usage_to_slot(usages[i]);
        if (slot >= 0) {
            append_slot_unique(curr_slots, &curr_slot_count, (uint8_t)slot);
        }
    }
    process_consumer_slot_set(curr_slots, curr_slot_count);
}

static void release_all_target_inputs(void) {
    struct hogp_target_state *previous_target = active_target_ptr;

    for (uint8_t i = 0U; i < MAX_ACTIVE_TARGETS; i++) {
        if (!target_slots[i].conn) {
            continue;
        }
        active_target_ptr = &target_slots[i];
        process_keyboard_usage_set(NULL, 0U);
        process_consumer_slot_set(NULL, 0U);
        if (prev_pointer_buttons != 0U) {
            prev_pointer_buttons = 0U;
            if (IS_ENABLED(CONFIG_ZMK_BLE_HOGP_SNIFFER_POINTER_USE_INPUT_LISTENER)) {
                (void)zmk_hogp_proxy_pointer_event_ex(0, 0, 0, 0,
                                                       aggregate_pointer_buttons(0U));
            }
        }
    }
    active_target_ptr = previous_target;
}

static void update_descriptor_keyboard_state(uint8_t sub_idx, const uint8_t *usages,
                                             size_t usage_count) {
    uint8_t combined[MAX_PRESSED_USAGES];
    size_t combined_count = 0U;

    if (sub_idx >= MAX_REPORT_SUBSCRIPTIONS) {
        return;
    }
    usage_count = MIN(usage_count, (size_t)MAX_PRESSED_USAGES);
    active_target.report_key_usage_count[sub_idx] = (uint8_t)usage_count;
    memcpy(active_target.report_key_usages[sub_idx], usages, usage_count);

    for (uint8_t report = 0U; report < report_sub_count; report++) {
        for (uint8_t i = 0U; i < active_target.report_key_usage_count[report]; i++) {
            append_usage_unique(combined, &combined_count,
                                active_target.report_key_usages[report][i]);
        }
    }
    process_keyboard_usage_set(combined, combined_count);
}

static void update_descriptor_consumer_state(uint8_t sub_idx, const uint16_t *usages,
                                             size_t usage_count) {
    uint8_t combined_slots[CONSUMER_SLOT_COUNT];
    size_t combined_count = 0U;

    if (sub_idx >= MAX_REPORT_SUBSCRIPTIONS) {
        return;
    }

    active_target.report_consumer_slot_count[sub_idx] = 0U;
    for (size_t i = 0U; i < usage_count; i++) {
        int slot = consumer_usage_to_slot(usages[i]);
        if (slot >= 0) {
            size_t count = active_target.report_consumer_slot_count[sub_idx];
            append_slot_unique(active_target.report_consumer_slots[sub_idx], &count,
                               (uint8_t)slot);
            active_target.report_consumer_slot_count[sub_idx] = (uint8_t)count;
        }
    }

    for (uint8_t report = 0U; report < report_sub_count; report++) {
        for (uint8_t i = 0U; i < active_target.report_consumer_slot_count[report]; i++) {
            append_slot_unique(combined_slots, &combined_count,
                               active_target.report_consumer_slots[report][i]);
        }
    }
    process_consumer_slot_set(combined_slots, combined_count);
}

static void process_nkro12_report(const uint8_t *report, size_t report_len) {
    uint8_t slots[CONSUMER_SLOT_COUNT];
    uint16_t usages[CONSUMER_SLOT_COUNT];
    size_t slot_count = 0;

    build_consumer_slots_from_12byte_report(report, report_len, slots, &slot_count);
    for (size_t i = 0; i < slot_count; i++) {
        usages[i] = 0U;
        for (uint8_t n = 0U; n < 6U; n++) {
            uint16_t usage = sys_get_le16(&report[n * 2U]);
            if (consumer_usage_to_slot(usage) == slots[i]) {
                usages[i] = usage;
                break;
            }
        }
    }
    process_consumer_usage_set(usages, slot_count);
}

static void inject_pointer_pulse(uint16_t col) {
    (void)zmk_hogp_proxy_kscan_inject(0, col, true);
    (void)zmk_hogp_proxy_kscan_inject(0, col, false);
}

static void emit_pointer_axis_pulses(int8_t delta, uint16_t negative_slot, uint16_t positive_slot) {
    int16_t abs_delta;
    uint8_t pulses;
    uint16_t slot;

    if (delta == 0) {
        return;
    }

    abs_delta = delta < 0 ? (int16_t)(-delta) : (int16_t)delta;
    pulses = (uint8_t)(abs_delta / CONFIG_ZMK_BLE_HOGP_SNIFFER_POINTER_STEP_DIV);
    if (pulses == 0U) {
        pulses = 1U;
    }
    if (pulses > CONFIG_ZMK_BLE_HOGP_SNIFFER_POINTER_MAX_PULSES) {
        pulses = CONFIG_ZMK_BLE_HOGP_SNIFFER_POINTER_MAX_PULSES;
    }

    slot = delta < 0 ? negative_slot : positive_slot;
    for (uint8_t i = 0; i < pulses; i++) {
        inject_pointer_pulse(slot);
    }
}

static void process_mouse_report(const uint8_t *report, size_t report_len) {
    uint8_t buttons;
    int8_t x;
    int8_t y;
    int8_t wheel;

    if (report_len < 3U) {
        return;
    }

    buttons = report[0];
    x = (int8_t)report[1];
    y = (int8_t)report[2];
    wheel = (report_len >= 4U) ? (int8_t)report[3] : 0;

    if (IS_ENABLED(CONFIG_ZMK_BLE_HOGP_SNIFFER_POINTER_USE_INPUT_LISTENER)) {
        int err = zmk_hogp_proxy_pointer_event_ex((int16_t)x, (int16_t)y, 0, (int16_t)wheel,
                                                  aggregate_pointer_buttons(buttons));
        if (err == -ENOTSUP) {
            err = zmk_hogp_proxy_pointer_event((int16_t)x, (int16_t)y, wheel,
                                               aggregate_pointer_buttons(buttons));
        }
        if (err == 0) {
            prev_pointer_buttons = buttons;
        } else if (IS_ENABLED(CONFIG_ZMK_BLE_HOGP_SNIFFER_POINTER_DEBUG_LOG)) {
            LOG_WRN("pointer listener route failed (%d)", err);
        }
        return;
    }

    if (zmk_hogp_proxy_pointer_event((int16_t)x, (int16_t)y, wheel,
                                     aggregate_pointer_buttons(buttons)) == 0) {
        prev_pointer_buttons = buttons;
        return;
    }

    for (uint8_t bit = 0; bit < POINTER_BUTTON_SLOT_COUNT; bit++) {
        bool prev = (prev_pointer_buttons & BIT(bit)) != 0U;
        bool curr = (buttons & BIT(bit)) != 0U;
        if (prev != curr) {
            (void)inject_held_position(0, (uint16_t)(POINTER_SLOT_BASE + bit), curr);
        }
    }
    prev_pointer_buttons = buttons;

    emit_pointer_axis_pulses(x, POINTER_AXIS_LEFT_SLOT, POINTER_AXIS_RIGHT_SLOT);
    /* HID mouse Y is positive when moving down. */
    emit_pointer_axis_pulses(y, POINTER_AXIS_UP_SLOT, POINTER_AXIS_DOWN_SLOT);
    emit_pointer_axis_pulses(wheel, POINTER_WHEEL_DOWN_SLOT, POINTER_WHEEL_UP_SLOT);
}

static void process_pointer_9byte_report(const uint8_t *report, size_t report_len) {
    uint8_t buttons;
    int16_t dx;
    int16_t dy;
    int16_t wheel;
    int16_t hwheel;

    if (report_len != 9U) {
        return;
    }

    buttons = report[0];
    dx = (int16_t)sys_get_le16(&report[1]);
    dy = (int16_t)sys_get_le16(&report[3]);
    wheel = (int16_t)sys_get_le16(&report[5]);
    hwheel = (int16_t)sys_get_le16(&report[7]);

    if (IS_ENABLED(CONFIG_ZMK_BLE_HOGP_SNIFFER_POINTER_USE_INPUT_LISTENER)) {
        int err = zmk_hogp_proxy_pointer_event_ex(dx, dy, hwheel, wheel,
                                                  aggregate_pointer_buttons(buttons));
        if (err == 0) {
            prev_pointer_buttons = buttons;
        } else if (IS_ENABLED(CONFIG_ZMK_BLE_HOGP_SNIFFER_POINTER_DEBUG_LOG)) {
            LOG_WRN("pointer listener route failed (%d)", err);
        }
        return;
    }

    for (uint8_t bit = 0; bit < POINTER_BUTTON_SLOT_COUNT; bit++) {
        bool prev = (prev_pointer_buttons & BIT(bit)) != 0U;
        bool curr = (buttons & BIT(bit)) != 0U;
        if (prev != curr) {
            (void)inject_held_position(0, (uint16_t)(POINTER_SLOT_BASE + bit), curr);
        }
    }
    prev_pointer_buttons = buttons;

    emit_pointer_axis_pulses((int8_t)CLAMP(dx, -127, 127), POINTER_AXIS_LEFT_SLOT, POINTER_AXIS_RIGHT_SLOT);
    emit_pointer_axis_pulses((int8_t)CLAMP(dy, -127, 127), POINTER_AXIS_UP_SLOT, POINTER_AXIS_DOWN_SLOT);
    emit_pointer_axis_pulses((int8_t)CLAMP(wheel, -127, 127), POINTER_WHEEL_DOWN_SLOT, POINTER_WHEEL_UP_SLOT);
    emit_pointer_axis_pulses((int8_t)CLAMP(hwheel, -127, 127), POINTER_HWHEEL_LEFT_SLOT,
                             POINTER_HWHEEL_RIGHT_SLOT);
}

static bool is_keyboard_usage_value(uint8_t usage) {
    if (usage == 0U) {
        return true;
    }

    return ((usage >= 0x04U && usage <= 0xA4U) || (usage >= 0xE0U && usage <= 0xE7U));
}

static bool looks_like_report_id_boot_kbd_9(const uint8_t *p) {
    bool any_active = (p[1] != 0U);

    if (!(p[0] >= 1U && p[0] <= 32U)) {
        return false;
    }

    if (p[2] != 0U) {
        return false;
    }

    for (uint8_t i = 3U; i < 9U; i++) {
        if (!is_keyboard_usage_value(p[i])) {
            return false;
        }

        if (p[i] != 0U) {
            any_active = true;
        }
    }

    return any_active;
}

static void process_decoded_pointer(const struct hogp_hid_decoded_report *decoded) {
    uint8_t buttons = decoded->has_buttons ? decoded->buttons : prev_pointer_buttons;
    int16_t dx = (int16_t)CLAMP(decoded->dx, INT16_MIN, INT16_MAX);
    int16_t dy = (int16_t)CLAMP(decoded->dy, INT16_MIN, INT16_MAX);
    int16_t wheel = (int16_t)CLAMP(decoded->wheel, INT16_MIN, INT16_MAX);
    int16_t hwheel = (int16_t)CLAMP(decoded->hwheel, INT16_MIN, INT16_MAX);

    if (IS_ENABLED(CONFIG_ZMK_BLE_HOGP_SNIFFER_POINTER_USE_INPUT_LISTENER)) {
        int err = zmk_hogp_proxy_pointer_event_ex(dx, dy, hwheel, wheel,
                                                  aggregate_pointer_buttons(buttons));
        if (err == 0) {
            prev_pointer_buttons = buttons;
        } else if (IS_ENABLED(CONFIG_ZMK_BLE_HOGP_SNIFFER_POINTER_DEBUG_LOG)) {
            LOG_WRN("descriptor pointer route failed (%d)", err);
        }
        return;
    }

    for (uint8_t bit = 0; bit < POINTER_BUTTON_SLOT_COUNT; bit++) {
        bool prev = (prev_pointer_buttons & BIT(bit)) != 0U;
        bool curr = (buttons & BIT(bit)) != 0U;
        if (prev != curr) {
            (void)inject_held_position(0, (uint16_t)(POINTER_SLOT_BASE + bit), curr);
        }
    }
    prev_pointer_buttons = buttons;
    emit_pointer_axis_pulses((int8_t)CLAMP(dx, -127, 127), POINTER_AXIS_LEFT_SLOT,
                             POINTER_AXIS_RIGHT_SLOT);
    emit_pointer_axis_pulses((int8_t)CLAMP(dy, -127, 127), POINTER_AXIS_UP_SLOT,
                             POINTER_AXIS_DOWN_SLOT);
    emit_pointer_axis_pulses((int8_t)CLAMP(wheel, -127, 127), POINTER_WHEEL_DOWN_SLOT,
                             POINTER_WHEEL_UP_SLOT);
    emit_pointer_axis_pulses((int8_t)CLAMP(hwheel, -127, 127), POINTER_HWHEEL_LEFT_SLOT,
                             POINTER_HWHEEL_RIGHT_SLOT);
}

static void handle_input_report_bytes(const uint8_t *data, uint16_t length, uint8_t sub_idx) {
    const uint8_t *p = data;
    uint16_t len = length;
    uint8_t hint = (sub_idx < MAX_REPORT_SUBSCRIPTIONS) ? report_format_hint[sub_idx] : 0U;

    if (!p || len == 0U) {
        return;
    }

    if (report_map_valid && sub_idx < report_sub_count && !report_meta[sub_idx].boot_keyboard) {
        struct hogp_hid_decoded_report decoded;
        int err = hogp_hid_parser_decode(&active_target.hid_parser, report_meta[sub_idx].report_id,
                                         report_meta[sub_idx].report_ref_valid, p, len, &decoded);
        if (err == 0) {
            if (decoded.has_keyboard) {
                update_descriptor_keyboard_state(sub_idx, decoded.key_usages,
                                                 decoded.key_usage_count);
            }
            if (decoded.has_consumer) {
                update_descriptor_consumer_state(sub_idx, decoded.consumer_usages,
                                                 decoded.consumer_usage_count);
            }
            if (decoded.has_pointer &&
                IS_ENABLED(CONFIG_ZMK_BLE_HOGP_SNIFFER_ENABLE_POINTER_REPORTS)) {
                process_decoded_pointer(&decoded);
            }
            return;
        }
        LOG_DBG("Report Map decode fallback: sub=%u id=%u err=%d len=%u", sub_idx,
                report_meta[sub_idx].report_id, err, len);
    }

    /* Hint values: 0=unknown,1=boot8,2=consumer12,3=pointer9,4=boot8+rid */
    if (hint == 4U && len == POINTER_EXT_REPORT_LEN) {
        process_boot_report(&p[1], BOOT_KBD_REPORT_LEN);
        return;
    } else if (hint == 3U && len == POINTER_EXT_REPORT_LEN) {
        process_pointer_9byte_report(p, len);
        return;
    } else if (hint == 1U && len == BOOT_KBD_REPORT_LEN) {
        process_boot_report(p, len);
        return;
    } else if (hint == 2U && len == 12U) {
        process_nkro12_report(p, len);
        return;
    }

    if (len == POINTER_EXT_REPORT_LEN) {
        if (looks_like_report_id_boot_kbd_9(p)) {
            if (sub_idx < MAX_REPORT_SUBSCRIPTIONS) {
                report_format_hint[sub_idx] = 4U;
            }
            process_boot_report(&p[1], BOOT_KBD_REPORT_LEN);
            return;
        }

        if (sub_idx < MAX_REPORT_SUBSCRIPTIONS) {
            report_format_hint[sub_idx] = 3U;
        }
        process_pointer_9byte_report(p, len);
        return;
    }

    /* Some devices prepend Report ID. If len is not recognized, try stripping 1 byte. */
    if (len != BOOT_KBD_REPORT_LEN && len != 12U && len > 1U) {
        uint8_t rid = p[0];
        if (rid >= 1U && rid <= 32U) {
            p++;
            len--;
            LOG_DBG("Assume Report ID=%u, strip 1 byte -> len=%u", rid, len);
        }
    }

    if (len == BOOT_KBD_REPORT_LEN) {
        if (sub_idx < MAX_REPORT_SUBSCRIPTIONS) {
            report_format_hint[sub_idx] = 1U;
        }
        process_boot_report(p, len);
    } else if (len == 12U) {
        if (sub_idx < MAX_REPORT_SUBSCRIPTIONS) {
            report_format_hint[sub_idx] = 2U;
        }
        process_nkro12_report(p, len);
    } else if (IS_ENABLED(CONFIG_ZMK_BLE_HOGP_SNIFFER_ENABLE_POINTER_REPORTS) &&
               (len == 3U || len == 4U)) {
        process_mouse_report(p, len);
    } else {
        LOG_DBG("Unsupported report format for key mapper (len=%u)", len);
    }
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

static uint8_t notify_cb(struct bt_conn *conn, struct bt_gatt_subscribe_params *params,
                         const void *data, uint16_t length) {
    struct hogp_target_state *previous_target = active_target_ptr;
    struct hogp_target_state *notification_target = find_target_slot_by_conn(conn);
    uint8_t sub_idx = 0xFF;

    if (!notification_target) {
        return BT_GATT_ITER_STOP;
    }
    active_target_ptr = notification_target;

    for (uint8_t i = 0; i < report_sub_count; i++) {
        if (params == &subscribe_params[i]) {
            sub_idx = i;
            break;
        }
    }

    if (!data) {
        LOG_INF("Notification stopped (sub=%u, vh=0x%04x)", sub_idx, params->value_handle);
        active_target_ptr = previous_target;
        return BT_GATT_ITER_STOP;
    }

    LOG_INF("HID Input notify: sub=%u vh=0x%04x len=%u", sub_idx, params->value_handle, length);
    LOG_HEXDUMP_INF(data, length, "HID Input");

    if (!input_passthrough_enabled) {
        LOG_DBG("HID input held while device manager is open");
        active_target_ptr = previous_target;
        return BT_GATT_ITER_CONTINUE;
    }

#if defined(CONFIG_ZMK_BLE_HOGP_SNIFFER_FORWARD_KEY_EVENTS)
    if (!target_ready_announced) {
        zmk_hogp_sniffer_type_text_line(screen_emit_usage_state, "target ready");
        target_ready_announced = true;
    }
#endif

    /* First real input means candidate-connect phase succeeded. */
    in_candidate_sequence = false;
    candidate_count = 0;
    candidate_index = 0;

    handle_input_report_bytes(data, length, sub_idx);
    active_target_ptr = previous_target;
    return BT_GATT_ITER_CONTINUE;
}

static void finish_report_discovery(void) {
    gatt_discovery_started = false;
    pending_gatt_stage = HOGP_GATT_STAGE_NONE;

    if (report_sub_count == 0U) {
        LOG_ERR("No notifiable HID input characteristic subscribed");
#if defined(CONFIG_ZMK_BLE_HOGP_SNIFFER_FORWARD_KEY_EVENTS)
        zmk_hogp_sniffer_screen_log_verbose_text(screen_emit_usage_state, "no report sub");
#endif
        schedule_security_disconnect(BT_HCI_ERR_REMOTE_USER_TERM_CONN, 100U);
        return;
    }

    LOG_INF("HID discovery complete (subscriptions=%u, map=%s)", report_sub_count,
            report_map_valid ? "parsed" : "fallback");
    int registry_err = target_registry_add(&target_addr, target_name_valid ? target_name : NULL);
    if (registry_err) {
        LOG_WRN("Failed to save target in device registry (%d)", registry_err);
    }
#if defined(CONFIG_ZMK_BLE_HOGP_SNIFFER_FORWARD_KEY_EVENTS)
    zmk_hogp_sniffer_type_text_line(screen_emit_usage_state, "target ready");
    zmk_hogp_sniffer_type_text_line(screen_emit_usage_state, "input stream on");
    zmk_hogp_sniffer_screen_log_verbose_code(screen_emit_usage_state, "sub total", report_sub_count);
#endif
}

static void queue_pending_subscription(bool report_ref_valid, uint8_t report_id,
                                       uint8_t report_type, bool boot_keyboard) {
    pending_sub_report_ref_valid = report_ref_valid;
    pending_sub_report_id = report_id;
    pending_sub_report_type = report_type;
    pending_sub_boot_keyboard = boot_keyboard;
    schedule_gatt_stage(HOGP_GATT_STAGE_SUBSCRIBE_INPUT, 1U);
}

static void subscribe_complete_cb(struct bt_conn *conn, uint8_t err,
                                  struct bt_gatt_subscribe_params *params) {
    uint8_t sub_idx = 0xFFU;
    struct hogp_target_state *target = find_target_slot_by_conn(conn);

    if (!target) {
        return;
    }
    active_target_ptr = target;

    for (uint8_t i = 0U; i < report_sub_count; i++) {
        if (params == &subscribe_params[i]) {
            sub_idx = i;
            break;
        }
    }

    if (err) {
        LOG_ERR("HID input subscription rejected (sub=%u vh=0x%04x att=%u)", sub_idx,
                params->value_handle, err);
        if (sub_idx != 0xFFU && sub_idx + 1U == report_sub_count) {
            report_sub_count--;
            memset(&subscribe_params[sub_idx], 0, sizeof(subscribe_params[sub_idx]));
            memset(&report_meta[sub_idx], 0, sizeof(report_meta[sub_idx]));
        }
    } else {
        reconnect_fail_count = 0;
        target_hid_verified = true;
        LOG_INF("Subscribed HID input #%u (vh=0x%04x ccc=0x%04x id=%u%s)", sub_idx + 1U,
                params->value_handle, params->ccc_handle,
                sub_idx == 0xFFU ? 0U : report_meta[sub_idx].report_id,
                sub_idx == 0xFFU
                    ? " unknown"
                    : (report_meta[sub_idx].boot_keyboard
                           ? " boot"
                           : (report_meta[sub_idx].report_ref_valid ? "" : " unknown")));
#if defined(CONFIG_ZMK_BLE_HOGP_SNIFFER_FORWARD_KEY_EVENTS)
        zmk_hogp_sniffer_screen_log_verbose_code(screen_emit_usage_state, "sub ok",
                                                 report_sub_count);
#endif
    }

    pending_hids_characteristic++;
    schedule_gatt_stage(HOGP_GATT_STAGE_DISCOVER_NEXT_INPUT, 1U);
}

static int start_pending_subscription(struct bt_conn *conn) {
    int err;

    if (pending_sub_report_ref_valid && pending_sub_report_type != 1U) {
        LOG_DBG("Skip non-input Report id=%u type=%u vh=0x%04x", pending_sub_report_id,
                pending_sub_report_type,
                pending_report_value_handle);
        pending_hids_characteristic++;
        schedule_gatt_stage(HOGP_GATT_STAGE_DISCOVER_NEXT_INPUT, 1U);
        return 0;
    }

    if (report_sub_count >= MAX_REPORT_SUBSCRIPTIONS) {
        LOG_WRN("Reached max report subscriptions (%u), skip vh=0x%04x",
                MAX_REPORT_SUBSCRIPTIONS, pending_report_value_handle);
        pending_hids_characteristic++;
        schedule_gatt_stage(HOGP_GATT_STAGE_DISCOVER_NEXT_INPUT, 1U);
        return 0;
    }

    struct bt_gatt_subscribe_params *sub = &subscribe_params[report_sub_count];
    struct hogp_report_meta *meta = &report_meta[report_sub_count];

    memset(sub, 0, sizeof(*sub));
    memset(meta, 0, sizeof(*meta));
    sub->notify = notify_cb;
    sub->subscribe = subscribe_complete_cb;
    sub->value = (pending_report_properties & BT_GATT_CHRC_NOTIFY) != 0U
                     ? BT_GATT_CCC_NOTIFY
                     : BT_GATT_CCC_INDICATE;
    sub->value_handle = pending_report_value_handle;
    sub->ccc_handle = pending_ccc_handle;
    atomic_set_bit(sub->flags, BT_GATT_SUBSCRIBE_FLAG_VOLATILE);
    meta->report_id = pending_sub_report_id;
    meta->report_type = pending_sub_report_type;
    meta->report_ref_valid = pending_sub_report_ref_valid;
    meta->boot_keyboard = pending_sub_boot_keyboard;

    err = bt_gatt_subscribe(conn, sub);
    if (err) {
        if (err == -ENOMEM || err == -EAGAIN) {
            return err;
        }
        LOG_ERR("bt_gatt_subscribe failed for vh=0x%04x (%d)", pending_report_value_handle,
                err);
#if defined(CONFIG_ZMK_BLE_HOGP_SNIFFER_FORWARD_KEY_EVENTS)
        zmk_hogp_sniffer_screen_log_verbose_code(screen_emit_usage_state, "sub err",
                                                 (uint32_t)(-err));
#endif
        pending_hids_characteristic++;
        schedule_gatt_stage(HOGP_GATT_STAGE_DISCOVER_NEXT_INPUT, 1U);
        return 0;
    }

    /* Reserve the slot before the CCC write completes so an early notification
     * can already resolve its report metadata. The completion callback advances
     * to the next characteristic only after the ATT transaction has finished.
     */
    report_sub_count++;
    LOG_INF("HID input subscription queued (vh=0x%04x ccc=0x%04x)",
            pending_report_value_handle, pending_ccc_handle);
    return 0;
}

static uint8_t report_ref_read_cb(struct bt_conn *conn, uint8_t err,
                                  struct bt_gatt_read_params *params, const void *data,
                                  uint16_t length) {
    ARG_UNUSED(params);

    struct hogp_target_state *target = find_target_slot_by_conn(conn);
    if (!target) {
        return BT_GATT_ITER_STOP;
    }
    active_target_ptr = target;

    if (err || !data || length < 2U) {
        LOG_WRN("Report Reference read failed for vh=0x%04x (att=%u len=%u)",
                pending_report_value_handle, err, length);
        queue_pending_subscription(false, 0U, 0U, false);
        return BT_GATT_ITER_STOP;
    }

    const uint8_t *ref = data;
    queue_pending_subscription(true, ref[0], ref[1], false);
    return BT_GATT_ITER_STOP;
}

static uint8_t discover_report_descriptor_cb(struct bt_conn *conn,
                                              const struct bt_gatt_attr *attr,
                                              struct bt_gatt_discover_params *params) {
    ARG_UNUSED(params);

    struct hogp_target_state *target = find_target_slot_by_conn(conn);
    if (!target) {
        return BT_GATT_ITER_STOP;
    }
    active_target_ptr = target;

    if (attr) {
        if (bt_uuid_cmp(attr->uuid, &ccc_uuid.uuid) == 0) {
            pending_ccc_handle = attr->handle;
        } else if (bt_uuid_cmp(attr->uuid, &report_ref_uuid.uuid) == 0) {
            pending_report_ref_handle = attr->handle;
        }
        return BT_GATT_ITER_CONTINUE;
    }

    const struct hids_characteristic *characteristic =
        &active_target.hids_characteristics[pending_hids_characteristic];
    bool boot_keyboard = characteristic->uuid16 == 0x2A22U;

    if (pending_ccc_handle == 0U) {
        LOG_WRN("CCC not found in characteristic boundary for vh=0x%04x",
                pending_report_value_handle);
        pending_hids_characteristic++;
        schedule_gatt_stage(HOGP_GATT_STAGE_DISCOVER_NEXT_INPUT, 1U);
        return BT_GATT_ITER_STOP;
    }

    if (boot_keyboard || pending_report_ref_handle == 0U) {
        queue_pending_subscription(false, 0U, 0U, boot_keyboard);
        return BT_GATT_ITER_STOP;
    }

    schedule_gatt_stage(HOGP_GATT_STAGE_READ_REPORT_REFERENCE, 1U);
    return BT_GATT_ITER_STOP;
}

static int start_report_reference_read(struct bt_conn *conn) {
    memset(&active_target.report_ref_read_params, 0,
           sizeof(active_target.report_ref_read_params));
    active_target.report_ref_read_params.func = report_ref_read_cb;
    active_target.report_ref_read_params.handle_count = 1U;
    active_target.report_ref_read_params.single.handle = pending_report_ref_handle;
    active_target.report_ref_read_params.single.offset = 0U;
    int err = bt_gatt_read(conn, &active_target.report_ref_read_params);
    if (err) {
        if (err == -ENOMEM || err == -EAGAIN) {
            return err;
        }
        LOG_WRN("Report Reference read start failed (%d)", err);
        queue_pending_subscription(false, 0U, 0U, false);
        return 0;
    }
    LOG_INF("Reading HID Report Reference (handle=0x%04x)", pending_report_ref_handle);
    return 0;
}

static void discover_next_input_report(struct bt_conn *conn) {
    while (pending_hids_characteristic < hids_characteristic_count) {
        const struct hids_characteristic *characteristic =
            &active_target.hids_characteristics[pending_hids_characteristic];
        bool is_report = characteristic->uuid16 == BT_UUID_HIDS_REPORT_VAL;
        bool is_boot_keyboard = characteristic->uuid16 == 0x2A22U;
        bool can_stream = (characteristic->properties &
                           (BT_GATT_CHRC_NOTIFY | BT_GATT_CHRC_INDICATE)) != 0U;

        if ((!is_report && !is_boot_keyboard) || !can_stream) {
            pending_hids_characteristic++;
            continue;
        }

        pending_report_char_handle = characteristic->declaration_handle;
        pending_report_value_handle = characteristic->value_handle;
        pending_report_properties = characteristic->properties;
        pending_report_ref_handle = 0U;
        pending_ccc_handle = 0U;

        if (characteristic->value_handle >= characteristic->end_handle) {
            LOG_WRN("No descriptor range for HID input vh=0x%04x", characteristic->value_handle);
            pending_hids_characteristic++;
            continue;
        }

        /* Keep successive descriptor procedures on alternating parameter
         * objects as an extra guard against cleanup of the previous request.
         */
        active_target.report_descriptor_discover_slot ^= 1U;
        struct bt_gatt_discover_params *descriptor_params =
            &active_target.report_descriptor_discover_params
                 [active_target.report_descriptor_discover_slot];
        memset(descriptor_params, 0, sizeof(*descriptor_params));
        descriptor_params->uuid = NULL;
        descriptor_params->start_handle = (uint16_t)(characteristic->value_handle + 1U);
        descriptor_params->end_handle = characteristic->end_handle;
        descriptor_params->type = BT_GATT_DISCOVER_DESCRIPTOR;
        descriptor_params->func = discover_report_descriptor_cb;

        int err = bt_gatt_discover(conn, descriptor_params);
        if (err) {
            if (err == -ENOMEM || err == -EAGAIN) {
                schedule_gatt_stage(HOGP_GATT_STAGE_DISCOVER_NEXT_INPUT, 50U);
                return;
            }
            LOG_ERR("HID descriptor discovery failed for vh=0x%04x (%d)",
                    characteristic->value_handle, err);
            pending_hids_characteristic++;
            continue;
        }

        LOG_INF("Inspecting HID input characteristic vh=0x%04x range=0x%04x-0x%04x",
                characteristic->value_handle, descriptor_params->start_handle,
                descriptor_params->end_handle);
        return;
    }

    finish_report_discovery();
}

static void begin_input_report_discovery(struct bt_conn *conn) {
    pending_hids_characteristic = 0U;
    discover_next_input_report(conn);
}

static uint8_t report_map_read_cb(struct bt_conn *conn, uint8_t err,
                                  struct bt_gatt_read_params *params, const void *data,
                                  uint16_t length) {
    ARG_UNUSED(params);

    struct hogp_target_state *target = find_target_slot_by_conn(conn);
    if (!target) {
        return BT_GATT_ITER_STOP;
    }
    active_target_ptr = target;

    if (err) {
        LOG_WRN("Report Map read failed (att=%u); fixed-format fallback remains active", err);
        report_map_valid = false;
        pending_hids_characteristic = 0U;
        schedule_gatt_stage(HOGP_GATT_STAGE_DISCOVER_NEXT_INPUT, 1U);
        return BT_GATT_ITER_STOP;
    }

    if (data) {
        size_t room = sizeof(active_target.report_map) - report_map_len;
        size_t copy_len = MIN((size_t)length, room);
        if (copy_len > 0U) {
            memcpy(&active_target.report_map[report_map_len], data, copy_len);
            report_map_len += (uint16_t)copy_len;
        }
        if (copy_len != length) {
            report_map_overflow = true;
        }
        return BT_GATT_ITER_CONTINUE;
    }

    if (report_map_overflow) {
        LOG_WRN("Report Map exceeds %u bytes; fixed-format fallback remains active",
                MAX_REPORT_MAP_SIZE);
    } else {
        int parse_err = hogp_hid_parser_parse(&active_target.hid_parser,
                                              active_target.report_map, report_map_len);
        report_map_valid = parse_err == 0;
        if (parse_err) {
            LOG_WRN("Report Map parse failed (%d, len=%u); using fallback", parse_err,
                    report_map_len);
        } else {
            LOG_INF("Report Map parsed (len=%u reports=%u fields=%u%s)", report_map_len,
                    active_target.hid_parser.report_count, active_target.hid_parser.field_count,
                    active_target.hid_parser.truncated ? " truncated" : "");
        }
    }

    pending_hids_characteristic = 0U;
    schedule_gatt_stage(HOGP_GATT_STAGE_DISCOVER_NEXT_INPUT, 1U);
    return BT_GATT_ITER_STOP;
}

static int start_report_map_read(struct bt_conn *conn) {
    uint16_t report_map_handle = 0U;

    for (uint8_t i = 0U; i < hids_characteristic_count; i++) {
        if (active_target.hids_characteristics[i].uuid16 == 0x2A4BU) {
            report_map_handle = active_target.hids_characteristics[i].value_handle;
            break;
        }
    }

    if (report_map_handle == 0U) {
        LOG_WRN("Report Map characteristic not found; using fixed-format fallback");
        begin_input_report_discovery(conn);
        return 0;
    }

    memset(&active_target.report_map_read_params, 0,
           sizeof(active_target.report_map_read_params));
    active_target.report_map_read_params.func = report_map_read_cb;
    active_target.report_map_read_params.handle_count = 1U;
    active_target.report_map_read_params.single.handle = report_map_handle;
    active_target.report_map_read_params.single.offset = 0U;
    report_map_len = 0U;
    report_map_overflow = false;
    report_map_valid = false;

    int err = bt_gatt_read(conn, &active_target.report_map_read_params);
    if (err) {
        if (err == -ENOMEM || err == -EAGAIN) {
            return err;
        }
        LOG_WRN("Report Map read start failed (%d); using fallback", err);
        begin_input_report_discovery(conn);
    } else {
        LOG_INF("Reading HID Report Map (vh=0x%04x)", report_map_handle);
    }
    return 0;
}

static void select_boot_protocol_if_needed(struct bt_conn *conn) {
    static const uint8_t boot_protocol = 0U;
    uint16_t protocol_mode_handle = 0U;
    bool has_report_input = false;
    bool has_boot_keyboard_input = false;

    for (uint8_t i = 0U; i < hids_characteristic_count; i++) {
        const struct hids_characteristic *characteristic =
            &active_target.hids_characteristics[i];
        bool can_stream = (characteristic->properties &
                           (BT_GATT_CHRC_NOTIFY | BT_GATT_CHRC_INDICATE)) != 0U;

        if (characteristic->uuid16 == BT_UUID_HIDS_REPORT_VAL && can_stream) {
            has_report_input = true;
        } else if (characteristic->uuid16 == 0x2A22U && can_stream) {
            has_boot_keyboard_input = true;
        } else if (characteristic->uuid16 == 0x2A4EU) {
            protocol_mode_handle = characteristic->value_handle;
        }
    }

    if (!has_report_input && has_boot_keyboard_input && protocol_mode_handle != 0U) {
        int err = bt_gatt_write_without_response(conn, protocol_mode_handle, &boot_protocol,
                                                 sizeof(boot_protocol), false);
        if (err) {
            LOG_WRN("Boot Protocol Mode write failed (%d)", err);
        } else {
            LOG_INF("Selected HID Boot Protocol fallback (vh=0x%04x)", protocol_mode_handle);
        }
    }
}

static uint8_t discover_hids_characteristic_cb(struct bt_conn *conn,
                                               const struct bt_gatt_attr *attr,
                                               struct bt_gatt_discover_params *params) {
    ARG_UNUSED(params);

    struct hogp_target_state *target = find_target_slot_by_conn(conn);
    if (!target) {
        return BT_GATT_ITER_STOP;
    }
    active_target_ptr = target;

    if (!attr) {
        finish_hids_characteristic_discovery(conn, "ATT range complete");
        return BT_GATT_ITER_STOP;
    }

    const struct bt_gatt_chrc *chrc = attr->user_data;
    if (hids_characteristic_count >= MAX_HIDS_CHARACTERISTICS) {
        LOG_WRN("HID characteristic table full (%u)", MAX_HIDS_CHARACTERISTICS);
        return BT_GATT_ITER_CONTINUE;
    }

    struct hids_characteristic *characteristic =
        &active_target.hids_characteristics[hids_characteristic_count++];
    memset(characteristic, 0, sizeof(*characteristic));
    characteristic->declaration_handle = attr->handle;
    characteristic->value_handle = chrc->value_handle;
    characteristic->properties = chrc->properties;
    if (chrc->uuid->type == BT_UUID_TYPE_16) {
        characteristic->uuid16 = ((const struct bt_uuid_16 *)chrc->uuid)->val;
    }
    LOG_DBG("HID characteristic #%u uuid=0x%04x decl=0x%04x value=0x%04x props=0x%02x",
            hids_characteristic_count, characteristic->uuid16, characteristic->declaration_handle,
            characteristic->value_handle, characteristic->properties);

    /* Some keyboards expose HIDS as the final service (end handle 0xffff) and
     * never answer the terminal "anything after this handle?" request. In the
     * observed standard HIDS layout, Control Point follows Report Map and all
     * Report characteristics. Stop there only for that unbounded-service case;
     * services with a real end handle still use normal ATT completion.
     */
    if (characteristic->uuid16 == 0x2A4CU && hids_end_handle == BT_ATT_LAST_ATTRIBUTE_HANDLE) {
        finish_hids_characteristic_discovery(conn, "HID Control Point reached");
        return BT_GATT_ITER_STOP;
    }

    return BT_GATT_ITER_CONTINUE;
}

static void finish_hids_characteristic_discovery(struct bt_conn *conn, const char *reason) {
    for (uint8_t i = 0U; i < hids_characteristic_count; i++) {
        active_target.hids_characteristics[i].end_handle =
            (i + 1U < hids_characteristic_count)
                ? (uint16_t)(active_target.hids_characteristics[i + 1U].declaration_handle - 1U)
                : hids_end_handle;
    }
    LOG_INF("HID characteristic topology discovered (count=%u, %s)",
            hids_characteristic_count, reason);
    schedule_gatt_stage(HOGP_GATT_STAGE_READ_REPORT_MAP, 5U);
    ARG_UNUSED(conn);
}

static uint8_t discover_hids_cb(struct bt_conn *conn, const struct bt_gatt_attr *attr,
                                struct bt_gatt_discover_params *params) {
    const struct bt_gatt_service_val *svc;
    ARG_UNUSED(params);

    struct hogp_target_state *target = find_target_slot_by_conn(conn);
    if (!target) {
        return BT_GATT_ITER_STOP;
    }
    active_target_ptr = target;

    if (!attr) {
        LOG_ERR("HID service not found");
        gatt_discovery_started = false;
        schedule_security_disconnect(BT_HCI_ERR_REMOTE_USER_TERM_CONN, 100U);
        return BT_GATT_ITER_STOP;
    }

    svc = attr->user_data;
    hids_start_handle = attr->handle;
    hids_end_handle = svc->end_handle;

    report_sub_count = 0;
    hids_characteristic_count = 0;
    active_target.report_descriptor_discover_slot = 0U;
    pending_report_char_handle = 0;
    pending_report_value_handle = 0;
    memset(subscribe_params, 0, sizeof(subscribe_params));
    memset(report_meta, 0, sizeof(report_meta));
    memset(active_target.hids_characteristics, 0, sizeof(active_target.hids_characteristics));
    memset(active_target.report_key_usages, 0, sizeof(active_target.report_key_usages));
    memset(active_target.report_key_usage_count, 0, sizeof(active_target.report_key_usage_count));
    memset(active_target.report_consumer_slots, 0, sizeof(active_target.report_consumer_slots));
    memset(active_target.report_consumer_slot_count, 0,
           sizeof(active_target.report_consumer_slot_count));
    memset(report_format_hint, 0, sizeof(report_format_hint));
    hogp_hid_parser_reset(&active_target.hid_parser);
    report_map_valid = false;

    LOG_INF("HID service found; characteristic discovery deferred from BT RX callback");
#if defined(CONFIG_ZMK_BLE_HOGP_SNIFFER_FORWARD_KEY_EVENTS)
    zmk_hogp_sniffer_screen_log_verbose_text(screen_emit_usage_state, "hids found");
#endif
    schedule_gatt_stage(HOGP_GATT_STAGE_DISCOVER_CHARACTERISTICS, 1U);
    return BT_GATT_ITER_STOP;
}

static int start_hids_characteristic_discovery(struct bt_conn *conn) {
    struct bt_gatt_discover_params *characteristic_params =
        &active_target.hids_characteristic_discover_params;
    memset(characteristic_params, 0, sizeof(*characteristic_params));
    characteristic_params->uuid = NULL;
    characteristic_params->start_handle = (uint16_t)(hids_start_handle + 1U);
    characteristic_params->end_handle = hids_end_handle;
    characteristic_params->type = BT_GATT_DISCOVER_CHARACTERISTIC;
    characteristic_params->func = discover_hids_characteristic_cb;
    int err = bt_gatt_discover(conn, characteristic_params);
    if (err) {
        if (err == -ENOMEM || err == -EAGAIN) {
            return err;
        }
        LOG_ERR("HID characteristic discovery start failed (%d)", err);
#if defined(CONFIG_ZMK_BLE_HOGP_SNIFFER_FORWARD_KEY_EVENTS)
        zmk_hogp_sniffer_screen_log_verbose_code(screen_emit_usage_state, "report disc err",
                                                 (uint32_t)(-err));
#endif
    } else {
        LOG_INF("Discovering HID characteristic topology (range=0x%04x-0x%04x)",
                characteristic_params->start_handle, characteristic_params->end_handle);
    }
    return err;
}

static int discover_hids(struct bt_conn *conn) {
    struct bt_gatt_discover_params *service_params =
        &active_target.hids_service_discover_params;
    memset(service_params, 0, sizeof(*service_params));
    service_params->uuid = &hids_uuid.uuid;
    service_params->start_handle = BT_ATT_FIRST_ATTRIBUTE_HANDLE;
    service_params->end_handle = BT_ATT_LAST_ATTRIBUTE_HANDLE;
    service_params->type = BT_GATT_DISCOVER_PRIMARY;
    service_params->func = discover_hids_cb;

    return bt_gatt_discover(conn, service_params);
}

static void connected_cb(struct bt_conn *conn, uint8_t err) {
    int derr;
    struct hogp_target_state *target = find_target_slot_by_conn(conn);
    const bt_addr_le_t *peer = bt_conn_get_dst(conn);
    struct bt_conn_info info = {0};
    int info_err = bt_conn_get_info(conn, &info);
    bool is_peripheral = (info_err == 0 && info.role == BT_CONN_ROLE_PERIPHERAL);

    if (!target) {
        if (!err && is_peripheral) {
            host_connected = true;
            LOG_INF("Host PC connected");
            if (should_wait_for_host()) {
                (void)start_scan();
            }
        }
        return;
    }
    active_target_ptr = target;
    bt_security_t wanted_sec = get_desired_security_level();

    connecting = false;

    if (err) {
        LOG_ERR("Connection failed (err 0x%02x: %s)", err, zmk_hogp_sniffer_hci_reason_to_str(err));
        if (err == BT_HCI_ERR_CONN_FAIL_TO_ESTAB || err == BT_HCI_ERR_UNKNOWN_CONN_ID) {
            next_connect_allowed_ms = k_uptime_get() + 15000;
        }
#if defined(CONFIG_ZMK_BLE_HOGP_SNIFFER_FORWARD_KEY_EVENTS)
        zmk_hogp_sniffer_screen_log_target_reason(
            screen_emit_usage_state, "target connect err", err,
            zmk_hogp_sniffer_hci_reason_to_str(err));
#endif
        clear_default_conn_ref();
        if (reconnect_fail_count < UINT8_MAX) {
            reconnect_fail_count++;
        }
        if (picker_name_probe_active) {
            picker_try_next_name_probe();
            return;
        }
        if (err == BT_HCI_ERR_UNKNOWN_CONN_ID) {
            /* Tear down candidate chain on stale-conn race and restart from scan after cooldown. */
            in_candidate_sequence = false;
            candidate_count = 0;
            candidate_index = 0;
            schedule_scan_restart();
            return;
        }
        (void)try_next_candidate_or_rescan();
        return;
    }

    LOG_INF("Connected to target slot %u", target_slot_number(target));
    if (info_err == 0 && info.type == BT_CONN_TYPE_LE) {
        uint32_t interval_ms_x100 = (uint32_t)info.le.interval * 125U;
        LOG_INF("Target conn params initial: interval=%u (%u.%02u ms), latency=%u, "
                "timeout=%u ms",
                info.le.interval, interval_ms_x100 / 100U, interval_ms_x100 % 100U,
                info.le.latency, (uint32_t)info.le.timeout * 10U);
    }
    security_failure_latched = false;
    screen_typing_enabled = picker_menu_active;
    if (sec_policy_cycle_active) {
        LOG_WRN("Using security policy step L%u", (uint32_t)wanted_sec);
#if defined(CONFIG_ZMK_BLE_HOGP_SNIFFER_FORWARD_KEY_EVENTS)
        zmk_hogp_sniffer_type_text_line(screen_emit_usage_state, "sec policy step");
#endif
    }
    target_ready_announced = false;
#if defined(CONFIG_ZMK_BLE_HOGP_SNIFFER_FORWARD_KEY_EVENTS)
    zmk_hogp_sniffer_screen_log_target_addr(screen_emit_usage_state, "target connected", peer);
    zmk_hogp_sniffer_type_text_line(screen_emit_usage_state, "target link up");
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

#if defined(CONFIG_BT_SMP)
    /* ZMK registers a global authentication callback for its peripheral/host
     * role. Overlay callbacks only on this central-side target connection so
     * keyboards that require authenticated pairing can use passkey display.
     */
    derr = bt_conn_auth_cb_overlay(conn, &auth_cb);
    if (derr) {
        LOG_ERR("Target authentication callback overlay failed (%d)", derr);
#if defined(CONFIG_ZMK_BLE_HOGP_SNIFFER_FORWARD_KEY_EVENTS)
        zmk_hogp_sniffer_screen_log_verbose_code(screen_emit_usage_state, "auth overlay err",
                                                 (uint32_t)(-derr));
#endif
        schedule_security_disconnect(BT_HCI_ERR_REMOTE_USER_TERM_CONN, 50U);
        return;
    }
    LOG_INF("Target authentication callbacks installed");
#endif

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
        /* Do not persist a requested level as though it had succeeded. The
         * security callback stores the actually negotiated level later.
         */
        target_sec_level_hint = 0U;
        target_sec_hint_valid = false;
        (void)save_persisted_target_meta(0U, target_name, target_name_valid);
    }
    gatt_discovery_started = false;
    k_work_cancel_delayable(&hid_discovery_work);
    pending_gatt_stage = HOGP_GATT_STAGE_NONE;
    k_work_cancel_delayable(&gatt_stage_work);
    apply_host_adv_policy(true);

    /* bt_conn_le_create() already used target_conn_param. Do not immediately
     * issue a second update: several commercial keyboards react poorly while
     * security and service discovery are starting. Incoming peripheral
     * parameter requests remain accepted by Zephyr's default policy.
     */
    LOG_INF("Using compatibility conn params (30-50ms, lat=0, timeout=32s)");

    if (wanted_sec <= BT_SECURITY_L1) {
        LOG_INF("Security L1 path: schedule HID discovery");
        schedule_hid_discovery(200U);
        return;
    }

    LOG_INF("Requesting security L%u", (uint32_t)wanted_sec);
    derr = bt_conn_set_security(conn, wanted_sec);
    if (derr == -EALREADY) {
        LOG_INF("Security already satisfied (L%u)", (uint32_t)wanted_sec);
        schedule_hid_discovery(200U);
        return;
    }

    if (derr == 0) {
        /* For L2+, wait for security_changed callback, then start discovery. */
#if defined(CONFIG_ZMK_BLE_HOGP_SNIFFER_FORWARD_KEY_EVENTS)
        zmk_hogp_sniffer_screen_log_verbose_text(screen_emit_usage_state, "wait sec");
#endif
        return;
    }

    LOG_WRN("bt_conn_set_security failed (%d), reconnect with next security policy", derr);
    step_security_policy_on_failure(derr, "set_security_failed");
    schedule_security_disconnect(BT_HCI_ERR_REMOTE_USER_TERM_CONN, 50U);
}

static void disconnected_cb(struct bt_conn *conn, uint8_t reason) {
    struct hogp_target_state *previous_target = active_target_ptr;
    struct hogp_target_state *target = find_target_slot_by_conn(conn);
    const bt_addr_le_t *peer = bt_conn_get_dst(conn);
    struct bt_conn_info info = {0};
    bool is_peripheral = (bt_conn_get_info(conn, &info) == 0 && info.role == BT_CONN_ROLE_PERIPHERAL);

    if (!target) {
        if (is_peripheral) {
            host_connected = false;
            LOG_INF("Host PC disconnected (reason 0x%02x)", reason);
#if defined(CONFIG_ZMK_BLE_HOGP_SNIFFER_FORWARD_KEY_EVENTS)
            zmk_hogp_sniffer_screen_log_verbose_code(screen_emit_usage_state, "host disc", reason);
#endif
        }
        return;
    }
    active_target_ptr = target;
    bool was_discovering = gatt_discovery_started;

    LOG_INF("Target slot %u disconnected (reason 0x%02x: %s)", target_slot_number(target),
            reason, zmk_hogp_sniffer_hci_reason_to_str(reason));
    if (was_discovering) {
        k_work_cancel_delayable(&hid_discovery_work);
        pending_gatt_stage = HOGP_GATT_STAGE_NONE;
        k_work_cancel_delayable(&gatt_stage_work);
    }
    gatt_discovery_started = false;
    if (reason == BT_HCI_ERR_CONN_FAIL_TO_ESTAB || reason == BT_HCI_ERR_REMOTE_USER_TERM_CONN ||
        reason == BT_HCI_ERR_CONN_TIMEOUT) {
        next_connect_allowed_ms = k_uptime_get() + 10000;
    }
#if defined(CONFIG_ZMK_BLE_HOGP_SNIFFER_FORWARD_KEY_EVENTS)
    zmk_hogp_sniffer_screen_log_target_addr(screen_emit_usage_state, "target disconnected", peer);
    zmk_hogp_sniffer_screen_log_target_reason(
        screen_emit_usage_state, "target disc reason", reason,
        zmk_hogp_sniffer_hci_reason_to_str(reason));
    zmk_hogp_sniffer_screen_log_verbose_text(screen_emit_usage_state, "reconnect");
#endif

    clear_default_conn_ref();

    for (size_t i = 0; i < prev_consumer_slot_count; i++) {
        (void)inject_held_position(0, (uint16_t)(CONSUMER_SLOT_BASE + prev_consumer_slots[i]),
                                   false);
    }

    memset(subscribe_params, 0, sizeof(subscribe_params));
    memset(report_meta, 0, sizeof(report_meta));
    memset(active_target.hids_characteristics, 0, sizeof(active_target.hids_characteristics));
    memset(active_target.report_key_usages, 0, sizeof(active_target.report_key_usages));
    memset(active_target.report_key_usage_count, 0, sizeof(active_target.report_key_usage_count));
    memset(active_target.report_consumer_slots, 0, sizeof(active_target.report_consumer_slots));
    memset(active_target.report_consumer_slot_count, 0,
           sizeof(active_target.report_consumer_slot_count));
    report_sub_count = 0;
    hids_characteristic_count = 0;
    memset(report_format_hint, 0, sizeof(report_format_hint));
    hogp_hid_parser_reset(&active_target.hid_parser);
    report_map_len = 0U;
    report_map_valid = false;
    report_map_overflow = false;
    target_ready_announced = false;
    pending_report_char_handle = 0;
    pending_report_value_handle = 0;
    prev_consumer_slot_count = 0;
    memset(prev_consumer_slots, 0, sizeof(prev_consumer_slots));
    if (prev_pointer_buttons != 0U &&
        IS_ENABLED(CONFIG_ZMK_BLE_HOGP_SNIFFER_POINTER_USE_INPUT_LISTENER)) {
        (void)zmk_hogp_proxy_pointer_event_ex(0, 0, 0, 0, aggregate_pointer_buttons(0U));
    }
    prev_pointer_buttons = 0;

#if defined(CONFIG_ZMK_BLE_HOGP_SNIFFER_FORWARD_KEY_EVENTS)
    if (IS_ENABLED(CONFIG_ZMK_BLE_HOGP_SNIFFER_FORWARD_KEY_EVENTS) &&
        !IS_ENABLED(CONFIG_ZMK_BLE_HOGP_SNIFFER_EMIT_POSITION_EVENTS)) {
        for (size_t i = 0; i < prev_usage_count; i++) {
            emit_usage_state(prev_usages[i], false);
        }
    }
#endif
#if defined(CONFIG_ZMK_BLE_HOGP_SNIFFER_EMIT_POSITION_EVENTS)
    if (IS_ENABLED(CONFIG_ZMK_BLE_HOGP_SNIFFER_EMIT_POSITION_EVENTS)) {
        for (size_t i = 0; i < prev_usage_count; i++) {
            uint16_t row, col;
            if (usage_to_row_col(prev_usages[i], &row, &col)) {
                (void)inject_held_position(row, col, false);
            }
        }
    }
#endif
    prev_usage_count = 0;
    security_failure_latched = false;
    screen_typing_enabled = picker_menu_active;
    apply_host_adv_policy(should_wait_for_host() ? true : false);

    if (reconnect_fail_count < UINT8_MAX) {
        reconnect_fail_count++;
    }

    if (picker_name_probe_active) {
        k_work_cancel_delayable(&picker_probe_timeout_work);
        picker_try_next_name_probe();
        return;
    }

    selected_target_valid = false;
    target_hid_verified = false;
    if (previous_target != target && previous_target->conn) {
        active_target_ptr = previous_target;
    }
    LOG_INF("Manual connection mode: press D0 to reload and D3 to reconnect");
}

static void le_param_updated_cb(struct bt_conn *conn, uint16_t interval, uint16_t latency,
                                uint16_t timeout) {
    uint32_t interval_ms_x100 = (uint32_t)interval * 125U;
    struct hogp_target_state *target = find_target_slot_by_conn(conn);

    if (!target) {
        return;
    }

    LOG_INF("Target conn params active: interval=%u (%u.%02u ms), latency=%u, timeout=%u ms",
            interval, interval_ms_x100 / 100U, interval_ms_x100 % 100U, latency,
            (uint32_t)timeout * 10U);
}

static bool le_param_req_cb(struct bt_conn *conn, struct bt_le_conn_param *param) {
    uint16_t requested_timeout;
    struct hogp_target_state *target = find_target_slot_by_conn(conn);

    if (!target) {
        return true;
    }

    requested_timeout = param->timeout;
    /* A few keyboards request a sub-second supervision timeout. It is legal
     * for their interval/latency, but too fragile during encrypted GATT
     * discovery and causes a single missed burst to drop the whole link.
     * Keep the keyboard's preferred interval and latency, while raising only
     * the timeout to a conservative four seconds.
     */
    if (param->timeout < 400U) {
        param->timeout = 400U;
    }

    LOG_INF("Target conn param request: interval=%u-%u, latency=%u, timeout=%u ms%s",
            param->interval_min, param->interval_max, param->latency,
            (uint32_t)requested_timeout * 10U,
            requested_timeout != param->timeout ? " (timeout adjusted to 4000 ms)" : "");
    return true;
}

static void security_changed_cb(struct bt_conn *conn, bt_security_t level, enum bt_security_err err) {
    struct hogp_target_state *target = find_target_slot_by_conn(conn);

    if (!target) {
        return;
    }
    active_target_ptr = target;
    bt_security_t wanted_sec = get_desired_security_level();

    if (err) {
        if (security_failure_latched) {
            return;
        }
        security_failure_latched = true;
        LOG_WRN("Security changed failed (level %u, err %d: %s)", (uint32_t)level, (int)err,
                zmk_hogp_sniffer_sec_err_to_str(err));
#if defined(CONFIG_ZMK_BLE_HOGP_SNIFFER_FORWARD_KEY_EVENTS)
        zmk_hogp_sniffer_screen_log_verbose_code(screen_emit_usage_state, "sec err", (uint32_t)err);
        zmk_hogp_sniffer_type_text_line(screen_emit_usage_state, "target sec fail");
#endif
        step_security_policy_on_failure((int)err, "security_failed");
        schedule_security_disconnect(BT_HCI_ERR_REMOTE_USER_TERM_CONN, 50U);
        return;
    }

    if (level < wanted_sec || gatt_discovery_started) {
        if (level < wanted_sec) {
            LOG_WRN("Security level insufficient: got L%u want L%u", (uint32_t)level,
                    (uint32_t)wanted_sec);
        }
        return;
    }

    sec_policy_cycle_active = false;
    sec_policy_try_idx = 0U;
    target_sec_level_hint = (uint8_t)level;
    target_sec_hint_valid = true;
    (void)save_persisted_target_meta(target_sec_level_hint, target_name, target_name_valid);
    schedule_hid_discovery(200U);
#if defined(CONFIG_ZMK_BLE_HOGP_SNIFFER_FORWARD_KEY_EVENTS)
    zmk_hogp_sniffer_type_text_line(screen_emit_usage_state, "target secure");
    zmk_hogp_sniffer_screen_log_verbose_text(screen_emit_usage_state, "disc hids");
#endif
}

static void pairing_complete_cb(struct bt_conn *conn, bool bonded) {
    struct hogp_target_state *target = find_target_slot_by_conn(conn);
    if (target) {
        active_target_ptr = target;
    }
    LOG_INF("Pairing complete (bonded=%u)", bonded ? 1U : 0U);
}

static void pairing_failed_cb(struct bt_conn *conn, enum bt_security_err reason) {
    struct hogp_target_state *target = find_target_slot_by_conn(conn);
    if (!target) {
        return;
    }
    active_target_ptr = target;
    if (security_failure_latched) {
        return;
    }
    security_failure_latched = true;
    LOG_WRN("Pairing failed (reason=%d: %s)", (int)reason,
            zmk_hogp_sniffer_sec_err_to_str(reason));
    step_security_policy_on_failure((int)reason, "pair_failed");
#if defined(CONFIG_ZMK_BLE_HOGP_SNIFFER_FORWARD_KEY_EVENTS)
    zmk_hogp_sniffer_screen_log_target_reason(
        screen_emit_usage_state, "pair fail", (uint8_t)reason,
        zmk_hogp_sniffer_sec_err_to_str(reason));
#endif
    schedule_security_disconnect(BT_HCI_ERR_REMOTE_USER_TERM_CONN, 50U);
}

#if defined(CONFIG_BT_SMP)
static enum bt_security_err auth_pairing_accept_cb(struct bt_conn *conn,
                                                   const struct bt_conn_pairing_feat *const feat) {
    struct bt_conn_info info;
    char addr[BT_ADDR_LE_STR_LEN];

    ARG_UNUSED(feat);
    bt_addr_le_to_str(bt_conn_get_dst(conn), addr, sizeof(addr));

    if (bt_conn_get_info(conn, &info) != 0) {
        LOG_WRN("Pairing accept: info unavailable for %s, allowing", addr);
        return BT_SECURITY_ERR_SUCCESS;
    }

    if (info.role == BT_CONN_ROLE_CENTRAL) {
        LOG_INF("Pairing request from target accepted: %s", addr);
    }
    return BT_SECURITY_ERR_SUCCESS;
}

static void auth_passkey_display_cb(struct bt_conn *conn, unsigned int passkey) {
    char addr[BT_ADDR_LE_STR_LEN];

    bt_addr_le_to_str(bt_conn_get_dst(conn), addr, sizeof(addr));
    LOG_INF("Passkey display for %s: %06u", addr, passkey);
#if defined(CONFIG_ZMK_BLE_HOGP_SNIFFER_FORWARD_KEY_EVENTS)
    bool output_ready = host_connected;
#if defined(CONFIG_ZMK_USB)
    output_ready = output_ready || zmk_usb_is_hid_ready();
#endif
    if (IS_ENABLED(CONFIG_ZMK_BLE_HOGP_SNIFFER_SHOW_PASSKEY_ON_HOST) && output_ready) {
        char line[32];
        snprintf(line, sizeof(line), "target passkey %06u", passkey);
        zmk_hogp_sniffer_type_text_line(emit_usage_state, line);
        LOG_INF("Passkey typed to connected host");
    }
#endif
}

static void auth_passkey_entry_cb(struct bt_conn *conn) {
    char addr[BT_ADDR_LE_STR_LEN];
    int err;

    bt_addr_le_to_str(bt_conn_get_dst(conn), addr, sizeof(addr));
    LOG_ERR("Passkey entry requested by %s", addr);

    if (IS_ENABLED(CONFIG_ZMK_BLE_HOGP_SNIFFER_PASSKEY_ENTRY_USE_FIXED)) {
        unsigned int passkey = 0U;
#if defined(CONFIG_ZMK_BLE_HOGP_SNIFFER_PASSKEY_ENTRY_FIXED)
        passkey = (unsigned int)CONFIG_ZMK_BLE_HOGP_SNIFFER_PASSKEY_ENTRY_FIXED;
#endif
        err = bt_conn_auth_passkey_entry(conn, passkey);
        if (err && err != -EALREADY) {
            LOG_WRN("bt_conn_auth_passkey_entry failed (%d)", err);
            return;
        }
        LOG_WRN("Fixed passkey entry sent: %06u", passkey);
        return;
    }

    LOG_ERR("No passkey input path implemented. Enable fixed passkey or add UI input path.");
}

static void auth_passkey_confirm_cb(struct bt_conn *conn, unsigned int passkey) {
    char addr[BT_ADDR_LE_STR_LEN];

    bt_addr_le_to_str(bt_conn_get_dst(conn), addr, sizeof(addr));
    LOG_WRN("Numeric comparison requested by %s: %06u", addr, passkey);

    if (IS_ENABLED(CONFIG_ZMK_BLE_HOGP_SNIFFER_AUTH_AUTO_CONFIRM)) {
        int err = bt_conn_auth_passkey_confirm(conn);
        if (err && err != -EALREADY) {
            LOG_WRN("bt_conn_auth_passkey_confirm failed (%d)", err);
            return;
        }
        LOG_INF("Numeric comparison auto-confirmed");
    } else {
        LOG_WRN("Auto-confirm disabled; pairing may fail if confirmation is required");
    }
}

static void auth_pairing_confirm_cb(struct bt_conn *conn) {
    char addr[BT_ADDR_LE_STR_LEN];

    bt_addr_le_to_str(bt_conn_get_dst(conn), addr, sizeof(addr));
    LOG_WRN("Pairing confirm requested by %s", addr);

    if (IS_ENABLED(CONFIG_ZMK_BLE_HOGP_SNIFFER_AUTH_AUTO_CONFIRM)) {
        int err = bt_conn_auth_pairing_confirm(conn);
        if (err && err != -EALREADY) {
            LOG_WRN("bt_conn_auth_pairing_confirm failed (%d)", err);
            return;
        }
        LOG_INF("Pairing confirm auto-accepted");
    } else {
        LOG_WRN("Auto-confirm disabled; pairing may fail if confirmation is required");
    }
}

static void auth_cancel_cb(struct bt_conn *conn) {
    char addr[BT_ADDR_LE_STR_LEN];

    bt_addr_le_to_str(bt_conn_get_dst(conn), addr, sizeof(addr));
    LOG_WRN("Pairing cancelled by peer: %s", addr);
}

static struct bt_conn_auth_cb auth_cb = {
    .pairing_accept = auth_pairing_accept_cb,
    .passkey_display = auth_passkey_display_cb,
    .passkey_entry = auth_passkey_entry_cb,
    .passkey_confirm = auth_passkey_confirm_cb,
    .pairing_confirm = auth_pairing_confirm_cb,
    .cancel = auth_cancel_cb,
};

static struct bt_conn_auth_info_cb auth_info_cb = {
    .pairing_complete = pairing_complete_cb,
    .pairing_failed = pairing_failed_cb,
};
#endif

BT_CONN_CB_DEFINE(conn_callbacks) = {
    .connected = connected_cb,
    .disconnected = disconnected_cb,
    .le_param_req = le_param_req_cb,
    .le_param_updated = le_param_updated_cb,
#if defined(CONFIG_BT_SMP)
    .security_changed = security_changed_cb,
#endif
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

static bool adv_type_can_connect(uint8_t adv_type) {
    /* An active scan reports scan responses separately. They often contain
     * the device name, but are not themselves valid LE Create Connection
     * targets. Wait for a connectable advertising packet from that address.
     */
    return adv_type == BT_GAP_ADV_TYPE_ADV_IND ||
           adv_type == BT_GAP_ADV_TYPE_ADV_DIRECT_IND;
}

static void scan_cb(const bt_addr_le_t *addr, int8_t rssi, uint8_t adv_type,
                    struct net_buf_simple *ad) {
    char addr_str[BT_ADDR_LE_STR_LEN];
    char name[PICKER_NAME_MAX];
    bool has_name = false;

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

    has_name = extract_alnum_name(ad, name, sizeof(name)) && name[0] != '\0';

    if (IS_ENABLED(CONFIG_ZMK_BLE_HOGP_SNIFFER_BUTTON_SELECTOR) && !selected_target_valid) {
        if (has_name) {
            picker_add_or_update(addr, name, rssi);
        } else {
            snprintf(name, sizeof(name), "UNKNOWN%02x%02x%02x", addr->a.val[2], addr->a.val[1],
                     addr->a.val[0]);
            picker_add_or_update(addr, name, rssi);
        }
        return;
    }

    if (!target_any_addr) {
        bool addr_match = false;

        if (target_match_any_type) {
            addr_match = bt_addr_eq(&addr->a, &target_addr.a);
        } else {
            if (addr->type == target_addr.type && bt_addr_eq(&addr->a, &target_addr.a)) {
                addr_match = true;
            }
        }

        if (!addr_match) {
            bool name_match = false;

            if (target_name_valid && has_name && strcmp(name, target_name) == 0) {
                name_match = true;
            }

            if (!name_match) {
                return;
            }

            /* A bonded privacy device may advertise under a refreshed RPA.
             * Remember the address found in its name-bearing scan response,
             * then connect only after its connectable ADV packet arrives.
             */
            bt_addr_le_copy(&target_addr, addr);
            target_match_any_type = true;
        }
    }

    if (!adv_type_can_connect(adv_type)) {
        LOG_DBG("Matched target in non-connectable advertising packet type=%u; waiting for "
                "connectable packet",
                adv_type);
        return;
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
        zmk_hogp_sniffer_screen_log_verbose_code(screen_emit_usage_state, "cand", candidate_count);
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

static void candidate_same_addr_progress(uint8_t idx, uint8_t *rank, uint8_t *total) {
    uint8_t r = 0U;
    uint8_t t = 0U;

    if (!rank || !total || idx >= candidate_count) {
        return;
    }

    for (uint8_t i = 0; i < candidate_count; i++) {
        if (bt_addr_eq(&candidate_addrs[i].a, &candidate_addrs[idx].a)) {
            t++;
            if (i <= idx) {
                r++;
            }
        }
    }

    *rank = r;
    *total = t;
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
        zmk_hogp_sniffer_screen_log_verbose_text(screen_emit_usage_state, "wait host pc");
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
    zmk_hogp_sniffer_screen_log_verbose_text(screen_emit_usage_state, "scan start");
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

    if (scanning) {
        int serr = bt_le_scan_stop();
        if (serr && serr != -EALREADY) {
            LOG_WRN("Scan stop before connect failed (%d)", serr);
        }
        scanning = false;
    }

    connecting = true;
#if defined(CONFIG_ZMK_BLE_HOGP_SNIFFER_FORWARD_KEY_EVENTS)
    zmk_hogp_sniffer_screen_log_verbose_text(screen_emit_usage_state, "connect try");
#endif
    err = bt_conn_le_create(addr, BT_CONN_LE_CREATE_CONN, &target_conn_param, &default_conn);
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

    if (!err && data && length > 0 && picker_probe_addr_valid) {
        char name[PICKER_NAME_MAX];
        size_t n = MIN((size_t)length, sizeof(name) - 1U);

        memcpy(name, data, n);
        name[n] = '\0';
        for (size_t i = 0; i < n; i++) {
            uint8_t c = (uint8_t)name[i];
            if (!zmk_hogp_sniffer_is_ascii_alnum(c)) {
                name[i] = 'x';
            }
        }

        if (name[0] != '\0') {
            picker_add_or_update(&picker_probe_addr, name, 0);
            picker_unknown_remove_by_addr(&picker_probe_addr);
            LOG_INF("name probe ok: %s", name);
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
    int64_t now;
    uint32_t wait_ms;
    uint8_t same_rank = 0U;
    uint8_t same_total = 0U;
    ARG_UNUSED(work);

    if (!in_candidate_sequence || default_conn || connecting || candidate_index >= candidate_count) {
        return;
    }

    candidate_same_addr_progress(candidate_index, &same_rank, &same_total);
    if (same_total > 1U) {
        LOG_INF("Trying candidate %u/%u (same-mac %u/%u)", (uint8_t)(candidate_index + 1U),
                candidate_count, same_rank, same_total);
    } else {
        LOG_INF("Trying candidate %u/%u", (uint8_t)(candidate_index + 1U), candidate_count);
    }
#if defined(CONFIG_ZMK_BLE_HOGP_SNIFFER_FORWARD_KEY_EVENTS)
    zmk_hogp_sniffer_screen_log_verbose_code(screen_emit_usage_state, "try idx",
                                             (uint32_t)(candidate_index + 1U));
#endif
    err = connect_to_candidate(&candidate_addrs[candidate_index]);
    if (err == -EAGAIN) {
        now = k_uptime_get();
        wait_ms = (next_connect_allowed_ms > now) ? (uint32_t)(next_connect_allowed_ms - now) : 200U;
        LOG_INF("Retry same candidate after throttle in %u ms", wait_ms);
        schedule_connect_current_candidate(wait_ms);
        return;
    }
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
        err = bt_le_scan_stop();
        if (err && err != -EALREADY) {
            LOG_WRN("Picker scan stop failed (%d)", err);
        }
        scanning = false;
        LOG_INF("Picker scan complete: devices=%u selected=%u", picker_device_count,
                picker_device_count == 0U ? 0U : (uint8_t)(picker_selected_index + 1U));
        picker_print_list();
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
    /* Avoid controller state race right after scan stop. */
    schedule_connect_current_candidate(200U);
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
#if defined(CONFIG_ZMK_BLE) &&                                                                  \
    defined(CONFIG_ZMK_BLE_HOGP_SNIFFER_BLOCK_HOST_ADV_UNTIL_TARGET_CONNECTED)
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
        case 0: /* Reload target list */
            if (connecting || gatt_discovery_started) {
                LOG_WRN("Device list reload deferred: target setup is still in progress");
                break;
            }
            release_all_target_inputs();
            picker_menu_active = true;
            input_passthrough_enabled = false;
            screen_typing_enabled = true;
            {
                struct hogp_target_state *free_target = find_free_target_slot();
                if (!free_target) {
                    LOG_WRN("All %u target slots are connected; reset one before adding another",
                            MAX_ACTIVE_TARGETS);
                    picker_print_list();
                    break;
                }
                active_target_ptr = free_target;
                memset(free_target, 0, sizeof(*free_target));
            }
            picker_device_count = 0U;
            picker_unknown_count = 0U;
            picker_selected_index = 0U;
            selected_target_valid = false;
            memset(picker_devices, 0, sizeof(picker_devices));
            memset(picker_unknown_addrs, 0, sizeof(picker_unknown_addrs));
            picker_load_saved_and_connected_devices();
            LOG_INF("Device list reload requested");
            if (scanning) {
                (void)bt_le_scan_stop();
                scanning = false;
                k_work_cancel_delayable(&scan_cycle_work);
            }
            if (!connecting) {
                (void)start_scan();
            }
            picker_print_list();
            break;

        case 1: /* Up */
            if (items > 0U) {
                if (picker_selected_index == 0U) {
                    picker_selected_index = (uint8_t)(items - 1U);
                } else {
                    picker_selected_index--;
                }
            }
            picker_announce_current("sel");
            break;

        case 2: /* Down */
            if (items > 0U) {
                picker_selected_index = (uint8_t)((picker_selected_index + 1U) % items);
            }
            picker_announce_current("sel");
            break;

        case 3: /* Connect selected device */
            if (items == 0U) {
                picker_announce_current("empty");
                break;
            }
            if (picker_device_is_connected(&picker_devices[picker_selected_index].addr)) {
                picker_announce_current("connected");
                break;
            }
            if (connecting || gatt_discovery_started) {
                picker_announce_current("busy");
                break;
            }
            if (default_conn) {
                struct hogp_target_state *free_target = find_free_target_slot();
                if (!free_target) {
                    picker_announce_current("slots full");
                    break;
                }
                active_target_ptr = free_target;
                memset(free_target, 0, sizeof(*free_target));
            }

            {
                const char *new_name = picker_devices[picker_selected_index].name;
                bool same_name = (target_name_valid && strcmp(target_name, new_name) == 0);
                if (!same_name) {
                    target_sec_hint_valid = false;
                }
            }
            bt_addr_le_copy(&target_addr, &picker_devices[picker_selected_index].addr);
            strncpy(target_name, picker_devices[picker_selected_index].name,
                    sizeof(target_name) - 1U);
            target_name[sizeof(target_name) - 1U] = '\0';
            target_name_valid = (target_name[0] != '\0');
            sec_policy_cycle_active = false;
            sec_policy_try_idx = 0U;
            last_sec_policy_step_ms = 0;
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

        case 4: /* Reset selected device */
            if (items == 0U) {
                picker_announce_current("empty");
                break;
            }
            {
                const bt_addr_le_t *addr = &picker_devices[picker_selected_index].addr;
                struct bt_conn *conn = bt_conn_lookup_addr_le(BT_ID_DEFAULT, addr);
                if (!conn) {
                    for (uint8_t i = 0U; i < MAX_ACTIVE_TARGETS; i++) {
                        if (target_slots[i].conn &&
                            bt_addr_eq(&target_slots[i].addr.a, &addr->a)) {
                            conn = bt_conn_ref(target_slots[i].conn);
                            break;
                        }
                    }
                }
                if (conn) {
                    (void)bt_conn_disconnect(conn, BT_HCI_ERR_REMOTE_USER_TERM_CONN);
                    bt_conn_unref(conn);
                }
                int err = bt_unpair(BT_ID_DEFAULT, addr);
                int registry_err = target_registry_remove(addr);
                LOG_INF("Selected device reset #%u %s (%d)",
                        (uint32_t)(picker_selected_index + 1U),
                        picker_devices[picker_selected_index].name, err);
                if (registry_err && registry_err != -ENOENT) {
                    LOG_WRN("Failed to remove selected device registry entry (%d)", registry_err);
                }
            }
            picker_print_list();
            break;

        case 5: /* Reset all input-device settings; preserve host profiles */
            LOG_INF("Resetting all input-device bonds/settings; preserving host profiles");
            release_all_target_inputs();
            picker_menu_active = true;
            input_passthrough_enabled = false;
            screen_typing_enabled = true;
            if (scanning) {
                (void)bt_le_scan_stop();
                scanning = false;
            }
            k_work_cancel_delayable(&scan_cycle_work);
            k_work_cancel_delayable(&reconnect_work);
            k_work_cancel_delayable(&candidate_connect_work);
            k_work_cancel_delayable(&picker_probe_timeout_work);
            k_work_cancel_delayable(&hid_discovery_work);
            k_work_cancel_delayable(&gatt_stage_work);
            in_candidate_sequence = false;
            candidate_count = 0U;
            candidate_index = 0U;
            picker_name_probe_active = false;
            for (uint8_t i = 0U; i < MAX_ACTIVE_TARGETS; i++) {
                if (target_slots[i].conn) {
                    (void)bt_conn_disconnect(target_slots[i].conn,
                                             BT_HCI_ERR_REMOTE_USER_TERM_CONN);
                }
                if (target_slots[i].selected_valid) {
                    int err = bt_unpair(BT_ID_DEFAULT, &target_slots[i].addr);
                    if (err && err != -ENOENT) {
                        LOG_WRN("Failed to clear connected input bond slot %u (%d)",
                                (uint32_t)(i + 1U), err);
                    }
                }
            }
            for (uint8_t i = 0U; i < target_registry.count; i++) {
                bt_addr_le_t addr = {.type = target_registry.targets[i].type};
                memcpy(addr.a.val, target_registry.targets[i].a, sizeof(addr.a.val));
                int err = bt_unpair(BT_ID_DEFAULT, &addr);
                if (err && err != -ENOENT) {
                    LOG_WRN("Failed to clear registered input bond %u (%d)",
                            (uint32_t)(i + 1U), err);
                }
            }
            (void)settings_delete("ble_hogp_sniffer/target_addr");
            (void)settings_delete("ble_hogp_sniffer/target_meta");
            (void)settings_delete("ble_hogp_sniffer/devices");
            memset(&target_registry, 0, sizeof(target_registry));
            selected_target_valid = false;
            target_hid_verified = false;
            target_name[0] = '\0';
            target_name_valid = false;
            target_sec_hint_valid = false;
            picker_device_count = 0U;
            picker_unknown_count = 0U;
            picker_selected_index = 0U;
            memset(picker_devices, 0, sizeof(picker_devices));
            memset(picker_unknown_addrs, 0, sizeof(picker_unknown_addrs));
            picker_print_list();
            break;

        case 6: /* Exit menu and pass connected HID input through */
            picker_menu_active = false;
            input_passthrough_enabled = true;
            screen_typing_enabled = false;
            LOG_INF("Device manager closed; HID input passthrough enabled");
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

    if (idx > 6U) {
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
    target_name[0] = '\0';
    target_name_valid = false;
    target_sec_hint_valid = false;

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
    LOG_INF("Pairing compatibility: %s; host output: %s",
            IS_ENABLED(CONFIG_BT_SMP_SC_PAIR_ONLY) ? "LE Secure Connections only"
                                                   : "Legacy + Secure Connections",
            IS_ENABLED(CONFIG_ZMK_BLE) ? "USB + BLE" : "USB");

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

#if defined(CONFIG_SETTINGS) && !defined(CONFIG_ZMK_BLE)
    /* ZMK normally loads settings from main() before its BLE stack is
     * enabled. In central-only compatibility mode Bluetooth is enabled here,
     * later, so load again after bt_enable() to create/restore the local
     * identity and bonds before scanning. Otherwise bt_le_scan_start() fails
     * with -EAGAIN and the controller reports "App must call settings_load".
     */
    err = settings_load();
    if (err) {
        LOG_ERR("Bluetooth settings load failed (%d)", err);
        return err;
    }
    LOG_INF("Bluetooth settings loaded; identity ready");
#endif

#if defined(CONFIG_BT_SMP)
    err = bt_conn_auth_info_cb_register(&auth_info_cb);
    if (err && err != -EALREADY) {
        LOG_WRN("bt_conn_auth_info_cb_register failed (%d)", err);
    }
#endif

#if defined(CONFIG_ZMK_BLE)
    /* Ensure host advertising state machine is nudged at boot. */
    (void)zmk_ble_set_device_name((char *)CONFIG_BT_DEVICE_NAME);
#endif

    target_any_addr = false;
    if (IS_ENABLED(CONFIG_ZMK_BLE_HOGP_SNIFFER_BUTTON_SELECTOR)) {
        bool loaded = false;
        bool mloaded = false;
        int lerr = load_persisted_target_addr(&target_addr, &loaded);
        int merr = load_persisted_target_meta(&target_sec_level_hint, target_name, &target_name_valid,
                                              &mloaded);
        if (lerr) {
            LOG_WRN("Persisted target load failed (%d)", lerr);
        }
        if (merr) {
            LOG_WRN("Persisted target meta load failed (%d)", merr);
        }
        /* Saved metadata is used only for marks/security hints. Connections
         * are initiated explicitly with D3 in device-manager mode.
         */
        selected_target_valid = false;
        target_sec_hint_valid = mloaded;
        picker_device_count = 0;
        picker_unknown_count = 0;
        picker_selected_index = 0;
        picker_load_saved_and_connected_devices();
        if (loaded) {
            target_any_addr = false;
            target_match_any_type = true;
            LOG_INF("Device manager: saved target metadata loaded; waiting for D3 connect");
        } else {
            memset(&target_addr, 0, sizeof(target_addr));
            target_name[0] = '\0';
            target_name_valid = false;
            target_sec_hint_valid = false;
            LOG_INF("Device manager enabled (D0 reload, D1 up, D2 down, D3 connect, "
                    "D4 reset selected, D5 reset all inputs, D6 exit)");
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
    screen_typing_enabled = true;
    picker_menu_active = IS_ENABLED(CONFIG_ZMK_BLE_HOGP_SNIFFER_BUTTON_SELECTOR);
    input_passthrough_enabled = !picker_menu_active;
    next_connect_allowed_ms = 0;
    sec_policy_cycle_active = false;
    sec_policy_try_idx = 0U;
    last_sec_policy_step_ms = 0;
    picker_name_probe_active = false;
    picker_probe_count = 0;
    picker_probe_pos = 0;
    picker_probe_addr_valid = false;

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
    k_work_init_delayable(&security_disconnect_work, security_disconnect_work_handler);
    k_work_init_delayable(&hid_discovery_work, hid_discovery_work_handler);
    k_work_init_delayable(&gatt_stage_work, gatt_stage_work_handler);
    k_work_init(&picker_button_work, picker_button_work_handler);
    k_work_init_delayable(&sniffer_start_work, sniffer_start_work_handler);
    k_work_schedule(&sniffer_start_work, K_SECONDS(3));
    return 0;
}

SYS_INIT(ble_hogp_sniffer_schedule_init, APPLICATION, CONFIG_APPLICATION_INIT_PRIORITY);

