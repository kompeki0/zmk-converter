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
#include <zephyr/sys/util.h>

#include <zmk/event_manager.h>
#include <zmk/events/usb_conn_state_changed.h>
#include <zmk/usb.h>
#include <zmk/endpoints.h>

#if defined(CONFIG_ZMK_BLE_HOGP_SNIFFER_FORWARD_KEY_EVENTS)
#include <zmk/events/keycode_state_changed.h>
#endif

LOG_MODULE_REGISTER(ble_hogp_sniffer, CONFIG_ZMK_BLE_HOGP_SNIFFER_LOG_LEVEL);

#define BOOT_KBD_REPORT_LEN 8
#define MAX_PRESSED_USAGES 14

#if defined(ZMK_ENDPOINT_USB) && defined(ZMK_ENDPOINT_BLE)
#define HOGP_OUT_USB ZMK_ENDPOINT_USB
#define HOGP_OUT_BLE ZMK_ENDPOINT_BLE
#elif defined(ZMK_TRANSPORT_USB) && defined(ZMK_TRANSPORT_BLE)
#define HOGP_OUT_USB ZMK_TRANSPORT_USB
#define HOGP_OUT_BLE ZMK_TRANSPORT_BLE
#endif

static struct bt_conn *default_conn;
static struct bt_gatt_discover_params discover_params;
static struct bt_gatt_subscribe_params subscribe_params;
static bt_addr_le_t target_addr;
static struct k_work_delayable sniffer_start_work;

static uint16_t hids_start_handle;
static uint16_t hids_end_handle;
static bool scanning;
static bool connecting;

static struct bt_uuid_16 hids_uuid = BT_UUID_INIT_16(BT_UUID_HIDS_VAL);
static struct bt_uuid_16 report_uuid = BT_UUID_INIT_16(BT_UUID_HIDS_REPORT_VAL);
static struct bt_uuid_16 ccc_uuid = BT_UUID_INIT_16(BT_UUID_GATT_CCC_VAL);

static uint8_t prev_usages[MAX_PRESSED_USAGES];
static size_t prev_usage_count;

static int start_scan(void);
static void set_output_endpoint_auto(const char *reason);
static int clear_non_target_bonds(void);

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
    if (IS_ENABLED(CONFIG_ZMK_BLE_HOGP_SNIFFER_FORWARD_KEY_EVENTS)) {
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

    prev_usage_count = curr_usage_count;
    memcpy(prev_usages, curr_usages, curr_usage_count);
}

static void set_output_endpoint_auto(const char *reason) {
    enum zmk_usb_conn_state usb_state = zmk_usb_get_conn_state();
    bool use_usb = (usb_state == ZMK_USB_CONN_HID);
#if defined(HOGP_OUT_USB) && defined(HOGP_OUT_BLE)
    int endpoint = use_usb ? HOGP_OUT_USB : HOGP_OUT_BLE;
    int err = zmk_endpoints_select(endpoint);

    if (err) {
        LOG_WRN("Endpoint select failed (%d) reason=%s", err, reason);
        return;
    }

    LOG_INF("Endpoint set to %s reason=%s", use_usb ? "USB" : "BLE", reason);
#else
    ARG_UNUSED(reason);
    LOG_WRN("Endpoint select constants not available in this ZMK version");
#endif
}

#if defined(CONFIG_ZMK_BLE_HOGP_SNIFFER_CLEAR_NON_TARGET_BONDS_ON_START)
struct clear_bonds_ctx {
    bt_addr_le_t keep;
};

static void clear_non_target_bonds_cb(const struct bt_bond_info *info, void *user_data) {
    struct clear_bonds_ctx *ctx = user_data;
    int err;
    char addr_str[BT_ADDR_LE_STR_LEN];

    if (info->addr.type == ctx->keep.type && bt_addr_eq(&info->addr.a, &ctx->keep.a)) {
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

static int usb_conn_state_listener(const zmk_event_t *eh) {
    if (as_zmk_usb_conn_state_changed(eh) != NULL) {
        set_output_endpoint_auto("usb_state_changed");
    }

    return ZMK_EV_EVENT_BUBBLE;
}

ZMK_LISTENER(ble_hogp_sniffer_usb_conn_state, usb_conn_state_listener);
ZMK_SUBSCRIPTION(ble_hogp_sniffer_usb_conn_state, zmk_usb_conn_state_changed);

static uint8_t notify_cb(struct bt_conn *conn, struct bt_gatt_subscribe_params *params,
                         const void *data, uint16_t length) {
    ARG_UNUSED(conn);
    ARG_UNUSED(params);

    if (!data) {
        LOG_INF("Notification stopped");
        return BT_GATT_ITER_STOP;
    }

    LOG_HEXDUMP_INF(data, length, "HID Input");
    process_boot_report(data, length);
    return BT_GATT_ITER_CONTINUE;
}

static uint8_t discover_ccc_cb(struct bt_conn *conn, const struct bt_gatt_attr *attr,
                               struct bt_gatt_discover_params *params) {
    int err;

    if (!attr) {
        LOG_ERR("CCC descriptor not found");
        return BT_GATT_ITER_STOP;
    }

    if (bt_uuid_cmp(attr->uuid, &ccc_uuid.uuid) != 0) {
        return BT_GATT_ITER_CONTINUE;
    }

    subscribe_params.notify = notify_cb;
    subscribe_params.value = BT_GATT_CCC_NOTIFY;
    subscribe_params.value_handle = params->start_handle - 1;
    subscribe_params.ccc_handle = attr->handle;

    err = bt_gatt_subscribe(conn, &subscribe_params);
    if (err) {
        LOG_ERR("bt_gatt_subscribe failed (%d)", err);
    } else {
        LOG_INF("Subscribed to Input Report notifications");
    }

    return BT_GATT_ITER_STOP;
}

static uint8_t discover_report_cb(struct bt_conn *conn, const struct bt_gatt_attr *attr,
                                  struct bt_gatt_discover_params *params) {
    int err;
    const struct bt_gatt_chrc *chrc;
    ARG_UNUSED(params);

    if (!attr) {
        LOG_ERR("Input Report characteristic not found");
        return BT_GATT_ITER_STOP;
    }

    chrc = attr->user_data;
    if (!(chrc->properties & BT_GATT_CHRC_NOTIFY)) {
        return BT_GATT_ITER_CONTINUE;
    }

    discover_params.uuid = &ccc_uuid.uuid;
    discover_params.start_handle = chrc->value_handle + 1;
    discover_params.end_handle = hids_end_handle;
    discover_params.type = BT_GATT_DISCOVER_DESCRIPTOR;
    discover_params.func = discover_ccc_cb;

    err = bt_gatt_discover(conn, &discover_params);
    if (err) {
        LOG_ERR("CCC discovery failed (%d)", err);
    } else {
        LOG_INF("Discovering CCC descriptor");
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

    discover_params.uuid = &report_uuid.uuid;
    discover_params.start_handle = hids_start_handle + 1;
    discover_params.end_handle = hids_end_handle;
    discover_params.type = BT_GATT_DISCOVER_CHARACTERISTIC;
    discover_params.func = discover_report_cb;

    err = bt_gatt_discover(conn, &discover_params);
    if (err) {
        LOG_ERR("Report characteristic discovery failed (%d)", err);
    } else {
        LOG_INF("HID service found, discovering Input Report characteristic");
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
        (void)start_scan();
        return;
    }

    LOG_INF("Connected to target");
    derr = discover_hids(conn);
    if (derr) {
        LOG_ERR("HID discovery start failed (%d)", derr);
    }
}

static void disconnected_cb(struct bt_conn *conn, uint8_t reason) {
    if (conn != default_conn) {
        return;
    }

    LOG_INF("Disconnected (reason 0x%02x)", reason);

    bt_conn_unref(default_conn);
    default_conn = NULL;
    subscribe_params.value_handle = 0U;
    subscribe_params.ccc_handle = 0U;

#if defined(CONFIG_ZMK_BLE_HOGP_SNIFFER_FORWARD_KEY_EVENTS)
    if (IS_ENABLED(CONFIG_ZMK_BLE_HOGP_SNIFFER_FORWARD_KEY_EVENTS)) {
        for (size_t i = 0; i < prev_usage_count; i++) {
            emit_usage_state(prev_usages[i], false);
        }
    }
#endif
    prev_usage_count = 0;

    (void)start_scan();
}

BT_CONN_CB_DEFINE(conn_callbacks) = {
    .connected = connected_cb,
    .disconnected = disconnected_cb,
};

static void scan_cb(const bt_addr_le_t *addr, int8_t rssi, uint8_t adv_type,
                    struct net_buf_simple *ad) {
    int err;
    char addr_str[BT_ADDR_LE_STR_LEN];

    ARG_UNUSED(ad);

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

    LOG_INF("Target found, connecting");

    err = bt_le_scan_stop();
    if (err && err != -EALREADY) {
        LOG_ERR("Scan stop failed (%d)", err);
        return;
    }

    scanning = false;
    connecting = true;

    err = bt_conn_le_create(addr, BT_CONN_LE_CREATE_CONN, BT_LE_CONN_PARAM_DEFAULT, &default_conn);
    if (err) {
        connecting = false;
        default_conn = NULL;
        LOG_ERR("bt_conn_le_create failed (%d)", err);
        (void)start_scan();
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

    err = bt_le_scan_start(&scan_param, scan_cb);
    if (err) {
        LOG_ERR("bt_le_scan_start failed (%d)", err);
        return err;
    }

    scanning = true;
    LOG_INF("Scanning started");
    return 0;
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

    set_output_endpoint_auto("init");

    err = bt_enable(NULL);
    if (err && err != -EALREADY) {
        LOG_ERR("bt_enable failed (%d)", err);
        return err;
    }

    err = parse_target_addr();
    if (err) {
        return err;
    }

    (void)clear_non_target_bonds();

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
    k_work_init_delayable(&sniffer_start_work, sniffer_start_work_handler);
    k_work_schedule(&sniffer_start_work, K_SECONDS(3));
    return 0;
}

SYS_INIT(ble_hogp_sniffer_schedule_init, APPLICATION, CONFIG_APPLICATION_INIT_PRIORITY);
