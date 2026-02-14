#include <errno.h>
#include <stdbool.h>
#include <stddef.h>

#include <zephyr/bluetooth/addr.h>
#include <zephyr/bluetooth/bluetooth.h>
#include <zephyr/bluetooth/conn.h>
#include <zephyr/bluetooth/gatt.h>
#include <zephyr/bluetooth/uuid.h>
#include <zephyr/init.h>
#include <zephyr/logging/log.h>
#include <zephyr/sys/util.h>

LOG_MODULE_REGISTER(ble_hogp_sniffer, CONFIG_ZMK_BLE_HOGP_SNIFFER_LOG_LEVEL);

static struct bt_conn *default_conn;
static struct bt_gatt_discover_params discover_params;
static struct bt_gatt_subscribe_params subscribe_params;
static bt_addr_le_t target_addr;

static uint16_t hids_start_handle;
static uint16_t hids_end_handle;
static bool scanning;
static bool connecting;

static struct bt_uuid_16 hids_uuid = BT_UUID_INIT_16(BT_UUID_HIDS_VAL);
static struct bt_uuid_16 report_uuid = BT_UUID_INIT_16(BT_UUID_HIDS_REPORT_VAL);
static struct bt_uuid_16 ccc_uuid = BT_UUID_INIT_16(BT_UUID_GATT_CCC_VAL);

static int start_scan(void);

static uint8_t notify_cb(struct bt_conn *conn, struct bt_gatt_subscribe_params *params,
                         const void *data, uint16_t length) {
    ARG_UNUSED(conn);
    ARG_UNUSED(params);

    if (!data) {
        LOG_INF("Notification stopped");
        return BT_GATT_ITER_STOP;
    }

    LOG_HEXDUMP_INF(data, length, "HID Input");
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

    LOG_INF("BLE HOGP sniffer init");

    err = bt_enable(NULL);
    if (err && err != -EALREADY) {
        LOG_ERR("bt_enable failed (%d)", err);
        return err;
    }

    err = parse_target_addr();
    if (err) {
        return err;
    }

    return start_scan();
}

SYS_INIT(ble_hogp_sniffer_init, APPLICATION, CONFIG_APPLICATION_INIT_PRIORITY);
