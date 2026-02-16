#include <errno.h>

#include <zephyr/bluetooth/bluetooth.h>
#include <zephyr/devicetree.h>
#include <zephyr/init.h>
#include <zephyr/logging/log.h>
#include <zephyr/storage/flash_map.h>

LOG_MODULE_REGISTER(proxy_factory_reset, LOG_LEVEL_INF);

static int proxy_factory_reset_init(void) {
    int err;

    LOG_WRN("Factory reset mode: clearing BLE bonds and storage partition");

    err = bt_enable(NULL);
    if (err && err != -EALREADY) {
        LOG_ERR("bt_enable failed (%d)", err);
        return 0;
    }

    err = bt_unpair(BT_ID_DEFAULT, NULL);
    if (err) {
        LOG_WRN("bt_unpair(all) failed (%d)", err);
    } else {
        LOG_INF("All BLE bonds cleared");
    }

#if DT_NODE_EXISTS(DT_NODELABEL(storage_partition))
    const struct flash_area *fa;

    err = flash_area_open(FIXED_PARTITION_ID(storage_partition), &fa);
    if (err) {
        LOG_ERR("flash_area_open(storage_partition) failed (%d)", err);
        return 0;
    }

    err = flash_area_erase(fa, 0, fa->fa_size);
    flash_area_close(fa);
    if (err) {
        LOG_ERR("storage_partition erase failed (%d)", err);
    } else {
        LOG_INF("storage_partition erased");
    }
#else
    LOG_WRN("storage_partition node not found; skipped erase");
#endif

    LOG_WRN("Factory reset complete. Flash normal firmware next.");
    return 0;
}

SYS_INIT(proxy_factory_reset_init, APPLICATION, CONFIG_APPLICATION_INIT_PRIORITY);
