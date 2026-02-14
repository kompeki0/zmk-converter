# Phase 0: BLE Keyboard Proxy (XIAO BLE)

## Goal
Receive BLE HID Input Reports from a fixed target keyboard and verify that incoming report bytes are logged.

## Current target
- MAC: `dd:75:7b:9c:8a:1f`
- Address type: random (default)

## Build
From your ZMK workspace:

```sh
west build -s zmk/app -b seeeduino_xiao_ble -- -DZMK_CONFIG=<this_repo>/config -DSHIELD=xiao_ble_proxy
```

If needed, add extra overrides:

```sh
west build -s zmk/app -b seeeduino_xiao_ble -- -DZMK_CONFIG=<this_repo>/config -DSHIELD=xiao_ble_proxy -DEXTRA_CONF_FILE=<this_repo>/config/proxy_phase0.conf
```

## Flash
```sh
west flash
```

## Expected logs
Successful flow:
1. `Scanning started`
2. `Target found, connecting`
3. `Connected to target`
4. `HID service found, discovering Input Report characteristic`
5. `Subscribed to Input Report notifications`
6. `HID Input` hexdump lines when keys are pressed on target keyboard

## Troubleshooting
1. No `Target found, connecting`
- Verify target MAC and address type.
- Confirm target keyboard is advertising and not bonded/connected elsewhere.

2. Connect fails repeatedly
- Move devices closer and reset both sides.
- Keep target keyboard in pairing/advertising mode.

3. Connected but no HID service/report discovery
- Confirm target truly exposes HOGP (UUID `0x1812`).
- Test against a known BLE keyboard first.

4. Discovery/subscription succeeds but no hexdump
- Confirm keypresses are sent as notifications from target.
- Check if target requires encryption/pairing before input notifications.

## Notes
- This is a minimum single-link verification path (1 target, 1 subscription).
- `CONFIG_ZMK_SPLIT=n` is set in shield config to avoid split-central conflicts in this phase.
