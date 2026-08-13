# Phase 0: BLE Keyboard Proxy (XIAO BLE)

## Goal
Receive BLE HID Input Reports from a target keyboard, decode its HID Report Map, and feed the
result through the normal ZMK keymap pipeline.

## Current target
- MAC: `dd:75:7b:9c:8a:1f`
- Address type: random (default)

## Build
From your ZMK workspace:

```sh
west build -s zmk/app -b seeeduino_xiao_ble -- -DZMK_CONFIG=<this_repo>/config -DSHIELD=xiao_ble_proxy -DCONFIG_BT_SMP_SC_PAIR_ONLY=n
```

The default `xiao_ble_proxy_normal` and `xiao_ble_proxy_debug_com` profiles use USB for output to
the PC and accept both LE Legacy Pairing and LE Secure Connections from the target keyboard. Keep
the XIAO connected to the PC by USB while using either profile.

`xiao_ble_proxy_secure_ble_output` additionally outputs to a PC over BLE, but upstream ZMK v0.3
forces Secure-Connections-only pairing in that configuration. It therefore cannot connect to a
target keyboard that supports only LE Legacy Pairing.

If needed, add extra overrides:

```sh
west build -s zmk/app -b seeeduino_xiao_ble -- -DZMK_CONFIG=<this_repo>/config -DSHIELD=xiao_ble_proxy -DEXTRA_CONF_FILE=<this_repo>/config/proxy_phase0.conf -DCONFIG_BT_SMP_SC_PAIR_ONLY=n
```

For BLE visibility test from PC (fresh pair each boot):

```sh
west build -s zmk/app -b seeeduino_xiao_ble -- -DZMK_CONFIG=<this_repo>/config -DSHIELD=xiao_ble_proxy -DEXTRA_CONF_FILE=\"<this_repo>/config/proxy_phase0.conf;<this_repo>/config/ble_test_visible.conf\"
```

This visibility-test profile is also Secure-Connections-only; it is not the profile used to test
a Legacy-only target keyboard.

For one-shot full reset firmware (clear all bonds/settings-related BLE state):

```sh
west build -p always -s zmk/app -b seeeduino_xiao_ble -- -DZMK_CONFIG=<this_repo>/config -DSHIELD=xiao_ble_proxy -DEXTRA_CONF_FILE=\"<this_repo>/config/reset_all_once.conf\"
```

After flashing and booting this reset firmware once, flash your normal firmware again.

## Flash
```sh
west flash
```

## Button selector operation

Connect four normally-open buttons between the XIAO pins and GND. Internal pull-ups are enabled:

- `D0` (`P0.02`): Up
- `D1` (`P0.03`): Down
- `D2` (`P0.28`): OK
- `D3` (`P0.29`): Back/disconnect

Put the target keyboard into pairing mode, then wait for `Found candidate ...` in the serial log.
If its advertised name contains `AUTO_SELECT_NAME_CONTAINS`, `TARGET1_NAME_CONTAINS`, or
`TARGET2_NAME_CONTAINS` (case-insensitive), it is selected and connected automatically; no button
operation is needed. The buttons are the fallback for other devices.
The initial selection is `RESETALL`; press Down twice to reach the first named device, checking the
`sel ...` log after each press, then press OK. If the device has no advertised name, select
`OTHER(n)` with one Down press and press OK to probe its GATT device name. `RESETALL` + OK clears
all target bonds and saved selection, so do not select it during an ordinary connection.

## Expected logs
Successful flow (wording can vary slightly):
1. `Pairing compatibility: Legacy + Secure Connections; host output: USB`
2. `Bluetooth settings loaded; identity ready`
3. `Scanning started`
4. `Target candidate ... found`
5. `Connected to target`
6. `Pairing request from target accepted`
7. `HID service found, discovering characteristic topology`
8. `Report Map parsed`
9. `Subscribed HID input`
10. `HID discovery complete`
11. `HID Input` hexdump lines when keys are pressed on target keyboard

## Troubleshooting
1. No `Target found, connecting`
- Verify target MAC and address type.
- Confirm target keyboard is advertising and not bonded/connected elsewhere.

2. Connect fails repeatedly
- Move devices closer and reset both sides.
- Keep target keyboard in pairing/advertising mode.
- Confirm the startup log says `Legacy + Secure Connections`. If it says `Secure Connections only`,
  the BLE-output artifact was flashed and a Legacy-only target cannot pair with it.

3. Connected but no HID service/report discovery
- Confirm target truly exposes HOGP (UUID `0x1812`).
- Test against a known BLE keyboard first.

4. Discovery/subscription succeeds but no hexdump
- Confirm keypresses are sent as notifications from target.
- Check if target requires encryption/pairing before input notifications.

5. A passkey is requested
- With the debug-COM build, read `Passkey display ...` from the serial log.
- If a USB or BLE host is already connected, the firmware also types
  `target passkey NNNNNN` to it. Keep a text field focused, then type those six digits on the
  target keyboard and press Enter.
- Both sides may retain a failed bond. If retries fail immediately, run the factory-reset image
  once, put the keyboard back into pairing mode, and flash the normal image again.

## Compatibility notes
- Report characteristics are associated with their own CCC and Report Reference descriptors;
  output/feature reports are not subscribed accidentally.
- Standard boot-style arrays, Report-ID reports, keyboard NKRO bitmaps, consumer controls, and
  relative pointer fields are decoded from the Report Map. Fixed-length parsing remains only as a
  fallback for devices with an unreadable or malformed map.
- Up to 12 input characteristics are subscribed. Multi-report keyboard and consumer state is
  merged before ZMK events are emitted.
- `CONFIG_ZMK_SPLIT=n` avoids split-central conflicts.
- Classic Bluetooth (BR/EDR HID) and proprietary 2.4 GHz receivers are not supported; the target
  must expose Bluetooth LE HID service UUID `0x1812`.
