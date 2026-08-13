# Phase 0: BLE Keyboard Proxy (XIAO BLE)

## Goal
Receive BLE HID Input Reports from a target keyboard, decode its HID Report Map, and feed the
result through the normal ZMK keymap pipeline.

## Input targets

The device-manager build does not use a fixed MAC or auto-connect rule. It can keep up to three
selected BLE HID keyboards/mice connected concurrently.

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

## Seven-button device manager

Connect seven normally-open buttons between the XIAO pins and GND. Internal pull-ups are enabled.
No input device is connected automatically.

- `D0` (`P0.02`): reload/scan and print the numbered device list
- `D1` (`P0.03`): selection up
- `D2` (`P0.28`): selection down
- `D3` (`P0.29`): connect the selected device
- `D4` (`P0.04`): disconnect and remove the selected device's bond
- `D5` (`P0.05`): disconnect all inputs and clear only their bonds/settings
- `D6` (`P1.11`): close the manager and pass connected HID input to ZMK

Each row has a combined status: `C` means connected, `R` means registered after successful HID
discovery, and `B` means bonded (for example `[CRB]`). Devices are added to a persistent
input-only registry after HID discovery succeeds, so host-PC bonds are not mixed into this list.
Scanning refreshes the saved name and RSSI when the input device is advertising. Up to three BLE
HID input devices can remain connected at the same time. After connecting one device, press D0
again, select another, and press D3. Press D6 when all desired devices are connected.

Opening/reloading the manager releases any keys/buttons currently held toward the host, preventing
stuck keys while input passthrough is paused.

`D4` and `D5` never erase PC-host bonds or ZMK host-profile selections. The one-shot factory/reset
firmware remains available when a deliberate reset of both input and host Bluetooth state is needed.

## Host output over ZMK Bluetooth

Host output is selected in the configuration file with:

```conf
# Default: USB only, broadest input-device compatibility
CONFIG_ZMK_PROXY_HOST_BLE_OUTPUT=n

# Optional: USB + ordinary ZMK Bluetooth host profiles
# CONFIG_ZMK_PROXY_HOST_BLE_OUTPUT=y
```

The default normal and debug builds keep this option disabled, so they can accept both Legacy
Pairing and Secure Connections from input devices; host output is USB. The
`xiao_ble_proxy_secure_ble_output`
artifact enables ordinary ZMK Bluetooth output and reserves the fourth connection for the host.
It advertises under ZMK's normal profile policy rather than waiting for an input device.
Bond storage is sized for five host profiles plus three input devices. The simultaneous connection
limit remains three inputs plus one host.

On an input keyboard, hold the Application/Menu key (position 75) to enter keymap layer 2. Esc runs
`BT_CLR`, and F1 through F5 run `BT_SEL 0` through `BT_SEL 4`. These are standard ZMK Bluetooth
behaviors and can be changed in the keymap normally. Because upstream ZMK v0.3 forces
Secure-Connections-only mode when `CONFIG_ZMK_BLE=y`, the BLE-output artifact cannot pair with a
Legacy-only input keyboard; use the USB-output build for those devices.

## Expected logs
Successful flow (wording can vary slightly):
1. `Pairing compatibility: Legacy + Secure Connections; host output: USB`
2. `Bluetooth settings loaded; identity ready`
3. `Scanning started`
4. `Target candidate ... found`
5. `Connected to target slot ...`
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
- `Unknown Connection Identifier (0x02)` means the create-connection attempt was cancelled or
  timed out. The picker now waits for a connectable advertising packet instead of trying to use a
  name-bearing scan response; put the input device back into pairing mode and retry D0 then D3.
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
