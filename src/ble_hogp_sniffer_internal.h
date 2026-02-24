#pragma once

#include <stdbool.h>
#include <stdint.h>

#include <zephyr/bluetooth/addr.h>
#include <zephyr/bluetooth/conn.h>

typedef void (*zmk_hogp_sniffer_emit_usage_cb_t)(uint8_t usage, bool pressed);

const char *zmk_hogp_sniffer_hci_reason_to_str(uint8_t reason);
const char *zmk_hogp_sniffer_sec_err_to_str(enum bt_security_err err);
bt_security_t zmk_hogp_sniffer_sec_policy_level_for_idx(uint8_t idx);
bool zmk_hogp_sniffer_is_ascii_alnum(uint8_t c);

void zmk_hogp_sniffer_type_text_line(zmk_hogp_sniffer_emit_usage_cb_t emit_usage,
                                     const char *text);
void zmk_hogp_sniffer_screen_log_target_addr(zmk_hogp_sniffer_emit_usage_cb_t emit_usage,
                                             const char *prefix, const bt_addr_le_t *addr);
void zmk_hogp_sniffer_screen_log_target_code(zmk_hogp_sniffer_emit_usage_cb_t emit_usage,
                                             const char *prefix, uint8_t code);
void zmk_hogp_sniffer_screen_log_target_reason(zmk_hogp_sniffer_emit_usage_cb_t emit_usage,
                                               const char *prefix, uint8_t code,
                                               const char *reason);
void zmk_hogp_sniffer_screen_log_verbose_code(zmk_hogp_sniffer_emit_usage_cb_t emit_usage,
                                              const char *prefix, uint32_t code);
void zmk_hogp_sniffer_screen_log_verbose_text(zmk_hogp_sniffer_emit_usage_cb_t emit_usage,
                                              const char *text);
