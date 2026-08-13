#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define HOGP_HID_MAX_FIELDS 192
#define HOGP_HID_MAX_REPORTS 16
#define HOGP_HID_MAX_KEY_USAGES 32
#define HOGP_HID_MAX_CONSUMER_USAGES 16

struct hogp_hid_field {
    uint16_t bit_offset;
    uint16_t usage_page;
    uint16_t usage;
    uint16_t usage_min;
    uint8_t report_id;
    uint8_t bit_size;
    uint8_t count;
    uint8_t flags;
    bool is_array;
    bool is_signed;
};

struct hogp_hid_report_layout {
    uint16_t bit_count;
    uint8_t report_id;
};

struct hogp_hid_parser {
    struct hogp_hid_field fields[HOGP_HID_MAX_FIELDS];
    struct hogp_hid_report_layout reports[HOGP_HID_MAX_REPORTS];
    uint8_t field_count;
    uint8_t report_count;
    bool truncated;
};

struct hogp_hid_decoded_report {
    uint8_t key_usages[HOGP_HID_MAX_KEY_USAGES];
    uint16_t consumer_usages[HOGP_HID_MAX_CONSUMER_USAGES];
    size_t key_usage_count;
    size_t consumer_usage_count;
    int32_t dx;
    int32_t dy;
    int32_t wheel;
    int32_t hwheel;
    uint8_t buttons;
    bool has_keyboard;
    bool has_consumer;
    bool has_pointer;
    bool has_buttons;
};

void hogp_hid_parser_reset(struct hogp_hid_parser *parser);
int hogp_hid_parser_parse(struct hogp_hid_parser *parser, const uint8_t *descriptor, size_t length);
int hogp_hid_parser_decode(const struct hogp_hid_parser *parser, uint8_t report_id,
                           bool report_id_valid, const uint8_t *data, size_t length,
                           struct hogp_hid_decoded_report *out);
