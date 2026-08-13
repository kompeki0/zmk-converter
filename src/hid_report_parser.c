#include "hid_report_parser.h"

#include <errno.h>
#include <limits.h>
#include <string.h>

#define HID_ITEM_TYPE_MAIN 0U
#define HID_ITEM_TYPE_GLOBAL 1U
#define HID_ITEM_TYPE_LOCAL 2U

#define HID_MAIN_INPUT 8U

#define HID_GLOBAL_USAGE_PAGE 0U
#define HID_GLOBAL_LOGICAL_MINIMUM 1U
#define HID_GLOBAL_REPORT_SIZE 7U
#define HID_GLOBAL_REPORT_ID 8U
#define HID_GLOBAL_REPORT_COUNT 9U
#define HID_GLOBAL_PUSH 10U
#define HID_GLOBAL_POP 11U

#define HID_LOCAL_USAGE 0U
#define HID_LOCAL_USAGE_MINIMUM 1U
#define HID_LOCAL_USAGE_MAXIMUM 2U

#define HID_INPUT_CONSTANT 0x01U
#define HID_INPUT_VARIABLE 0x02U
#define HID_INPUT_RELATIVE 0x04U

#define HID_USAGE_PAGE_GENERIC_DESKTOP 0x01U
#define HID_USAGE_PAGE_KEYBOARD 0x07U
#define HID_USAGE_PAGE_BUTTON 0x09U
#define HID_USAGE_PAGE_CONSUMER 0x0CU

#define HID_USAGE_X 0x30U
#define HID_USAGE_Y 0x31U
#define HID_USAGE_WHEEL 0x38U
#define HID_USAGE_AC_PAN 0x0238U

#define HID_LOCAL_USAGE_CAP 16U
#define HID_GLOBAL_STACK_CAP 4U

struct hid_globals {
    uint16_t usage_page;
    int32_t logical_minimum;
    uint16_t report_size;
    uint16_t report_count;
    uint8_t report_id;
};

struct hid_locals {
    uint32_t usages[HID_LOCAL_USAGE_CAP];
    uint8_t usage_count;
    uint32_t usage_minimum;
    uint32_t usage_maximum;
    bool has_usage_minimum;
    bool has_usage_maximum;
};

static uint32_t item_unsigned_value(const uint8_t *data, uint8_t size) {
    uint32_t value = 0U;

    for (uint8_t i = 0U; i < size; i++) {
        value |= ((uint32_t)data[i]) << (8U * i);
    }
    return value;
}

static int32_t sign_extend(uint32_t value, uint8_t bits) {
    if (bits == 0U || bits >= 32U) {
        return (int32_t)value;
    }

    if ((value & (1UL << (bits - 1U))) != 0U) {
        value |= ~((1UL << bits) - 1UL);
    }
    return (int32_t)value;
}

static bool relevant_usage_page(uint16_t usage_page) {
    return usage_page == HID_USAGE_PAGE_GENERIC_DESKTOP || usage_page == HID_USAGE_PAGE_KEYBOARD ||
           usage_page == HID_USAGE_PAGE_BUTTON || usage_page == HID_USAGE_PAGE_CONSUMER;
}

static struct hogp_hid_report_layout *find_or_add_report(struct hogp_hid_parser *parser,
                                                          uint8_t report_id) {
    for (uint8_t i = 0U; i < parser->report_count; i++) {
        if (parser->reports[i].report_id == report_id) {
            return &parser->reports[i];
        }
    }

    if (parser->report_count >= HOGP_HID_MAX_REPORTS) {
        parser->truncated = true;
        return NULL;
    }

    struct hogp_hid_report_layout *layout = &parser->reports[parser->report_count++];
    memset(layout, 0, sizeof(*layout));
    layout->report_id = report_id;
    return layout;
}

static uint16_t usage_page_from_value(uint32_t usage, uint16_t default_page) {
    return usage > UINT16_MAX ? (uint16_t)(usage >> 16U) : default_page;
}

static uint16_t usage_id_from_value(uint32_t usage) { return (uint16_t)usage; }

static uint32_t local_usage_for_index(const struct hid_locals *locals, uint16_t index,
                                      uint16_t default_page) {
    if (index < locals->usage_count) {
        return locals->usages[index];
    }
    if (locals->has_usage_minimum) {
        uint32_t usage = locals->usage_minimum + index;
        if (locals->usage_minimum <= UINT16_MAX) {
            usage |= ((uint32_t)default_page << 16U);
        }
        return usage;
    }
    return ((uint32_t)default_page << 16U);
}

static void add_input_field(struct hogp_hid_parser *parser, const struct hid_globals *globals,
                            uint16_t bit_offset, uint16_t count, uint32_t usage_value,
                            const struct hid_locals *locals, uint8_t flags, bool is_array) {
    if (parser->field_count >= HOGP_HID_MAX_FIELDS || globals->report_size > UINT8_MAX ||
        count > UINT8_MAX) {
        parser->truncated = true;
        return;
    }

    struct hogp_hid_field *field = &parser->fields[parser->field_count++];
    memset(field, 0, sizeof(*field));
    field->bit_offset = bit_offset;
    field->usage_page = usage_page_from_value(usage_value, globals->usage_page);
    field->usage = usage_id_from_value(usage_value);
    field->usage_min = usage_id_from_value(locals->usage_minimum);
    field->report_id = globals->report_id;
    field->bit_size = (uint8_t)globals->report_size;
    field->count = (uint8_t)count;
    field->flags = flags;
    field->is_array = is_array;
    field->is_signed = globals->logical_minimum < 0;
}

static void parse_input_item(struct hogp_hid_parser *parser, const struct hid_globals *globals,
                             const struct hid_locals *locals, uint8_t flags) {
    struct hogp_hid_report_layout *layout = find_or_add_report(parser, globals->report_id);
    uint32_t input_bits = (uint32_t)globals->report_size * globals->report_count;

    if (!layout) {
        return;
    }

    if ((flags & HID_INPUT_CONSTANT) == 0U && relevant_usage_page(globals->usage_page) &&
        globals->report_size > 0U) {
        if ((flags & HID_INPUT_VARIABLE) != 0U) {
            for (uint16_t i = 0U; i < globals->report_count; i++) {
                uint32_t usage = local_usage_for_index(locals, i, globals->usage_page);
                uint16_t page = usage_page_from_value(usage, globals->usage_page);

                if (relevant_usage_page(page)) {
                    add_input_field(parser, globals,
                                    (uint16_t)(layout->bit_count + i * globals->report_size), 1U,
                                    usage, locals, flags, false);
                }
            }
        } else {
            uint32_t usage = ((uint32_t)globals->usage_page << 16U) |
                             usage_id_from_value(locals->usage_minimum);
            add_input_field(parser, globals, layout->bit_count, globals->report_count, usage, locals,
                            flags, true);
        }
    }

    if ((uint32_t)layout->bit_count + input_bits > UINT16_MAX) {
        layout->bit_count = UINT16_MAX;
        parser->truncated = true;
    } else {
        layout->bit_count = (uint16_t)(layout->bit_count + input_bits);
    }
}

void hogp_hid_parser_reset(struct hogp_hid_parser *parser) {
    if (parser) {
        memset(parser, 0, sizeof(*parser));
    }
}

int hogp_hid_parser_parse(struct hogp_hid_parser *parser, const uint8_t *descriptor, size_t length) {
    struct hid_globals globals = {0};
    struct hid_globals global_stack[HID_GLOBAL_STACK_CAP];
    struct hid_locals locals = {0};
    uint8_t global_stack_depth = 0U;
    size_t pos = 0U;

    if (!parser || (!descriptor && length != 0U)) {
        return -EINVAL;
    }

    hogp_hid_parser_reset(parser);
    (void)find_or_add_report(parser, 0U);

    while (pos < length) {
        uint8_t prefix = descriptor[pos++];

        if (prefix == 0xFEU) {
            if (pos + 2U > length) {
                return -EINVAL;
            }
            uint8_t long_size = descriptor[pos];
            pos += 2U;
            if (pos + long_size > length) {
                return -EINVAL;
            }
            pos += long_size;
            continue;
        }

        uint8_t size_code = prefix & 0x03U;
        uint8_t item_size = size_code == 3U ? 4U : size_code;
        uint8_t item_type = (prefix >> 2U) & 0x03U;
        uint8_t item_tag = (prefix >> 4U) & 0x0FU;

        if (pos + item_size > length) {
            return -EINVAL;
        }

        uint32_t value = item_unsigned_value(&descriptor[pos], item_size);
        int32_t signed_value = sign_extend(value, (uint8_t)(item_size * 8U));
        pos += item_size;

        if (item_type == HID_ITEM_TYPE_GLOBAL) {
            switch (item_tag) {
            case HID_GLOBAL_USAGE_PAGE:
                globals.usage_page = (uint16_t)value;
                break;
            case HID_GLOBAL_LOGICAL_MINIMUM:
                globals.logical_minimum = signed_value;
                break;
            case HID_GLOBAL_REPORT_SIZE:
                globals.report_size = (uint16_t)value;
                break;
            case HID_GLOBAL_REPORT_ID:
                if (value == 0U || value > UINT8_MAX) {
                    return -EINVAL;
                }
                globals.report_id = (uint8_t)value;
                (void)find_or_add_report(parser, globals.report_id);
                break;
            case HID_GLOBAL_REPORT_COUNT:
                globals.report_count = (uint16_t)value;
                break;
            case HID_GLOBAL_PUSH:
                if (global_stack_depth < HID_GLOBAL_STACK_CAP) {
                    global_stack[global_stack_depth++] = globals;
                } else {
                    parser->truncated = true;
                }
                break;
            case HID_GLOBAL_POP:
                if (global_stack_depth > 0U) {
                    globals = global_stack[--global_stack_depth];
                }
                break;
            default:
                break;
            }
        } else if (item_type == HID_ITEM_TYPE_LOCAL) {
            switch (item_tag) {
            case HID_LOCAL_USAGE:
                if (locals.usage_count < HID_LOCAL_USAGE_CAP) {
                    locals.usages[locals.usage_count++] = value;
                }
                break;
            case HID_LOCAL_USAGE_MINIMUM:
                locals.usage_minimum = value;
                locals.has_usage_minimum = true;
                break;
            case HID_LOCAL_USAGE_MAXIMUM:
                locals.usage_maximum = value;
                locals.has_usage_maximum = true;
                break;
            default:
                break;
            }
        } else if (item_type == HID_ITEM_TYPE_MAIN) {
            if (item_tag == HID_MAIN_INPUT) {
                parse_input_item(parser, &globals, &locals, (uint8_t)value);
            }
            memset(&locals, 0, sizeof(locals));
        }
    }

    return parser->field_count > 0U ? 0 : -ENOENT;
}

static const struct hogp_hid_report_layout *find_report(const struct hogp_hid_parser *parser,
                                                         uint8_t report_id) {
    for (uint8_t i = 0U; i < parser->report_count; i++) {
        if (parser->reports[i].report_id == report_id) {
            return &parser->reports[i];
        }
    }
    return NULL;
}

static uint32_t read_bits(const uint8_t *data, size_t length, uint16_t bit_offset, uint8_t bit_size) {
    uint32_t value = 0U;

    if (bit_size > 32U || (size_t)bit_offset + bit_size > length * 8U) {
        return 0U;
    }

    for (uint8_t bit = 0U; bit < bit_size; bit++) {
        size_t source_bit = (size_t)bit_offset + bit;
        if ((data[source_bit / 8U] & (1U << (source_bit % 8U))) != 0U) {
            value |= 1UL << bit;
        }
    }
    return value;
}

static void append_key_usage(struct hogp_hid_decoded_report *out, uint16_t usage) {
    if (usage == 0U || usage > UINT8_MAX) {
        return;
    }
    for (size_t i = 0U; i < out->key_usage_count; i++) {
        if (out->key_usages[i] == (uint8_t)usage) {
            return;
        }
    }
    if (out->key_usage_count < HOGP_HID_MAX_KEY_USAGES) {
        out->key_usages[out->key_usage_count++] = (uint8_t)usage;
    }
}

static void append_consumer_usage(struct hogp_hid_decoded_report *out, uint16_t usage) {
    if (usage == 0U) {
        return;
    }
    for (size_t i = 0U; i < out->consumer_usage_count; i++) {
        if (out->consumer_usages[i] == usage) {
            return;
        }
    }
    if (out->consumer_usage_count < HOGP_HID_MAX_CONSUMER_USAGES) {
        out->consumer_usages[out->consumer_usage_count++] = usage;
    }
}

int hogp_hid_parser_decode(const struct hogp_hid_parser *parser, uint8_t report_id,
                           bool report_id_valid, const uint8_t *data, size_t length,
                           struct hogp_hid_decoded_report *out) {
    const struct hogp_hid_report_layout *layout = NULL;
    bool any_field = false;

    if (!parser || !data || !out) {
        return -EINVAL;
    }
    memset(out, 0, sizeof(*out));

    if (report_id_valid) {
        layout = find_report(parser, report_id);
    } else if (parser->report_count == 1U) {
        layout = &parser->reports[0];
        report_id = layout->report_id;
    } else if (length > 0U) {
        layout = find_report(parser, data[0]);
        if (layout && length == ((size_t)layout->bit_count + 7U) / 8U + 1U) {
            report_id = data[0];
            data++;
            length--;
        } else {
            layout = NULL;
        }
    }

    if (!layout) {
        return -ENOENT;
    }

    size_t expected_length = ((size_t)layout->bit_count + 7U) / 8U;
    if (report_id != 0U && length == expected_length + 1U && data[0] == report_id) {
        data++;
        length--;
    }
    if (length * 8U < layout->bit_count) {
        return -EMSGSIZE;
    }

    for (uint8_t i = 0U; i < parser->field_count; i++) {
        const struct hogp_hid_field *field = &parser->fields[i];
        if (field->report_id != report_id) {
            continue;
        }

        any_field = true;
        if (field->is_array) {
            for (uint8_t n = 0U; n < field->count; n++) {
                uint32_t value = read_bits(data, length,
                                           (uint16_t)(field->bit_offset + n * field->bit_size),
                                           field->bit_size);
                if (field->usage_page == HID_USAGE_PAGE_KEYBOARD) {
                    out->has_keyboard = true;
                    append_key_usage(out, (uint16_t)value);
                } else if (field->usage_page == HID_USAGE_PAGE_CONSUMER) {
                    out->has_consumer = true;
                    append_consumer_usage(out, (uint16_t)value);
                }
            }
            continue;
        }

        uint32_t raw = read_bits(data, length, field->bit_offset, field->bit_size);
        int32_t value = field->is_signed ? sign_extend(raw, field->bit_size) : (int32_t)raw;

        switch (field->usage_page) {
        case HID_USAGE_PAGE_KEYBOARD:
            out->has_keyboard = true;
            if (raw != 0U) {
                append_key_usage(out, field->usage);
            }
            break;
        case HID_USAGE_PAGE_CONSUMER:
            out->has_consumer = true;
            if (raw != 0U) {
                append_consumer_usage(out, field->usage);
            }
            break;
        case HID_USAGE_PAGE_BUTTON:
            out->has_pointer = true;
            out->has_buttons = true;
            if (raw != 0U && field->usage >= 1U && field->usage <= 8U) {
                out->buttons |= (uint8_t)(1U << (field->usage - 1U));
            }
            break;
        case HID_USAGE_PAGE_GENERIC_DESKTOP:
            if ((field->flags & HID_INPUT_RELATIVE) == 0U) {
                break;
            }
            if (field->usage == HID_USAGE_X) {
                out->dx += value;
                out->has_pointer = true;
            } else if (field->usage == HID_USAGE_Y) {
                out->dy += value;
                out->has_pointer = true;
            } else if (field->usage == HID_USAGE_WHEEL) {
                out->wheel += value;
                out->has_pointer = true;
            }
            break;
        default:
            break;
        }

        if (field->usage_page == HID_USAGE_PAGE_CONSUMER && field->usage == HID_USAGE_AC_PAN &&
            (field->flags & HID_INPUT_RELATIVE) != 0U) {
            out->hwheel += value;
            out->has_pointer = true;
        }
    }

    return any_field ? 0 : -ENOENT;
}
