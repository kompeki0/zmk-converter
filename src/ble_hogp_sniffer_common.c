#include "ble_hogp_sniffer_internal.h"

const char *zmk_hogp_sniffer_hci_reason_to_str(uint8_t reason) {
    switch (reason) {
#ifdef BT_HCI_ERR_UNKNOWN_CONN_ID
    case BT_HCI_ERR_UNKNOWN_CONN_ID:
        return "unknown_conn_id";
#endif
#ifdef BT_HCI_ERR_AUTH_FAIL
    case BT_HCI_ERR_AUTH_FAIL:
        return "auth_fail";
#endif
#ifdef BT_HCI_ERR_PIN_OR_KEY_MISSING
    case BT_HCI_ERR_PIN_OR_KEY_MISSING:
        return "pin_or_key_missing";
#endif
#ifdef BT_HCI_ERR_CONN_TIMEOUT
    case BT_HCI_ERR_CONN_TIMEOUT:
        return "conn_timeout";
#endif
#ifdef BT_HCI_ERR_CONN_LIMIT_EXCEEDED
    case BT_HCI_ERR_CONN_LIMIT_EXCEEDED:
        return "conn_limit_exceeded";
#endif
#ifdef BT_HCI_ERR_CONN_FAIL_TO_ESTAB
    case BT_HCI_ERR_CONN_FAIL_TO_ESTAB:
        return "conn_fail_to_estab";
#endif
#ifdef BT_HCI_ERR_REMOTE_USER_TERM_CONN
    case BT_HCI_ERR_REMOTE_USER_TERM_CONN:
        return "remote_user_term";
#endif
#ifdef BT_HCI_ERR_REMOTE_LOW_RESOURCES
    case BT_HCI_ERR_REMOTE_LOW_RESOURCES:
        return "remote_low_resources";
#endif
#ifdef BT_HCI_ERR_REMOTE_POWER_OFF
    case BT_HCI_ERR_REMOTE_POWER_OFF:
        return "remote_power_off";
#endif
#ifdef BT_HCI_ERR_UNSUPP_REMOTE_FEATURE
    case BT_HCI_ERR_UNSUPP_REMOTE_FEATURE:
        return "unsupported_remote_feature";
#endif
#ifdef BT_HCI_ERR_PAIRING_NOT_SUPPORTED
    case BT_HCI_ERR_PAIRING_NOT_SUPPORTED:
        return "pairing_not_supported";
#endif
#ifdef BT_HCI_ERR_UNACCEPT_CONN_PARAM
    case BT_HCI_ERR_UNACCEPT_CONN_PARAM:
        return "unacceptable_conn_param";
#endif
#ifdef BT_HCI_ERR_ADV_TIMEOUT
    case BT_HCI_ERR_ADV_TIMEOUT:
        return "adv_timeout";
#endif
#ifdef BT_HCI_ERR_TERM_DUE_TO_MIC_FAIL
    case BT_HCI_ERR_TERM_DUE_TO_MIC_FAIL:
        return "mic_fail";
#endif
    default:
        if (reason == 22U) {
            return "local_host_term";
        }
        return "unknown";
    }
}

const char *zmk_hogp_sniffer_sec_err_to_str(enum bt_security_err err) {
    switch (err) {
#ifdef BT_SECURITY_ERR_SUCCESS
    case BT_SECURITY_ERR_SUCCESS:
        return "success";
#endif
#ifdef BT_SECURITY_ERR_AUTH_FAIL
    case BT_SECURITY_ERR_AUTH_FAIL:
        return "auth_fail";
#endif
#ifdef BT_SECURITY_ERR_PIN_OR_KEY_MISSING
    case BT_SECURITY_ERR_PIN_OR_KEY_MISSING:
        return "pin_or_key_missing";
#endif
#ifdef BT_SECURITY_ERR_OOB_NOT_AVAILABLE
    case BT_SECURITY_ERR_OOB_NOT_AVAILABLE:
        return "oob_not_available";
#endif
#ifdef BT_SECURITY_ERR_AUTH_REQUIREMENT
    case BT_SECURITY_ERR_AUTH_REQUIREMENT:
        return "auth_requirement";
#endif
#ifdef BT_SECURITY_ERR_PAIR_NOT_SUPPORTED
    case BT_SECURITY_ERR_PAIR_NOT_SUPPORTED:
        return "pair_not_supported";
#endif
#ifdef BT_SECURITY_ERR_PAIR_NOT_ALLOWED
    case BT_SECURITY_ERR_PAIR_NOT_ALLOWED:
        return "pair_not_allowed";
#endif
#ifdef BT_SECURITY_ERR_INVALID_PARAM
    case BT_SECURITY_ERR_INVALID_PARAM:
        return "invalid_param";
#endif
#ifdef BT_SECURITY_ERR_UNSPECIFIED
    case BT_SECURITY_ERR_UNSPECIFIED:
        return "unspecified";
#endif
#ifdef BT_SECURITY_ERR_CONFIRM_VALUE_FAILED
    case BT_SECURITY_ERR_CONFIRM_VALUE_FAILED:
        return "confirm_value_failed";
#endif
#ifdef BT_SECURITY_ERR_PAIRING_IN_PROGRESS
    case BT_SECURITY_ERR_PAIRING_IN_PROGRESS:
        return "pairing_in_progress";
#endif
#ifdef BT_SECURITY_ERR_CROSS_TRANSP_NOT_ALLOWED
    case BT_SECURITY_ERR_CROSS_TRANSP_NOT_ALLOWED:
        return "cross_transport_not_allowed";
#endif
    default:
        if ((int)err == 4) {
            return "auth_requirement";
        }
        if ((int)err == 5) {
            return "pair_not_supported";
        }
        return "unknown";
    }
}

bt_security_t zmk_hogp_sniffer_sec_policy_level_for_idx(uint8_t idx) {
    switch (idx) {
    case 0U:
        return BT_SECURITY_L3;
    case 1U:
        return BT_SECURITY_L2;
    default:
        return BT_SECURITY_L1;
    }
}

bool zmk_hogp_sniffer_is_ascii_alnum(uint8_t c) {
    return ((c >= '0' && c <= '9') || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z'));
}
