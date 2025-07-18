#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# Python-3 edition of the original Python-2 BLE helper file
# ---------------------------------------------------------------------------
# Changes:
#   • print() function
#   • struct.unpack('B', byte)[0] → byte   (iteration over bytes returns int)
#   • thread.setDaemon(True) → thread.daemon = True   (not present here)
#   • xrange → range
#   • minor bytes/str fixes
# ---------------------------------------------------------------------------

import subprocess
import bluetooth._bluetooth as bluez
import struct

# -----------------------------------------------------------------------------
# Constants (unchanged)
# -----------------------------------------------------------------------------
# OMRON company ID (Bluetooth SIG.)
COMPANY_ID = 0x02D5

# BEACON Measured power (RSSI at 1m distance)
BEACON_MEASURED_POWER = -59

# BLE OpCode group field for the LE related OpCodes.
OGF_LE_CTL = 0x08

# BLE OpCode Commands.
OCF_LE_SET_EVENT_MASK = 0x0001
OCF_LE_READ_BUFFER_SIZE = 0x0002
OCF_LE_READ_LOCAL_SUPPORTED_FEATURES = 0x0003
OCF_LE_SET_RANDOM_ADDRESS = 0x0005
OCF_LE_SET_ADVERTISING_PARAMETERS = 0x0006
OCF_LE_READ_ADVERTISING_CHANNEL_TX_POWER = 0x0007
OCF_LE_SET_ADVERTISING_DATA = 0x0008
OCF_LE_SET_SCAN_RESPONSE_DATA = 0x0009
OCF_LE_SET_ADVERTISE_ENABLE = 0x000A
OCF_LE_SET_SCAN_PARAMETERS = 0x000B
OCF_LE_SET_SCAN_ENABLE = 0x000C
OCF_LE_CREATE_CONN = 0x000D
OCF_LE_CREATE_CONN_CANCEL = 0x000E
OCF_LE_READ_WHITE_LIST_SIZE = 0x000F
OCF_LE_CLEAR_WHITE_LIST = 0x0010
OCF_LE_ADD_DEVICE_TO_WHITE_LIST = 0x0011
OCF_LE_REMOVE_DEVICE_FROM_WHITE_LIST = 0x0012
OCF_LE_CONN_UPDATE = 0x0013
OCF_LE_SET_HOST_CHANNEL_CLASSIFICATION = 0x0014
OCF_LE_READ_CHANNEL_MAP = 0x0015
OCF_LE_READ_REMOTE_USED_FEATURES = 0x0016
OCF_LE_ENCRYPT = 0x0017
OCF_LE_RAND = 0x0018
OCF_LE_START_ENCRYPTION = 0x0019
OCF_LE_LTK_REPLY = 0x001A
OCF_LE_LTK_NEG_REPLY = 0x001B
OCF_LE_READ_SUPPORTED_STATES = 0x001C
OCF_LE_RECEIVER_TEST = 0x001D
OCF_LE_TRANSMITTER_TEST = 0x001E
OCF_LE_TEST_END = 0x001F

# BLE events; all LE commands result in a metaevent, specified by the subevent
# code below.
EVT_LE_META_EVENT = 0x3E

# LE_META_EVENT subevents.
EVT_LE_CONN_COMPLETE = 0x01
EVT_LE_ADVERTISING_REPORT = 0x02
EVT_LE_CONN_UPDATE_COMPLETE = 0x03
EVT_LE_READ_REMOTE_USED_FEATURES_COMPLETE = 0x04
EVT_LE_LTK_REQUEST = 0x05

# BLE address types.
LE_PUBLIC_ADDRESS = 0x00
LE_RANDOM_ADDRESS = 0x01

# Roles.
LE_ROLE_MASTER = 0x00
LE_ROLE_SLAVE = 0x01

# Advertisment event types.
LE_ADV_IND = 0x00
LE_ADV_DIRECT_IND = 0x01
LE_ADV_SCAN_IND = 0x02
LE_ADV_NONCONN_IND = 0x03
LE_ADV_SCAN_RSP = 0x04

# BLE scan types.
LE_SCAN_PASSIVE = 0x00
LE_SCAN_ACTIVE = 0x01

# BLE filter policies.
LE_FILTER_ALLOW_ALL = 0x00
LE_FILTER_WHITELIST_ONLY = 0x01
LE_FILTER_DUPLICATES_OFF = 0x00
LE_FILTER_DUPLICATES_ON = 0x01

# HCI error codes (unused)
HCI_UNKNOWN_COMMAND = 0x01
HCI_NO_CONNECTION = 0x02
HCI_HARDWARE_FAILURE = 0x03
HCI_PAGE_TIMEOUT = 0x04
HCI_AUTHENTICATION_FAILURE = 0x05
HCI_PIN_OR_KEY_MISSING = 0x06
HCI_MEMORY_FULL = 0x07
HCI_CONNECTION_TIMEOUT = 0x08
HCI_MAX_NUMBER_OF_CONNECTIONS = 0x09
HCI_MAX_NUMBER_OF_SCO_CONNECTIONS = 0x0A
HCI_ACL_CONNECTION_EXISTS = 0x0B
HCI_COMMAND_DISALLOWED = 0x0C
HCI_REJECTED_LIMITED_RESOURCES = 0x0D
HCI_REJECTED_SECURITY = 0x0E
HCI_REJECTED_PERSONAL = 0x0F
HCI_HOST_TIMEOUT = 0x10
HCI_UNSUPPORTED_FEATURE = 0x11
HCI_INVALID_PARAMETERS = 0x12
HCI_OE_USER_ENDED_CONNECTION = 0x13
HCI_OE_LOW_RESOURCES = 0x14
HCI_OE_POWER_OFF = 0x15
HCI_CONNECTION_TERMINATED = 0x16
HCI_REPEATED_ATTEMPTS = 0x17
HCI_PAIRING_NOT_ALLOWED = 0x18
HCI_UNKNOWN_LMP_PDU = 0x19
HCI_UNSUPPORTED_REMOTE_FEATURE = 0x1A
HCI_SCO_OFFSET_REJECTED = 0x1B
HCI_SCO_INTERVAL_REJECTED = 0x1C
HCI_AIR_MODE_REJECTED = 0x1D
HCI_INVALID_LMP_PARAMETERS = 0x1E
HCI_UNSPECIFIED_ERROR = 0x1F
HCI_UNSUPPORTED_LMP_PARAMETER_VALUE = 0x20
HCI_ROLE_CHANGE_NOT_ALLOWED = 0x21
HCI_LMP_RESPONSE_TIMEOUT = 0x22
HCI_LMP_ERROR_TRANSACTION_COLLISION = 0x23
HCI_LMP_PDU_NOT_ALLOWED = 0x24
HCI_ENCRYPTION_MODE_NOT_ACCEPTED = 0x25
HCI_UNIT_LINK_KEY_USED = 0x26
HCI_QOS_NOT_SUPPORTED = 0x27
HCI_INSTANT_PASSED = 0x28
HCI_PAIRING_NOT_SUPPORTED = 0x29
HCI_TRANSACTION_COLLISION = 0x2A
HCI_QOS_UNACCEPTABLE_PARAMETER = 0x2C
HCI_QOS_REJECTED = 0x2D
HCI_CLASSIFICATION_NOT_SUPPORTED = 0x2E
HCI_INSUFFICIENT_SECURITY = 0x2F
HCI_PARAMETER_OUT_OF_RANGE = 0x30
HCI_ROLE_SWITCH_PENDING = 0x32
HCI_SLOT_VIOLATION = 0x34
HCI_ROLE_SWITCH_FAILED = 0x35
HCI_EIR_TOO_LARGE = 0x36
HCI_SIMPLE_PAIRING_NOT_SUPPORTED = 0x37
HCI_HOST_BUSY_PAIRING = 0x38

# Advertisment data format
ADV_TYPE_FLAGS = 0x01
ADV_TYPE_16BIT_SERVICE_UUID_MORE_AVAILABLE = 0x02
ADV_TYPE_16BIT_SERVICE_UUID_COMPLETE = 0x03
ADV_TYPE_32BIT_SERVICE_UUID_MORE_AVAILABLE = 0x04
ADV_TYPE_32BIT_SERVICE_UUID_COMPLETE = 0x05
ADV_TYPE_128BIT_SERVICE_UUID_MORE_AVAILABLE = 0x06
ADV_TYPE_128BIT_SERVICE_UUID_COMPLETE = 0x07
ADV_TYPE_SHORT_LOCAL_NAME = 0x08
ADV_TYPE_COMPLETE_LOCAL_NAME = 0x09
ADV_TYPE_TX_POWER_LEVEL = 0x0A
ADV_TYPE_CLASS_OF_DEVICE = 0x0D
ADV_TYPE_SIMPLE_PAIRING_HASH_C = 0x0E
ADV_TYPE_SIMPLE_PAIRING_RANDOMIZER_R = 0x0F
ADV_TYPE_SECURITY_MANAGER_TK_VALUE = 0x10
ADV_TYPE_SECURITY_MANAGER_OOB_FLAGS = 0x11
ADV_TYPE_SLAVE_CONNECTION_INTERVAL_RANGE = 0x12
ADV_TYPE_SOLICITED_SERVICE_UUIDS_16BIT = 0x14
ADV_TYPE_SOLICITED_SERVICE_UUIDS_128BIT = 0x15
ADV_TYPE_SERVICE_DATA = 0x16
ADV_TYPE_PUBLIC_TARGET_ADDRESS = 0x17
ADV_TYPE_RANDOM_TARGET_ADDRESS = 0x18
ADV_TYPE_APPEARANCE = 0x19
ADV_TYPE_MANUFACTURER_SPECIFIC_DATA = 0xFF


# -----------------------------------------------------------------------------
# HCI Commands (unchanged signatures)
# -----------------------------------------------------------------------------
def hci_le_read_local_supported_features(sock):
    bluez.hci_send_cmd(sock, OGF_LE_CTL, OCF_LE_READ_LOCAL_SUPPORTED_FEATURES, b"")


def hci_le_read_remote_used_features(sock, handle):
    cmd_pkt = struct.pack("<H", handle)
    bluez.hci_send_cmd(sock, OGF_LE_CTL, OCF_LE_READ_REMOTE_USED_FEATURES, cmd_pkt)


# BLE and Bluetooth use the same disconnect command
def hci_disconnect(sock, handle, reason=0x13):
    cmd_pkt = struct.pack("<HB", handle, reason)
    bluez.hci_send_cmd(sock, bluez.OGF_LINK_CTL, bluez.OCF_DISCONNECT, cmd_pkt)


def hci_le_connect(
    sock,
    peer_bdaddr,
    interval=0x0004,
    window=0x0004,
    initiator_filter=LE_FILTER_ALLOW_ALL,
    peer_bdaddr_type=LE_RANDOM_ADDRESS,
    own_bdaddr_type=LE_PUBLIC_ADDRESS,
    min_interval=0x000F,
    max_interval=0x000F,
    latency=0x0000,
    supervision_timeout=0x0C80,
    min_ce_length=0x0001,
    max_ce_length=0x0001,
):
    package_bdaddr = get_packed_bdaddr(peer_bdaddr)
    cmd_pkt = (
        struct.pack("<HHBB", interval, window, initiator_filter, peer_bdaddr_type)
        + package_bdaddr
    )
    cmd_pkt += struct.pack(
        "<BHHHHHH",
        own_bdaddr_type,
        min_interval,
        max_interval,
        latency,
        supervision_timeout,
        min_ce_length,
        max_ce_length,
    )
    bluez.hci_send_cmd(sock, OGF_LE_CTL, OCF_LE_CREATE_CONN, cmd_pkt)


def hci_le_enable_scan(sock):
    hci_le_toggle_scan(sock, 0x01)


def hci_le_disable_scan(sock):
    hci_le_toggle_scan(sock, 0x00)


def hci_le_toggle_scan(sock, enable):
    cmd_pkt = struct.pack("<BB", enable, 0x00)
    bluez.hci_send_cmd(sock, OGF_LE_CTL, OCF_LE_SET_SCAN_ENABLE, cmd_pkt)


def hci_le_set_scan_parameters(
    sock,
    scan_type=LE_SCAN_ACTIVE,
    interval=0x0010,
    window=0x0010,
    own_bdaddr_type=LE_RANDOM_ADDRESS,
    filter_type=LE_FILTER_ALLOW_ALL,
):
    cmd_pkt = struct.pack("<HHBB", interval, window, scan_type, own_bdaddr_type)
    cmd_pkt += struct.pack("<B", filter_type)
    bluez.hci_send_cmd(sock, OGF_LE_CTL, OCF_LE_SET_SCAN_PARAMETERS, cmd_pkt)


# -----------------------------------------------------------------------------
# HCI Response parsers
# -----------------------------------------------------------------------------
def hci_le_parse_response_packet(pkt):
    """
    Parse a BLE packet.

    Returns a dictionary which contains the event id, length and packet type,
    and possibly additional key/value pairs that represent the parsed content
    of the packet.
    """
    result = {}
    ptype, event, plen = struct.unpack("<BBB", pkt[:3])
    result["packet_type"] = ptype
    result["bluetooth_event_id"] = event
    result["packet_length"] = plen
    # We give the user the full packet back as the packet is small, and
    # the user may have additional parsing they want to do.
    result["packet_str"] = packet_as_hex_string(pkt)
    result["packet_bin"] = pkt

    # We only care about events that relate to BLE
    if event == EVT_LE_META_EVENT:
        result["bluetooth_event_name"] = "EVT_LE_META_EVENT"
        result.update(_handle_le_meta_event(pkt[3:]))
    elif event == bluez.EVT_NUM_COMP_PKTS:
        result["bluetooth_event_name"] = "EVT_NUM_COMP_PKTS"
        result.update(_handle_num_completed_packets(pkt[3:]))
    elif event == bluez.EVT_INQUIRY_RESULT_WITH_RSSI:
        result["bluetooth_event_name"] = "EVT_INQUIRY_RESULT_WITH_RSSI"
        result.update(_handle_inquiry_result_with_rssi(pkt[3:]))
    elif event == bluez.EVT_INQUIRY_RESULT:
        result["bluetooth_event_name"] = "EVT_INQUIRY_RESULT"
        result.update(_handle_inquiry_result(pkt[3:]))
    elif event == bluez.EVT_DISCONN_COMPLETE:
        result["bluetooth_event_name"] = "EVT_DISCONN_COMPLETE"
        result.update(_handle_disconn_complete(pkt[3:]))
    elif event == bluez.EVT_CMD_STATUS:
        result["bluetooth_event_name"] = "EVT_CMD_STATUS"
        result.update(_handle_command_status(pkt[3:]))
    elif event == bluez.EVT_CMD_COMPLETE:
        result["bluetooth_event_name"] = "EVT_CMD_COMPLETE"
        result.update(_handle_command_complete(pkt[3:]))
    elif event == bluez.EVT_INQUIRY_COMPLETE:
        raise NotImplementedError("EVT_CMD_COMPLETE")
    else:
        result["bluetooth_event_name"] = "UNKNOWN"
    return result


# -----------------------------------------------------------------------------
# Internal helpers
# -----------------------------------------------------------------------------
def _handle_num_completed_packets(pkt):
    result = {}
    num_handles = struct.unpack("<B", pkt[0:1])[0]
    pkt = pkt[1:]
    result["num_connection_handles"] = num_handles
    result["handles"] = []
    for _ in range(num_handles):
        handle = struct.unpack("<H", pkt[0:2])[0]
        completed = struct.unpack("<H", pkt[2:4])[0]
        result["handles"].append({"handle": handle, "num_completed_packets": completed})
        pkt = pkt[4:]
    return result


def _handle_inquiry_result_with_rssi(pkt):
    result = {}
    num = struct.unpack("<B", pkt[0:1])[0]
    pkt = pkt[1:]
    result["num_inquiry_results"] = num
    result["inquiry_results"] = []
    for i in range(num):
        addr = bluez.ba2str(pkt[6 * i : 6 * i + 6])
        rssi = struct.unpack("<b", pkt[13 * num + i : 13 * num + i + 1])[0]
        result["inquiry_results"].append({"Address": addr, "RSSI": rssi})
    return result


def _handle_inquiry_result(pkt):
    result = {}
    num = struct.unpack("<B", pkt[0:1])[0]
    pkt = pkt[1:]
    result["num_inquiry_results"] = num
    result["inquiry_results"] = []
    for i in range(num):
        addr = bluez.ba2str(pkt[6 * i : 6 * i + 6])
        result["inquiry_results"].append({"Address": addr})
    return result


def _handle_disconn_complete(pkt):
    status, handle, reason = struct.unpack("<BHB", pkt)
    return {"status": status, "handle": handle, "reason": reason}


def _handle_command_status(pkt):
    status, ncmd, opcode = struct.unpack("<BBH", pkt)
    ogf, ocf = ogf_and_ocf_from_opcode(opcode)
    return {
        "status": status,
        "number_of_commands": ncmd,
        "opcode": opcode,
        "opcode_group_field": ogf,
        "opcode_command_field": ocf,
    }


def _handle_command_complete(pkt):
    ncmd, opcode = struct.unpack("<BH", pkt[:3])
    ogf, ocf = ogf_and_ocf_from_opcode(opcode)
    return {
        "number_of_commands": ncmd,
        "opcode": opcode,
        "opcode_group_field": ogf,
        "opcode_command_field": ocf,
        "command_return_values": pkt[3:] if len(pkt) > 3 else b"",
    }


def _handle_le_meta_event(pkt):
    result = {}
    subevent = struct.unpack("<B", pkt[0:1])[0]
    result["bluetooth_le_subevent_id"] = subevent
    pkt = pkt[1:]
    if subevent == EVT_LE_ADVERTISING_REPORT:
        result["bluetooth_le_subevent_name"] = "EVT_LE_ADVERTISING_REPORT"
        result.update(_handle_le_advertising_report(pkt))
    elif subevent == EVT_LE_CONN_COMPLETE:
        result["bluetooth_le_subevent_name"] = "EVT_LE_CONN_COMPLETE"
        result.update(_handle_le_connection_complete(pkt))
    elif subevent == EVT_LE_CONN_UPDATE_COMPLETE:
        result["bluetooth_le_subevent_name"] = "EVT_LE_CONN_UPDATE_COMPLETE"
        raise NotImplementedError("EVT_LE_CONN_UPDATE_COMPLETE")
    elif subevent == EVT_LE_READ_REMOTE_USED_FEATURES_COMPLETE:
        result["bluetooth_le_subevent_name"] = (
            "EVT_LE_READ_REMOTE_USED_FEATURES_COMPLETE"
        )
        result.update(_handle_le_read_remote_used_features(pkt))
    else:
        result["bluetooth_le_subevent_name"] = "UNKNOWN"
    return result


def _handle_le_connection_complete(pkt):
    status, handle, role, bdaddr_type = struct.unpack("<BHBB", pkt[:5])
    addr = packed_bdaddr_to_string(pkt[5:11])
    interval, latency, timeout, clkacc = struct.unpack("<HHHB", pkt[11:])
    return {
        "status": status,
        "handle": handle,
        "role": role,
        "peer_bluetooth_address_type": bdaddr_type,
        "peer_device_address": addr,
        "interval": interval,
        "latency": latency,
        "supervision_timeout": timeout,
        "master_clock_accuracy": clkacc,
    }


def _handle_le_read_remote_used_features(pkt):
    status, handle = struct.unpack("<BH", pkt[:3])
    features = list(struct.unpack("<" + "B" * 8, pkt[3:11]))
    return {"status": status, "handle": handle, "features": features}


def _handle_le_advertising_report(pkt):
    result = {}
    num_reports = struct.unpack("<B", pkt[0:1])[0]
    result["number_of_advertising_reports"] = num_reports
    result["advertising_reports"] = []
    offset = 1
    for _ in range(num_reports):
        report = {}
        report["report_type_id"] = struct.unpack("<B", pkt[offset + 1 : offset + 2])[0]
        report["peer_bluetooth_address_type"] = struct.unpack(
            "<B", pkt[offset + 2 : offset + 3]
        )[0]
        addr = packed_bdaddr_to_string(pkt[offset + 3 : offset + 9])
        report["peer_bluetooth_address"] = addr.upper()
        report["peer_bluetooth_address_s"] = short_bt_address(addr)

        data_len = struct.unpack("<B", pkt[offset + 9 : offset + 10])[0]
        report["report_metadata_length"] = data_len

        report["report_type_string"] = {
            LE_ADV_IND: "LE_ADV_IND",
            LE_ADV_DIRECT_IND: "LE_ADV_DIRECT_IND",
            LE_ADV_SCAN_IND: "LE_ADV_SCAN_IND",
            LE_ADV_NONCONN_IND: "LE_ADV_NONCONN_IND",
            LE_ADV_SCAN_RSP: "LE_ADV_SCAN_RSP",
        }.get(report["report_type_id"], "UNKNOWN")

        if data_len > 0:
            report["payload_binary"] = pkt[offset + 10 : offset + 10 + data_len]
            report["payload"] = packet_as_hex_string(
                report["payload_binary"],
                flag_with_spacing=True,
                flag_force_capitalize=True,
            )
        rssi = struct.unpack(
            "<b", pkt[offset + 10 + data_len : offset + 10 + data_len + 1]
        )[0]
        report["rssi"] = rssi
        result["advertising_reports"].append(report)
        offset += 10 + data_len + 1
    return result


# -----------------------------------------------------------------------------
# Utility helpers
# -----------------------------------------------------------------------------
def get_packed_bdaddr(bdaddr_string):
    addr = bdaddr_string.split(":")[::-1]
    return struct.pack("<BBBBBB", *[int(b, 16) for b in addr])


def packed_bdaddr_to_string(bdaddr_packed):
    return ":".join("{:02x}".format(b) for b in bdaddr_packed[::-1])


def short_bt_address(bt_addr):
    return "".join(bt_addr.split(":"))


def packet_as_hex_string(pkt, flag_with_spacing=False, flag_force_capitalize=False):
    space = " " if flag_with_spacing else ""
    hex_str = space.join("{:02x}".format(b) for b in pkt)
    return hex_str.upper() if flag_force_capitalize else hex_str


def ogf_and_ocf_from_opcode(opcode):
    ogf = (opcode >> 10) & 0x3F
    ocf = opcode & 0x03FF
    return ogf, ocf


def reset_hci():
    subprocess.call("sudo hciconfig hci0 down", shell=True)
    subprocess.call("sudo hciconfig hci0 up", shell=True)


def get_companyid(pkt):
    return (pkt[1] << 8) | pkt[0]


# -----------------------------------------------------------------------------
# Beacon verification helpers
# -----------------------------------------------------------------------------
def verify_beacon_packet(report):
    if report["report_metadata_length"] != 31:
        return False
    if report["payload_binary"][4] != ADV_TYPE_MANUFACTURER_SPECIFIC_DATA:
        return False
    if get_companyid(report["payload_binary"][5:7]) != COMPANY_ID:
        return False

    # shortened local name checks
    if report["payload_binary"][28] == ADV_TYPE_SHORT_LOCAL_NAME:
        name = report["payload_binary"][29:31]
        if name in (b"IM", b"EP"):
            return True
    elif report["payload_binary"][27] == ADV_TYPE_SHORT_LOCAL_NAME:
        name = report["payload_binary"][28:31]
        if name == b"Rbt" and report["payload_binary"][7] in (0x01, 0x02):
            return True
    return False


def classify_beacon_packet(report):
    if report["payload_binary"][29:31] == b"IM":
        return "IM"
    elif report["payload_binary"][29:31] == b"EP":
        return "EP"
    elif report["payload_binary"][28:31] == b"Rbt":
        return {
            0x01: "Rbt 0x01",
            0x02: "Rbt 0x02",
            0x03: "Rbt 0x03",
            0x04: "Rbt 0x04",
            0x05: "Rbt 0x05",
            0x06: "Rbt 0x06",
        }.get(report["payload_binary"][7], "UNKNOWN")
    return "UNKNOWN"
