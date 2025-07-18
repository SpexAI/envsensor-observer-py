#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# python Environment Sensor Observer for Linux   (Python-3 edition)
#
# target device : OMRON Environment Sensor (2JCIE-BL01 & BU01) in Broadcaster mode
#
# require : python-bluez
#         : fluent-logger-python (when FLUENTD_FORWARD = True in configuration)
#               $ sudo pip3 install fluent-logger
#         : influxdb-python (when INFLUXDB_OUTPUT = True in configuration)
#               $ sudo pip3 install influxdb
#
# Note: Proper operation of this sample application is not guaranteed.

import sys
import os
import argparse
import requests
import socket
import datetime
import threading
# import struct

import sensor_beacon as envsensor
import conf
import ble

if conf.CSV_OUTPUT:
    import logging
    import csv_logger
if conf.FLUENTD_FORWARD:
    from fluent import sender, event
if conf.INFLUXDB_OUTPUT:
    from influxdb import InfluxDBClient

# ---------------------------------------------------------------------------
VER = 1.2
GATEWAY = socket.gethostname()

influx_client = None
sensor_list = []
flag_update_sensor_status = False
debug = False
log = None


# ---------------------------------------------------------------------------
def parse_events(sock, loop_count=10):
    global sensor_list

    pkt = sock.recv(255)

    # Raw avertise packet data from Bluez scan
    # Packet Type (1byte) + BT Event ID (1byte) + Packet Length (1byte) +
    # BLE sub-Event ID (1byte) + Number of Advertising reports (1byte) +
    # Report type ID (1byte) + BT Address Type (1byte) + BT Address (6byte) +
    # Data Length (1byte) + Data ((Data Length)byte) + RSSI (1byte)
    #
    # Packet Type = 0x04
    # BT Event ID = EVT_LE_META_EVENT = 0x3E (BLE events)
    # (All LE commands result in a metaevent, specified by BLE sub-Event ID)
    # BLE sub-Event ID = {
    #                       EVT_LE_CONN_COMPLETE = 0x01
    #                       EVT_LE_ADVERTISING_REPORT = 0x02
    #                       EVT_LE_CONN_UPDATE_COMPLETE = 0x03
    #                       EVT_LE_READ_REMOTE_USED_FEATURES_COMPLETE = 0x04
    #                       EVT_LE_LTK_REQUEST = 0x05
    #                     }
    # Number of Advertising reports = 0x01 (normally)
    # Report type ID = {
    #                       LE_ADV_IND = 0x00
    #                       LE_ADV_DIRECT_IND = 0x01
    #                       LE_ADV_SCAN_IND = 0x02
    #                       LE_ADV_NONCONN_IND = 0x03
    #                       LE_ADV_SCAN_RSP = 0x04
    #                   }
    # BT Address Type = {
    #                       LE_PUBLIC_ADDRESS = 0x00
    #                       LE_RANDOM_ADDRESS = 0x01
    #                    }
    # Data Length = 0x00 - 0x1F
    # * Maximum Data Length of an advertising packet = 0x1F

    parsed_packet = ble.hci_le_parse_response_packet(pkt)

    if (
        "bluetooth_le_subevent_name" in parsed_packet
        and parsed_packet["bluetooth_le_subevent_name"] == "EVT_LE_ADVERTISING_REPORT"
    ):
        if debug:
            for report in parsed_packet["advertising_reports"]:
                print("----------------------------------------------------")
                print("Found BLE device:", report["peer_bluetooth_address"])
                print("Raw Advertising Packet:")
                print(
                    ble.packet_as_hex_string(
                        pkt, flag_with_spacing=True, flag_force_capitalize=True
                    )
                )
                print()
                for k, v in report.items():
                    if k != "payload_binary":
                        print("\t%s: %s" % (k, v))
                print()

        for report in parsed_packet["advertising_reports"]:
            if ble.verify_beacon_packet(report):
                sensor = envsensor.SensorBeacon(
                    report["peer_bluetooth_address_s"],
                    ble.classify_beacon_packet(report),
                    GATEWAY,
                    report["payload_binary"],
                )

                index = find_sensor_in_list(sensor, sensor_list)

                if debug:
                    print("\t--- sensor data ---")
                    print(f"\tindex: {index}")
                    sensor.debug_print()
                    print()

                with threading.Lock():
                    if index != -1:  # known sensor
                        if sensor.check_diff_seq_num(sensor_list[index]):
                            handling_data(sensor)
                            if debug:
                                print("\tknown sensor")
                        sensor.update(sensor_list[index])
                    else:  # new sensor
                        if debug:
                            print("\tnew sensor")
                        sensor_list.append(sensor)
                        handling_data(sensor)


# ---------------------------------------------------------------------------
def handling_data(sensor):
    if conf.INFLUXDB_OUTPUT:
        sensor.upload_influxdb(influx_client)
    if conf.FLUENTD_FORWARD:
        sensor.forward_fluentd(event)
    if conf.CSV_OUTPUT:
        log.info(sensor.csv_format())


# ---------------------------------------------------------------------------
def eval_sensor_state():
    global flag_update_sensor_status, sensor_list
    nowtick = datetime.datetime.now()
    for sensor in sensor_list:
        if sensor.flag_active:
            pastSec = (nowtick - sensor.tick_last_update).total_seconds()
            if pastSec > conf.INACTIVE_TIMEOUT_SECONDS:
                if debug:
                    print("timeout sensor : " + sensor.bt_address)
                sensor.flag_active = False

    flag_update_sensor_status = True
    timer = threading.Timer(conf.CHECK_SENSOR_STATE_INTERVAL_SECONDS, eval_sensor_state)
    timer.daemon = True  # ← new Python-3 attribute
    timer.start()


# ---------------------------------------------------------------------------
def print_sensor_state():
    print("----------------------------------------------------")
    print(
        "sensor status : %s (Intvl. %ssec)"
        % (datetime.datetime.today(), conf.CHECK_SENSOR_STATE_INTERVAL_SECONDS)
    )
    for sensor in sensor_list:
        print(
            " " + sensor.bt_address,
            ": %s :" % sensor.sensor_type,
            ("ACTIVE" if sensor.flag_active else "DEAD"),
            "(%s)" % sensor.tick_last_update,
        )
    print()


# ---------------------------------------------------------------------------
# Utility helpers   (struct.unpack("B", c)[0] → c)
# ---------------------------------------------------------------------------
def return_number_packet(pkt):
    myInteger = 0
    multiple = 256
    for b in pkt:  # b is already int in Py3
        myInteger += b * multiple
        multiple = 1
    return myInteger


def return_string_packet(pkt):
    return "".join("{:02x}".format(b) for b in pkt)


def find_sensor_in_list(sensor, lst):
    for idx, s in enumerate(lst):
        if sensor.bt_address == s.bt_address:
            return idx
    return -1


# ---------------------------------------------------------------------------
def init_fluentd():
    sender.setup(conf.FLUENTD_TAG, host=conf.FLUENTD_ADDRESS, port=conf.FLUENTD_PORT)


def create_influx_database():
    uri = (
        f"http://{conf.FLUENTD_INFLUXDB_ADDRESS}:"
        f"{conf.FLUENTD_INFLUXDB_PORT_STRING}/query"
    )
    params = {"q": f"CREATE DATABASE {conf.FLUENTD_INFLUXDB_DATABASE}"}
    r = requests.get(uri, params=params)
    if debug:
        print("-- create database :", r.status_code)


# ---------------------------------------------------------------------------
def arg_parse():
    parser = argparse.ArgumentParser()
    parser.add_argument("-d", "--debug", help="debug mode", action="store_true")
    parser.add_argument("--version", action="version", version="%(prog)s " + str(VER))
    return parser.parse_args()


# ---------------------------------------------------------------------------
if __name__ == "__main__":
    try:
        flag_scanning_started = False

        debug = False
        args = arg_parse()
        if args.debug:
            debug = True

        # reset bluetooth
        try:
            if debug:
                print("-- reseting bluetooth device")
            ble.reset_hci(debug)
            if debug:
                print("-- reseting bluetooth device : success")
        except Exception as e:
            print("error enabling bluetooth device")
            print(str(e))
            sys.exit(1)

        # InfluxDB
        try:
            if conf.INFLUXDB_OUTPUT:
                if debug:
                    print("-- initialize influxDB interface")
                influx_client = InfluxDBClient(
                    conf.INFLUXDB_ADDRESS,
                    conf.INFLUXDB_PORT,
                    conf.INFLUXDB_USER,
                    conf.INFLUXDB_PASSWORD,
                    conf.INFLUXDB_DATABASE,
                )
                influx_client.create_database(conf.INFLUXDB_DATABASE)
                if debug:
                    print("-- initialize influxDB interface : success")
        except Exception as e:
            print("error initializing influxDB output interface")
            print(str(e))
            sys.exit(1)

        # Fluentd
        try:
            if conf.FLUENTD_FORWARD:
                if debug:
                    print("-- initialize fluentd")
                init_fluentd()
                if conf.FLUENTD_INFLUXDB:
                    create_influx_database()
                if debug:
                    print("-- initialize fluentd : success")
        except Exception as e:
            print("error initializing fluentd forwarder")
            print(str(e))
            sys.exit(1)

        # CSV logger
        try:
            if conf.CSV_OUTPUT:
                if debug:
                    print("-- initialize csv logger")

                os.makedirs(conf.CSV_DIR_PATH, exist_ok=True)
                csv_path = os.path.join(conf.CSV_DIR_PATH, "env_sensor_log.csv")
                loghndl = csv_logger.CSVHandler(csv_path, "midnight", 1)
                loghndl.setFormatter(logging.Formatter("%(message)s"))

                log = logging.getLogger("CSVLogger")
                loghndl.configureHeaderWriter(envsensor.csv_header(), log)
                log.addHandler(loghndl)
                log.setLevel(logging.INFO)
                # log.info(envsensor.csv_header())

                if debug:
                    print("-- initialize csv logger : success")
        except Exception as e:
            print("error initializing csv output interface")
            print(str(e))
            sys.exit(1)

        # Bluetooth socket
        try:
            if debug:
                print("-- open bluetooth device")
            sock = ble.bluez.hci_open_dev(conf.BT_DEV_ID)
            if debug:
                print("-- ble thread started")
        except Exception as e:
            print("error accessing bluetooth device:", conf.BT_DEV_ID)
            print(str(e))
            sys.exit(1)

        # scan parameters & start
        try:
            if debug:
                print("-- set ble scan parameters")
            ble.hci_le_set_scan_parameters(sock)
            if debug:
                print("-- set ble scan parameters : success")

            if debug:
                print("-- enable ble scan")
            ble.hci_le_enable_scan(sock)
            if debug:
                print("-- ble scan started")
        except Exception as e:
            print("failed to activate scan! need sudo")
            print(str(e))
            sys.exit(1)

        flag_scanning_started = True
        print("envsensor_observer : complete initialization")
        print()

        # periodic sensor-state timer
        timer = threading.Timer(
            conf.CHECK_SENSOR_STATE_INTERVAL_SECONDS, eval_sensor_state
        )
        timer.daemon = True
        timer.start()

        # HCI filter
        old_filter = sock.getsockopt(ble.bluez.SOL_HCI, ble.bluez.HCI_FILTER, 14)
        flt = ble.bluez.hci_filter_new()
        ble.bluez.hci_filter_all_events(flt)
        ble.bluez.hci_filter_set_ptype(flt, ble.bluez.HCI_EVENT_PKT)
        sock.setsockopt(ble.bluez.SOL_HCI, ble.bluez.HCI_FILTER, flt)

        while True:
            parse_events(sock)
            if flag_update_sensor_status:
                print_sensor_state()
                flag_update_sensor_status = False

    except Exception as e:
        print("Exception:", str(e))
        import traceback

        traceback.print_exc()
        sys.exit(1)

    finally:
        if flag_scanning_started:
            sock.setsockopt(ble.bluez.SOL_HCI, ble.bluez.HCI_FILTER, old_filter)
            ble.hci_le_disable_scan(sock)
        print("Exit")
