#!/usr/bin/env python3

import subprocess
import bluetooth

# address should be "EE:05:14:9F:08:F1"
# bluetoothctl
#  scan on
# => [bluetooth]# [NEW] Device EE:05:14:9F:08:F1 Rbt
TARGET_NAME = "Rbt"


def discover(duration=8, lookup_names=False):
    """
    Since both the Bluetooth detection and name lookup process are
    probabilistic, discover_devices() will sometimes fail to detect
    devices that are in range, and lookup_name() will sometimes return
    None to indicate that it couldn't determine the user-friendly name
    of the detected device. In these cases, it may be a good idea to
    try again once or twice before giving up.
    https://people.csail.mit.edu/albert/bluez-intro/c212.html
    """
    target_address = None
    print(
        f"  bluetooth.discover_devices(duration={duration}, lookup_names={lookup_names}) ..."
    )
    nearby_devices = bluetooth.discover_devices(
        duration=duration, lookup_names=lookup_names
    )
    for bdaddr in nearby_devices:
        name = bluetooth.lookup_name(bdaddr)
        print(f"  saw {name} at {bdaddr}")
        if name[0:3] == TARGET_NAME:
            target_address = bdaddr
            break
    return target_address


def report(target_name, target_address):
    if target_address is not None:
        print(f'Found bluetooth device "{target_name}" with address {target_address}')
    else:
        print(f'Could not find a bluetooth device "{target_name}" nearby')


if __name__ == "__main__":
    address = discover(12, True)
    if address is not None:
        report(TARGET_NAME, address)
    else:
        print("  sudo hciconfig hci0 down + up")
        subprocess.call("sudo hciconfig hci0 down", shell=True)
        subprocess.call("sudo hciconfig hci0 up", shell=True)
        target_address = discover(5)
        report(TARGET_NAME, address)
