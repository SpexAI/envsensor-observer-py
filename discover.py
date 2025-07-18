#!/usr/bin/env python3

import bluetooth

print("  bluetooth.discover_devices(duration=30) ...")

nearby_devices = bluetooth.discover_devices(
    duration=30, lookup_names=True, flush_cache=True, lookup_class=False
)

print("Found {} devices.".format(len(nearby_devices)))

for addr, name in nearby_devices:
    print("  {} - {}".format(addr, name))
