import bluetooth

target_address = "0C:90:43:39:C0:FC"  # Replace with the target device's address
port = 1  # Standard RFCOMM port for many devices

sock = bluetooth.BluetoothSocket(bluetooth.RFCOMM)
try:
    sock.connect((target_address, port))
    print("Connected to {}".format(target_address))

    sock.send("Hello from Python!")
    data = sock.recv(1024)
    print("Received: {}".format(data.decode("utf-8")))

except bluetooth.BluetoothError as e:
    print(f"Bluetooth error for {target_address}: {e}")
finally:
    sock.close()
