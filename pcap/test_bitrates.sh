#!/bin/bash

# test procedure:
# 1. start wireshark usbmon capture
# 2. plug in usb adapter
# 3. run test script
# 4. unplug usb adapter
# 5. stop wireshark capture
# 6. filter for usb.idVendor==0xc72 -> find device_address n
# 7. filter for usb.device_address==n
# 8. "export specified packets..." 

function set_speed {
    ip link set $1 down
    sleep 0.5
    echo "setting device $1 to bitrate $2"
    ip link set $1 up type can bitrate $2
    sleep 0.5
}

set_speed can0 100000
set_speed can0 125000
set_speed can0 200000
set_speed can0 250000
set_speed can0 500000
set_speed can0 1000000

set_speed can1 100000
set_speed can1 125000
set_speed can1 200000
set_speed can1 250000
set_speed can1 500000
set_speed can1 1000000

