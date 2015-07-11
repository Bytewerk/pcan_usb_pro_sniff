#!/bin/bash

# test procedure:
# 0. connect pcan usb can1 && can2, add termination resistor 
# 1. start wireshark usbmon capture
# 2. plug in usb adapter
# 3. run test script
# 4. unplug usb adapter
# 5. stop wireshark capture
# 6. filter for usb.idVendor==0xc72 -> find device_address n
# 7. filter for usb.device_address==n
# 8. "export specified packets..." 


function send_both {
    cansend can0 $1
    sleep 0.5
    cansend can1 $1
    sleep 0.5
}

ip link set can0 down
ip link set can1 down
ip link set can0 up type can bitrate 500000
ip link set can1 up type can bitrate 500000

sleep 1

send_both 123#
send_both 123#01
send_both 123#0102
send_both 123#010203
send_both 123#01020304
send_both 123#0102030405
send_both 123#010203040506
send_both 123#01020304050607
send_both 123#0102030405060708

sleep 1

send_both 13370123#
send_both 13370123#01
send_both 13370123#0102
send_both 13370123#010203
send_both 13370123#01020304
send_both 13370123#0102030405
send_both 13370123#010203040506
send_both 13370123#01020304050607
send_both 13370123#0102030405060708

sleep 1

for (( i=1; i <= 5000; i++ ))
do
    cansend can0 456#8877665544332211
done
sleep 2

for (( i=1; i <= 5000; i++ ))
do
    cansend can1 456#8877665544332211
done
sleep 2

for (( i=1; i <= 5000; i++ ))
do
    cansend can0 456#8877665544332211
    cansend can1 456#8877665544332211
done
sleep 2


