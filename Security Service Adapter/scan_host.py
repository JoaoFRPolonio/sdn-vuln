#!/bin/bash

IP_ADDRESS=$1
#Scanning Host
gvm-script --gmp-username kali --gmp-password kali socket --hostname /usr/share/gvm-tools/scan-new-system.gmp.py $1 4a4717fe-57d2-11e1-9a26-406186ea4fc5
