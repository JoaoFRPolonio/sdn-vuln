#!/bin/bash

REPORT_ID=$1
#Scanning Host
gvm-cli --gmp-username kali --gmp-password kali socket --xml "<get_reports report_id='$1' filter='apply_overrides=0 levels=hml rows=1000 min_qod=70 first=1 sort-reverse=severity notes=1 overrides=1' details='1'/>"
