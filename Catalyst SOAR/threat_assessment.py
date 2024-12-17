#!/usr/bin/env python
import subprocess
import sys
import json
import requests
from datetime import datetime, timedelta

def calculate_max_threat():
    print("Asked for report:"+ str(datetime.utcnow()))
    r = requests.post(url = "https://192.168.13.6:8432/get_report/", verify=False)
    print("Report received:"+ str(datetime.utcnow()))
    report = r.json()
    #print(type(report))
    #print(report)
    #print(report.keys())
    ip_address = report['result'][0]['host']['#text']
    print(ip_address)
    sev_array = []
    qod_array = []
    for vuln in report['result']:
    	name = vuln['name']
    	sev = vuln['severity']
    	qod = vuln['qod']['value']
    	print(name)
    	sev_array.append(sev)
    	qod_array.append(qod)
    print(sev_array)
    print(qod_array)
    print("Parsing report:"+ str(datetime.utcnow()))
    products = [float(sev) * float(qod) for sev, qod in zip(sev_array, qod_array)]
    max_product = max(products)
    print(max_product/100)
    r = requests.get(url = "http://192.168.13.6:8080/simpleswitch/change_vlan/" + str(ip_address) + "/20", verify=False)
    print("VLAN changed:"+ str(datetime.utcnow()))
    
    return "finished"

print(json.dumps(calculate_max_threat()))
