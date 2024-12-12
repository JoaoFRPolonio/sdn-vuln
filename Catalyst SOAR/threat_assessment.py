#!/usr/bin/env python
import subprocess
import sys
import json
import requests
from datetime import datetime, timedelta
#inpt = json.loads(sys.argv[1])['payload']['default']

def calculate_max_threat():#data):
    print("Asked for report:"+ str(datetime.utcnow()))
    r = requests.post(url = "https://192.168.13.6:8432/get_report/", verify=False)
    print("Report received:"+ str(datetime.utcnow()))
    #r.session().close()
    report = r.json()
    #report_json = json.loads(report)
    print(type(report))
    #print("estou aqui")
    #report_json = {"model": "Model X", "year": 2022}
    #report_json = r.json()
    #vuln = report_json['model']
    print(report)
    print(report.keys())
    #print("uau")
    #print(vulnerabilities)
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
    	#qod = vuln.get('qod', {}).get('value')
    	#severity = vuln.get('severity')
    	#print("QoD:", qod, "Severity:", severity)
      #name = vulnerability["name"]
      #severity = vulnerability["nvt"]["severities"]["@score"] if "severities" in vulnerability["nvt"] else "N/A"
      #cvss_base = vulnerability["nvt"]["cvss_base"] if "cvss_base" in vulnerability["nvt"] else "N/A"
      #print("Name:", name)
      #print("Severity:", severity)
      #print("CVSS Base Score:", cvss_base)
      #print("-" * 50)'''
    
    
    '''cvss_list = data[0]['address']['cvss']
    qod_list = data[0]['address']['qod']

    products = [float(cvss) * float(qod) for cvss, qod in zip(cvss_list, qod_list)]
    max_product = max(products)
    ip_address = data[0]['ip']
    return {"score": max_product/100, "ip_address": ip_address}'''
    return "batata"

print(json.dumps(calculate_max_threat()))
#print(inpt)
