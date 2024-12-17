#!/usr/bin/env python
import subprocess
import sys
import os
import json
import requests
import time
from datetime import datetime, timedelta

inpt = json.loads(sys.argv[1])['payload']['default']
def run(msg):
    b = True
    while(True & b):
      print("Scan range requested:"+ str(datetime.utcnow()))
      r = requests.get(url = "https://172.20.0.7:8432/scan_range/" + str(inpt), verify=False)
      input_data = str(r.json())
      print("Scan range answer:"+ str(datetime.utcnow()))
      # Remove square brackets and single quotes
      cleaned_string = input_data.replace("[", "").replace("]", "").replace("'", "")

      # Split the string into a list of IPs
      ip_list = cleaned_string.split(", ")
      print(ip_list)
      # Iterate over each IP and retrieve it
      for ip in ip_list:
        #print(ip)
        data1 = {"host": ip}
        r1 = requests.post(url = "https://192.168.13.6:8432/host_status/", headers={'Content-Type': 'application/json'}, json=data1, verify=False)
        
        try:
          int(r1.json())
          print(r1.json())
          r = requests.post(url = "https://192.168.13.161:8432/create_ticket/", verify=False)
        except:
          next_scan_date = datetime.fromisoformat(r1.json())
          print(next_scan_date)
          if next_scan_date > datetime.utcnow():
            print(datetime.utcnow())
            print("Stored datetime is in the future.")
          else:
            print("Host on queue:"+ str(datetime.utcnow()))
            r2 = requests.post(url = "https://192.168.13.6:8432/host_queue/", headers={'Content-Type': 'application/json'}, json=data1, verify=False)
            print("Stored datetime is in the past or present.")
            print("Created Ticket:"+ str(datetime.utcnow()))
            r = requests.post(url = "https://192.168.13.161:8432/create_ticket/", verify=False)
      time.sleep(200)
      b = False
    return {"range": r1.json()}

print(json.dumps(run(inpt)))
