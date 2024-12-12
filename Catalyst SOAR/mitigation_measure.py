#!/usr/bin/env python
import subprocess
import sys
import os
import json
import requests

inpt = json.loads(sys.argv[1])#['payload']['default']
def run(ip_address, score):
    if(float(score) > 5):
        r = requests.get(url = "http://192.168.13.6:8080/simpleswitch/change_vlan/" + str(ip_address) + "/20", verify=False)
        return {"output": r.json()}
    else:
        return {"output": "Safe host"}

ip_address = inpt['context']['ticket']['playbooks']['host-discovery']['tasks']['threat-score']['data']['ip_address']
score = inpt['context']['ticket']['playbooks']['host-discovery']['tasks']['threat-score']['data']['score']

print(json.dumps(run(ip_address, score)))
#print("IP Address:", ip_address)
#print("Score:", score)
##
