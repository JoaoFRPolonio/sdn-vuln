import requests
import json

url = "https://catalystdomain/api/"
headers = {"Content-Type": "application/json; charset=utf-8", "PRIVATE-TOKEN":"6vIjzG1zryvqX5csISZXAp9ez7nH55f0"}

import json
from fastapi import Depends, FastAPI
import uvicorn
import redis

from collections import defaultdict

import random
import numpy as np

from datetime import datetime

app = FastAPI()



'''def get_tickets(headers, url):
    response = requests.get(url, headers=headers, verify='/home/catalyst/Documents/SSL_Certificates/rootCA.crt')
    return(response.json())
    
def get_single_ticket(headers, ticket_id, url):
    url = url + "tickets/"+str(ticket_id)
    response = requests.get(url, headers=headers)
    return(response.json())
    
def get_automations(headers, url):
    response = requests.get(url+str('automations/my-automation'), headers=headers, verify='/home/catalyst/Documents/SSL_Certificates/rootCA.crt')
    return(response.json())
    
resp = get_automations(headers, url)
print(resp)'''

'''def list_tickets(headers, url):
    response = requests.get(url+str('tickets'), headers=headers, verify='/home/catalyst/Documents/SSL_Certificates/rootCA.crt')
    return(response.json())

print(list_tickets(headers, url))'''

'''def create_ticket(headers, url):
    data1 = {"artifacts": [{"enrichments": {"property1": {"created": "2019-08-24T14:15:22Z","data": {"hash": "b7a067a742c20d07a7456646de89bc2d408a1153"},"name": "hash.sha1"},"property2": {"created": "2019-08-24T14:15:22Z","data": {"hash": "b7a067a742c20d07a7456646de89bc2d408a1153"},"name": "hash.sha1"}},"name": "2.2.2.2","status": "Unknown","type": "string"}],"comments": [{"created": "2019-08-24T14:15:22Z","creator": "string","message": "string"}],"created": "2019-08-24T14:15:22Z","details": {"description": "my little incident"},"files": [{"key": "myfile","name": "notes.docx"}],"id": 143,"modified": "2019-08-24T14:15:22Z","name": "WannyCry","owner": "bob","playbooks": [{"id":"phishing","yaml":"name: Phishing\ntasks:\n  board:\n    name: Board Involvement?\n    description: Is a board member involved?\n    type: input\n    schema:\n      properties:\n        boardInvolved:\n          default: false\n          title: A board member is involved.\n          type: boolean\n      required:\n        - boardInvolved\n      title: Board Involvement?\n      type: object\n    next:\n      escalate: \"boardInvolved == true\"\n      mail-available: \"boardInvolved == false\"\n\n  escalate:\n    name: Escalate to CISO\n    description: Please escalate the task to the CISO\n    type: task\n\n  mail-available:\n    name: Mail available\n    type: input\n    schema:\n      oneOf:\n        - properties:\n            mail:\n              title: Mail\n              type: string\n              x-display: textarea\n            schemaKey:\n              const: 'yes'\n              type: string\n          required:\n            - mail\n          title: 'Yes'\n        - properties:\n            schemaKey:\n              const: 'no'\n              type: string\n          title: 'No'\n      title: Mail available\n      type: object\n    next:\n      block-sender: \"schemaKey == 'yes'\"\n      extract-iocs: \"schemaKey == 'yes'\"\n      search-email-gateway: \"schemaKey == 'no'\"\n\n  search-email-gateway:\n    name: Search email gateway\n    description: Please search email-gateway for the phishing mail.\n    type: task\n    next:\n      extract-iocs:\n\n  block-sender:\n    name: Block sender\n    type: task\n    next:\n      extract-iocs:\n\n  extract-iocs:\n    name: Extract IOCs\n    description: Please insert the IOCs\n    type: input\n    schema:\n      properties:\n        iocs:\n          items:\n            type: string\n          title: IOCs\n          type: array\n      title: Extract IOCs\n      type: object\n    next:\n      block-iocs:\n\n  block-iocs:\n    name: Block IOCs\n    type: task\n"},{"id":"simple","name":"Simple","yaml":"name: Simple\ntasks:\n  input:\n    name: Enter something to hash\n    type: input\n    schema:\n      title: Something\n      type: object\n      properties:\n        something:\n          type: string\n          title: Something\n          default: \"\"\n    next:\n      hash: \"something != ''\"\n\n  hash:\n    name: Hash the something\n    type: automation\n    automation: hash.sha1\n    payload:\n      default: \"playbook.tasks['input'].data['something']\"\n    next:\n      comment: \"hash != ''\"\n\n  comment:\n    name: Comment the hash\n    type: automation\n    automation: comment\n    payload:\n      default: \"playbook.tasks['hash'].data['hash']\"\n    next:\n      done: \"done\"\n\n  done:\n    name: You can close this case now\n    type: task\n"}],"read": ["bob"],"references": [{"href": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=cve-2017-0144","name": "CVE-2017-0144"}],"schema": "{}","status": "open","type": "incident","write": ["alice"]}
    x = requests.post(url+str('tickets'), data=json.dumps(data1), headers=headers, verify=False)
    print(x.json())
    #print(x.headers.get('content-type'))'''

#create_ticket(headers,url)


def list_jobs(headers, url):
    response = requests.get(url+str('jobs'), headers=headers, verify='/home/catalyst/Documents/SSL_Certificates/rootCA.crt')
    return(response.json())
    
def get_single_ticket(headers, ticket_id, url):
    url = url + "tickets/"+str(ticket_id)
    response = requests.get(url, headers=headers, verify='/home/catalyst/Documents/SSL_Certificates/rootCA.crt')
    return(response.json())
    
#print(get_single_ticket(headers, 450755, url))

def get_automations(headers, url):
    response = requests.get(url+str('playbooks'), headers=headers, verify=False)
    return(response.json())
    
#print(get_automations(headers, url))

def run_ticket_playbook_task(headers, url):
    ticket_id = 450755
    playbook_id = 'virus-total-hash-check'
    task_id = 'task'
    x = requests.post(url+str(f'tickets/{ticket_id}/playbooks/{playbook_id}/task/{task_id}/run'), headers=headers, verify='/home/catalyst/Documents/SSL_Certificates/rootCA.crt')
    return x.json()
    
#print(run_ticket_playbook_task(headers, url))

def get_playbook(headers, url, playbook_id):
   response = requests.get(url+str(f'playbooks/{playbook_id}'), headers=headers, verify=False)
   return(response.json())
   
def run_playbook_task():
    response = requests.get(url+str(f'playbooks/{playbook_id}'), headers=headers, verify='/home/catalyst/Documents/SSL_Certificates/rootCA.crt')
    
def generate_ticket_id():
    # Connect to the Redis server
    redis_host = 'localhost'  # Replace with your Redis server's host
    redis_port = 6379
    redis_client = redis.Redis(host=redis_host, port=redis_port, decode_responses=True)
    
 
    id = int(redis_client.get("t_id"))
    print(id)
    next_id = id + 1
    print(next_id)
    redis_client.set("t_id", next_id)
    return id

@app.post('/create_ticket/')
async def create_ticket():
    url = "https://catalystdomain/api/"
    headers = {"Content-Type": "application/json; charset=utf-8", "PRIVATE-TOKEN":"6vIjzG1zryvqX5csISZXAp9ez7nH55f0"}
    r = get_playbook(headers,url,'scan-vulnerability')
    tck_id = generate_ticket_id()
    print(tck_id)
    data1 = {"id": tck_id, "name": "WannyCry","owner": "alice","playbooks": [{"yaml":r['yaml']}],"status": "open","type": "incident"}
    x = requests.post(url+str('tickets'), data=json.dumps(data1), headers=headers, verify=False)
    print("XXXXXXXXX")
    
    #Logging
    time = datetime.utcnow()
    file_path = 'file.log'
    with open(file_path, 'a') as file:
    	file.write(f"Vulnerability ticket created at {time}\n")
    
    #print(x.json())
    
@app.post('/create_ticket_threat/')
async def create_ticket_threat():
    url = "https://catalystdomain/api/"
    headers = {"Content-Type": "application/json; charset=utf-8", "PRIVATE-TOKEN":"6vIjzG1zryvqX5csISZXAp9ez7nH55f0"}
    r = get_playbook(headers,url,'threat-assessment')
    tck_id = generate_ticket_id()
    print(tck_id)
    data1 = {"id": tck_id, "name": "WannyCryA","owner": "alice","playbooks": [{"yaml":r['yaml']}],"status": "open","type": "incident"}
    x = requests.post(url+str('tickets'), data=json.dumps(data1), headers=headers, verify=False)
    print("YYYYYYYYYY")
    
    #Logging
    time = datetime.utcnow()
    file_path = 'file.log'
    with open(file_path, 'a') as file:
    	file.write(f"Threat ticket created at {time}\n")
    
@app.post('/scan_report/')
async def scan_report():
    url = "https://catalystdomain/api/"
    headers = {"Content-Type": "application/json; charset=utf-8", "PRIVATE-TOKEN":"6vIjzG1zryvqX5csISZXAp9ez7nH55f0"}
    
    

#create_ticket()
"""tck_id = 100025
x = requests.post(url+str('tickets')+'/'+str(tck_id)+'/playbooks/scan-vulnerability/task/vuln-scan/run', headers=headers, verify=False)
x = requests.put(url+str('tickets')+'/'+str(tck_id)+'/playbooks/scan-vulnerability/task/vuln-scan/complete', headers=headers, verify=False)
print(x.json())"""

#h = requests.post(url = "https://192.168.13.6:8432/get_host/", headers={'Content-Type': 'application/json'}, verify=False)
#print(h.json())
#data = {"ip_address": h.json()}
#print(data)
##

def calculate_max_threat():#data):
    r = requests.post(url = "https://192.168.13.6:8432/get_report/", verify=False)
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
    products = [float(sev) * float(qod) for sev, qod in zip(sev_array, qod_array)]
    max_product = max(products)
    print(max_product/100)
    r = requests.get(url = "http://192.168.13.6:8080/simpleswitch/change_vlan/" + str(ip_address) + "/20", verify=False)
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

#print("Zezoca")    
#calculate_max_threat()

if __name__ == '__main__':
    uvicorn.run("main:app",
                host="0.0.0.0",
                port=8432,
                reload=True,
                ssl_keyfile="./key.pem", 
                ssl_certfile="./cert.pem"
                )
