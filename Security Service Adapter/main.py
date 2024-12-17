from fastapi import Depends, FastAPI
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
import uvicorn
import subprocess
from subprocess import Popen, PIPE

from xml.dom import minidom

import os 
import scan_handler

from pydantic import BaseModel
from typing import Union

import redis
from datetime import datetime, timedelta
from RedisQueue import RedisQueue
import json


class Vuln_Scan_Req(BaseModel):
    ip_address: str
    
class Detected_Host(BaseModel):
    host: str

class Host(BaseModel):
    host: str




app = FastAPI()

disc_hosts = RedisQueue('disc_hosts')
reports_queue = RedisQueue('reports_queue')

'''#Security
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

@app.post('/token')
async def token_generate(form_data: OAuth2PasswordRequestForm = Depends()):
	print(form_data)
	return {"access_token": form_data.username, "token_type": "bearer"}'''

@app.get('/')
def hello():#token: str = Depends(oauth2_scheme)):
	#print(token)
	return { 
		"Response" : "Hello"
	}

#Registar/procurar o host na base de dados
@app.post('/host_status/')
def host_status(host_given: Host):
	
	# Connect to the Redis server
	redis_host = 'localhost'  # Replace with your Redis server's host
	redis_port = 6379
	redis_client = redis.Redis(host=redis_host, port=redis_port, decode_responses=True)
	
	# Set the key-value pair in Redis
	time = datetime.utcnow()
	key = host_given.host
	disc_hosts.put(key)
	print(time)
	# Retrieve and print the value using the key
	redis_client.set(key, time.isoformat())
	if redis_client.exists(key):
    	# Key exists, retrieve and print its value
    		stored_value = redis_client.get(key)
    		if datetime.fromisoformat(stored_value) < time:
    			time_plus_15mins = time + timedelta(minutes=1)
    			time_plus_15mins_str = time_plus_15mins.isoformat()
    			redis_client.set(key, time_plus_15mins_str)
    		stored_value = redis_client.get(key)
    		print(stored_value)
    			
	else:
    	# Key doesn't exist, set the key-value pair in Redis
    		redis_client.set(key, time.isoformat())
    		stored_value = time
	
	#redis_client.set(key, 1)
	#stored_value = redis_client.get(key)
	#print(stored_value)
	
	# Add 15 minutes to the current datetime
	#time_plus_15mins = time + timedelta(minutes=5)
	#time_plus_15mins_str = time_plus_15mins.isoformat()
	#redis_client.set(key, time_plus_15mins_str)
	redis_client.close()
	
	#Logging
	file_path = '/home/kali/Documents/API_dev/logs/file.log'
	with open(file_path, 'a') as file:
    		# Write content to the file
    		file.write(f"{key} registered as discovered at {time}\n")
	
	return stored_value

@app.post('/host_queue/')
def host_queue(host_given: Host):
	
	# Connect to the Redis server
	redis_host = 'localhost'  # Replace with your Redis server's host
	redis_port = 6379
	redis_client = redis.Redis(host=redis_host, port=redis_port, decode_responses=True)
	
	# Set the key-value pair in Redis
	time = datetime.now()
	key = host_given.host
	disc_hosts.put(key)
	
	#print("Colocado" + key)
	#print("Retirado" + disc_hosts.get().decode('utf-8'))
	redis_client.close()
	
	return "Success"

@app.post('/get_host/')
def get_host():
	
	# Connect to the Redis server
	redis_host = 'localhost' 
	redis_port = 6379
	redis_client = redis.Redis(host=redis_host, port=redis_port, decode_responses=True)
	
	# Set the key-value pair in Redis
	time = datetime.now()
	#key = host_given.host
	
	
	#Logging
	'''file_path = '/home/kali/Documents/API_dev/logs/file.log'
	with open(file_path, 'w') as file:
    		# Write content to the file
    		file.write("{key} registered at {time}\n")'''
    	
	#key='192.168.13.99'
	#disc_hosts.put(key)
	
	
	byte_string = disc_hosts.get()
	redis_client.close()
	
	regular_string = byte_string.decode('utf-8')
	
	return regular_string

@app.post('/scan_new_target/')
def scan_new_target(target: Vuln_Scan_Req):
	target_ip = target.ip_address
	print("Request to scan the target with the IP address: " + target_ip)
	ip_to_report_dict = scan_handler.request_tasks(target_ip)
	print(scan_handler.check_scan_status(ip_to_report_dict))	
	scan_status = scan_handler.poll_scan_status(ip_to_report_dict)
	output = scan_handler.retrieve_threat_info(ip_to_report_dict)
	print(output)
	
	# Connect to the Redis server
	redis_host = 'localhost' 
	redis_port = 6379
	redis_client = redis.Redis(host=redis_host, port=redis_port, decode_responses=True)
	reports_queue.put(output)
	
	redis_client.close()
	return output
	
@app.post('/get_report/')
def get_report():
	# Connect to the Redis server
	redis_host = 'localhost' 
	redis_port = 6379
	redis_client = redis.Redis(host=redis_host, port=redis_port, decode_responses=True)
	
	byte_string = reports_queue.get()
	regular_string = byte_string.decode('utf-8')
	
	redis_client.close()
	#print(regular_string)
	#obj = json.loads(scan_handler.retrieve_threat_info(''))
	obj = json.loads(regular_string)
	print(type(obj))
	report = obj['get_reports_response']['report']['report']['results']
	print(report)
	
	time = datetime.utcnow()
	#Logging
	file_path = '/home/kali/Documents/API_dev/logs/file.log'
	with open(file_path, 'a') as file:
    		# Write content to the file
    		file.write(f"Host registered as discovered at {time}\n")
	
	return report
	
	#return regular_string
	
'''@app.get('/scan_run_status/')
def is_report_ready(report: Vuln_Report):
	report_id = report.id
	try:
		output = subprocess.check_output(['sh', './get_report.sh', report_id], stderr=subprocess.STDOUT)
	except subprocess.CalledProcessError as e:
		raise RuntimeError("command '{}' return with error (code {}): {}".format(e.cmd, e.returncode, e.output))
	xml_output = output.decode('utf-8')
	f = open('/home/kali/Documents/API_dev/XML_Reports/' + report_id + '.xml', "w")
	f.write(xml_output)
	f.close()
	
	#Read
	file = minidom.parse('/home/kali/Documents/API_dev/XML_Reports/' + report_id + '.xml')
	#use getElementsByTagName() to get tag
	models = file.getElementsByTagName('scan_run_status')
	return models[0].firstChild.data'''


'''@app.get('/get_report/')
def is_cert_ready(report: Vuln_Report):
	report_id = report.id
	try:
		output = subprocess.check_output(['sh', './get_report.sh', report_id], stderr=subprocess.STDOUT)
	except subprocess.CalledProcessError as e:
		raise RuntimeError("command '{}' return with error (code {}): {}".format(e.cmd, e.returncode, e.output))
	##Client will have to remove quotation marks and \n at the end of the file
	return output'''

'''@app.get('/scan_range/{ip_range}')
def scan_range(ip_range: str):
        print("Request to scan the IP range: " + ip_range)
        try:
                output = nmap_scan.alive_hosts(ip_range) 
        except subprocess.CalledProcessError as e:
                raise RuntimeError("command '{}' return with error (code {}): {}".format(e.cmd, e.returncode, e.output))
        return output'''
	
if __name__ == '__main__':
    os.system('sudo /home/kali/Documents/API_dev/start_gvm.sh')
    os.system('sudo /home/kali/Documents/API_dev/change_socket_permissions.sh')
    uvicorn.run("main:app",
                host="0.0.0.0",
                port=8432,
                reload=True,
                ssl_keyfile="./key.pem", 
                ssl_certfile="./cert.pem"
                )
   
