from fastapi import Depends, FastAPI
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
import uvicorn
import subprocess
from subprocess import Popen, PIPE

from xml.dom import minidom

import os 
import nmap_scan
import time

app = FastAPI()

@app.get('/')
def hello():
	return { 
		"Response" : "Hello"
	}

@app.get('/scan_range/{ip_range}')
def scan_range(ip_range: str):
	print("Request to scan the IP range: " + ip_range)
	try:
                start_time = time.time()
                output = nmap_scan.alive_hosts(ip_range)
                end_time = time.time()
                exec_time = end_time - start_time
                print(f"Execution time: {exec_time:.6f} seconds") 
	except subprocess.CalledProcessError as e:
		raise RuntimeError("command '{}' return with error (code {}): {}".format(e.cmd, e.returncode, e.output))
	return output

if __name__ == '__main__':
        uvicorn.run("main:app",
                host="0.0.0.0",
                port=8432,
                reload=True,
                ssl_keyfile="./key.pem", 
                ssl_certfile="./cert.pem"
                )

