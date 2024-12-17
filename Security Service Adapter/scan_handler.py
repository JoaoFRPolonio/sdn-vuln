import subprocess
from subprocess import Popen, PIPE

import ast
from xml.dom import minidom
import time

import parsing_xml
import json
import xmltodict

def request_tasks(alive_hosts_str):
	print(alive_hosts_str)
	ip = alive_hosts_str
	report_id_dict = {}
	
	try:
		output = subprocess.check_output(['sh', './scan_host.sh', ip], stderr=subprocess.STDOUT)
		report_id = extract_report_id(output)
		report_id_dict[ip] = report_id
	except subprocess.CalledProcessError as e:
		raise RuntimeError("command '{}' return with error (code {}): {}".format(e.cmd, e.returncode, e.output))
	return report_id_dict
	
def extract_report_id(s):
	start_index = s.find(b"report ID is ") + len(b"report ID is ")

	# Find the position of the newline character after the report ID
	end_index = s.find(b"\n", start_index)

	# Extract the report ID value using slicing
	report_id = s[start_index:end_index].decode()
	print(report_id)
	return report_id
	
def get_report(report_id):
	try:
		output = subprocess.check_output(['sh', './get_report.sh', report_id], stderr=subprocess.STDOUT)
	except subprocess.CalledProcessError as e:
		raise RuntimeError("command '{}' return with error (code {}): {}".format(e.cmd, e.returncode, e.output))
	##Client will have to remove quotation marks and \n at the end of the file
	return output

def check_scan_status(ip_to_id):
	report_ids = list(ip_to_id.values())
	status_lst = []
	for report_id in report_ids:
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
		status = models[0].firstChild.data
		status_lst.append(status)
	return status_lst

def poll_scan_status(ip_to_id):
	while True:
    		results = check_scan_status(ip_to_id)  # Call the function
    		if all(status == "Done" for status in results):
    			print(results)
    			print("All results are done!")  # Output: All results are done!
    			break
    		else:
    			print(results)
    		time.sleep(120)  # Wait for 120 seconds before checking again
	return results

def weight_fair_queuing(values, weights):
    # convert the weight array to integers
    weights = list(map(int, weights))

    # calculate the total weight
    total_weight = sum(weights)

    # calculate the weight for each value
    value_weights = [weight / total_weight for weight in weights]

    # create a list of (value, weight) tuples
    pairs = list(zip(values, value_weights))

    # sort the pairs by weight in descending order
    pairs.sort(key=lambda x: x[1], reverse=True)

    # initialize the cumulative weight and result array
    cum_weight = 0
    result = []

    # iterate over the pairs and add the corresponding number of values to the result array
    for value, weight in pairs:
        num_values = int(len(values) * weight)
        result.extend([value] * num_values)
        cum_weight += weight

        # handle rounding errors by adding any remaining values to the result array
        if cum_weight >= 1.0:
            break
    return result
 


'''def calculate_host_score(report_id):
	# Parsing XML
	score_array, qod_array = parsing_xml.vuln_score_to_qod(report_id)
	print(score_array)
	print(qod_array)
	score = [float(score_array[i]) * float(qod_array[i]) / 100 for i in range(len(score_array))]
	print(max(score))
	return max(score)'''
	
'''def calculate_net_score(host_scores):
	net_score = max(host_scores)
	return net_score'''
	


'''def calculate_threat_score(ip_to_id):
	report_ids = list(ip_to_id.values())
	host_scores = []
	for host in report_ids:
		host_scores.append(calculate_host_score(host))
	net_score = calculate_net_score(host_scores)
	return net_score'''

def parsing_host(report_id):
	# Parsing XML
	score_array, qod_array = parsing_xml.vuln_score_to_qod(report_id)
	print(score_array)
	print(qod_array)
	return score_array, qod_array	

'''def retrieve_threat_info(ip_to_id):
	report_ids = list(ip_to_id.values())
	host_nvt_scores = []
	host_nvt_qods = []
	hosts = []
	host = 0
	for report_id in report_ids:
		score_array, qod_array = parsing_host(report_id)
		ip = parsing_xml.get_report_ip(report_id)
		#host_nvt_scores.append(score_array)
		#host_nvt_qods.append(qod_array)
		host = {
		    "ip": ip,
		    "address": {
		        "cvss": score_array,
		        "qod": qod_array
		    }
		}
		hosts.append(host)
	return hosts'''
	
def retrieve_threat_info(report_id):
    data = xml_to_json(report_id)

    return data
    
def xml_to_json(report_id):
	xml_file=open('/home/kali/Documents/API_dev/XML_Reports/' + report_id + '.xml',"r")
	xml_string=xml_file.read()
	python_dict=xmltodict.parse(xml_string)
	json_string=json.dumps(python_dict)
	return json_string	
		
'''def create_json_info():
    hosts = [
        {
            "ip": "192.168.233.132",
            "address": {
                "cvss": ["10.0","8.1","5.0","2.6","2.1"],
                "qod": ["80","95","80","80","80"]
            }
        },
        {
            "ip": "192.168.233.133",
            "address": {
                "cvss": ["7.5","4.3","2.1","1.0","0.5"],
                "qod": ["70","85","70","70","70"]
            }
        },
        {
            "ip": "192.168.233.134",
            "address": {
                "cvss": ["9.0","6.2","4.0","2.0","1.5"],
                "qod": ["75","90","75","75","75"]
            }
        }
    ]
    json_data = json.dumps(hosts)
    return json_data'''
