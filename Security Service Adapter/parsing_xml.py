import xml.etree.ElementTree as ET
import xmltodict
import json
    
def vuln_score_to_qod(report_id):

	score_array = []
	qod_array = []
	count_vts = 0
	
	tree = ET.parse('/home/kali/Documents/API_dev/XML_Reports/' + report_id + '.xml')
	root = tree.getroot()
	
	for vuln in root.findall('.//result'):
		name = vuln.find('name')
		severity_vuln = vuln.find('severity')
		qod = vuln.find('.//qod')

		if (severity_vuln and name and qod) is not None:
			severity_vuln_text = severity_vuln.text
			name_text = name.text
			qod_text = qod.find('value').text
		else:
			severity_text = ""
			name_text = ""
			qod = ""
		if(name_text != ""):
			count_vts = count_vts + 1
			print(f"{name_text} - {severity_vuln_text} - {qod_text}")
			score_array.append(severity_vuln_text)
			qod_array.append(qod_text)	   
	return score_array, qod_array 

def get_report_ip(report_id):
	tree = ET.parse('/home/kali/Documents/API_dev/XML_Reports/' + report_id + '.xml')
	root = tree.getroot()
	
	task_elem = root.find('.//task')
	ip = task_elem.find('name').text.split()[-1]
	
	return ip
