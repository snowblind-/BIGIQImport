#!/usr/bin/python
# Written for Python 2.7 on Mac OSX Sierra 10.12.6
# by Brandon Frelich (b.frelich@f5.com)
# This comes with no warranty whatsoever.
#
# Designed to aid in trust establishment, discovery and import of BIG-IP objects in to BIG-IQ
# 
# Steps required in order
# --action start-trust
# --action start-discovery
# --action start-import
#
# Todo:
# Working on pretty output of conflicts
# Bulk operations from list of IP addresses/file
#

import argparse
import requests
import json
import difflib

requests.packages.urllib3.disable_warnings()

parser = argparse.ArgumentParser(description='F5 BIG-IP License Manager Utilities')
parser.add_argument('--bigiq_ip', help='F5 BIG-IQ IP Address', required=True)
parser.add_argument('--bigiq_adm', help='F5 BIG-IQ admin username', required=True)
parser.add_argument('--bigiq_pwd', help='F5 BIG-IQ admin password', required=True)
parser.add_argument('--bigip_ip', help='BIG-IP IP address (license target)', required=False)
parser.add_argument('--bigip_adm', help='BIG-IP admin username (e.g. admin)', required=False)
parser.add_argument('--bigip_pwd', help='BIG-IP admin password', required=False)
parser.add_argument('--bigip_cluster_name', help='BIG-IP cluster name', required=False)
parser.add_argument('--filename', help='File with BIGIPs to import', required=False)
parser.add_argument('--action', help='F5 license manager actions (dump-hosts, get-status, get-trust, check-trust', required=True)

headers = {
     'Content-Type': 'application/json'
}

####################################
# Function: Generate X-F5-Auth-Token
####################################
def bigiq_authtoken (ip,username,password):
	url = 'https://'+ip+'/mgmt/shared/authn/login'
	payload = {
		'username': username,
		'password': password
	}
	resp = requests.post(url,headers=headers, data=json.dumps(payload), verify=False)
	json_data =  json.loads(resp.text)
	#print(json.dumps(resp.json(), indent=2))
	#print json_data['token']['token']
	return json_data['token']['token'];

###############################################
# Function: Dump BIG-IQ Known Hosts
###############################################
def biqdump_hosts(auth_token,ip):
	url = 'https://'+ip+'/mgmt/cm/system/machineid-resolver'
	i = 0
	headers = {
     'Content-Type': 'application/json',
     'X-F5-Auth-Token': auth_token
	}
	resp = requests.get(url, headers=headers, verify=False)
	json_data = json.loads(resp.text)
	for uuid in json_data['items']:
		if len(json_data['items']) > 0:
			print '{:35s} {:35s} {:20s} {:35}'.format(json_data['items'][i]['hostname'], json_data['items'][i]['uuid'], json_data['items'][i]['managementAddress'],json_data['items'][i]['state'])
			i += 1
	return;

###############################################
# Function: Determine Trust Status
###############################################
def determine_management_status(auth_token,ip,bip_ip):
	url = 'https://'+ip+'/mgmt/cm/system/machineid-resolver?$filter=(%27address%27+eq+%27'+bip_ip+'%27)'
	#url = 'https://'+ip+'/mgmt/cm/system/machineid-resolver?%24filter=%28%27address%27%2Beq%2B%27+bip_ip+%27%29'
	#https://{{bigiq_mgmt}}/mgmt/cm/system/machineid-resolver?$filter=('address'+eq+'10.192.87.187')
	headers = {
     'Content-Type': 'application/json',
     'X-F5-Auth-Token': auth_token
	}
	resp = requests.get(url, headers=headers, verify=False)
	json_data = json.loads(resp.text)
	uuid = json_data['items'][0]['uuid']
	#print(json.dumps(resp.json(), indent=2))
	#print '{:35}'.format(json_data['items'][0]['uuid'])
	#return;
	return uuid;

###############################################
# Function: Not sure what this was???? Looks like check trust progress
###############################################
def determine_trust_status(auth_token,ip,uuid):
	url = 'https://'+ip+'/mgmt/cm/global/tasks/device-trust/'+uuid+'?$select=address,status,currentStep'
	#https://{{bigiq_mgmt}}/mgmt/cm/global/tasks/device-trust/725e3918-60f8-4854-a1c1-bb388e9de7a1?$select=address,status,currentStep
	headers = {
     'Content-Type': 'application/json',
     'X-F5-Auth-Token': auth_token
	}
	resp = requests.get(url, headers=headers, verify=False)
	json_data = json.loads(resp.text)
	print(json.dumps(resp.json(), indent=2))
	return;

###############################################
# Function: Initiate Trust (start-trust) $$$ NEED TO ADD ARGS FOR BIGIP ADMIN/PWD
###############################################
#POST: https://<mgmtip>/mgmt/cm/gloal/tasks/device-trust
def initiate_trust(auth_token,ip,bip_ip,bip_cluster,bip_adm,bip_pwd):
	url = 'https://'+ip+'/mgmt/cm/global/tasks/device-trust/'
	headers = {
     'Content-Type': 'application/json',
     'X-F5-Auth-Token': auth_token
	}
	payload = {
		"address": bip_ip,
    	"clusterName": bip_cluster,
    	"password": bip_pwd,
    	"useBigiqSync": "true",
    	"userName": bip_adm
	}
	resp = requests.post(url,headers=headers, data=json.dumps(payload), verify=False)
	json_data = json.loads(resp.text)
	print(json.dumps(resp.json(), indent=2))
	#selfLink is used for polling status.
	#selfLink = json_data['items'][0]['selfLink']
	return;

###############################################
# Function: Check Trust Status
###############################################
#GET: https://localhost/mgmt/cm/global/tasks/device-trust/a27f6fd7-d0cc-4f2a-892b-cb859b182cdb?$select=address,status,currentStep
# TODO need to determine how I want to handle monitoring status and passing selfLink back to monitoring process

def check_trust(auth_token,ip,bigip_ip,uuid):
	url = 'https://'+ip+'/mgmt/cm/global/tasks/device-trust/'+uuid+'?%24select=address,status,currentStep'
	headers = {
     'Content-Type': 'application/json',
     'X-F5-Auth-Token': auth_token
	}

	resp = requests.get(url,headers=headers, verify=False)
	json_data = json.loads(resp.text)
	print(json.dumps(resp.json(), indent=2))
	return;

###############################################
# Function: Start Discovery 
###############################################
#https://{{bigiq_mgmt}}/mgmt/cm/global/tasks/device-discovery
def start_discovery(auth_token,ip,bigip_ip,uuid):
	url = 'https://'+ip+'/mgmt/cm/global/tasks/device-discovery'
	headers = {
     'Content-Type': 'application/json',
     'X-F5-Auth-Token': auth_token
	}
	payload = {
    "deviceReference": {
        "link": "https://localhost/mgmt/cm/system/machineid-resolver/"+uuid
    },
    "moduleList": [
        {
            "module": "adc_core"
        }
    ],
    "status": "STARTED"
	}
	resp = requests.post(url,headers=headers, data=json.dumps(payload), verify=False)
	json_data = json.loads(resp.text)
	print(json.dumps(resp.json(), indent=2))
	return;

###############################################
# Function: Check Discovery Status ---Validate Later Can Use get-status and view
###############################################
# https://{{bigiq_mgmt}}/mgmt/cm/global/tasks/device-discovery?$filter=deviceReference/link+eq+'*2d68e323-8185-4736-abca-2626cb040552'
def check_discovery(auth_token,ip,bigip_ip,uuid):
	url = 'https://'+ip+'/mgmt/cm/global/tasks/device-trust/'+uuid
	#https://{{bigiq_mgmt}}/mgmt/cm/global/tasks/device-trust/725e3918-60f8-4854-a1c1-bb388e9de7a1?$select=address,status,currentStep
	headers = {
     'Content-Type': 'application/json',
     'X-F5-Auth-Token': auth_token
	}
	resp = requests.get(url,headers=headers, verify=False)
	json_data = json.loads(resp.text)
	print(json.dumps(resp.json(), indent=2))
	return;

###############################################
# Function: Start LTM Import 
###############################################
#https://{{bigiq_mgmt}}/mgmt/cm/global/tasks/device-discovery
#'https://'+ip+'/mgmt/cm/global/tasks/device-import'
def start_ltm_import(auth_token,ip,uuid,bip_cluster):
	url = 'https://'+ip+'/mgmt/cm/adc-core/tasks/declare-mgmt-authority'
	headers = {
     'Content-Type': 'application/json',
     'X-F5-Auth-Token': auth_token
	}
	payload = {
	"clusterName": bip_cluster,
	"createChildTasks": "false",
	"deviceReference": {
		"link": "https://localhost/mgmt/cm/system/machineid-resolver/"+uuid
	},
	"skipDiscovery": "true",
	"snapshotWorkingConfig": "true",
	"useBigiqSync": "true"
	}
	resp = requests.post(url,headers=headers, data=json.dumps(payload), verify=False)
	json_data = json.loads(resp.text)
	selfLink = json_data['selfLink']
	print(json.dumps(resp.json(), indent=2))
	check_ltm_import(auth_token,ip,selfLink)
	return;

###############################################
# Function: Get LTM Import Status
###############################################
#uuid=task ID (WILL LIKELY NEED TO CANCEL IMPORT PROCESS ONCE STUCK SINCE IT SEEMS TO LOCK THE CONFIGURATION DATABASE)
#GET: mgmt/cm/adc-core/tasks/declare-mgmt-authority/820399be-aa4d-4521-b184-44eebcb3e1d0
def check_ltm_import(auth_token,ip,selfLink):
	importStatus = "STARTED"
	exit = 0
	url = selfLink
	url = url.replace("localhost",ip)
	#print(url)
	headers = {
     'Content-Type': 'application/json',
     'X-F5-Auth-Token': auth_token
	}

	while importStatus <> "FINISHED":
		resp = requests.get(url,headers=headers, verify=False)
		json_data = json.loads(resp.text)
		#print(json.dumps(resp.json(), indent=2))
		importStatus = json_data['status']
		importStep = json_data['currentStep']
		print(importStatus, " : ", importStep)
		i = 0

		if (importStep == "PENDING_CONFLICTS" and importStatus == "FINISHED"):
			#print(json.dumps(resp.json(), indent=2))
			for toReference in json_data['conflicts']:
			###	#print(json_data['conflicts'][i]['toReference']['link'])
			###	#print(json_data['conflicts'][i]['fromReference']['link'])
				toReferenceSelfLink = json_data['conflicts'][i]['toReference']['link']
				fromReferenceSelfLink = json_data['conflicts'][i]['fromReference']['link']
				printConflicts(auth_token,ip,toReferenceSelfLink, fromReferenceSelfLink)
				i = i + 1
				#print(toReferenceSelfLink, "         ", fromReferenceSelfLink)
			#cancelPayload = {
			#	"status": "CANCELED"
			#}
			cancelPayload = {
				"status": "CANCEL_REQUESTED"
			}
			cancelResp = requests.patch(url,headers=headers, data=json.dumps(cancelPayload), verify=False)
			print(json.dumps(cancelResp.json(), indent=2))
	return;
	#return(importStatus,importStep);
#			print(json.dumps(resp.json(), indent=2))
#			exit == 1
#		elif status == "CREATE_SNAPSHOT":
#			print(json.dumps(resp.json(), indent=2))

	#resp = requests.get(url,headers=headers, verify=False)
	#json_data = json.loads(resp.text)
	#print(json.dumps(resp.json(), indent=2))
	#return;
# JUST A NOTE ON WHAT WAS RETURNED
 #       {
 #           "fromReference": {
 #               "link": "https://localhost/mgmt/cm/adc-core/working-config/ltm/profile/client-ssl/c8be104f-0858-3135-a00d-59169bc16969"
 #           },
 #           "toReference": {
 #               "link": "https://localhost/mgmt/cm/adc-core/current-config/ltm/profile/client-ssl/ce34ded8-a033-3833-9b95-f9b00a268b05"
 #           },
 #           "resolution": "NONE"
 #       }

def printConflicts(auth_token,ip,toReferenceSelfLink, fromReferenceSelfLink):
	urlToReference = toReferenceSelfLink.replace("localhost",ip)
	urlFromReference = fromReferenceSelfLink.replace("localhost",ip)

	headers = {
     'Content-Type': 'application/json',
     'X-F5-Auth-Token': auth_token
	}

	respTo = requests.get(urlToReference,headers=headers, verify=False)
	jsonTo = json.loads(respTo.text)
	respFrom = requests.get(urlFromReference,headers=headers, verify=False)
	jsonFrom = json.loads(respFrom.text)

	#print("***************************************************************")
	#print("****", jsonTo['name'])
	#print("***************************************************************")
	# create output file names to be used in difflib -> Html
	bigipFilename = jsonTo['name']+'fromBIGIP.txt'
	bigiqFilename = jsonTo['name']+'fromBIGIQ.txt'

	#print(json.dumps(respTo.json(), indent=2))
	#fromBIGIP = json.dumps(respTo.json())
	with open(bigipFilename, "w") as outfile:
		json.dump(respTo.json(), outfile, indent=4)
	#with open(bigipFilename, 'w', newline="\r\n") as outfile:
	#	json.dump(data, outfile, indent=4, sort_keys=True, ensure_ascii=False)
	#f = io.open(bigipFilename, 'w', newline="\r\n")
	#f.write(json.dumps(respTo.json()), bigipFilename, indent=4, sort_keys=True, ensure_ascii=False)
	#f.close()
	
	#print(fromBIGIP)
	#print("***************************************************************")
	#print(json.dumps(respFrom.json(), indent=4))
	with open(bigiqFilename, "w") as outfile:
		json.dump(respFrom.json(), outfile, indent=4)
	#with open(bigiqFilename, 'w') as outfile:
	#	json.dumps(respFrom.json(), outfile)
	genDiffReport(bigiqFilename, bigipFilename, jsonTo['name'])

def genDiffReport(firstFile, secondFile, objName):
	firstFileLines = open(firstFile).readlines()
	secondFileLines = open(secondFile).readlines()
	difference = difflib.HtmlDiff().make_file(firstFileLines, secondFileLines, firstFile, secondFile)
	#difference_report = open(objName + 'BIGIQimport.html','a')
	difference_report = open('BIGIQimport.html','a')
	difference_report.write(difference)

################## Begin ARGS parsing ##########################

args = vars(parser.parse_args())

if args['action'] == 'dump-hosts':
	biq_ip = args['bigiq_ip']
	biq_adm = args['bigiq_adm']
	biq_pwd = args['bigiq_pwd']

	auth_token = bigiq_authtoken(biq_ip,biq_adm,biq_pwd)
	biqdump_hosts(auth_token,biq_ip)

if args['action'] == 'get-status':
	biq_ip = args['bigiq_ip']
	biq_adm = args['bigiq_adm']
	biq_pwd = args['bigiq_pwd']
	bip_ip = args['bigip_ip']

	auth_token = bigiq_authtoken(biq_ip,biq_adm,biq_pwd)
	determine_management_status(auth_token,biq_ip,bip_ip)

#### Not working at the moment needing selfLink
if args['action'] == 'get-trust':
	biq_ip = args['bigiq_ip']
	biq_adm = args['bigiq_adm']
	biq_pwd = args['bigiq_pwd']
	bip_ip = args['bigip_ip']

	auth_token = bigiq_authtoken(biq_ip,biq_adm,biq_pwd)
	uuid = determine_management_status(auth_token,biq_ip,bip_ip)
	determine_trust_status(auth_token,biq_ip,uuid)

### Working
if args['action'] == 'start-trust':
	biq_ip = args['bigiq_ip']
	biq_adm = args['bigiq_adm']
	biq_pwd = args['bigiq_pwd']
	bip_ip = args['bigip_ip']
	bip_adm = args['bigip_adm']
	bip_pwd = args['bigip_pwd']
	bip_cluster = args['bigip_cluster_name']

	auth_token = bigiq_authtoken(biq_ip,biq_adm,biq_pwd)

	if args['filename']:
		file = args['filename']
		with open(file, "r") as filestream:
			for line in filestream:
				currentline = line.split(",")
				bip_ip = str(currentline[0])
				print(bip_ip)
				bip_cluster = str(currentline[1])
				bip_cluster = bip_cluster.strip('\n')
				print(bip_cluster)
				initiate_trust(auth_token,biq_ip,bip_ip,bip_cluster,bip_adm,bip_pwd)
	else:
		initiate_trust(auth_token,biq_ip,bip_ip,bip_cluster,bip_adm,bip_pwd)

if args['action'] == 'check-trust':
	biq_ip = args['bigiq_ip']
	biq_adm = args['bigiq_adm']
	biq_pwd = args['bigiq_pwd']
	bip_ip = args['bigip_ip']

	auth_token = bigiq_authtoken(biq_ip,biq_adm,biq_pwd)
	uuid = determine_management_status(auth_token,biq_ip,bip_ip)
	check_trust(auth_token,biq_ip,bip_ip,uuid)

### Working
if args['action'] == 'start-discovery':
	biq_ip = args['bigiq_ip']
	biq_adm = args['bigiq_adm']
	biq_pwd = args['bigiq_pwd']
	bip_ip = args['bigip_ip']

	auth_token = bigiq_authtoken(biq_ip,biq_adm,biq_pwd)
	uuid = determine_management_status(auth_token,biq_ip,bip_ip)
	start_discovery(auth_token,biq_ip,bip_ip,uuid)

if args['action'] == 'start-ltm-import':
	biq_ip = args['bigiq_ip']
	biq_adm = args['bigiq_adm']
	biq_pwd = args['bigiq_pwd']
	bip_ip = args['bigip_ip']
	bip_cluster = args['bigip_cluster_name']

	auth_token = bigiq_authtoken(biq_ip,biq_adm,biq_pwd)
	uuid = determine_management_status(auth_token,biq_ip,bip_ip)
	start_ltm_import(auth_token,biq_ip,uuid,bip_cluster)

if args['action'] == 'check-ltm-import':
	biq_ip = args['bigiq_ip']
	biq_adm = args['bigiq_adm']
	biq_pwd = args['bigiq_pwd']
	bip_ip = args['bigip_ip']

	auth_token = bigiq_authtoken(biq_ip,biq_adm,biq_pwd)
	uuid = determine_management_status(auth_token,biq_ip,bip_ip)
	check_ltm_import(auth_token,biq_ip,uuid)

# Does trust establishment, device discovery, and import all in one 
if args['action'] == 'do-all-ltm-import':
	biq_ip = args['bigiq_ip']
	biq_adm = args['bigiq_adm']
	biq_pwd = args['bigiq_pwd']
	bip_ip = args['bigip_ip']
	bip_adm = args['bigip_adm']
	bip_pwd = args['bigip_pwd']
	bip_cluster = args['bigip_cluster_name']

	auth_token = bigiq_authtoken(biq_ip,biq_adm,biq_pwd)
	initiate_trust(auth_token,biq_ip,bip_ip,bip_cluster,bip_adm,bip_pwd)
	uuid = determine_management_status(auth_token,biq_ip,bip_ip)
	start_discovery(auth_token,biq_ip,bip_ip,uuid)
	start_ltm_import(auth_token,biq_ip,uuid,bip_cluster)

###################################################################
