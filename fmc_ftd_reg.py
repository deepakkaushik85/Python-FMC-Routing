import paramiko
import time
import re
import json
import sys
import requests
import time
import yaml
import argparse
import logging
from functools import wraps
from requests.packages.urllib3.exceptions import InsecureRequestWarning


requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

#####################Function to Generate Token##########
def generate_token():
    global headers, domainUUID, auth_token
    headers = {'Content-Type': 'application/json'}
    api_auth_path = "/api/fmc_platform/v1/auth/generatetoken"
    auth_url = server + api_auth_path
#    print("Auth url is {}".format(auth_url))

    try:
        r = requests.post(auth_url, headers=headers, auth=requests.auth.HTTPBasicAuth(username,password), verify=False)
        auth_headers = r.headers
#        print("Header output is {}".format(auth_headers))
        auth_token = auth_headers.get('X-auth-access-token', default=None)
        domainUUID = auth_headers.get('DOMAIN_UUID', default = None)
#        print("Domain ID is {}".format(domainUUID))
        if auth_token== None:
            print("Authentication Token not found. Exiting....")
            return 0
        else:
            print("Authentication token is {}".format(auth_token))
            headers['X-auth-access-token'] = auth_token
            print(headers)
            return auth_token
    except Exception as err:
        print("Error in generating auth token-->" + str(err))
        return 0

def api_ops(op_type, url, payload=None):
    global headers
    global auth_token
    headers = {'Content-Type': 'application/json', 'x-auth-access-token': auth_token}
    retries = 3
    url = server + url
    print("URL is {}".format(url))

    if (url[-1] == '/'):
        url = url[:-1]
    while retries:
 #       print("url is: ", url)
 #       print("Payload is: ", payload)
 #       print("Headers: ", headers)
        operation = op_type.lower()
        if operation == 'put':
            resp = requests.put(url, data=json.dumps(payload), headers=headers, verify=False)
        elif operation == 'get':
            resp = requests.get(url, data=payload, headers=headers, verify=False)
        elif operation == 'post':
            resp = requests.post(url, data=json.dumps(payload), headers=headers, verify=False)
        else:
            print('Unknown operation type' + operation)
            sys.exit(1)
        if resp.status_code == 200 or resp.status_code == 201:
            print(operation, " API call Success!!!")
            return json.loads(resp.text)
        elif resp.status_code == 429:
            print("The maximum limit of 120 API calls per minute has been exceeded. Retrying in 60 seconds ... ")
            time.sleep(63)
        elif resp.status_code == 401:
            print("Token expired, Generate new token")
            auth_token = generate_token()
            print(auth_token)
            continue
            if auth_token:
                headers['X-auth-access-token'] = auth_token
                return auth_token
            else:
                print("Failed to generate token, Abort")
        else:
            print("PUT Failed, Error --> ", resp.text)
            return resp.text
        retries = retries - 1
        assert (False)

########################################
######Function to ssh device############
########################################
class ssh:
	def __init__(self,dev_name,ip,port,uname,pwd):
		self.dev_name=dev_name
		self.ip=ip
		self.port=port
		self.uname=uname
		self.pwd=pwd

	def ssh_device(self):
		host_pre = self.dev_name
		host_pre = paramiko.SSHClient()
		host_pre.set_missing_host_key_policy(paramiko.AutoAddPolicy())
		print("++++++++")
		try:
			host_pre.connect(self.ip, self.port, username=self.uname, password=self.pwd,look_for_keys=False, allow_agent=False)
			print("+++++++++")
			print("SSH connection established to {}".format(self.dev_name))
			host = host_pre.invoke_shell()
			return host
		except TimeoutError:
			print("Connection timed out")


#############################################
###Fn to configure FMC Manager###############
#############################################


def access_policy_default_blk(name):
	url = '/api/fmc_config/v1/domain/{}/policy/accesspolicies'.format(domainUUID)
	payload = {
			  "type": "AccessPolicy",
			  "name": name,
			  "defaultAction": {
			    "action": "BLOCK"
			  }
			}
	response = api_ops('post', url, payload)
	print(response)
	response_json = json.loads(response)
	if 'duplicate' or 'Duplicate' in response_json['error']['messages'][0]['description']:
		print("Access-policy already exists")
class fmc_ftd_reg:
	def __init__(self,dev_name,device_ip,key,access_policy,mgr,device_handle):
		self.dev_name = dev_name
		self.device_ip = device_ip
		self.key = key
		self.access_policy = access_policy
		self.mgr = mgr
		self.device_handle = device_handle

	def config_mgr(self):
		self.device_handle.send("show managers\n")
		time.sleep(5)
		mgr_output=self.device_handle.recv(5000).decode("utf-8")
		list_ip = re.findall('[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+',mgr_output)
		print("Duplicate list of IPs : {}".format(list_ip))
		mgrs_ip = []
		for i in range(0,len(list_ip)):
			if list_ip[i] in mgrs_ip:
				continue
			else:
				mgrs_ip.append(list_ip[i])
		print("Actual Managers configured are : {}".format(mgrs_ip))
		if not mgrs_ip:
			self.device_handle.send("\n")
			self.device_handle.send("configure manager add {} cisco123\n".format(self.mgr))
			time.sleep(40)
			output1 = self.device_handle.recv(5000).decode("utf-8")
			self.device_handle.send("\n")
			print("The output is {}".format(output1))
			if 'successfully' in output1:
			    print("Manager is added Successfully")
		else:
			if self.mgr in mgrs_ip:
				for i in range(0,len(mgrs_ip)):
					if self.mgr == mgrs_ip[i]:
						print("Manager is already configured")
						continue
					else:
						self.device_handle.send("configure manager delete {}\n".format(mgrs_ip[i]))
						time.sleep(5)
						output1 = self.device_handle.recv(5000)
						print(output1)
						if b'successfully' in output1:
							print("Manager {} is deleted successfully".format(mgrs_ip[i]))
			else:
				for i in range(0,len(mgrs_ip)):
					self.device_handle.send("configure manager delete {}\n".format(mgrs_ip[i]))
					time.sleep(5)
					output1 = self.device_handle.recv(5000)
					if b'successfully' in output1:
						print("Manager {} is deleted successfully".format(mgrs_ip[i]))
				self.device_handle.send("\n")
				self.device_handle.send("configure manager add {} cisco123\n".format(self.mgr))
				time.sleep(40)
				output1 = self.device_handle.recv(5000).decode("utf-8")
				self.device_handle.send("\n")
				print("The output is {}".format(output1))

				if 'successfully' in output1:
				    print("Manager is added Successfully")
		print("No Extra Managers exist, Desired manager is configured successfully")

	def add_device(self):
		url1 = '/api/fmc_config/v1/domain/{}/policy/accesspolicies'.format(domainUUID)
		response1 = api_ops('get', url1)
		print(response1)
		for i in range(0,len(response1['items'])):
			if self.access_policy == response1['items'][i]['name']:
				access_policy_id = response1['items'][i]['id']
		url = '/api/fmc_config/v1/domain/{}/devices/devicerecords'.format(domainUUID)
		payload = {
				  "name": self.dev_name,
				  "hostName": self.device_ip,
				  "regKey": self.key,
				  "type": "Device",
				  "license_caps": [
				    "MALWARE",
				    "URLFilter",
				    "THREAT",
				    "BASE"
				  ],
				  "accessPolicy": {
				    "id": access_policy_id,
				    "type": "AccessPolicy"
				  }
				}
		response = api_ops('post', url, payload)
		print(response)
		for i in range(0,20):
			response2 = api_ops('get', url)
			for i in range(0,len(response2['items'])):
				if self.dev_name != response2['items'][i]['name']:
					print("Device is not yet listed")
				else:
					print('Device is listed')
					return 1
			time.sleep(30)

dev2=ssh("wm-101", "10.106.239.143", 57040, "admin", "C1sco@13")
dev1_handle=dev2.ssh_device()
if dev1_handle:
	print(dev1_handle)
	dev1_handle.send("\n")
	dev1_handle.send("show version\n")
	time.sleep(5)

	output1 = dev1_handle.recv(5000).decode("utf-8")
	print(output1)


global server
server = 'https://10.106.239.143:59211'
username = 'api'
password = 'abc123'

print("Generating Authentication Token \n+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++")
generate_token()
print("Starting to add device")
access_policy_default_blk('1140-routed')

dev1_fmc_ftd_reg = fmc_ftd_reg('1140','192.168.1.40','cisco123','1140-routed','192.168.1.11',dev1_handle)
dev1_fmc_ftd_reg.config_mgr()
dev1_fmc_ftd_reg.add_device()
