import paramiko
import time
import re
import json
import sys
import requests
import time
import yaml
import argparse
from functools import wraps
from requests.packages.urllib3.exceptions import InsecureRequestWarning


requests.packages.urllib3.disable_warnings(InsecureRequestWarning)


########################################
######Includes Fn to ssh device#########
########################################
class ssh:
	def __init__(self,dev_name,ip,port,uname,pwd):
		self.dev_name=dev_name
		self.ip=ip
		self.port=port
		self.uname=uname
		self.pwd=pwd
  ##########################################
  ##########Function to SSH Device##########
  ##########################################
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

dev2=ssh("wm-101", "10.106.239.143", 57101, "admin", "C1sco@13")
dev1=dev2.ssh_device()
if dev1:
	print(dev1)
	dev1.send("\n")
	dev1.send("show version\n")
	time.sleep(5)

	output1 = dev1.recv(5000).decode("utf-8")
	print(output1)
