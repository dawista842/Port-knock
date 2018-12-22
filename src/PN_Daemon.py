#! /usr/bin/env python2
#
#   File:       PN_Daemon.py
#   Author:     David Stanek
#   License:    GNU GPLv2 or newer
#

import datetime
import getpass
import gnupg
import os
import socket
import subprocess
import time

class PN_Daemon:
	##
	# Variables
	##############
	appName = "Port-Knock Daemon"
	configPath = "/etc/port-knock.conf"
	daemonSocket = None
	gpg = None

	##
	# Structures
	##############
	daemonSettings = {
		'daemonPort': int(),
		'firewallTimeout': int(),
		'gpgHome': "~/.gnupg",
		'gpgKey': str(),
		'timestampDifference': 5,
		'logPath': str()
	}
	firewall = {
		'type': str(),
		'rules': [],
		'zone': None
	}

	##
	# Contructor
	##############
	def __init__(self):
		# Init some variables
		self.daemonSettings['gpgHome'] = "/home/%s/.gnupg" % (getpass.getuser())

		# Load settings from configuration file
		self.daemonSettings = self.loadSettings(self.configPath)

		# Check firewall type (iptables/firewalld)
		if os.path.isfile("/usr/bin/firewall-cmd"):
			(isFirewallD, tmp) = subprocess.Popen(["firewall-cmd --state"], stdout=subprocess.PIPE, shell=True).communicate()
			if isFirewallD[:-1] != "not running":
				self.firewall['type'] = "firewalld"
				zone = os.popen('firewall-cmd --get-default-zone').read()
				self.firewall['zone'] = zone[:-1]
			else:
				self.firewall['type'] = "iptables"
		else:
			self.firewall['type'] = "iptables"

		# Set GPG object
		self.gpg = gnupg.GPG(gnupghome=self.daemonSettings['gpgHome'])

		# Create raw socket
		self.daemonSocket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
		self.daemonSocket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
		self.daemonSocket.setblocking(0)
		self.daemonSocket.bind(('', self.daemonSettings['daemonPort']))

	##
	# Methods
	##############
	#
	# addFirewallRule:
	#	Add rule to firewall.
	def addFirewallRule(self, ipAddress, port):
		if self.firewall['type'] == "firewalld":
			cmd = "sudo firewall-cmd --zone=%s --add-rich-rule 'rule family=ipv4 source address=%s port port=%s protocol=tcp accept' &> /dev/null; " % (self.firewall['zone'], ipAddress, port)
			cmd = cmd+"sudo firewall-cmd --zone=%s --add-rich-rule 'rule family=ipv4 source address=%s port port=%s protocol=udp accept' &> /dev/null" % (self.firewall['zone'], ipAddress, port)
		elif self.firewall['type'] == "iptables":
			cmd = "sudo iptables -A INPUT -s %s -p tcp --dport %s -m conntrack --ctstate NEW,ESTABLISHED -j ACCEPT; " % (ipAddress, port)
			cmd = cmd+"sudo iptables -A INPUT -s %s -p udp --dport %s -m conntrack --ctstate NEW,ESTABLISHED -j ACCEPT" % (ipAddress, port)
		print cmd
		subprocess.Popen(cmd, stdout=subprocess.PIPE, shell=True)

	#
	# deleteFirewallRule:
	#	Delete rule from firewall.
	def deleteFirewallRule(self, firewallRule):
		if self.firewall['type'] == "firewalld":
			cmd = "sudo firewall-cmd --zone=%s --remove-rich-rule 'rule family=ipv4 source address=%s port port=%s protocol=tcp accept'; " % (self.firewall['zone'], firewallRule['ipAddress'], firewallRule['orderedPort'])
			cmd = cmd+"sudo firewall-cmd --zone=%s --remove-rich-rule 'rule family=ipv4 source address=%s port port=%s protocol=udp accept'" % (self.firewall['zone'], firewallRule['ipAddress'], firewallRule['orderedPort'])
		elif self.firewall['type'] == "iptables":
			cmd = "sudo iptables -D INPUT -s %s -p tcp --dport %s -m conntrack --ctstate NEW,ESTABLISHED -j ACCEPT; " % (firewallRule['ipAddress'], firewallRule['orderedPort'])
			cmd = cmd+"sudo iptables -D INPUT -s %s -p udp --dport %s -m conntrack --ctstate NEW,ESTABLISHED -j ACCEPT" % (firewallRule['ipAddress'], firewallRule['orderedPort'])
		subprocess.Popen(cmd, stdout=subprocess.PIPE, shell=True)

	#
	# loadSettings:
	#	Read and parse settings in "port-knock.conf" configuration file
	def loadSettings(self, configPath):
		# Open file
		configFile = open(configPath, 'r')
		settings = self.daemonSettings

		# Read config file line by line
		for line in configFile:
			if line[0] != "#":
				if line.split("=")[0] == "daemonPort":
					settings['daemonPort'] = line.split("=")[1].replace('"', '')
					settings['daemonPort'] = int(settings['daemonPort'][:-1])
				elif line.split("=")[0] == "gpgHome":
					settings['gpgHome'] = line.split("=")[1].replace('"', '')
					settings['gpgHome'] = settings['gpgHome'][:-1]
				elif line.split("=")[0] == "gpgKey":
					settings['gpgKey'] = line.split("=")[1].replace('"', '')
					settings['gpgKey'] = settings['gpgKey'][:-1]
				elif line.split("=")[0] == "firewallTimeout":
					settings['firewallTimeout'] = line.split("=")[1].replace('"', '')
					settings['firewallTimeout'] = int(settings['firewallTimeout'][:-1])
				elif line.split("=")[0] == "timestampDifference":
					settings['timestampDifference'] = line.split("=")[1].replace('"', '')
					settings['timestampDifference'] = int(settings['timestampDifference'][:-1])
				elif line.split("=")[0] == "logPath":
					settings['logPath'] = line.split("=")[1].replace('"', '')
					settings['logPath'] = settings['logPath'][:-1]
		return settings

	#
	# run:
	# 	Main function of PN_Daemon class.
	def run(self):
		# Check id gpgKey option in configuration file is set
		if not self.daemonSettings['gpgKey']:
			print "[Error] GPG Key is not set."
			return

		# Infinite loop
		print "[Info] Daemon started successfully."
		while True:
			try:
				requestContentEncrypted, header = self.daemonSocket.recvfrom(4096)
				srcIpAddress = header[0]
				self.showAndLog("[Info] Get encrypted request from %s." % str(srcIpAddress))
				requestContent = self.gpg.decrypt(requestContentEncrypted)
			except:
				continue

			# If decryption is successful
			if requestContent.ok == True:
				timestamp = float(requestContent.data.split(";")[1])

				# If timestamp matches, check request port and open it on firewall
				if timestamp >= time.time()-self.daemonSettings['timestampDifference'] and timestamp <= time.time()+self.daemonSettings['timestampDifference']:
					portToOpen = int(requestContent.data.split(";")[0])
					self.showAndLog("[Info] Adding rule to firewall for host %s and port %d." % (srcIpAddress, portToOpen))

					# Unblock firewall and save this request in array
					self.addFirewallRule(srcIpAddress, portToOpen)

					# Add firewall rule to database
					firewallRule = {
						'ipAddress': srcIpAddress,
						'orderedPort': portToOpen,
						'timestamp': time.time()
					}
					self.firewall['rules'].append(firewallRule)
				else:
					self.showAndLog("[Error] Timestamp mismatch. Check your system time.")
			else:
				self.showAndLog("[Error] Cannot decrypt request. %s" % requestContent.status)
				print requestContent.stderr

			# Check if there are old firewall rules to remove
			if self.firewall['rules'] and self.daemonSettings['firewallTimeout'] > 0 and float(self.firewall['rules'][0]['timestamp']+self.daemonSettings['firewallTimeout']) < time.time():
				self.showAndLog("[Info] Removing rule from firewall for host %s and port %d (Reason: timeout)." % (self.firewall['rules'][0]['ipAddress'], self.firewall['rules'][0]['orderedPort']))
				self.deleteFirewallRule(self.firewall['rules'][0])
				self.firewall['rules'].remove(self.firewall['rules'][0])

	#
	# showAndLog:
	#	Shows msg and logs it to log file.
	def showAndLog(self, msg):
		print msg
		logFile = open(self.daemonSettings['logPath'], 'a')
		logFile.write("<" + str(datetime.datetime.now()) + "> " + msg + "\n")
		logFile.close()

