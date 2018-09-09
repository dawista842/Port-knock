#! /usr/bin/env python2
import os
from multiprocessing import Process, Pipe
from PNServer import Server
from PNSniffer import Sniffer

class Daemon:
	appName = "Port-Knock Daemon"
	settingsArray = []
	serverPipe = None
	snifferPipe = None
	server = None
	sniffer = None
	configPath = "port-knock.conf"

	def __init__(self):
		self.settingsArray = self.loadSettings()
		
		# If cert file not exists then show message and exit
		if not os.path.exists(self.settingsArray[0]):
			print "[Daemon] Bad path or no cert file."
			exit()

		# If log path is not set then use default
		if self.settingsArray[4] == "":
			self.settingsArray[4] = "/var/log/port-knock.log"

		# Check if firewalld exists (if not then assume that iptables is used)
		if not os.path.exists("/usr/bin/firewalld-cmd"):
			self.settingsArray.append("firewalld")
			defaultZone = os.popen('firewall-cmd --get-default-zone').read()
			defaultZone = defaultZone[:-1]
			self.settingsArray.append(defaultZone)
		else:
			self.settingsArray.append("iptables")
		
		# Init some variables
		self.serverPipe, self.snifferPipe = Pipe()
		self.server = Server(self.serverPipe, self.settingsArray)
		self.sniffer = Sniffer(self.snifferPipe, self.settingsArray)

		# Start daemon!
		print "[Daemon] Daemon started."

	# loadSettings:
	# Loads settings from /etc/port-knock.conf file and configures daemon.
	def loadSettings(self):
		configFile = open(self.configPath, 'r')
		for line in configFile:
			if line[0] != "#":
				if line.split("=")[0] == "certPath":
					sslCertPath = line.split("=")[1]
					sslCertPath = sslCertPath.replace('"', '')
					sslCertPath = sslCertPath[:-1]
				if line.split("=")[0] == "daemonPort":
					port = line.split("=")[1]
					port = port.replace('"', '')
					port = int(port[:-1])
				if line.split("=")[0] == "requestTimeout":
					requestTimeout = line.split("=")[1]
					requestTimeout = requestTimeout.replace('"', '')
					requestTimeout = int(requestTimeout[:-1])
				if line.split("=")[0] == "firewallTimeout":
					firewallTimeout = line.split("=")[1]
					firewallTimeout = firewallTimeout.replace('"', '')
					firewallTimeout = int(firewallTimeout[:-1])
				if line.split("=")[0] == "logPath":
					logPath = line.split("=")[1]
					logPath = logPath.replace('"', '')
					logPath = logPath[:-1]
		settingsArray = [sslCertPath, port, requestTimeout, firewallTimeout, logPath]
		return settingsArray

	# run:
	# Main function of Daemon class.
	def run(self, mode):
		if mode == "server":
			server = Process(target=self.server.run)
			server.start()
		elif mode == "sniffer":
			sniffer = Process(target=self.sniffer.run)
			sniffer.start()

