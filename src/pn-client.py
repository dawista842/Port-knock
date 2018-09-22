#! /usr/bin/env python2
import base64
import os
import socket
import ssl
import sys
import time
import random

class App:
	appName = str()
	orderedPort = int()
	orderedPortEncoded = str()
	message = str()
	randomInt = str()
	seqenceArray = []
	isStaticSeq = False

	# Unlock entire port
	connectAddres = str()
	daemonPort = ""
	sslCertPath = str()
	requestTimeout = int()
	firewallTimeout = int()

	# run:
	# Main method where everything starts from here.
	def run(self):
		self.appName = sys.argv[0]
		showHelpFlag = False
		showUnknownParameterFlag = False
		lastIndex = len(sys.argv)-1
		i = 1

		# Read arguments passed to the program via cmd
		while (i <= lastIndex):
			if sys.argv[i] == "-p" or sys.argv[i] == "--port":
				if i+1 <= lastIndex:
					self.port = sys.argv[i+1]
					i = i+1
				else:
					showUnknownParameterFlag = True
			elif sys.argv[i] == "-a" or sys.argv[i] == "--address":
				if i+1 <= lastIndex:
					self.address = sys.argv[i+1]
					i = i+1
				else:
					showUnknownParameterFlag = True
			elif sys.argv[i] == "-d" or sys.argv[i] == "--destination":
				if i+1 <= lastIndex:
					self.connectAddress = sys.argv[i+1].split(":")[0]
					self.orderedPort = sys.argv[i+1].split(":")[1]
					i = i+1
				else:
					showUnknownParameterFlag = True
			elif sys.argv[i] == "-st" or sys.argv[i] == "--static-seqence":
				if i+1 <= lastIndex:
					self.seqenceArray = map(int, sys.argv[i+1].split(","))
					self.isStaticSeq = True
				else:
					showUnknownParameterFlag = True
			elif sys.argv[i] == "-h" or sys.argv[i] == "--help":
				showHelpFlag = True
			i = i+1

		# Action
		if showHelpFlag == True or len(sys.argv) == 1:
			self.showHelp()
		elif showUnknownParameterFlag == True:
			self.showUnknownParameter()
		elif self.orderedPort == None or self.connectAddress == None:
			self.showNeedAddressAndPort()
		else:
			self.loadSettings()

			# If cert file not exists then show message nad exit
			if not os.path.exists(self.sslCertPath):
				print "[Daemon] Bad path or no cert file."
				exit()
			self.knockToPort()

	# encodeBase64:
	# Encodes ordered port in UDP seqence packet using Base64 encryption.
	def encodeBase64(self, key, clear):
		enc = []
		for i in range(len(clear)):
			keyC = key[i % len(key)]
			encC = chr((ord(clear[i]) + ord(keyC)) % 256)
			enc.append(encC)
		return base64.urlsafe_b64encode("".join(enc))

	# generateRandomInt:
	# Generates random number which will be used to generate seqence.
	def generateRandomInt(self):
		self.randomInt = str(random.randint(100000000, 999999999))

		i=0
		while i < len(self.randomInt):
			if self.randomInt[i] == '0':
				self.randomInt = self.randomInt[:i] + str(random.randint(1,9)) + self.randomInt[i+1:]
			i = i+1
		if self.isStaticSeq == False:
			self.generateSeqence()

	# generateSeqence:
	# Generates packet seqence using random number
	# (generated in previous step).
	def generateSeqence(self):
		i=0
		j=0

		# It's kind of Magic...
		while i < int(self.randomInt[4]):
			tmp = int(self.randomInt[-i-1])
			if tmp > 4:
				tmp = 4
			tmpRandomExtended = self.randomInt + self.randomInt + self.randomInt + self.randomInt
			self.seqenceArray.append(int(tmpRandomExtended[j:j+tmp]))

			i = i+1
			j = j+tmp
			
	# knockToPort:
	# Send packets to various ports to unlock entire port
	def knockToPort(self):
		self.generateRandomInt()
		self.orderedPortEncoded = self.encodeBase64(self.randomInt, self.orderedPort)
		self.message = "REQ" + self.orderedPort + "; RDM" + self.randomInt
		isOrdered = False

		# Create SSL socket
		clientSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		clientSocket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
		sslSocket = ssl.SSLContext(ssl.PROTOCOL_SSLv23)
		sslSocket.verify_mode = ssl.CERT_REQUIRED
		sslSocket.check_hostname = True
		sslSocket.load_verify_locations(self.sslCertPath)
		sslSocket.wrap_socket(clientSocket, server_hostname="PN")

		# Connect, send data and close connection
		clientSocket.connect((self.connectAddress, self.daemonPort))
		clientSocket.sendall(self.message)

		# Waiting for "SRV_LISTENING" which means that server
		# listen our packet seqence
		while True:
			data = clientSocket.recv(1024)
			if data == "SRV_LISTENING":
				print "[Client] Get SRV_LISTENING code"

				# Send knock seqence
				self.sendKnockSeq()
				break

		# After sending knock seqence we are here, waiting
		# for "PASS" code
		while True:
			data = clientSocket.recv(1024)
			if data == "PASS":
				print "[Client] Port knock procedure finished successfully!"
			elif data == "TIMEOUT":
				print "[Client] Port knock procedure expired (timeout)."
			elif data == "ERROR":
				print "[Client] Port knock procedure error (bad seqence)."
			clientSocket.close()
			break

	# loadSettings:
	# Loads settings from configuration file.
	def loadSettings(self):
#		configPath = "/etc/port-knock.conf"
		configPath = "port-knock.conf"
		configFile = open(configPath, 'r')

		for line in configFile:
			if line[0] != "#":
				if line.split("=")[0] == "certPath":
					self.sslCertPath = line.split("=")[1]
					self.sslCertPath = self.sslCertPath.replace('"','')
					self.sslCertPath = self.sslCertPath[:-1]
				elif line.split("=")[0] == "daemonPort":
					self.daemonPort = line.split("=")[1]
					self.daemonPort = self.daemonPort.replace('"','')
					self.daemonPort = int(self.daemonPort[:-1])
				elif line.split("=")[0] == "requestTimeout":
					self.requestTimeout = line.split("=")[1]
					self.requestTimeout = self.requestTimeout.replace('"','')
					self.requestTimeout = int(self.requestTimeout[:-1])
				elif line.split("=")[0] == "firewallTimeout":
					self.firewallTimeout = line.split("=")[1]
					self.firewallTimeout = self.firewallTimeout.replace('"','')
					self.firewallTimeout = int(self.firewallTimeout[:-1])
		configFile.close()

	# sendKnockSeq:
	# Sends packet seqence (knock-knock!).
	def sendKnockSeq(self):
		# Send seqence of packets
		print "[Client] Sending seqence of packets..."
		knockSocket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM) # UDP
		knockSocket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
		clientMsg = "KNOCK" + self.orderedPortEncoded

		for port in self.seqenceArray:
			print "[Client] Send packet to %s on port %d" % (self.connectAddress, port)
			knockSocket.sendto(clientMsg, (self.connectAddress, port))

	# showNeedAddressAndPort:
	# Show information about address and port is needed
	def showNeedAddressAndPort(self):
		print ("Missing port or address of destination device")

	# showhelp:
	# Shows list of available parameters.
	def showHelp(self):
		help = """
Syntax: %s [OPTION] [VALUE]

Examples:
%s -d 192.168.1.100:443 -st 12,345,6789
%s --address 192.168.1.100 --port 80

List of available parameters:
	-v,  --version		show version
	-h,  --help		show this message
	-a,  --address 		specify destination host
	-p,  --port		specify port request
	-d,  --destination	specify full address of device port separated by colon (see examples)
	-st, --static-seqence	force static seqence
"""
		print (help %(self.appName, self.appName, self.appName))

	# showUnknownParameter:
	# Show unknown parameter info.
	def showUnknownParameter(self):
		print ("Unknown parameter or value. Use '" + self.appName + " -h' or '" + self.appName + " --help' to list all available parameters.")

# Run application
myApp = App()
myApp.run()
