#! /usr/bin/env python2
import socket
import ssl
import sys
import time
import random

class App:
	appName = "port-knock"
	connectPort = int()
	message = str()
	randomInt = str()
	seqenceArray = []

	# Unlock entire port
	connectAddres = str()
	daemonPort = ""
	sslCertPath = str()

	def run(self):
		showHelpFlag = False
		showUnknownParameterFlag = False
		lastIndex = len(sys.argv)-1
		i = 1
		while (i <= lastIndex):
			if sys.argv[i] == "-p" or sys.argv[i] == "--port":
				if i+1 <= lastIndex:
					self.port = sys.argv[i+1]
					i = i+1
				else:
					showUnknownParameterFlag = True
			if sys.argv[i] == "-a" or sys.argv[i] == "--address":
				if i+1 <= lastIndex:
					self.address = sys.argv[i+1]
					i = i+1
				else:
					showUnknownParameterFlag = True

			if sys.argv[i] == "-d" or sys.argv[i] == "--destination":
				if i+1 <= lastIndex:
					self.connectAddress = sys.argv[i+1].split(":")[0]
					self.connectPort = sys.argv[i+1].split(":")[1]
					i = i+1
				else:
					showUnknownParameterFlag = True
			elif sys.argv[i] == "-h" or sys.argv[i] + "--help":
				showHelpFlag = True
			i = i+1

		if showHelpFlag == True or len(sys.argv) == 1:
			self.showHelp()

		elif showUnknownParameterFlag == True:
			self.showUnknownParameter()
		elif self.connectPort == None or self.connectAddress == None:
			self.showNeedAddressAndPort()
		else:
			self.loadSettings()
			self.knockToPort()

	def generateRandomInt(self):
		self.randomInt = str(random.randint(100000000, 999999999))

		i=0
		while i < len(self.randomInt):
			if self.randomInt[i] == '0':
				self.randomInt = self.randomInt[:i] + str(random.randint(1,9)) + self.randomInt[i+1:]
			i = i+1
		self.generateSeqence()

	def generateSeqence(self):
		i=0
		j=0

		while i < int(self.randomInt[4]):
			tmp = int(self.randomInt[-i-1])
			if tmp > 4:
				tmp = 4
			tmpRandomExtended = self.randomInt + self.randomInt + self.randomInt + self.randomInt
			self.seqenceArray.append(int(tmpRandomExtended[j:j+tmp]))

			i = i+1
			j = j+tmp
		print self.seqenceArray
			
	# knockToPort:
	# Send packets to various ports to unlock entire port
	def knockToPort(self):
		self.generateRandomInt()
		self.message = "REQ" + self.connectPort + "; RDM" + self.randomInt
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

		while True:
			data = clientSocket.recv(1024)
			if data == "SRV_LISTENING":
				print "[Client] Get SRV_LISTENING code"
				self.sendKnockSeq()
				break

		# After sending knock seqence we are here, waiting for "PASS" code
		while True:
			data = clientSocket.recv(1024)
			if data == "PASS":
				clientSocket.close()
				print "Port knock procedure finished successfully!"
				break

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
				if line.split("=")[0] == "port":
					self.daemonPort = line.split("=")[1]
					self.daemonPort = self.daemonPort.replace('"','')
					self.daemonPort = int(self.daemonPort[:-1])
		configFile.close()

	def sendKnockSeq(self):

		# Send seqence of packets
		print "[Client] Sending seqence of packets..."
		knockSocket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM) # UDP
		knockSocket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

		for port in self.seqenceArray:
			print "[Client] Send packet to %s on port %d" % (self.connectAddress, port)
			knockSocket.sendto("KNOCK", (self.connectAddress, port))

	# showNeedAddressAndPort:
	# Show information about address and port is needed
	def showNeedAddressAndPort(self):
		print ("Missing port or address of destination device")

	# showhelp:
	# Shows list of available parameters
	def showHelp(self):
		help = """
Syntax: %s [OPTION] [VALUE]

Examples:
%s -d 192.168.1.100:443
%s --address 192.168.1.100 --port 80

List of available parameters:
	-v, --version		show version
	-h, --help		show this message
	-a, --address 		specify destination host
	-d, --destination	specify full address of device port separated by colon (see examples)
"""
		print (help %(self.appName, self.appName, self.appName))

	# showUnknownParameter:
	# Show unknown parameter info
	def showUnknownParameter(self):
		print ("Unknown parameter or value. Use '" + self.appName + " -h' or '" + self.appName + " --help' to list all available parameters.")

# Run application
myApp = App()
myApp.run()
