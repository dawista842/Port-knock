#! /usr/bin/env python2
import base64
import ctypes
import datetime
import os
import socket
import sys
import ssl
import time
import thread
from multiprocessing import Process, Pipe
from struct import *

class Daemon:
	appName = "port-knockd"
	host = ''
	dbArray = []
	settingsArray = []

	# runServer:
	# Main function of the server process.
	def runServer(self, serverPipe, settingsArray):
		self.settingsArray = settingsArray

		# Create SSL socket
		daemonSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		daemonSocket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
		sslSocket = ssl.SSLContext(ssl.PROTOCOL_SSLv23)
		sslSocket.verify_mode = ssl.CERT_REQUIRED
		sslSocket.check_hostname = True
		sslSocket.load_verify_locations(settingsArray[0])
		sslSocket.wrap_socket(daemonSocket, server_hostname="PN")

		daemonSocket.bind((self.host, settingsArray[1]))
		daemonSocket.listen(1)

		while True:
			# Wait for connection
			connection, clientAddress = daemonSocket.accept()

			# Start thread for connection
			thread.start_new_thread(self.onNewClient, (connection, clientAddress[0]))

	# runSniffer:
	# Main function of the sniffer process.
	def runSniffer(self, snifferPipe, settingsArray):
		self.settingsArray = settingsArray

		snifferSocket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_UDP)
		snifferSocket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
		snifferSocket.setblocking(0)

		while True:
			# If there are any messages in the pipe then read them
			if snifferPipe.poll():
				infoArray = snifferPipe.recv()
				self.dbArray.append(infoArray)
				self.showAndLog("[Sniffer] Get seqence: " + str(infoArray))

			# If it's not, then check if there are any UDP port knock packets from network
			else:
				try:
					packet = snifferSocket.recvfrom(65565)
					srcIpAddress, dstPort, protocol, data = self.unpackFrame(packet)
					if protocol == 17:
						code = data[:5]
						try:
							orderedPortEncoded = self.decodeBase64(infoArray[4], data[5:])
							orderedPort = int(orderedPortEncoded)
						except:
							continue
						if code == "KNOCK":
							self.showAndLog("[Sniffer] Get packet from %s destined to port %d: %s" % (srcIpAddress, dstPort, data))
							self.checkReceivedPacket(snifferPipe, srcIpAddress, dstPort, orderedPort)
				except socket.error, e:
					continue

	# checkReceivedPacket:
	# Check if packet match to the seqence.
	def checkReceivedPacket(self, snifferPipe, srcIpAddress, dstPort, orderedPort):

		for infoArray in self.dbArray:
			if srcIpAddress == infoArray[0] and orderedPort == infoArray[1]:

				# If ports match
				if infoArray[2][0] == dstPort:

					# If there are others seqence numbers
					# then remove first of them
					if len(infoArray[2]) > 1:
						if ((infoArray[3]+self.settingsArray[3]) <= time.time()) or (settingsArray[3] <= -1):
							self.showAndLog("[Sniffer] Found and removed port %s from seqence." % infoArray[2][0])
						else:
							self.showAndLog("[Sniffer] Reqest timeout")
							snifferPipe.send("TIMEOUT")
						del infoArray[2][0]
						return

					# If it is last seqence number, then
					# remove item from "self.dbArray" and
					# order unblock firewall.
					else:
						self.dbArray.remove(infoArray)
						self.unblockFirewall(infoArray)
						snifferPipe.send("PASS")
						return

				# Wrong seqence, return error
				else:
					snifferPipe.send("ERROR")
					return

	# computeCode:
	# It generates seqences from random numbers.
	def computeCode(self, clientAddress, data):
		orderedPort = data[3:].split(";")[0]
		randomIntStart = len(orderedPort)+8
		randomInt = data[randomIntStart:randomIntStart+9]
		orderedPort = int(orderedPort)
		seqenceArray = []

		i=0
		j=0
		while i < int(randomInt[4]):
			tmp = int(randomInt[-i-1])
			if tmp > 4:
				tmp = 4
			tmpRandomExtended = randomInt+randomInt+randomInt+randomInt
			seqenceArray.append(int(tmpRandomExtended[j:j+tmp]))

			i = i+1
			j = j+tmp

		infoArray = [clientAddress, orderedPort, seqenceArray, time.time(), randomInt]
		self.showAndLog("[Server] Seqence is " + str(seqenceArray)[1:-1])
		return infoArray

	# decodeBase64:
	# Decodes ordered port from UDP seqence packet using Base64 encryption.
	def decodeBase64(self, key, enc):
		dec = []
		enc = base64.urlsafe_b64decode(enc)
		for i in range(len(enc)):
			keyC = key[i % len(key)]
			decC = chr((256 + ord(enc[i]) - ord(keyC)) % 256)
			dec.append(decC)
		return "".join(dec)

	# loadSettings:
	# Loads settings from /etc/port-knock.conf file and configures daemon.
	def loadSettings(self):
#		configPath = "/etc/port-knock.conf"
		configPath = "port-knock.conf"
		configFile = open(configPath, 'r')
		for line in configFile:
			if line[0] != "#":
				if line.split("=")[0] == "certPath":
					sslCertPath = line.split("=")[1]
					sslCertPath = sslCertPath.replace('"', '')
					sslCertPath = sslCertPath[:-1]
				if line.split("=")[0] == "port":
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

	# showAndLog:
	# Shows msg and logs it to log file.
	def showAndLog(self, msg):
		print msg
		logFile = open(settingsArray[4], 'a')
		logFile.write("<" + str(datetime.datetime.now()) + "> " + msg + "\n")
		logFile.close()

	# onNewClient:
	# If new host connects this function handling it.
	def onNewClient(self, connection, clientAddress):
		self.showAndLog("[Server] Connection from: " + str(clientAddress))

		# Receive the data from client and compute random code.
		# The result will be in "infoArray[2]".
		while True:
			data = connection.recv(1024)

			if data != "":
				self.showAndLog("[Server] Received: %s" % data)
				infoArray = self.computeCode(clientAddress, data)

				# Send to sniffer process info about new client and it's knock seqence
				serverPipe.send(infoArray)
				
				# Wait for the moment because sniffer needs
				# some time to receive "infoArray", add it
				# to "self.dbArray" and switch to listen mode
				time.sleep(0.1)

				# Send to client info that sniffer is ready
				connection.sendall("SRV_LISTENING")

				while True:
					if serverPipe.poll():
						snifferMsg = serverPipe.recv()

						if snifferMsg == "PASS":
							connection.sendall("PASS")
						elif snifferMsg == "ERROR":
							connection.sendall("ERROR")
						elif snifferMsg == "TIMEOUT":
							connection.sendall("TIMEOUT")
						break
				connection.close()
				break

	# unblockFirewall:
	# If host send right seqence then this method is responsible for
	# add a rule to firewall to unblock ordered port.
	def unblockFirewall(self, infoArray):
		self.showAndLog("[Sniffer] Adding rule to firewall for host %s and port %d." % (infoArray[0], infoArray[1]))

	# unpackFrame:
	# When packet arrive to raw socket, then this method unpack it.
	def unpackFrame(self, packet):
		# IP header
		packet = packet[0]
		ipHeader = packet[0:20]
		ipHeaderUnpacked = unpack('!BBHHHBBH4s4s', ipHeader)
		versionIhl = ipHeaderUnpacked[0]
		version = versionIhl >> 4
		ihl = versionIhl & 0xF
		ipHeaderLength = ihl * 4

		# Protocol
		protocol = ipHeaderUnpacked[6]

		# Source IP address
		srcIpAddress = socket.inet_ntoa(ipHeaderUnpacked[8])

		# Destination port
		udpHeaderLength = 8
		udpHeader = packet[ipHeaderLength:ipHeaderLength+udpHeaderLength]
		udpHeaderUnpacked = unpack('!HHHH', udpHeader)
		dstPort = int(udpHeaderUnpacked[1])

		# Data
		headerSize = ipHeaderLength + udpHeaderLength
		dataSize = len(packet) - headerSize
		data = packet[headerSize:]

		return (srcIpAddress, dstPort, protocol, data)

if __name__ == '__main__':
	daemon = Daemon()
	settingsArray = daemon.loadSettings()

	# If cert file not exists then show message and exit
	if not os.path.exists(settingsArray[0]):
		print "[Daemon] Bad path or no cert file."
		exit()
	# If log path is not set then use default
	if settingsArray[4] == "":
		settingsArray[4] = "/var/log/port-knock.log"

	serverPipe, snifferPipe = Pipe()
	print "[Daemon] Starting daemon"

	server = Process(target=daemon.runServer, args=(serverPipe, settingsArray))
	server.start()
	sniffer = Process(target=daemon.runSniffer, args=(snifferPipe, settingsArray))
	sniffer.start()
