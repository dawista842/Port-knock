#! /usr/bin/env python2
import ctypes
import socket
import sys
import ssl
import time
import thread
from multiprocessing import Process, Array, Value, Pipe
from struct import *

class Daemon:
	appName = "port-knockd"
	host = ''
	sslCertPath = str()
	dbArray = []

	# Symbolic name meaning all available interfaces
	port = 36886

	# Arbitrary non-privileged port
	def runServer(self, serverPipe):
		self.loadSettings()

		daemonSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		daemonSocket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
		sslSocket = ssl.SSLContext(ssl.PROTOCOL_SSLv23)
		sslSocket.verify_mode = ssl.CERT_REQUIRED
		sslSocket.check_hostname = True
		sslSocket.load_verify_locations(self.sslCertPath)
		sslSocket.wrap_socket(daemonSocket, server_hostname="PN")

		daemonSocket.bind((self.host, self.port))
		daemonSocket.listen(1)

		while True:
			# Wait for connection
			connection, clientAddress = daemonSocket.accept()

			# Start thread for connection
			thread.start_new_thread(self.onNewClient, (connection, clientAddress[0]))

	def runSniffer(self, snifferPipe):
		snifferSocket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_UDP)
#		snifferSocket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
#		snifferSocket.setblocking(0)

		while True:
			# If there are any messages in the pipe then read them
			if snifferPipe.poll():
				infoArray = snifferPipe.recv()
				self.dbArray.append(infoArray)
				print "[Sniffer] Get seqence: " + str(infoArray)

			# If it's not, then check if there are any UDP port knock packets from network
			else:
				try:
					packet = snifferSocket.recvfrom(65565)
					srcIpAddress, dstPort, protocol, data = self.unpackFrame(packet)
					if data == "KNOCK":
#						self.checkReceivedPacket(srcIpAddress, srcPort)
						print "[Sniffer] Get packet from '%s:%d': %s" % (srcIpAddress, dstPort, data)
				except socket.error, e:
					continue

#
#	while True:
#		if self.dbArray[i][0] == srcIpAddress:
#			if self.dbArray[i][2][0] == srcPort and content == "KNOCK":
#				if len(self.dbArray[i][2]) == 1:
#					unblockFirewall(srcIpAddress, self.dbArray[i][1])
#
#					# Sending "PASS" code to host which means that everything is OK
#					snifferPipe.send("PASS")
#					del self.dbArray[i][2][0]
#			i = i+1

	def checkReceivedPacket(self, srcIpAddress, srcPort):
		for infoArray in self.dbArray:
			print infoArray

	def computeCode(self, clientAddress, data):
		randomInt = data[11:20]
		orderedPort = int(data[3:6])
		seqenceArray = []

		i=0
		j=0
		while i < int(randomInt[4]):
			tmp = int(randomInt[-i-1])
			if tmp > 4:
				tmp = 4
			tmpRandomExtended = randomInt+randomInt+randomInt+randomInt
			seqenceArray.append(tmpRandomExtended[j:j+tmp])

			i = i+1
			j = j+tmp

		infoArray = [clientAddress, orderedPort, seqenceArray]
		print "[Server] Seqence is " + str(seqenceArray)[1:-1]
		return infoArray

	def loadSettings(self):
#		configPath = "/etc/port-knock.conf"
		configPath = "port-knock.conf"
		configFile = open(configPath, 'r')
		for line in configFile:
			if line[0] != "#":
				if line.split("=")[0] == "certPath":
					self.sslCertPath = line.split("=")[1]
					self.sslCertPath = self.sslCertPath.replace('"', '')
					self.sslCertPath = self.sslCertPath[:-1]

	def onNewClient(self, connection, clientAddress):
		print "[Server] Connection from: " + str(clientAddress)

		# Receive the data from client and compute random code.
		# The result will be in "infoArray[2]".
		while True:
			data = connection.recv(1024)

			if data != "":
				print "[Server] Received: %s" % data
				infoArray = self.computeCode(clientAddress, data)

				# Send to sniffer process info about new client and it's knock seqence
				serverPipe.send(infoArray)
				
				# Wait for the moment because sniffer needs
				# some time to receive "infoArray", add it
				# to "self.dbArray" and switch to listen mode
				time.sleep(0.5)

				# Send to client info that sniffer is ready
				connection.sendall("SRV_LISTENING")

				while True:
					if snifferPipe.poll():
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

	def unblockFirewall(self, srcIpAddress, orderedPort):
		print "[Sniffer] Adding rule to firewall"

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
		dstPort = udpHeaderUnpacked[1]

		# Data
		headerSize = ipHeaderLength + udpHeaderLength
		dataSize = len(packet) - headerSize
		data = packet[headerSize:]

		return (srcIpAddress, dstPort, protocol, data)

if __name__ == '__main__':
	daemon = Daemon()
	serverPipe, snifferPipe = Pipe()
	print "[Daemon] Starting daemon"

	server = Process(target=daemon.runServer, args=(serverPipe,))
	server.start()
	sniffer = Process(target=daemon.runSniffer, args=(snifferPipe,))
	sniffer.start()
