#! /usr/bin/env python2
import ctypes
import socket
import sys
import ssl
import time
import thread
import struct
from multiprocessing import Process, Array, Value, Pipe

class Daemon:
	appName = "port-knockd"
	host = ''
	sslCertPath = str()
	dbArray = []

	# Shared memory between processes (server -> sniffer)
	seqence = Array('i', 0)
	srcIp = Value(ctypes.c_char_p, "")
	orderedPort = Value('i', 0)
	isNew = Value('i', 0)

	# Shared memory between processes (sniffer -> server)
#	srcIpPass = Value

	# Symbolic name meaning all available interfaces
	port = 36886

	# Arbitrary non-privileged port
	def runServer(self, serverPipe):
		self.loadSettings()

		daemonSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		daemonSocket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
#		daemonSocket.setblocking(0)
		sslSocket = ssl.SSLContext(ssl.PROTOCOL_SSLv23)
		sslSocket.verify_mode = ssl.CERT_REQUIRED
		sslSocket.check_hostname = True
		sslSocket.load_verify_locations(self.sslCertPath)
		sslSocket.wrap_socket(daemonSocket, server_hostname="PN")

		daemonSocket.bind((self.host, self.port))
		daemonSocket.listen(1)

		while True:
			# Wait for connection
			print >> sys.stderr, 'Waiting for a connection...'
			connection, clientAddress = daemonSocket.accept()

			thread.start_new_thread(self.onNewClient, (connection, clientAddress))

	def runSniffer(self, snifferPipe):
		snifferSocket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

		while True:
			# If there are any messages in the pipe then read them
			if snifferPipe.poll():
				infoArray = snifferPipe.recv()
				self.dbArray.append(infoArray)
			# If it's not, then check if there are any UDP port knock packets from network
			else:
				data, srcIpAddress = snifferSocket.recvfrom(1024)
				srcPort = getnameinfo()[1]

				i = 0
				while True:
					if self.dbArray[i][0] == srcIpAddress:
						if self.dbArray[i][2][0] == srcPort and content == "KNOCK":
							if len(self.dbArray[i][2]) == 1:
								unblockFirewall(srcIpAddress, self.dbArray[i][1])

								# Sending "PASS" code to host which means that everything is OK
								snifferPipe.send("PASS")
							del self.dbArray[i][2][0]
					i = i+1				

			
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
		print >> sys.stderr, 'Connection from: ', clientAddress

		# Receive the data from client and compute random code.
		# The result will be in "infoArray[2]".
		while True:
			data = connection.recv(1024)
			if data != "":
				print >> sys.stderr, 'Received "%s"' % data
				infoArray = self.computeCode(clientAddress, data)

				# Send to sniffer process info about new client and it's knock seqence
				serverPipe.send(infoArray)

				# Send to client info that sniffer is ready
				connection.sendall("SRV_LISTENING")

				if serverPipe.recv() == "PASS":
					connection.sendall("PASS")
				elif serverPipe.recv() == "ERROR":
					connection.sendall("ERROR")
				elif serverPipe.recv() == "TIMEOUT":
					connection.sendall("TIMEOUT")

				connection.close()
			break

	def unblockFirewall(self, srcIpAddress, orderedPort):
		print "Adding rule to firewall"


if __name__ == '__main__':
	daemon = Daemon()
	serverPipe, snifferPipe = Pipe()

	server = Process(target=daemon.runServer, args=(serverPipe,))
	server.start()
	sniffer = Process(target=daemon.runSniffer, args=(snifferPipe,))
	sniffer.start()
