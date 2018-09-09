#! /usr/bin/env python2
import datetime
import socket
import ssl
import thread
import time
from multiprocessing import Pipe

class Server:
	settingsArray = []
	pipe = None
	serverSocket = None
	sslWrapper = None

	def __init__(self, pipe, settingsArray):
		# Copy passed arguments
		self.pipe = pipe
		self.settingsArray = settingsArray

		# Create SSL socket
		self.serverSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		self.serverSocket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
		self.sslWrapper = ssl.SSLContext(ssl.PROTOCOL_SSLv23)
		self.sslWrapper.verify_mode = ssl.CERT_REQUIRED
		self.sslWrapper.check_hostname = False
		self.sslWrapper.load_verify_locations(self.settingsArray[0])
		self.sslWrapper.wrap_socket(self.serverSocket, server_hostname="PN")

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

	# run:
	# Main function of the server process.
	def run(self):
		self.serverSocket.bind(('', self.settingsArray[1]))
		self.serverSocket.listen(1)

		while True:
			# Wait for connection
			connection, clientAddress = self.serverSocket.accept()

			# Start thread for connection
			thread.start_new_thread(self.onNewClient, (connection, clientAddress[0]))

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
				self.pipe.send(infoArray)
				
				# Wait for the moment because sniffer needs
				# some time to receive "infoArray", add it
				# to "self.dbArray" and switch to listen mode
				time.sleep(0.1)

				# Send to client info that sniffer is ready
				connection.sendall("SRV_LISTENING")

				while True:
					if self.pipe.poll():
						snifferMsg = self.pipe.recv()

						# Return result of knocking to the client
						if snifferMsg == "PASS":
							connection.sendall("PASS")
						elif snifferMsg == "ERROR":
							connection.sendall("ERROR")
						elif snifferMsg == "TIMEOUT":
							connection.sendall("TIMEOUT")
						break
				connection.close()
				break

	# showAndLog:
	# Shows msg and logs it to log file.
	def showAndLog(self, msg):
		print msg
		logFile = open(self.settingsArray[4], 'a')
		logFile.write("<" + str(datetime.datetime.now()) + "> " + msg + "\n")
		logFile.close()

