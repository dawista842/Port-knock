#! /usr/bin/env python2
#
#   File:       PN_Client.py
#   Author:     David Stanek
#   License:    GNU GPLv2 or newer
#

import getpass
import gnupg
import os
import socket
import time

class PN_Client:
	##
	# Variables
	##############
	appName = str()
	appNameFull = "Port-knock client"
	ifUnknownParameterError = False
	ifShowHelp = False
	clientSocket = None
	gpg = None

	##
	# Structures
	##############
	requestData = {
		'daemonPort': 36886,
		'ipAddress': str(),
		'portToOpen': int(),
		'gpgHome': str(),
		'serverPublicKey': str(),
		'clientPrivateKey': str()
	}

	##
	# Contructor
	##############
	def __init__(self, argv):
		# Init some variables
		self.appName = os.path.basename(argv[0])
		self.requestData['gpgHome'] = "/home/%s/.gnupg" % (getpass.getuser())

		# Parse arguments passed via command line
		self.requestData = self.parseCmdLine(argv)

		# Create client UDP socket
		self.clientSocket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM) # UDP socket
		self.clientSocket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

		# Create GPG object
		self.gpg = gnupg.GPG(gnupghome=self.requestData['gpgHome'])

	##
	# Methods
	##############
	#
	# parseCmdLine:
	#	 Read and parse settings passed from cmd line (client)
	def parseCmdLine(self, argv):
		cmdLineSettings = self.requestData
		lastIndex = len(argv)-1
		i = 1

		# Read arguments passed to the program via cmd
		while (i <= lastIndex):
			if argv[i] == "-h" or argv[i] == "--help":
				self.ifShowHelp = True
			elif argv[i] == "-a" or argv[i] == "--address" and i+1 <= lastIndex:
				cmdLineSettings['ipAddress'] = argv[i+1]
				i += 1
			elif (argv[i] == "-p" or argv[i] == "--port") and i+1 <= lastIndex:
				try:
					cmdLineSettings['portToOpen'] = int(argv[i+1])
					i += 1
				except:
					self.ifUnknownParameterError = True			
			elif argv[i] == "-d" or argv[i] == "--destination" and i+1 <= lastIndex:
				try:
					cmdLineSettings['ipAddress'] = argv[i+1].split(":")[0]
					cmdLineSettings['portToOpen'] = int(argv[i+1].split(":")[1])
					i += 1
				except:
					self.ifUnknownParameterError = True
			elif argv[i] == "-s" or argv[i] == "--server-port" and i+1 <= lastIndex:
				try:
					cmdLineSettings['daemonPort'] = int(argv[i+1])
					i += 1
				except:
					self.ifUnknownParameterError = True
			elif argv[i] == "-g" or argv[i] == "--gpg-home" and i+1 <= lastIndex:
				cmdLineSettings['gpgHome'] = argv[i+1]
				i += 1
			elif argv[i] == "-pu" or argv[i] == "--public-key" and i+1 <= lastIndex:
				cmdLineSettings['serverPublicKey'] = argv[i+1]
				i += 1
			elif argv[i] == "-pr" or argv[i] == "--private-key" and i+1 <= lastIndex:
				cmdLineSettings['clientPrivateKey'] = argv[i+1]
				i += 1
			else:
				self.ifUnknownParameterError = True
			i += 1
		return cmdLineSettings

	#
	# run:
	# 	Main function of PN_Client class.
	def run(self):
		if self.ifShowHelp:
			self.showHelp()
			return
		if self.ifUnknownParameterError:
			print "[Error] Unknown parameter or value. Use '%s -h' or '%s --help' to list all \navailable parameters." % (self.appName, self.appName)
			return
		elif self.requestData['ipAddress'] == "" or self.requestData['portToOpen'] == "":
			print "[Error] Missing port or address of destination device"
			return

		# Ask user for passphrase to decrypt client's private key (this key is used to signing requests)
		passphrase = getpass.getpass("Client's private key passphrase:")

		# Prepare socket and request
		requestContent = "%d;%f" % (self.requestData['portToOpen'], time.time())

		# Encrypt the request content using server's public key
		requestContentEncrypted = self.gpg.encrypt(requestContent, self.requestData['serverPublicKey'], sign=self.requestData['clientPrivateKey'], passphrase=passphrase)
		if requestContentEncrypted.ok == True:
			print "[Info] Request content signed and encrypted successfully."
		else: 
			print "[Error] Cannot encrypt request. %s" % requestContentEncrypted.status
			return

		# If everything is ok, send encrypted request
		try:
			self.clientSocket.sendto(requestContentEncrypted.data, (self.requestData['ipAddress'], self.requestData['daemonPort']))
			print "[Info] Request send to %s:%d" % (self.requestData['ipAddress'], self.requestData['daemonPort'])
		except:
			print "[Error] Cannot sent request. Check IP address, daemon port and network connection."
			return

	#	
	# showhelp:
	# 	Shows list of available parameters.
	def showHelp(self):
		helpMsg = """
%s version 2.0
Syntax: %s [OPTION] [VALUE]

Examples:
%s -d 192.168.1.100:443 
%s --address 192.168.1.100 --port 80

List of available parameters:
      -h,  --help             show this message
      -a,  --address          specify destination host
      -p,  --port             specify port to open
      -d,  --destination      specify full address of device port separated
                              by colon (see examples)
      -s,  --server-port      specify server port (default is 36886)
      -g,  --gpg-home         specify GPG homedir (default is "~/.gnupg")
      -pu, --public-key       use server's public ID string (name, mail or
                              fingerprint). This key ensures confidentiality.
      -pr, --private-key      use client's private ID string (name, mail or
                              fingerprint). This key ensures authentication.
"""
		print helpMsg % (self.appNameFull, self.appName, self.appName, self.appName)

