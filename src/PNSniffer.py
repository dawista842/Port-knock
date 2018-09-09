#! /usr/bin/env python2
import base64
import datetime
import os
import socket
import time
import thread
from multiprocessing import Pipe
from struct import *

class Sniffer:
	settingsArray = []
	pipe = None
	snifferSocket = None
	dbArray = []
	firewallRules = []

	def __init__(self, pipe, settingsArray):
		# Copy passed arguments
		self.pipe = pipe
		self.settingsArray = settingsArray

		# Create raw socket
		self.snifferSocket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_UDP)
		self.snifferSocket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
		self.snifferSocket.setblocking(0)

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

	# deleteFirewallRule:
	# Deletes firewall rules when timeout expired.
	def deleteFirewallRule(self, firewallRule):
		if self.settingsArray[5] == "firewalld":
			cmd = "sudo firewall-cmd --zone=%s --remove-rich-rule 'rule family=ipv4 source address=%s port port=%s protocol=tcp accept';" % (self.settingsArray[6], firewallRule[1], firewallRule[2])
			cmd = cmd "sudo firewall-cmd --zone=%s --remove-rich-rule 'rule family=ipv4 source address=%s port port=%s protocol=udp accept'" % (self.settingsArray[6], firewallRule[1], firewallRule[2])
		elif self.settingsArray[5] == "iptables":
			cmd = "iptables rule ading procedure"
#		os.system(cmd)

	# runSniffer:
	# Main function of the sniffer process.
	def run(self):
		# Infinite loop
		while True:
			# If there are any messages in the pipe then read them
			if self.pipe.poll():
				infoArray = self.pipe.recv()
				self.dbArray.append(infoArray)
				self.showAndLog("[Sniffer] Get seqence: " + str(infoArray))

			# If it's not, then check if there are any UDP port knock packets from network
			else:
				try:
					packet = self.snifferSocket.recvfrom(65565)
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
							self.checkReceivedPacket(self.pipe, srcIpAddress, dstPort, orderedPort)
				except socket.error, e:
					continue

			# Check if there are old firewall rules to remove
			if self.firewallRules[0]+self.settingsArray[3] < time.time():
				self.firewallRules.remove(self.firewallRules[0])
				self.deleteFirewallRule(self.firewallRules[0])

	# showAndLog:
	# Shows msg and logs it to log file.
	def showAndLog(self, msg):
		print msg
		logFile = open(self.settingsArray[4], 'a')
		logFile.write("<" + str(datetime.datetime.now()) + "> " + msg + "\n")
		logFile.close()

	# unblockFirewall:
	# If host send right seqence then this method is responsible for
	# add a rule to firewall to unblock ordered port.
	def unblockFirewall(self, infoArray):
		self.showAndLog("[Sniffer] Adding rule to firewall for host %s and port %d." % (infoArray[0], infoArray[1]))
		if self.settingsArray[5] == "firewalld":
			cmd = "firewall-cmd --zone=%s --add-rich-rule 'rule family=ipv4 source address=%s port port=%s protocol=tcp accept';" % (self.settingsArray[6], infoArray[0], infoArray[1])
			cmd = cmd "sudo firewall-cmd --zone=%s --add-rich-rule 'rule family=ipv4 source address=%s port port=%s protocol=udp accept'" % (self.settingsArray[6], infoArray[0], infoArray[1])
		elif self.settingsArray[5] == "iptables":
			cmd = "iptables rule ading procedure"
#		os.system(cmd)
		firewallRule = [time.time(), infoArray[0], infoArray[1]]
		self.firewallRules.append(firewallRule)

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

