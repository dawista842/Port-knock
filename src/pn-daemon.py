#! /usr/bin/env python2
#
#   File:       pn-daemon.py
#   Author:     David Stanek
#   License:    GNU GPLv2 or newer
#
import getpass
from PNDaemon import Daemon

if __name__ == '__main__':
	if getpass.getuser() != "root":
		print "You must be root to run this program."
	else:
		daemon = Daemon()
		daemon.run("server")
		daemon.run("sniffer")
