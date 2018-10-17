#! /usr/bin/env python2
import getpass
from PNDaemon import Daemon

if __name__ == '__main__':
	if getpass.getuser() != "root":
		print "You must be root to run this program."
	else:
		daemon = Daemon()
		daemon.run("server")
		daemon.run("sniffer")
