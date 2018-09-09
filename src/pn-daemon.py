#! /usr/bin/env python2
from PNDaemon import Daemon

if __name__ == '__main__':
	daemon = Daemon()
	daemon.run("server")
	daemon.run("sniffer")
