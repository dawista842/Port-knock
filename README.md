# Port-knock
Port-knock is open source project licensed on GNU GPLv2 or newer. <br />

Tested on CentOS 7.5 and Mint 18.3.

# Installation
1. Download proper package for your Linux distribution.
2. Install package.

Debian & Ubuntu:
```
sudo apt-get install pn-client-<version>.deb pn-server-<version>.deb
```
Red Hat, CentOS and derivatives:
```
sudo yum install pn-client-<version>.rpm pn-server-<version>.rpm
```
3. Follow instructions displayed on terminal.

*WARNING:  
Do not type passphrase for your server GPG key. If passphrase will be set then port-knock daemon
cannot access to private GPG key.*

# Additional information
This project is part of BSc Thesis named "Advanced mechanism for opening transport layer ports on demand". You using this program on your own risk.

Author: David Stanek
