# Port-knock
Port-knock is open source project licensed on GNU GPLv2 or newer. <br />

Tested on CentOS 7.5 and Mint 18.3.

# Installation for Debian & Ubuntu
1. Download *.deb package.
2. Install the package using following command:
```
sudo apt-get install pn-client-<version>.deb pn-server-<version>.deb
```
3. Follow instructions displayed on terminal.

*WARNING:
Do not type passphrase for your server GPG key. If passphrase will be set then port-knock daemon
will cannot access to private GPG key.*

# Installation for Red Hat, CentOS and derivatives:
1. Download *.rpm package.
2. Install the package using following command:
```
sudo yum install pn-client-<version>.rpm pn-server-<version>.rpm
```
3. Create GPG key generation file using following instructions: https://www.gnupg.org/documentation/manuals/gnupg/Unattended-GPG-key-generation.html
4. Generate GPG key in port-knock user home directory by typing command:
```
sudo -H -u port-knock bash -c "gpg --gen-key --batch <gpg_key_generation_file>"
```
5. Show generated GPG key.
```
sudo -H -u port-knock bash -c "gpg -a --export <gpg_name>"
```
where gpg_name is owner's name, e-mail, description or fingerprint.

*WARNING:
Do not type passphrase for your server GPG key. If passphrase will be set then port-knock daemon
will cannot access to private GPG key.*

# Additional information
This project is part of BSc Thesis named "Advanced mechanism for opening transport layer ports on demand". You using this program on your own risk.

Author: David Stanek
