# socketsX
 Abstraction layer for BSD and other sockets

References:
    https://nmap.org/nsedoc/scripts/ssl-enum-ciphers.html
    https://github.com/ssllabs/research/wiki/SSL-Server-Rating-Guide
    https://wildwolf.name/mapping-openssl-cipher-suite-names-to-rfc-names/
    https://security.stackexchange.com/questions/14731/what-is-ecdhe-rsa
    https://ssl-config.mozilla.org/#server=apache&version=2.4.41&config=intermediate&openssl=1.1.1k&guideline=5.7
    

To optimise the MBedTLS config for a client we need to:
Identify all the hosts we need to connect to
For each host in the list use the command below to identify the ciphers supported:
    nmap -sV [-Pn] --script ssl-enum-ciphers.nse -p XXX host/IP
Once a list/table of the hosts and supported ciphers has been completed
    choose the minimum subset of ciphers that the client must support
    configure the firmware accordingly to include the minimal cipher support required
    test the firmware for consistent reliable connection

