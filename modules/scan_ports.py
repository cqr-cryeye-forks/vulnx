# !/usr/bin/env python

from __future__ import (absolute_import, division, print_function)

from common.colors import que, portopen, portclose
from common.uriParser import parsing_url as hostd
import socket

portsobject = {
    21: 'FTP',
    22: 'SSH',
    23: 'Telnet',
    25: 'SMTP',
    43: 'Whois',
    53: 'DNS',
    68: 'DHCP',
    80: 'HTTP',
    110: 'POP3',
    115: 'SFTP',
    119: 'NNTP',
    123: 'NTP',
    139: 'NetBIOS',
    143: 'IMAP',
    161: 'SNMP',
    220: 'IMAP3',
    389: 'LDAP',
    443: 'SSL',
    1521: 'Oracle_SQL',
    2049: 'NFS',
    3306: 'mySQL',
    5800: 'VNC',
}
port_data_info = {}


class ScanPort():
    def __init__(self, url, port):
        self.url = url
        self.port = port

    def portscan(self):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        if self.port == True:
            for key, value in portsobject.items():
                self.port = key
                print(self.port)
                result = sock.connect_ex((hostd(self.url), self.port))
                if result == 0:
                    print(que, self.port, portopen, portsobject[self.port])
                    port_data_info.update({f"{value}": "OPEN"})
                else:
                    print(que, self.port, portclose, portsobject[self.port])
                    port_data_info.update({f"{value}": "CLOSE"})
        else:
            self.port = int(self.port)
            result = sock.connect_ex((hostd(self.url), self.port))
            if result == 0:
                print(que, self.port, portopen, portsobject[self.port])
                port_data_info.update({"Port": "OPEN"})
            else:
                print(que, self.port, portclose, portsobject[self.port])
                port_data_info.update({"Port": "CLOSE"})
