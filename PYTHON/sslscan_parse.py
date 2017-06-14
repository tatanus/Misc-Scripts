#!/usr/bin/env python

import sys
import re

# ===============================================================
#
# TITLE: sslscan_parse.py
#
# AUTHOR: Adam (tatanus) Compton
#
# DATE: March 7th 2016
#
# DESCRIPTION: Parse an SSLSCAN output text file and output into
# csv format.  SSLSCAN should be run with the --no-color option
# enabled
#
# ===============================================================


infile = sys.argv[1]
infile = infile.strip('\r\n')

with open (infile, "r") as myfile:
    data=myfile.readlines()

ip = ""
port = ""
depricatedlist = []
weakciphers = []
keystrength = ""

print "Host/IP Address,Port,Depricated Protocol,Weak Ciphers,RSA Key Strength"
for line in data:
    m = re.match( r'^\s*Testing SSL server (.*) on port (\d\d*)', line)
    if (m):
        if (len(depricatedlist) > 0) or (len(weakciphers) > 0) or (keystrength is not ""): 
            print ip + "," + port + "," + ' '.join(depricatedlist) + "," + ' '.join(weakciphers) + "," + keystrength
        depricatedlist = []
        weakciphers = []
        keystrength = ""
        ip = m.group(1).strip()
        port = m.group(2).strip()

    else:
        m = re.match( r'^\s*Accepted\s\s+([^ ]*)\s\s*(\d\d*)\s\s*bits\s*([^ ]*)', line)
        if (m):
            protocol = m.group(1).strip()
            bit = m.group(2).strip()
            cipher = m.group(3).strip()
            if (protocol == "SSLv2"):
                if protocol not in depricatedlist:
                    depricatedlist.append(protocol)
            elif (protocol == "SSLv3"):
                if protocol not in depricatedlist:
                    depricatedlist.append(protocol)
            elif (protocol == "TLSv1.0"):
                if protocol not in depricatedlist:
                    depricatedlist.append(protocol)
            elif (protocol == "TLSv1.1"):
                if protocol not in depricatedlist:
                    depricatedlist.append(protocol)
            elif (protocol == "TLSv1.2"):
                if "ECDHE" not in cipher:
                    if "DES" in cipher:
                        if cipher not in weakciphers:
                            weakciphers.append(cipher)
                    elif "RSA" in cipher:
                        if cipher not in weakciphers:
                            weakciphers.append(cipher)
                    elif "NULL" in cipher:
                        if cipher not in weakciphers:
                            weakciphers.append(cipher)
                    elif int(bit) < 112:
                        if cipher not in weakciphers:
                            weakciphers.append(cipher)
        else:
            m = re.match( r'^\s*RSA Key Strength:\s*(\d\d*)', line)
            if (m):
                if int(m.group(1).strip()) < 2048:
                    keystrength = m.group(1).strip()

if (len(depricatedlist) > 0) or (len(weakciphers) > 0) or (keystrength is not ""): 
    print ip + "," + port + "," + ' '.join(depricatedlist) + "," + ' '.join(weakciphers) + "," + keystrength
