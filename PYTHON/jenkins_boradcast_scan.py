from socket import *
import re

s = socket(AF_INET, SOCK_DGRAM)
s.settimeout(1)
s.bind(('', 0))
s.setsockopt(SOL_SOCKET, SO_BROADCAST, 1)

data = repr(1) + '\n'
s.sendto(data, ('<broadcast>', 33848))

while 1:
    try:
        data, peer = s.recvfrom(1024)
        ver = re.match( r'.*version>(.*)<\/version.*', data)
        print "%s - has Jenkins Version %s" % (peer[0], ver.group(1))
    except timeout:
        break
