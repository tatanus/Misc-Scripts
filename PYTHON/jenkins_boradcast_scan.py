from socket import *

s = socket(AF_INET, SOCK_DGRAM)
s.bind(('', 0))
s.setsockopt(SOL_SOCKET, SO_BROADCAST, 1)

data = repr(1) + '\n'
s.sendto(data, ('<broadcast>', 33848))

while 1:
    print s.recvfrom(1024)
