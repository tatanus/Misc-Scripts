import sys
import os
import socket
import re
import ConfigParser

def irc_connect(server, port, channel, username, filename):
	outfile = open(filename, 'w')

	irc = socket.socket ( socket.AF_INET, socket.SOCK_STREAM )
	irc.connect ( ( server, int(port) ) )
	irc.send ( 'NICK '+username+'\r\n' )
	irc.send ( 'USER '+username+' 8 * :ExploitSearch.net\r\n' )
	irc.send ( 'JOIN '+channel+'\r\n' )
	while True:
		data = irc.recv ( 4096 )
		if (data != ""):
			if data.find ( 'PING' ) != -1:
				irc.send ( 'PONG ' + data.split() [ 1 ] + '\r\n' )
			if data.find ( 'hi '+username ) != -1:
				irc.send ( 'PRIVMSG '+channel+' :I already said hi...\r\n' )
			elif data.find ( 'hello '+username ) != -1:
				irc.send ( 'PRIVMSG '+channel+' :I already said hi...\r\n' )
			elif data.find ( 'KICK' ) != -1:
				irc.send ( 'JOIN '+channel+'\r\n' )
			else:
				m = re.match(r'.*PRIVMSG [^:]+:(.*)', data)
				if (m):
					outfile.write(m.group(1)+"\n")
				else:
					print data

def usage():
	print "\nUSAGE: "+sys.argv[0]+" <config file>\n"
	sys.exit()

if __name__ == "__main__":
	config_file = sys.argv[1] if len(sys.argv) >= 2 else usage()

	if (not os.path.isfile(config_file)):
		print "\n\nERROR: The provided confile ["+config_file+"] does not appear to be a valid file.\n\n"
		sys.exit(0)

	c = ConfigParser.ConfigParser()
	c.read(config_file)

	children = []
	for s in c.sections():
		try:
			server = c.get(s,'server')
			port = c.get(s,'port')
			channel = c.get(s,'channel')
			username = c.get(s,'username')
			outfile = c.get(s,'outfile')

			child = os.fork()
			if child:
				children.append(child)
				irc_connect(server, port, channel, username, outfile)
		except ConfigParser.NoOptionError:
			print "ERROR: The config section for ["+s+"] is invalid!"
