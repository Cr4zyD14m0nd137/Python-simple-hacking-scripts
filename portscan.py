#! /usr/bin/python

import socket

sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
socket.setdefaulttimeout(2)

host = input("[*] Enter The Host To Scan: ")
print(host)
port = int(input("[*] Enter The Port To Scan: "))
print(port)

def portscanner(port):
	if sock.connect_ex((host,port)):
		print ("Port %d is closed" % (port))
	else:
		print ("Port %d is opened" % (port))
portscanner(port)
