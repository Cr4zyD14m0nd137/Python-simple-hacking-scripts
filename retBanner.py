#! /usr/bin/python

import socket

def retBanner(ip,port):
	try:
		socket.setdefaulttimeout(2)
		s = socket.socket()
		s.connect((ip,port))
		banner = s.recv(1024)
		return banner
	except:
		return

def main():
	port = 22
	ip = "192.168.204.130"
	banner = retBanner(ip,port)
	if banner:
		print ("[+]" + ip +  ": " + str(banner))
main()
