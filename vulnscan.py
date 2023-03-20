#!/usr/bin/python

import socket
import os
import sys

def retBanner(ip, port):
    try:
        socket.setdefaulttimeout(2)
        s = socket.socket()
        s.connect((ip, port))
        banner = s.recv(1024)
        return banner
    except:
        return b'' # Devuelve una secuencia de bytes vacía si hay un error

def checkVulns(banner, filename):
    with open(filename, "rb") as f:
        for line in f:
            if line.strip(b"\n") in banner:
                print("[+] Server is vulnerable: " + banner.decode().strip()) # Decodifica los bytes a una cadena de texto antes de imprimirlos

def main():
    if len(sys.argv) != 2:
        print("[-] Usage: " + str(sys.argv[0]) + " <vuln filename>")
        exit(1)
        
    filename = sys.argv[1]
    
    if not os.path.isfile(filename):
        print("[-] File doesn't exist!")
        exit(1)
    elif not os.access(filename, os.R_OK):
        print("[-] Access denied!")
        exit(1)
        
    portlist = [21, 22, 25, 80, 110, 443, 445]
    
    for x in range(144, 148):
        ip = "192.168.192." + str(x)
        for port in portlist:
            banner = retBanner(ip, port)
            if banner:
                print("[+] " + ip + "/" + str(port) + " : " + banner.decode())
                checkVulns(banner, filename)

if __name__ == "__main__":
    main()
