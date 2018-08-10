import argparse
import urllib
import portscan
import sys
import httpenum
import socket
import requests
from multiprocessing.dummy import Pool as ThreadPool 
socket.setdefaulttimeout(1)

#Command Arg stuff
parser = argparse.ArgumentParser()
parser.add_argument("RHOST",help="The host you would like to scan",type=str)
parser.add_argument("-F","--fast",help="Scan only the top 100 most used ports. Defualt is top 1,000", action="store_true")
parser.add_argument("-d","--dictionary",help="Dictionary to bruteforce url filepaths if webserver found",type=str)
parser.add_argument("-t","--threads",help="Amound of threads to use in scanning, Default 4",default=4,type=int)
args = parser.parse_args()

#Start port scan
print("[+] Starting port scan on RHOST: %s\n" % args.RHOST)
ports = portscan.scan(args.fast,args.threads,args.RHOST)

#Print out the open ports
for i in range(0,len(ports)):
	print("Port: %d Open!" % ports[i])

#Checks to see if webserver at any ports, if so then bruteforce URL
print("\n[+] Starting webserver detection and bruteforce\n")
httpenum.scan(args.RHOST,ports,args.threads,args.dictionary)

print("\n[+] Scan done")
