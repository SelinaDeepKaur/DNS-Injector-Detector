from optparse import OptionParser
import netifaces as ni
import os
import socket
import pcap
from scapy.all import *

def detector(pkt):
	if pkt.haslayer(IP) and pkt.haslayer(DNS) and pkt.haslayer(DNSRR):
		if pkt[DNS].id in captured:
			oldpkt=captured[pkt[DNS].id]
		        if oldpkt[DNSRR].rdata != pkt[DNSRR].rdata:
				print "DNS poisoning attempt"
				print "TXID %s Request %s"%( pkt[DNS].id, pkt[DNS].qd.qname.rstrip('.'))
				print "Answer1 [%s]"%oldpkt[DNSRR].rdata
				print "Answer2 [%s]"%pkt[DNSRR].rdata
		else:
		   captured[pkt[DNS].id]=pkt
			

if __name__ == '__main__':
	spoofedPacketsFile = None
	captured={}
	parser = OptionParser()
	parser.set_conflict_handler("resolve")
	parser.add_option('-i', dest="interface",default=pcap.lookupdev())
	parser.add_option('-r', dest="spoofedPacketsFile")

	(options, remainder) = parser.parse_args()
	expression = remainder
	
	if len(expression)>0:
		exp = expression[0]
	else:
		exp = ""
	
	if spoofedPacketsFile == None:
		sniff(filter=exp, prn=detector, store=0, iface=options.interface)
	else:
		sniff(filter=exp, prn=detector, store=0, offline = spoofedPacketsFile)
