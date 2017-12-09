from optparse import OptionParser
import netifaces as ni
import os
import socket
import pcap
import scapy
from scapy.all import *

def detector(pkt):
	if pkt.haslayer(IP) and pkt.haslayer(DNS) and pkt[DNS].qr==1:
		if pkt[DNS].id in captured and (pkt[DNS].qd.qname.rstrip('.') == captured[pkt[DNS].id][DNS].qd.qname.rstrip('.')):
			l1=[]
			l2=[]
			oldpkt=captured[pkt[DNS].id]
			for i in range(pkt['DNS'].ancount):
				dnsrr=pkt['DNS'].an[i]
				if dnsrr.type== 1:
					l1.append(dnsrr.rdata)

			for i in range(oldpkt['DNS'].ancount):
				dnsrr=oldpkt['DNS'].an[i]
				if dnsrr.type== 1:
					l2.append(dnsrr.rdata)
			
			l1=sorted(l1)
			l2=sorted(l2)
			if l1!=l2:	
				print "DNS poisoning attempt"
				print "TXID %s Request %s"%( pkt[DNS].id, pkt[DNS].qd.qname.rstrip('.'))
				print "Answer1",
				print l1
				print "Answer2",
				print l2
		else:
		   captured[pkt[DNS].id]=pkt
			

if __name__ == '__main__':
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
	if options.spoofedPacketsFile!=None:
		sniff(filter=exp, prn=detector, store=0, offline = options.spoofedPacketsFile)
	else:
		sniff(filter=exp, prn=detector, store=0, iface=options.interface)
		
