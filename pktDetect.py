from optparse import OptionParser
import netifaces as ni
import os
import socket
import pcap
#mport sys
#sys.path.insert(0, 'path/to/your/py_file')

#import py_file
import scapy
from scapy.all import *

def detector(pkt):
	if pkt.haslayer(IP) and pkt.haslayer(DNS) and pkt[DNS].qr==1:
		print pkt[DNS].qd.qname
		#print pkt[DNSRR].rdata
		if pkt[DNS].id in captured and (pkt[DNS].qd.qname.rstrip('.') == captured[pkt[DNS].id][DNS].qd.qname.rstrip('.')):
			l1=[]
			l2=[]
			oldpkt=captured[pkt[DNS].id]
			for i in range(pkt['DNS'].ancount):
				dnsrr=pkt['DNS'].an[i]
				l1.append(dnsrr.rdata)
			print l1
			for i in range(oldpkt['DNS'].ancount):
				dnsrr=oldpkt['DNS'].an[i]
				l2.append(dnsrr.rdata)
			print l2
			l1=sorted(l1)
			l2=sorted(l2)
			if l1!=l2:	
		        #if oldpkt[DNSRR].rdata != pkt[DNSRR].rdata:
				print "DNS poisoning attempt---------------------------------------"
				print "TXID %s Request %s"%( pkt[DNS].id, pkt[DNS].qd.qname.rstrip('.'))
				#print "Answer1 [%s]"%oldpkt[DNSRR].rdata
				print "Answer1"
				print l1
				print "Answer2"
				print l2

				#if isinstance(oldpkt[DNSRR].rdata, str):
				#	print type(oldpkt[DNSRR].rdata)
				#	print "Answer1 [%s]"%oldpkt[DNSRR].rdata
				#else:
				#	print "type--------------------------"
				#	print type(oldpkt[DNSRR].rdata)
				#	print "Answer1 [%s]"%oldpkt[DNSRR].rdata.decode("utf-8")
				#if isinstance(pkt[DNSRR].rdata, str):
				#	print "Answer2 [%s]"%pkt[DNSRR].rdata
				#else:
				#	print "Answer2 [%s]"%pkt[DNSRR].rdata.decode("utf-8")
		else:
		
		   captured[pkt[DNS].id]=pkt
			

if __name__ == '__main__':
	#spoofedPacketsFile = ""
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
		print "hi"
		print options.spoofedPacketsFile
		sniff(filter=exp, prn=detector, store=0, offline = options.spoofedPacketsFile)
		
		
	else:
		print "there"
		print options.spoofedPacketsFile
		sniff(filter=exp, prn=detector, store=0, iface=options.interface)
		
