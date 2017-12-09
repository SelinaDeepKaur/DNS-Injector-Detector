# DNS-Injector-Detector

#DEPENDENCIES:

  sudo apt-get install python-libpcap 
  
  sudo apt install python-pip
  
  pip install netifaces
  
  pip install scapy
  
  



#COMMANDS TO RUN THE CODE:

  sudo python pktInject.py -i ens33 -h hostsmap udp      (Machine 1)

  sudo python pktDetect.py -i ens33 -r mypcap.pcap      (offline mode) (Machine 2)
  
  The BPF filter doesn’t get applied to sniff if it operates in the offline mode
  
  sudo python pktDetect.py -i ens33  udp                        (Machine 2)
  
  dig cs.stonybrook.edu (to generate requests)               (Machine 2)
  
  dig @77.88.8.8 amazon.com (to generate requests)    (Machine 2)
  
  
  
  

#DESIGN:

DNS INJECT:

  The code parses the command line arguments and calls the sniff() function with the 
  required parameters. The sniff() function in turn calls the callback function injector() which is 
  picked up from the parameter ‘prn’ of the sniff() function.
  Inside the injector() function I check if the packet received is a DNS request packet and only then
  proceed with the injection. Further if a file containing IP address and hostname pairs 
  specifying the hostnames to be hijacked has been supplied, only the packets containing 
  requests for these hostnames will be spoofed with the IPs mentioned across the hostnames in 
  the file. If such a file is not provided all the packets will be spoofed with the local machine’s IP.

DNS DETECT:

  The code parses the command line arguments in the same way as mentioned above. if a tracefile 
  to detect DNS poisoning is provided with the -r option in the command line. The sniff() function 
  is called in the offline mode otherwise the interface to detect the poisoning on, is passed to the 
  callback function detector(). Inside the callback function if the packet captured is a DNS 
  response packet, only then I proceed with the detection. The DNS response packets captured 
  are stored into a dictionary. When a new packet is received, I check if a packet with the same 
  TXID has been received, by comparing the new packet with the packets stored in the dictionary. 
  If a match is found, I store all the ‘type A rdata’ records of the both the packets in separate lists l1 
  and l2. The sorted lists l1 and l2 are compared against each other. If the lists do not match, it means a
  DNS poisoning attempt has been made.
  
  
  
  

#HANDLING THE FALSE POSITIVES:

  As mentioned above the detector callback function checks the rdata of the matching packets. 
  Only when there is a disparity in the rdata of the two packets, we say that a DNS poisoning 
  attempt has been made. The function returns if the rdata of the packets match and no alarm is raised.
  So if two genuine packets are sent by the server, they won’t be reported because their rdata would match.
  
  
  
  

#TEST ENVIRONMENT:

  Distributor ID:	Ubuntu
  
  Description:		Ubuntu 16.04.3 LTS
  
  Release:		16.04
  
  Codename:		xenial
  
  Language: 		Python 2.7.12
  
  
  
  

#REFERENCES:

  https://pymotw.com/2/optparse/
  
  https://stackoverflow.com/questions/11735821/python-get-localhost-ip 
  
  http://www.cs.dartmouth.edu/~sergey/netreads/local/reliable-dns-spoofing-with-python-scapy-nfqueue.html
  
  https://stackoverflow.com/questions/12501780/dnsrr-iteration





 




