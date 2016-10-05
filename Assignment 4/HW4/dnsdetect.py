#!/usr/bin/python
import sys, getopt
from collections import deque
from scapy.all import *
from datetime import datetime
import time

pkt_fifo = []

def handle_packet(pkt):
    
    # Redundancy check only for DNS packets
    if DNS in pkt:
	#print "Length of queue" , len(pkt_fifo)
        if len(pkt_fifo) > 0:
            #print 'Current number of cached packet:', len(pkt_fifo)
            # compare the fields with pkts in fifo
	    try:

		    for old_pkt in pkt_fifo:
			#print 'Current number of cached packet:', len(pkt_fifo)
		     	#print old_pkt.time-time.time()
			if (int(time.time()) - int(old_pkt.time) ) > 1:
				pkt_fifo.remove(old_pkt)
			        #print "Removing old pkt %d " %len(pkt_fifo)
			# compare with each one
		        if old_pkt[IP].src == pkt[IP].src and\
		        old_pkt[IP].dst == pkt[IP].dst and\
			old_pkt[DNS].id == pkt[DNS].id: #and\
			#old_pkt[Ether].src != pkt[Ether].src:
			    answer1_ans = []
			    answer2_ans = []
			    i = pkt[DNS].ancount
			    while(i > 0):
				if(pkt[i+4].type == 1):
					answer1_ans.append(pkt[i+4].rdata)
				i -= 1
			    i = old_pkt[DNS].ancount
			    while(i > 0):
				if(old_pkt[i+4].type == 1):
					answer2_ans.append(old_pkt[i+4].rdata)
				i -= 1
			    print '\tDNS poisoning attempt\n'
		            print datetime.fromtimestamp(pkt.time).strftime('%Y-%m-%d %H:%M:%S.%f')
		            print 'TXID: %s Request: %s' %(hex(pkt[DNS].id),pkt[DNSQR].qname)
			    print 'Answer 1 : %s' %(answer1_ans)
			    print 'Answer 2 : %s\n' %(answer2_ans)
			    #break
	    except IndexError as e:
			pass 
        pkt_fifo.append(pkt)

def main(argv):
    interface = ''
    filename = ''
    expression = ''
    
    try:
        opts, args = getopt.getopt(argv, 'i:r::')
    except getopt.GetoptError:
        print 'usage: python dnsdetect.py [-i <interface>] [-r <pcap>] [<expression>]'
        sys.exit()
    
    for opt, arg in opts:
        if opt == '-i':
            interface = arg
        elif opt == '-r':
            filename = arg
    
    if len(args) == 1:
        expression = args[0]
    elif len(args) > 1:
        print '\n\tMore non-option arguments than expected!\n'
        sys.exit()
    if len(expression) == 0:
	expression = "udp port 53"
    else:
	expression = "udp port 53 and " + expression
    print '\n\tInitializing  dnsdetect using following parameters:\n',\
        '\t\tinterface:', interface, '\n',\
        '\t\tpcap file:', filename, '\n',\
        '\t\tBPF expression:', expression, '\n'
    
    if interface == '' and filename == '':
        print '\tSniffing on all interfaces by default'
        sniff(prn = handle_packet, filter = expression)
    elif interface != '' and filename == '':
        print '\tSniffing on interface', interface
        sniff(iface = interface, prn = handle_packet, filter = expression)
    else:
        print '\tSniffing offline trace file', filename
        sniff(offline = filename, prn = handle_packet, filter = expression)

if __name__ == "__main__":
    main(sys.argv[1:])

