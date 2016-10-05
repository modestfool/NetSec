CSE508: Network Security, Spring 2016

Homework 4: DNS Packet Injection
Basava R Kanaparthi (110479710)
----------------------------------------------------------------------------------------------------------------------------------------
README 

Source files included: 
	dnsinject.c  	-  C program to spoof DNS packets 
	
	headers.h  	-  All the DNS, Ethernet , etc. headers as well as the constants are defined here.
		
	dnsinject 	  	- executable generated.

	Makefile	  	- makefile to generate the executable.
	
	hostnames	-  Sample list of hostnames and IPs to be targeted.

	dnsdetect.py	- Python program to detect the Spoofed responses, if any .	
	
	sample_output.txt - Sample output of the dnsdetect on the pcap file generated with the help of dnsinject .

Usage:
	
	PART 1:
		make 
		./dnsinject [-i <interface>] [-f <hostnames>] [-h] [<expression>]
		
		Options:
			-i  Listen on network device <interface> (e.g., eth0).
			If not specified, default interface is chosen to listen on.
 
			-f <hostnames> to read a list of IP address and hostname pairs specifying the hostnames to be hijacked. 	

			-h Prints this message about program usage.

			<expression> is a BPF filter that specifies which packets will be filtered. 
			 	If no filter is given, all packets seen on the interface (or contained in the trace)
				will be returned. Otherwise, only packets matching <expression> will be considered.
	
	PART 2:
		python dnsdetect.py [-i <interface>] [-r <tracefile>] [-h] [<expression>]
		
		Options:
			-i  Listen on network device <interface> (e.g., eth0).
			If not specified, default interface is chosen to listen on.
 
			-r <tracefile> to read the packets offline from the pcap file.	

			-h Prints this message about program usage.

			<expression> is a BPF filter that specifies which packets will be filtered. 
			 	If no filter is given, all packets seen on the interface (or contained in the trace)
				will be returned. Otherwise, only packets matching <expression> will be considered.

Strategy:
	For dnsdetect, a time flowing window of 1 seconds is maintained to buffer the packets received. 
	And whenever a new DNS packet arrives, this queue is traversed and checked for the dns spoofed responses. 
	I've used the logic, that multiple packets with the same transaction ID, source and destination addresses are likely to be spoofed.
	I did not consider different MAC addresses, because while orchestrating a spoof MAC could also be tampered. 
	Also, because of the DNS round robin load balancing policies, checking for different DNS responses might result in false- positives.

