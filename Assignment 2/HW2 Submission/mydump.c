/*******************************************************************************
*	mydump.c
*	@author: Basava R Kanaparthi (basava.08@gmail.com)
*	Lightweight 'tcpdump' like program.
* to compile: gcc -o mydump mydump.c -lpcap
* use 'mydump -h' to get help.
* Acknowledgement: Took a lot of help from http://www.tcpdump.org/pcap.html
*******************************************************************************/

#include <stdio.h>
#include <pcap.h>
#include <unistd.h>
#include <stdlib.h>
#include <ctype.h>
#include <string.h>
#include <netinet/ip.h>
#include <netinet/if_ether.h>
#include <arpa/inet.h>
#include "headers.h"

// Function prototypes
void got_packet(u_char *args, const struct pcap_pkthdr *header,const u_char *packet);

void tcp_packet(const u_char *packet, struct sniff_ip* ip,
	const struct sniff_ethernet* ethernet, int size_ip, int size_header, char* time_stamp);
void udp_packet(const u_char *packet, struct sniff_ip* ip,
	const struct sniff_ethernet* ethernet, int size_ip, int size_header, char* time_stamp);
void icmp_packet (const u_char *packet, struct sniff_ip* ip,
	const struct sniff_ethernet* ethernet, int size_ip, int size_header, char* time_stamp);
void arp_packet(const u_char* packet,
	const struct sniff_ethernet* ethernet, int size_header, char *time_stamp);
void other_packet (struct sniff_ip* ip,
	const struct sniff_ethernet* ethernet, int size_header, char *time_stamp);
void print_payload(const u_char *payload, int len);
void print_hex_ascii_line(const u_char *payload, int len, int offset);
void usage_help();

int string_matches (const u_char* payload, const char* string);

// Globally declare the string to look for a match in payloads
char* string = NULL;

// The time format to convert the unix time to. 'strptime' function is used.
const char* TIME_FORMAT = "%Y-%m-%d %H:%M:%S";

/**
*	Entry point to the program, fetches the arguments and sets up the packet sniffing.
*/
int main(int argc, char *argv[])
{
	pcap_t *handle;							/* Session handle */
	char errbuf[PCAP_ERRBUF_SIZE];			/* Error string */
	struct bpf_program fp;					/* The compiled filter */
	bpf_u_int32 mask;						/* Our netmask */
	bpf_u_int32 net;						/* Our IP */

	int opt;								/* getopt callback index */
	char *filename;							/* the 'file' to sniff from */
	char *filter_exp;						/* The filter expression */
	char *dev;								/* The device to sniff on */
	int filter_exp_len = 0;					/* The length of BPF filter expression. */
	int index = 0;							/* Looping variable, to make the BPF expression */

	/**
	* Parse command-line options
	*/
	while((opt = getopt(argc, argv, "i:r:s:h")) != -1 )
	{
		switch(opt)
		{
			case 'i':
				// Set up the interface to sniff on (e.g., eth0)
				dev = (char *) malloc(sizeof(char) * (strlen(optarg) + 1));
				strcpy(dev,optarg);
				break;
			case 'r':
				// Set up the file to process packets offline
				filename = (char *) malloc(sizeof(char)*(strlen(optarg) + 1));
				strcpy(filename,optarg);
				break;
			case 's':
				// The string to look for in the packet's payload
				string = (char *) malloc(sizeof(char)*(strlen(optarg) + 1));
				strcpy(string, optarg);
				break;
			case 'h':
				// Prints the help message about general usage.
				usage_help();
				exit(0); // exit without throwing an error.
			default:
				// Incase any other options
				printf("Error: Invalid usage\n\n");
				usage_help();
				exit(0); // exit the program execution.
		}
	}

	/* Compute the size of the expression even
		 if they are not given as a string (in quoutes) */
	for (index = optind; index < argc; index++){
		filter_exp_len += strlen(argv[index]) + 1;
	}
	// Allocate appropriate memory for the BPF filter expression.
	filter_exp = (char *) malloc(sizeof(char)*(filter_exp_len + 1));
	filter_exp[0] = '\0';

	// Concatenate even if the BPF filter is space separated and not bound in quotes.
	for (index = optind; index < argc; index++)
	{
		strcat(filter_exp,argv[index]);
		strcat(filter_exp, " ");
	}


	/* Define the device. If the interface is not passed, default is chosen. */
	if (dev == NULL)
		dev = pcap_lookupdev(errbuf);

	/* Throw an error if default device is not found. */
	if (dev == NULL) {
		fprintf(stderr, "Couldn't find default device: %s\n", errbuf);
		return(2);
	}

	/* Find the properties for the device
	 * prototype:
	 *	char *pcap_lookupdev(char *errbuf);
	 *		pcap_lookupdev() returns a pointer to a string giving the name of a network device 
	 * 		suitable for use with pcap_create() and pcap_activate(), or with pcap_open_live(), and with pcap_lookupnet().
	 * 		If there is an error, NULL is returned and errbuf is filled in with an appropriate error message. 
	 *		errbuf is assumed to be able to hold at least PCAP_ERRBUF_SIZE chars.
	 *
	 */
	
	if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1) {
		fprintf(stderr, "Couldn't get netmask for device %s: %s\n", dev, errbuf);
		net = 0;
		mask = 0;
		return(2);
	}

	/* Open the session in promiscuous mode. If the filename arg is not passed, open dev in live mode.
	 * prototype:  
	 *		pcap_t *pcap_open_live(const char *device, int snaplen,int promisc, int to_ms, char *errbuf);
	 * 			device argument of "any" or NULL can be used to capture packets from all interfaces.
	 * 			snaplen specifies the snapshot length to be set on the handle.
	 * 			promisc specifies if the interface is to be put into promiscuous mode.
	 * 			to_ms specifies the read timeout in milliseconds.  
	 */
	if (filename == NULL)
		handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
	else
		/* Start sniffing from the pcap file - filename.
		 * prototype: 
		 *	pcap_t *pcap_open_offline(const char *fname, char *errbuf);
		 *		fname specifies the name of the file to open. 
		 * 		If there is an error, NULL is returned and errbuf is filled in with an appropriate error message. 
	 	 *		errbuf is assumed to be able to hold at least PCAP_ERRBUF_SIZE chars.
		 */
		handle = pcap_open_offline(filename,errbuf);

	if (handle == NULL) {
		fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
		return(2);
	}

	/* Compile and apply the filter */
	if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
		fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
		return(2);
	}
	if (pcap_setfilter(handle, &fp) == -1) {
		fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(handle));
		return(2);
	}

	/* Loop over the packets, indefinitely if -1 is passed.
	 * prototype:
	 *	int pcap_loop(pcap_t *p, int cnt, pcap_handler callback, u_char *user);
	 *		callback specifies a pcap_handler routine to be called with three arguments: 
	 *			a u_char pointer which is passed in the user argument to pcap_loop() or pcap_dispatch(),
	 * 			a const struct pcap_pkthdr pointer pointing to the packet time stamp and lengths, 
	 *			and a const u_char pointer to the first caplen 
	 *			(as given in the struct pcap_pkthdr a pointer to which is passed to the callback routine) bytes of data from the packet. 
	 *		The struct pcap_pkthdr and the packet data are not to be freed by the callback routine, 
	 *		and are not guaranteed to be valid after the callback routine returns; 
	 *		if the code needs them to be valid after the callback, it must make a copy of them.
	*/
	pcap_loop(handle, -1,got_packet,NULL); // got_packet - callback function, as soon as you sniff a packet

	/* And close the session */
	// Free the memory, before leaving
	if(filename)
		free(filename);
	if(filter_exp)
		free(filter_exp);
	if(string)
		free(string);

	pcap_close(handle);
	return(0);
}

/**
* got_packet - callback function for the pcap_loop
* prototype:
*	typedef void (*pcap_handler)(u_char *user, const struct pcap_pkthdr *h,const u_char *bytes);
*
*/
void got_packet(u_char *args, const struct pcap_pkthdr *header,const u_char *packet)
{
	char time_stamp[64],tmbuf[64];
	struct tm *current_tm;
	char *time_format = (char *)TIME_FORMAT;
	current_tm = localtime(&(header->ts.tv_sec));
	strftime(tmbuf, sizeof tmbuf, time_format, current_tm);
	snprintf(time_stamp, sizeof time_stamp, "%s.%06d", tmbuf, header->ts.tv_usec);

	/* declare pointers to packet headers */
	const struct sniff_ethernet *ethernet;  /* The ethernet header [1] */
	const struct sniff_ip *ip;              /* The IP header */

	int size_ip;

	/* define ethernet header */
	ethernet = (struct sniff_ethernet*)(packet);

	/* Check if the packet is of type ARP */
	if((ntohs(ethernet->ether_type)) == ETHERTYPE_ARP)
	{
		arp_packet(packet,(const struct sniff_ethernet*) ethernet, header->len, time_stamp);
		return;
	}
	/* Else delve into the IP section. Define ip header offset */
	ip = (struct sniff_ip*)(packet + SIZE_ETHERNET);
	size_ip = IP_HL(ip)*4;
	if (size_ip < 20) {
		printf("   * Invalid IP header length: %u bytes\n", size_ip);
		return;
	}

	/* determine protocol */
	switch(ip->ip_p) {
		case IPPROTO_TCP:
			tcp_packet(packet,(struct sniff_ip*)ip,
			(const struct sniff_ethernet*) ethernet,size_ip, header->len, time_stamp);
			break;
		case IPPROTO_UDP:
			udp_packet(packet, (struct sniff_ip*)ip,
			 (const struct sniff_ethernet*) ethernet, size_ip, header->len, time_stamp );
			break;
		case IPPROTO_ICMP:
			icmp_packet(packet, (struct sniff_ip*)ip,
			 (const struct sniff_ethernet*) ethernet, size_ip, header->len, time_stamp);
			break;
		default:
			other_packet((struct sniff_ip*) ip,
			(const struct sniff_ethernet*) ethernet, header->len, time_stamp);
			break;
	}
}
/**
* 	Helper function to print the typical usage of the program.
*/
void usage_help()
{
	printf("Usage: mydump [-i interface] [-r file] [-s string] [-h] expression\n");
	printf("\n");
	printf("Options:\n");
	printf("\t-i  Listen on network device <interface> (e.g., eth0).\n\tIf not specified, default interface is chosen to listen on.\n ");
	printf("\n");
	printf("\t-r  Read packets from <file> (tcpdump format).\n");
	printf("\n");
	printf("\t-s  Keep only packets that contain <string> in their payload.\n");
	printf("\n");
	printf("\t-h Prints this message about program usage.\n");
	printf("\n");
	printf("\t<expression> is a BPF filter that specifies which packets will be dumped. \n \tIf no"
		" filter is given, all packets seen on the interface (or contained in the trace)\n\t"
		"will be dumped. Otherwise, only packets matching <expression> will be dumped.\n\n");
}
/**
* Handles the tcp packet in the stream.
*/
void tcp_packet(const u_char *packet, struct sniff_ip* ip, const struct sniff_ethernet* ethernet, int size_ip, int size_header, char *time_stamp)
{
	const struct sniff_tcp *tcp;            /* The TCP header */
	int size_tcp;
	int size_payload;
	const u_char *payload;   					/* Packet payload */
	/* define/compute tcp header offset */
	tcp = (struct sniff_tcp*)(packet + SIZE_ETHERNET + size_ip);
	size_tcp = TH_OFF(tcp)*4;

	if (size_tcp < 20) {
		printf("   * Invalid TCP header length: %u bytes\n", size_tcp);
		return;
	}

	/* define/compute tcp payload (segment) offset */
	payload = (u_char *)(packet + SIZE_ETHERNET + size_ip + size_tcp);

	/* compute tcp payload (segment) size */
	size_payload = ntohs(ip->ip_len) - (size_ip + size_tcp);

	if (string != NULL && size_payload > 0)
	{
		if (string_matches(payload, string) == 0)
			return;
	}
	else if (string != NULL && size_payload == 0)
		return;

	printf("%s ", time_stamp);
	printf("%-18s -> ", ether_ntoa((const struct  ether_addr*) ethernet->ether_shost));
	printf("%-18s ", ether_ntoa((const struct  ether_addr*) ethernet->ether_dhost));
	printf("type %#06x ", ntohs(ethernet->ether_type));
	printf("length: %d ", size_header);

	printf("%s:%d -> ", inet_ntoa(ip->ip_src),ntohs(tcp->th_sport));
	printf("%s:%d ", inet_ntoa(ip->ip_dst),ntohs(tcp->th_dport));
	printf("TCP ");
	printf("payload_len: %d\n",size_payload);

	/*
	* Print payload data; it might be binary, so don't just
	* treat it as a string.
	*/
	if (size_payload > 0) {
		print_payload(payload, size_payload);
	}

	return;
}
/**
* Handles the udp packet in the stream.
*/
void udp_packet(const u_char *packet, struct sniff_ip* ip, const struct sniff_ethernet* ethernet, int size_ip, int size_header, char *time_stamp)
{
	const struct sniff_udp *udp; /* The UDP Header*/
	int size_payload;
	const u_char *payload;
	/* define/compute udp header offset */
	udp = (struct sniff_udp*)(packet + SIZE_ETHERNET + SIZE_UDP);

	/* define/compute udp payload (segment) offset */
	payload = (u_char *)(packet + SIZE_ETHERNET + size_ip + SIZE_UDP);

	/* compute udp payload (segment) size */
	size_payload = ntohs(ip->ip_len) - (size_ip + SIZE_UDP);
	if (size_payload > ntohs(udp->uh_ulen))
		size_payload = ntohs(udp->uh_ulen);

	if (string != NULL && size_payload > 0)
	{
		if (string_matches(payload, string) == 0)
			return;
	}
	else if (string != NULL && size_payload == 0)
		return;

	printf("%s ", time_stamp);
	printf("%-18s -> ", ether_ntoa((const struct  ether_addr*) ethernet->ether_shost));
	printf("%-18s ", ether_ntoa((const struct  ether_addr*) ethernet->ether_dhost));
	printf("type %#06x ", ntohs(ethernet->ether_type));
	printf("length: %d ", size_header);

	printf("%s:%d -> ", inet_ntoa(ip->ip_src),ntohs(udp->uh_sport));
	printf("%s:%d ", inet_ntoa(ip->ip_dst),ntohs(udp->uh_dport));
	printf("UDP ");
	printf("payload_len: %d\n",size_payload);
	/*
	* Print payload data; it might be binary, so don't just
	* treat it as a string.
	*/
	if (size_payload > 0) {
		print_payload(payload, size_payload);
	}
	return;
}
/**
* Handles the icmp packet in the stream.
*/
void icmp_packet (const u_char *packet, struct sniff_ip* ip, const struct sniff_ethernet* ethernet, int size_ip, int size_header, char *time_stamp)
{
	struct sniff_icmp *icmp; /* The ICMP Header*/
	int size_payload;
	const u_char *payload;
	/* define/compute icmp header offset */
	icmp = (struct sniff_icmp*) (packet + SIZE_ETHERNET + size_ip);

	/* define/compute icmp payload (segment) offset */
	payload = (u_char *)(packet + SIZE_ETHERNET + size_ip + SIZE_ICMP);

	size_payload = ntohs(ip->ip_len) - (size_ip);

	if (string != NULL && size_payload > 0)
	{
		if (string_matches(payload, string) == 0)
			return;
	}
	else if (string != NULL && size_payload == 0)
		return;

	printf("%s ", time_stamp);
	printf("%-18s -> ", ether_ntoa((const struct  ether_addr*) ethernet->ether_shost));
	printf("%-18s ", ether_ntoa((const struct  ether_addr*) ethernet->ether_dhost));
	printf("type %#06x ", ntohs(ethernet->ether_type));
	printf("length: %d ", size_header);

	printf("%s -> ", inet_ntoa(ip->ip_src));
	printf("%s ", inet_ntoa(ip->ip_dst));
	printf("ICMP ");

	switch(icmp->icmp_type)
	{
		case ICMP_ECHOREPLY:
			printf("echo reply ");
			break;
		case ICMP_DEST_UNREACH:
			printf("dest unreachable: ");
			switch(icmp->icmp_code)
			{
				case ICMP_NET_UNREACH:
					printf("network unreachable	");
					break;
				case ICMP_HOST_UNREACH:
					printf("host unreachable ");
					break;
				case ICMP_PROT_UNREACH:
					printf("protocol unreachable ");
					break;
				case ICMP_PORT_UNREACH:
					printf("port unreachable ");
					break;
				case ICMP_FRAG_NEEDED:
					printf("fragmentation needed/DF set ");
					break;
				case ICMP_SR_FAILED:
					printf("source route failed	");
					break;
				case ICMP_NET_UNKNOWN:
					printf("network unknown ");
					break;
				case ICMP_HOST_UNKNOWN:
					printf("host unknown ");
					break;
				case ICMP_HOST_ISOLATED:
					printf("host isolated ");
					break;
				case ICMP_NET_ANO:
					printf("network prohibited ");
					break;
				case ICMP_HOST_ANO:
					printf("host prohibited ");
					break;
				default:
					printf("unknown ");
			}
			break;
		case ICMP_SOURCE_QUENCH:
			printf("packet lost, slow down ");
			break;
		case ICMP_REDIRECT:
			printf("redirect: ");
			switch (icmp->icmp_code)
			{
				case ICMP_REDIR_NET:
					printf("net ");
					break;
				case ICMP_REDIR_HOST:
					printf("host ");
					break;
				case ICMP_REDIR_NETTOS:
					printf("net for TOS ");
					break;
				case ICMP_REDIR_HOSTTOS:
					printf("host for TOS ");
					break;
				case ICMP_PKT_FILTERED:
					printf("packet filtered ");
					break;
				case ICMP_PREC_VIOLATION:
					printf("precedence violation ");
					break;
				case ICMP_PREC_CUTOFF:
					printf("precedence cut off ");
					break;
				default:
					printf("unknown reason ");
					break;
			}
			break;
		case ICMP_ECHO:
			printf("echo request ");
			break;
		case ICMP_TIME_EXCEEDED:
			printf("time exceeded: ");
			switch (icmp->icmp_code)
			{
				case ICMP_EXC_TTL:
					printf("TTL count exceeded ");
					break;
				case ICMP_EXC_FRAGTIME:
					printf("Fragment Reass time exceeded ");
					break;
				default:
					printf("unknown reason ");
					break;
			}
			break;
		case ICMP_PARAMETERPROB:
			printf("parameter problem ");
			break;
		case ICMP_TIMESTAMP:
			printf("timestamp request ");
			break;
		case ICMP_TIMESTAMPREPLY:
			printf("timestamp reply  ");
			break;
		case ICMP_INFO_REQUEST:
			printf("information request ");
			break;
		case ICMP_INFO_REPLY:
			printf("information reply ");
			break;
		case ICMP_ADDRESS:
			printf("address mask request ");
			break;
		case ICMP_ADDRESSREPLY:
			printf("address mask reply ");
			break;
		default:
			printf("unknown type ");
	}
	printf("payload_len: %d\n",size_payload);

	/*
	* Print payload data; it might be binary, so don't just
	* treat it as a string.
	*/
	if (size_payload > 0) {
		print_payload(payload, size_payload);
	}
	return;
}
/**
* Handles the arp packet in the stream.
*/
void arp_packet(const u_char* packet,const struct sniff_ethernet* ethernet, int size_header, char *time_stamp)
{

	struct sniff_arphdr *arpheader; /*The ARP Header */

	arpheader = (struct sniff_arphdr *)(packet + SIZE_ETHERNET); /* Point to the ARP header */

	printf("%s ", time_stamp);
	printf("%-18s -> ", ether_ntoa((const struct  ether_addr*) ethernet->ether_shost));
	printf("%-18s, ", ether_ntoa((const struct  ether_addr*) ethernet->ether_dhost));
	printf("ethertype ARP (%#06x), " , ntohs(ethernet->ether_type));
	printf("length: %d ", size_header);
	printf("%s ", (ntohs(arpheader->oper) == ARP_REQUEST)? "Request who-has " : "Reply ");

	/* If is Ethernet and IPv4, print packet contents */
	if (ntohs(arpheader->htype) == 1 && ntohs(arpheader->ptype) == 0x0800){
		int i;

		if (ntohs(arpheader->oper) == ARP_REQUEST)
		{
			// for(i=0; i<6;i++)
			// 	printf("%02X:", arpheader->sha[i]);
			for(i=0; i<4; i++)
			{
				printf("%d", arpheader->tpa[i]);
				if (i < 3)
					printf(".");
			}
			printf(" tell ");
			for(i=0; i<4;i++)
			{
				printf("%d", arpheader->spa[i]);
				if (i < 3)
					printf(".");
			}
		}
		else if(ntohs(arpheader->oper) == ARP_REPLY)
		{
			for(i=0; i<4; i++)
			{
				printf("%d", arpheader->tpa[i]);
				if (i < 3)
					printf(".");
			}
			printf(" is at ");
			for(i=0; i<6;i++)
			{
				printf("%02x", arpheader->sha[i]);
				if (i < 5)
					printf(":");
			}
		}
		printf(", length: %d", size_header - SIZE_ETHERNET);
	}
	printf("\n");
}
/**
* Handles the any other packet (tcp, udp, arp, icmp) in the stream.
*/
void other_packet (struct sniff_ip* ip, const struct sniff_ethernet* ethernet, int size_header, char *time_stamp)
{
	printf("%s ", time_stamp);
	printf("%-18s -> ", ether_ntoa((const struct  ether_addr*) ethernet->ether_shost));
	printf("%-18s ", ether_ntoa((const struct  ether_addr*) ethernet->ether_dhost));
	printf("type %#06x ", ntohs(ethernet->ether_type));
	printf("length: %d ", size_header);

	printf("%12s -> ", inet_ntoa(ip->ip_src));
	printf("%12s ", inet_ntoa(ip->ip_dst));
	printf("OTHER \n");
}

/*
* Print packet payload data (avoid printing binary data)
*/
void print_payload(const u_char *payload, int len)
{

	int len_rem = len;
	int line_width = 16;			/* number of bytes per line */
	int line_len;
	int offset = 0;					/* zero-based offset counter */
	const u_char *ch = payload;

	if (len <= 0)
		return;

	/* data fits on one line */
	if (len <= line_width) {
		print_hex_ascii_line(ch, len, offset);
		return;
	}

	/* data spans multiple lines */
	for ( ;; ) {
		/* compute current line length */
		line_len = line_width % len_rem;
		/* print line */
		print_hex_ascii_line(ch, line_len, offset);
		/* compute total remaining */
		len_rem = len_rem - line_len;
		/* shift pointer to remaining bytes to print */
		ch = ch + line_len;
		/* add offset */
		offset = offset + line_width;
		/* check if we have line width chars or less */
		if (len_rem <= line_width) {
			/* print last line and get out */
			print_hex_ascii_line(ch, len_rem, offset);
			break;
		}
	}

	return;
}


/*
* print data in rows of 16 bytes: offset   hex   ascii
*
* 00000   47 45 54 20 2f 20 48 54  54 50 2f 31 2e 31 0d 0a   GET / HTTP/1.1..
*/
void print_hex_ascii_line(const u_char *payload, int len, int offset)
{

	int i;
	int gap;
	const u_char *ch;

	/* offset */
	printf("%05d   ", offset);

	/* hex */
	ch = payload;
	for(i = 0; i < len; i++) {
		printf("%02x ", *ch);
		ch++;
		/* print extra space after 8th byte for visual aid */
		if (i == 7)
			printf(" ");
	}
	/* print space to handle line less than 8 bytes */
	if (len < 8)
		printf(" ");

	/* fill hex gap with spaces if not full line */
	if (len < 16) {
		gap = 16 - len;
		for (i = 0; i < gap; i++) {
			printf("   ");
		}
	}
	printf("   ");

	/* ascii (if printable) */
	ch = payload;
	for(i = 0; i < len; i++) {
		if (isprint(*ch))
			printf("%c", *ch);
		else
			printf(".");
		ch++;
	}

	printf("\n");

	return;
}

/**
*	Checks if the string is present in the payload, if so returns 1. Else returns 0
*/
int string_matches (const u_char* payload, const char* string)
{
	if(strstr((const char*)payload,string) != NULL)
		return 1;
	return 0;
}
