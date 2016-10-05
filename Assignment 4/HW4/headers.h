#define IP_SIZE 16
#define REQUEST_SIZE 100
#define PCAP_INTERFACENAME_SIZE 16
#define FILTER_SIZE 200
#define ETHER_ADDR_LEN  6
#define DATAGRAM_SIZE 8192
#define MAX_HIJACK_LIST_SIZE 256
#define NUM_PACKETS -1

/* ethernet header definition */
struct etherhdr{
  u_char ether_dhost[ETHER_ADDR_LEN]; /* dst address */
  u_char ether_shost[ETHER_ADDR_LEN]; /* src address */
  u_short ether_type; /* network protocol */
};

/* DNS header definition */
struct dnshdr {
  char id[2];
  char flags[2];
  char qdcount[2];
  char ancount[2];
  char nscount[2];
  char arcount[2];
};

/* DNS query structure */
struct dnsquery {
  char *qname;
  char qtype[2];
  char qclass[2];
};

/* DNS answer structure */
struct dnsanswer {
  char *name;
  char atype[2];
  char aclass[2];
  char ttl[4];
  char RdataLen[2];
  char *Rdata;
};

