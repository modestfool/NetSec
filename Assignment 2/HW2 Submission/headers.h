/* Ethernet addresses are 6 bytes */
#define ETHER_ADDR_LEN	6
/* ethernet headers are always exactly 14 bytes [1] */
#define SIZE_ETHERNET 14

	/* Ethernet header */
struct sniff_ethernet {
		u_char ether_dhost[ETHER_ADDR_LEN]; /* Destination host address */
		u_char ether_shost[ETHER_ADDR_LEN]; /* Source host address */
		u_short ether_type; /* IP? ARP? RARP? etc */
};

	/* IP header */
struct sniff_ip {
		u_char ip_vhl;		/* version << 4 | header length >> 2 */
		u_char ip_tos;		/* type of service */
		u_short ip_len;		/* total length */
		u_short ip_id;		/* identification */
		u_short ip_off;		/* fragment offset field */
	#define IP_RF 0x8000		/* reserved fragment flag */
	#define IP_DF 0x4000		/* dont fragment flag */
	#define IP_MF 0x2000		/* more fragments flag */
	#define IP_OFFMASK 0x1fff	/* mask for fragmenting bits */
		u_char ip_ttl;		/* time to live */
		u_char ip_p;		/* protocol */
		u_short ip_sum;		/* checksum */
		struct in_addr ip_src,ip_dst; /* source and dest address */
};
	#define IP_HL(ip)		(((ip)->ip_vhl) & 0x0f)
	#define IP_V(ip)		(((ip)->ip_vhl) >> 4)

	/* TCP header */
typedef u_int tcp_seq;

struct sniff_tcp {
		u_short th_sport;	/* source port */
		u_short th_dport;	/* destination port */
		tcp_seq th_seq;		/* sequence number */
		tcp_seq th_ack;		/* acknowledgement number */
		u_char th_offx2;	/* data offset, rsvd */
	#define TH_OFF(th)	(((th)->th_offx2 & 0xf0) >> 4)
	u_char th_flags;
	#define TH_FIN 0x01
	#define TH_SYN 0x02
	#define TH_RST 0x04
	#define TH_PUSH 0x08
	#define TH_ACK 0x10
	#define TH_URG 0x20
	#define TH_ECE 0x40
	#define TH_CWR 0x80
	#define TH_FLAGS (TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR)
		u_short th_win;		/* window */
		u_short th_sum;		/* checksum */
		u_short th_urp;		/* urgent pointer */
};

/* UDP header */

struct sniff_udp {
         u_short uh_sport;               /* source port */
         u_short uh_dport;               /* destination port */
         u_short uh_ulen;                /* udp length */
         u_short uh_sum;                 /* udp checksum */
};

#define SIZE_UDP        8               /* length of UDP header */		


/*
 * Structure of an icmp header.
 */
 struct sniff_icmp {
	u_char	icmp_type;		/* type of message, see below */
	u_char	icmp_code;		/* type sub code */
	u_short	icmp_cksum;		/* ones complement cksum of struct */
 	union {
		u_char ih_pptr;			/* ICMP_PARAMPROB */
		struct in_addr ih_gwaddr;	/* ICMP_REDIRECT */
 		struct ih_idseq {
 			n_short	icd_id;
 			n_short	icd_seq;
 		} ih_idseq;
 		int ih_void;
 	} icmp_hun;
#define	icmp_pptr	icmp_hun.ih_pptr
#define	icmp_gwaddr	icmp_hun.ih_gwaddr
#define	icmp_id		icmp_hun.ih_idseq.icd_id
#define	icmp_seq	icmp_hun.ih_idseq.icd_seq
#define	icmp_void	icmp_hun.ih_void
 	union {
 		struct id_ts {
 			n_time its_otime;
 			n_time its_rtime;
 			n_time its_ttime;
 		} id_ts;
 		struct id_ip  {
 			struct ip idi_ip;
			/* options and then 64 bits of data */
 		} id_ip;
 		u_long	id_mask;
 		char	id_data[1];
 	} icmp_dun;
#define	icmp_otime	icmp_dun.id_ts.its_otime
#define	icmp_rtime	icmp_dun.id_ts.its_rtime
#define	icmp_ttime	icmp_dun.id_ts.its_ttime
#define	icmp_ip		icmp_dun.id_ip.idi_ip
#define	icmp_mask	icmp_dun.id_mask
#define	icmp_data	icmp_dun.id_data
 };

#define SIZE_ICMP 8

/*
 * Definition of type and code field values.
 */
#define ICMP_ECHOREPLY          0       /* Echo Reply                   */
#define ICMP_DEST_UNREACH       3       /* Destination Unreachable      */
 		/* Codes for UNREACH. */
		#define ICMP_NET_UNREACH	0	/* Network Unreachable		*/
		#define ICMP_HOST_UNREACH	1	/* Host Unreachable		*/
		#define ICMP_PROT_UNREACH	2	/* Protocol Unreachable		*/
		#define ICMP_PORT_UNREACH	3	/* Port Unreachable		*/
		#define ICMP_FRAG_NEEDED	4	/* Fragmentation Needed/DF set	*/
		#define ICMP_SR_FAILED		5	/* Source Route failed		*/
		#define ICMP_NET_UNKNOWN	6
		#define ICMP_HOST_UNKNOWN	7
		#define ICMP_HOST_ISOLATED	8
		#define ICMP_NET_ANO		9
		#define ICMP_HOST_ANO		10
		#define ICMP_NET_UNR_TOS	11
		#define ICMP_HOST_UNR_TOS	12
		#define ICMP_PKT_FILTERED	13	/* Packet filtered */
		#define ICMP_PREC_VIOLATION	14	/* Precedence violation */
		#define ICMP_PREC_CUTOFF	15	/* Precedence cut off */
		#define NR_ICMP_UNREACH		15	/* instead of hardcoding immediate value */

#define ICMP_SOURCE_QUENCH      4       /* Source Quench                */
#define ICMP_REDIRECT           5       /* Redirect (change route)      */
 		/* Codes for REDIRECT. */
		#define ICMP_REDIR_NET		0	/* Redirect Net			*/
		#define ICMP_REDIR_HOST		1	/* Redirect Host		*/
		#define ICMP_REDIR_NETTOS	2	/* Redirect Net for TOS		*/
		#define ICMP_REDIR_HOSTTOS	3	/* Redirect Host for TOS	*/

#define ICMP_ECHO               8       /* Echo Request                 */
#define ICMP_TIME_EXCEEDED      11      /* Time Exceeded                */
 		/* Codes for TIME_EXCEEDED. */
		#define ICMP_EXC_TTL		0	/* TTL count exceeded		*/
		#define ICMP_EXC_FRAGTIME	1	/* Fragment Reass time exceeded	*/

#define ICMP_PARAMETERPROB      12      /* Parameter Problem            */
#define ICMP_TIMESTAMP          13      /* Timestamp Request            */
#define ICMP_TIMESTAMPREPLY     14      /* Timestamp Reply              */
#define ICMP_INFO_REQUEST       15      /* Information Request          */
#define ICMP_INFO_REPLY         16      /* Information Reply            */
#define ICMP_ADDRESS            17      /* Address Mask Request         */
#define ICMP_ADDRESSREPLY       18      /* Address Mask Reply           */
#define	ICMP_MAXTYPE		18

/* ARP Header, (assuming Ethernet+IPv4)            */ 
#define ARP_REQUEST 1   /* ARP Request             */ 
#define ARP_REPLY 2     /* ARP Reply               */ 
 struct sniff_arphdr{ 
    u_int16_t htype;    /* Hardware Type           */ 
    u_int16_t ptype;    /* Protocol Type           */ 
    u_char hlen;        /* Hardware Address Length */
    u_char plen;        /* Protocol Address Length */ 
    u_int16_t oper;     /* Operation Code          */ 
    u_char sha[6];      /* Sender hardware address */ 
    u_char spa[4];      /* Sender IP address       */ 
    u_char tha[6];      /* Target hardware address */ 
    u_char tpa[4];      /* Target IP address       */ 
 }; 