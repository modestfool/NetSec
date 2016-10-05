/*******************************************************************************
*	pbproxy.c
*	@author: Basava R Kanaparthi (basava.08@gmail.com)
*******************************************************************************/

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include "log.h"
#include "aes_init.h"
#include "sockets.h"

// Function prototypes
void usage_help();

/**
*	Entry point to the program, fetches the arguments and sets up the plugboard.
*/
int main(int argc, char *argv[])
{

	char* keyfile;					/* Name of the file that contains the static key, for encryption and decryption*/
	int listen_port = -1;			/* Port number on which the server instance of pbproxy listens to */
	char* dest;						/* Destination address that either the client or server instances connect with*/
	int dest_port;					/* Destination port */

	int isServer = 0;				/* Whether the instance of the program is running as a Server (reverse-proxy mode)*/

	int opt;						/* getopt callback index */
	
	char key[KEY_LEN];
	
	int isKey = 0;

	if(argc < 5)
	{
		usage_help();
		exit(1);
	}

	/**
	* Parse command-line options
	*/

	while((opt = getopt(argc, argv, "l:k:h")) != -1 )
	{
		switch(opt)
		{
			case 'l':
				listen_port = atoi(optarg);
				isServer = 1;
				break;
			case 'k':
				keyfile = (char*) malloc(sizeof(char) * (strlen(optarg) + 1));
				strcpy(keyfile,optarg);
				isKey = 1;
				break;
			case 'h':
				usage_help();
				exit(0);
			default:
				usage_help();
				exit(1);
		}
	}

	if(isKey == 0)
	{
		usage_help();
		exit(1);
	}
	
	if(optind != argc - 2)
	{
		usage_help();
		exit(1);
	}

	dest = (char *) malloc(sizeof(char) * (strlen(argv[optind++]) + 1));
	strcpy(dest,argv[optind-1]);
	
	/* Read the key from the keyfile */
	FILE *fp = fopen(keyfile, "r");
	fseek(fp, 0, SEEK_END); 	// Seek till the end of the file.
	size_t size = ftell(fp);   //  Compute the size
	fseek(fp, 0, SEEK_SET);


	if (fp == NULL)
	{
		/*ERROR detection if file == empty*/
        printf("Error: There was an Error reading the file %s \n", keyfile);           
        exit(1);
    }
    else if (fread((void*)key, sizeof(char), size, fp) != size)
    {
    	/* if count of read bytes != calculated size of .bin file -> ERROR*/
        printf("Error: There was an Error reading the file %s - %ld\n", keyfile, size);
        exit(1);
    }

	dest_port = atoi(argv[optind]);

	if (isServer == 1) {
        start_server(key, dest, dest_port, listen_port);
    } else {
        start_client(key, dest, dest_port);
    }
    return 0;
}

/**
* 	Helper function to print the typical usage of the program.
*/
void usage_help()
{
	printf("Usage: pbproxy [-l port] -k keyfile destination port\n");
	printf("\n");
	printf("Options:\n");
	printf("\t -l  Reverse-proxy mode: listen for inbound connections on <port> and relay them to <destination>:<port>\n");
	printf("\n");
	printf("\t-k  Use the symmetric key contained in <keyfile> (as a hexadecimal string)\n");
	printf("\n");
	printf("\t<destination>  Destination IP to relay to.\n");
	printf("\n");
	printf("\t<port> Port on the destination to relay to.\n");
	printf("\n");
}
