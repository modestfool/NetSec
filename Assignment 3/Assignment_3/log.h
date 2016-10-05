#ifndef LOG_H
#define LOG_H
#include <stdio.h>

// Log if client log
#define __CLIENT_LOG__ 1 
#define CLIENT_LOG(msg, arg...)                                          					\
    if (__CLIENT_LOG__) {				                                   					\
        FILE * client_log = fopen("client.log","a");					   					\
        fprintf(client_log,"%s [DEBUG:%s:%d] "msg"\n",__TIME__, __FILE__, __LINE__, ##arg); \
        fclose(client_log);																	\
    }


// Server instance's log
#define __SERVER_LOG__ 1 
#define SERVER_LOG(msg, arg...)                                        		     			\
    if (__SERVER_LOG__){                                                 		 			\
        FILE * server_log = fopen("server.log","a");					 		 			\
        fprintf(server_log,"%s [DEBUG:%s:%d] "msg"\n", __TIME__, __FILE__, __LINE__, ##arg);\
    	fclose(server_log);														 			\
    }

#endif
