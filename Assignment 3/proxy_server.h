
#ifndef PROXY_SERVER_H
#define PROXY_SERVER_H
#include <sys/socket.h>
#include <arpa/inet.h> //inet_addr
#include <pthread.h>
#include <time.h>
#include <netdb.h>
#include <openssl/aes.h>
#include "log.h"
#include "encrypt.h"



struct server_thread_data_t
{
    unsigned char iv[8];
    unsigned char key[256];
    int fd_proxyc;
    int fd_server;
};


// Forward message proxy client => server
static void * handle_c2s(void * args)
{
    struct server_thread_data_t * pdata = (struct server_thread_data_t*)args;
    int fd_proxyc = ((struct server_thread_data_t*)args)->fd_proxyc;
    int fd_server = ((struct server_thread_data_t*)args)->fd_server;

    AES_KEY aes_key;
    struct ctr_state cstate;
    unsigned char recv_buff[MAX_PACKET_LEN];
    unsigned char msg_buff[MAX_PACKET_LEN];

    memset(recv_buff, '0', sizeof(recv_buff));
    init_ctr(&cstate, pdata->iv);
    AES_set_encrypt_key(pdata->key, 128, &aes_key);

    SERVER_LOG ("Start handling c2s..");
    while (1) {
        int n = read(fd_proxyc, recv_buff, sizeof(recv_buff) - 1);
        if (n <= 0) {
            SERVER_LOG ("Errors occurred, read failed %m");
            break;
        }
        recv_buff[n] = 0;
        SERVER_LOG ("c2s receive buffer %s", recv_buff);

        // Decrypt the message sent to the proxy client
        AES_ctr128_encrypt(recv_buff, msg_buff, n,
                           &aes_key, cstate.ivec,
                           cstate.ecount, &cstate.num);
        SERVER_LOG ("Decryption from [%s] to [%s]\n", recv_buff, msg_buff);

        write(fd_server, msg_buff, n);
        SERVER_LOG ("c2s: The buffer is %s before decryption", recv_buff);

        memset(recv_buff, '0', sizeof(recv_buff));
    }
    close(fd_proxyc);
    close(fd_server);
    free(args);
    SERVER_LOG ("exit  c2s ......");
    return NULL;
}


// Forward message server => proxy client
static void * handle_s2c(void * args)
{
    struct server_thread_data_t * pdata = (struct server_thread_data_t*)args;
    int fd_proxyc = ((struct server_thread_data_t*)args)->fd_proxyc;
    int fd_server = ((struct server_thread_data_t*)args)->fd_server;

    AES_KEY aes_key;
    struct ctr_state cstate;
    unsigned char recv_buff[MAX_PACKET_LEN];
    unsigned char msg_buff[MAX_PACKET_LEN];

    memset(recv_buff, '0', sizeof(recv_buff));
    init_ctr(&cstate, pdata->iv);
    AES_set_encrypt_key(pdata->key, 128, &aes_key);

    SERVER_LOG ("Start handling s2c..");
    while (1) {
        int n = read(fd_server, recv_buff, sizeof(recv_buff) - 1);
        if (n <= 0) {
            SERVER_LOG ("Errors occurred, read failed %m");
            break;
        }
        recv_buff[n] = 0;
        SERVER_LOG ("s2c receive buffer %s", recv_buff);

        // Encrypt the message sent to the proxy client
        AES_ctr128_encrypt(recv_buff, msg_buff, n,
                           &aes_key, cstate.ivec,
                           cstate.ecount, &cstate.num);
        SERVER_LOG ("Encryption from [%s] to [%s]\n", recv_buff, msg_buff);

        write(fd_proxyc, msg_buff, n);
        SERVER_LOG ("s2c: the buffer is %s before encryption", recv_buff);

        memset(recv_buff, '0', sizeof(recv_buff));
    }
    close(fd_proxyc);
    close(fd_server);
    free(args);    
    SERVER_LOG ("exit  s2c ......");
    return NULL;
}



static int start_proxy_server(const char * mykey,
                              const char * server_addr,
                              int server_port, int listen_port)
{
    SERVER_LOG ("Pbproxy server started...");
    //// Forward the traffic to the local server
    int fd_server;
    struct sockaddr_in server;

    int listenfd = 0, fd_proxyc = 0;
    struct sockaddr_in serv_addr;

    /* */
    struct hostent* server_name;

    memset(&serv_addr, '0', sizeof(serv_addr));
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_addr.s_addr = htonl(INADDR_ANY);
    serv_addr.sin_port = htons(listen_port);
    listenfd = socket(AF_INET, SOCK_STREAM, 0);
    bind(listenfd, (struct sockaddr*)&serv_addr, sizeof(serv_addr));
    listen(listenfd, 10);

    while(1) {
        // Create connetions between proxyc---proxys
        fd_proxyc = accept(listenfd, (struct sockaddr*)NULL, NULL);
        if (fd_proxyc < 0) {
            SERVER_LOG ("Error occured. accept() failed %m");
            continue;
        }
        SERVER_LOG ("accepted...");
        server_name = gethostbyname(server_addr);
        if (server_name == NULL) 
        {
            SERVER_LOG("ERROR, no such host\n");
            continue;
        }

        // Create connetions between proxys-----server
        fd_server = socket(AF_INET , SOCK_STREAM , 0);
        if (fd_server == -1) {
            SERVER_LOG("Could not create socket");
        }


        bcopy((char *)server_name->h_addr, (char *)&server.sin_addr.s_addr,server_name->h_length);

        // server.sin_addr.s_addr = inet_addr(server_addr);
        server.sin_family = AF_INET;
        server.sin_port = htons(server_port);
        if (connect(fd_server , (struct sockaddr *)&server , sizeof(server)) < 0) {
            SERVER_LOG("Connect port %d error %m", server_port);
            close(fd_proxyc);
            continue;
        }
        
        SERVER_LOG ("connected...");

        struct server_thread_data_t * pdata =
                (struct server_thread_data_t *)malloc(sizeof(struct server_thread_data_t));

        // Construct pdata parameters
        pdata->fd_proxyc = fd_proxyc;
        pdata->fd_server = fd_server;        
        memcpy(pdata->key, mykey, sizeof(pdata->key));
        
        SERVER_LOG("key is %s, length %d", pdata->key, sizeof(pdata->key));
        // Get different IVs for each session
        int n;
        if ((n = read(fd_proxyc, pdata->iv, 8)) <= 0) {
            SERVER_LOG ("read IV failed");
            continue;
        }
        for (n = 0; n<8; ++n) {
            SERVER_LOG("Received IV %x", pdata->iv[n]);
        }

        // Duplicate another thread data
        struct server_thread_data_t * pdata2 =
                (struct server_thread_data_t *)malloc(sizeof(struct server_thread_data_t));
        memcpy(pdata2, pdata, sizeof(struct server_thread_data_t));

        // Create 2 threads for each session
        pthread_t pid_c2s, pid_s2c;
        // c2s: proxy client => proxy server
        int ret = pthread_create(&pid_c2s, NULL, handle_c2s, (void*)pdata);
        if (ret != 0) {
            SERVER_LOG ("pthread_create failed");
            return -1;
        }
        // s2c: proxy server => proxy client
        ret = pthread_create(&pid_s2c, NULL, handle_s2c, (void*)pdata2);
        if (ret != 0) {
            SERVER_LOG ("pthread_create failed");
            return -1;
        }

    }
    return 0;
}



#endif
