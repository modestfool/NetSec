#include <sys/socket.h>
#include <arpa/inet.h> //inet_addr
#include <pthread.h>
#include <time.h>
#include <netdb.h>
#include <openssl/aes.h>
#include <stdlib.h> 
#include <unistd.h>
#include "log.h"
#include "aes_init.h"


struct server_thread_data_t
{
    unsigned char iv[8];
    unsigned char key[KEY_LEN];
    int fd_client;
    int fd_server;
};



static void * client_to_server(void * args)
{
    struct server_thread_data_t * connection = (struct server_thread_data_t*)args;
    int fd_client = ((struct server_thread_data_t*)args)->fd_client;
    int fd_server = ((struct server_thread_data_t*)args)->fd_server;

    AES_KEY aes_key;
    struct ctr_state cstate;
    unsigned char recv_buff[MAX_PACKET_LEN];
    unsigned char msg_buff[MAX_PACKET_LEN];

    memset(recv_buff, '0', sizeof(recv_buff));
    init_ctr(&cstate, connection->iv);
    AES_set_encrypt_key(connection->key, 128, &aes_key);

    SERVER_LOG ("Start handling c2s..");
    while (1) {
        int n = read(fd_client, recv_buff, sizeof(recv_buff) - 1);
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
    close(fd_client);
    close(fd_server);
    free(args);
    SERVER_LOG ("exit  c2s ......");
    return NULL;
}


// Forward message server to client
static void * server_to_client(void * args)
{
    struct server_thread_data_t * connection = (struct server_thread_data_t*)args;
    int fd_client = ((struct server_thread_data_t*)args)->fd_client;
    int fd_server = ((struct server_thread_data_t*)args)->fd_server;

    AES_KEY aes_key;
    struct ctr_state cstate;
    unsigned char recv_buff[MAX_PACKET_LEN];
    unsigned char msg_buff[MAX_PACKET_LEN];

    memset(recv_buff, '0', sizeof(recv_buff));
    init_ctr(&cstate, connection->iv);
    AES_set_encrypt_key(connection->key, 128, &aes_key);

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

        write(fd_client, msg_buff, n);
        SERVER_LOG ("s2c: the buffer is %s before encryption", recv_buff);

        memset(recv_buff, '0', sizeof(recv_buff));
    }
    close(fd_client);
    close(fd_server);
    free(args);    
    SERVER_LOG ("exit  s2c ......");
    return NULL;
}


int start_server(const char * mykey,
                              const char * server_addr,
                              int server_port, int listen_port)
{
    SERVER_LOG ("Pbproxy server started...");
    //// Forward the traffic to the local server
    int fd_server;
    struct sockaddr_in server;

    int listenfd = 0, fd_client = 0;
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
        fd_client = accept(listenfd, (struct sockaddr*)NULL, NULL);
        if (fd_client < 0) {
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
            close(fd_client);
            continue;
        }
        
        SERVER_LOG ("connected...");

        struct server_thread_data_t * connection =
                (struct server_thread_data_t *)malloc(sizeof(struct server_thread_data_t));

        // Construct connection parameters
        connection->fd_client = fd_client;
        connection->fd_server = fd_server;        
        memcpy(connection->key, mykey, sizeof(connection->key));
        
        SERVER_LOG("key is %s, length %lu", connection->key, sizeof(connection->key));
        
        // Get different IVs for each session
        int n;
        if ((n = read(fd_client, connection->iv, 8)) <= 0) {
            SERVER_LOG ("Couldn't read the IV");
            continue;
        }
        for (n = 0; n < 8; ++n) {
            SERVER_LOG("Received IV %x", connection->iv[n]);
        }

        // Duplicate another thread data
        struct server_thread_data_t * connection2 =
                (struct server_thread_data_t *)malloc(sizeof(struct server_thread_data_t));
        memcpy(connection2, connection, sizeof(struct server_thread_data_t));

        // Create 2 threads for each session
        pthread_t pid_c2s, pid_s2c;
        // c2s: proxy client => proxy server
        int ret = pthread_create(&pid_c2s, NULL, client_to_server, (void*)connection);
        if (ret != 0) {
            SERVER_LOG ("pthread_create failed");
            return -1;
        }
        // s2c: proxy server => proxy client
        ret = pthread_create(&pid_s2c, NULL, server_to_client, (void*)connection2);
        if (ret != 0) {
            SERVER_LOG ("pthread_create failed");
            return -1;
        }

    }
    return 0;
}
