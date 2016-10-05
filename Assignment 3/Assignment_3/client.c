#include <sys/socket.h>
#include <arpa/inet.h> 
#include <pthread.h>
#include <openssl/rand.h>
#include <netdb.h>
#include <unistd.h>
#include "log.h"
#include "aes_init.h" 


struct client_thread_data_t
{
    unsigned char iv[8];
    unsigned char key[KEY_LEN];
    int fd_proxys;
};


static void * handle_send(void * args)
{
    int n;
    int fd_proxys;
    AES_KEY aes_key;
    struct ctr_state cstate;
    unsigned char send_buff[MAX_PACKET_LEN];
    unsigned char msg_buff[MAX_PACKET_LEN];

    struct client_thread_data_t * pdata = (struct client_thread_data_t*)args;
    fd_proxys = pdata->fd_proxys;
    init_ctr(&cstate, pdata->iv);
    AES_set_encrypt_key(pdata->key, 128, &aes_key);

    while (1) {
        if ((n = read(0, send_buff, sizeof(send_buff) - 1)) <= 0) {
            CLIENT_LOG ("read ends......");
            break;
        }
        send_buff[n] = 0;
        CLIENT_LOG ("have sent \"%s\" to remote server", send_buff);

        AES_ctr128_encrypt(send_buff, msg_buff, n,
                           &aes_key, cstate.ivec,
                           cstate.ecount, &cstate.num);
        CLIENT_LOG ("Encryption from [%s] to [%s]\n", send_buff, msg_buff);

        if ((n = write(fd_proxys, msg_buff, n)) <= 0) {
            CLIENT_LOG ("write ends......");
            break;
        }
    }
    return NULL;
}

static void * handle_recv(void * args)
{
    int n;
    int fd_proxys;
    AES_KEY aes_key;
    struct ctr_state cstate;
    unsigned char recv_buff[MAX_PACKET_LEN];
    unsigned char msg_buff[MAX_PACKET_LEN];

    struct client_thread_data_t * pdata = (struct client_thread_data_t*)args;
    fd_proxys = pdata->fd_proxys;
    init_ctr(&cstate, pdata->iv);
    AES_set_encrypt_key(pdata->key, 128, &aes_key);

    while (1) {
        if ((n = read(fd_proxys, recv_buff, sizeof(recv_buff) - 1)) <= 0) {
            break;
        }
        recv_buff[n] = 0;
        
        AES_ctr128_encrypt(recv_buff, msg_buff, n,
                           &aes_key, cstate.ivec,
                           cstate.ecount, &cstate.num);
        CLIENT_LOG ("Decryption from [%s] to [%s]\n", recv_buff, msg_buff);

        write(1, msg_buff, n);
    }
    return NULL;
}

int start_client(const char * mykey,
                              const char * server_addr, int port)
{
    int fd_proxys;
    struct sockaddr_in server;
     /* */
    struct hostent* server_name;

    //Create socket
    fd_proxys = socket(AF_INET , SOCK_STREAM , 0);
    if (fd_proxys == -1) {
        CLIENT_LOG("Could not create socket");
        exit(1);
    }

    server_name = gethostbyname(server_addr);
    if (server_name == NULL) 
    {
        CLIENT_LOG("ERROR, no such host\n");
        exit(1);
    }
    bcopy((char *)server_name->h_addr, (char *)&server.sin_addr.s_addr,server_name->h_length);
    // server.sin_addr.s_addr = inet_addr(server_addr);
    server.sin_family = AF_INET;
    server.sin_port = htons(port);

    //Connect to remote proxy server
    if (connect(fd_proxys , (struct sockaddr *)&server , sizeof(server)) < 0) {
        CLIENT_LOG("connect error %m");
        exit(1);
    }

    struct client_thread_data_t * pdata =
            (struct client_thread_data_t *)malloc(sizeof(struct client_thread_data_t));
    if (pdata == NULL) {
        CLIENT_LOG("malloc failed %m");
        exit(1);
    }
    pdata->fd_proxys = fd_proxys;
    memcpy(pdata->key, mykey, sizeof(pdata->key));

    if (!RAND_bytes(pdata->iv, 8)) {
        CLIENT_LOG ("RAND_bytes error");
        free(pdata);
        exit(1);
    }
    int n = 0;
    if ((n = write(fd_proxys, pdata->iv, 8)) < 0) {
        CLIENT_LOG ("send IV failed.");
        free(pdata);
        exit(1);
    }

    pthread_t pid_send, pid_recv;
    int ret = pthread_create(&pid_send, NULL, handle_send, (void*)pdata);
    if (ret != 0) {
        CLIENT_LOG ("pthread_create failed");
        free(pdata);
        exit(1);
    }

    ret = pthread_create(&pid_recv, NULL, handle_recv, (void*)pdata);
    if (ret != 0) {
        CLIENT_LOG ("pthread_create failed");
        free(pdata);
        exit(1);
    }

    pthread_join(pid_send, NULL);
    pthread_join(pid_recv, NULL);
    free(pdata);
    return 0;
}