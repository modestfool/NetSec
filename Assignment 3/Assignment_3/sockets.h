#ifndef SOCKETS
#define SOCKETS
int start_server(const char *,
                              const char *,
                              int server_port, int listen_port);
int start_client(const char * mykey,
                              const char * server_addr, int port);
#endif