#ifndef AES_INIT
#define AES_INIT
#include <openssl/aes.h>
#include <string.h>

#define MAX_PACKET_LEN 1024*20
#define KEY_LEN 256

/* With the help of: http://stackoverflow.com/questions/3141860/aes-ctr-256-encryption-mode-of-operation-on-openssl */
struct ctr_state {
    /* ivec[0..7] is the IV, ivec[8..15] is the big-endian counter */
    unsigned char ivec[16];  
    unsigned int num;
    unsigned char ecount[16];
};
void init_ctr(struct ctr_state *state, const unsigned char iv[8]);
#endif
