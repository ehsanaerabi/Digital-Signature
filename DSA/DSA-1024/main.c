/*
Ehsan Aerabi 
2019
DSA-1024
*/

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>

#define uchar unsigned char // 8-bit byte
#define uint unsigned long // 32-bit word
#define KE_ROTWORD(x) ( ((x) << 8) | ((x) >> 24) )
#define PRINTF_DEBUG 0


///////////////////////////////////////////////////////////////////////////////////////////
//#include "RSAkeys.h"
/* certs_test.h contains der formatted key buffer rsa_key_der_2048 */
#define USE_CERT_BUFFERS_1024
#ifdef USE_CERT_BUFFERS_1024
#include <wolfssl/certs_test.h>
#else
    #error "Please define USE_CERT_BUFFERS_2048 when building wolfSSL!"
#endif


void check_ret(int val, char* fail)
{
    if (val < 0) {
        if(PRINTF_DEBUG)printf("%s Failed with error %d\n", fail, val);
      //  exit(-99);
    }
    return;
}
#define RSA_TEST_BYTES 256 /* 256 bytes * 8 = 2048-bit key length */
#define AES_KEY_SZ 32 /* 32*8 = 256-bit AES KEY */
#define HEAP_HINT NULL
#include <wolfssl/wolfcrypt/dsa.h>
#include <wolfssl/wolfcrypt/sha.h>
#include <wolfssl/wolfcrypt/error-crypt.h>
#define out_size 2048
#define in_size 128
#define HEAP_HINT NULL


int main(void)
{
	
	    uint32_t err_code;
	char errorString[80];

int ret;			
DsaKey key;

byte   message[RSA_TEST_BYTES]      = "Thisismyfakeaeskeythatis32bytes!";

const unsigned char*   dsaKeyBuffer = dsa_key_der_1024;//{ /*holds the raw data from the DSA key, maybe from a file like dsa512.der*/ };

Sha    sha;

RNG    rng;

byte   hash[SHA_DIGEST_SIZE];

byte   signature[40];

word32 idx = 0;

int    answer;
wc_InitSha(&sha);


wc_InitDsaKey(&key);

wc_DsaPrivateKeyDecode(dsaKeyBuffer, &idx, &key, sizeof_dsa_key_der_1024);

wc_InitRng(&rng);	

	wc_ErrorString(ret,errorString);
	if(PRINTF_DEBUG)printf("\r\nGenerate B Error: (%d): %s",ret,errorString);
	

		


		////////////////////////////////////////////////////////////////////////////
	if(PRINTF_DEBUG)printf("test");
    while (true)
    {
			if(PRINTF_DEBUG)printf("\r\nmessage:  %s",message);
			wc_ShaUpdate(&sha, message, sizeof(message));

			wc_ShaFinal(&sha, hash);
			if(PRINTF_DEBUG)printf("\r\nhash:  %s",hash);
	
			ret = wc_DsaSign(hash, signature, &key, &rng);
			wc_ErrorString(ret,errorString);
			if(PRINTF_DEBUG)printf("\r\nwc_DsaSign: (%d): %s",ret,errorString);

			ret = wc_DsaVerify(hash, signature, &key, &answer);
			if(PRINTF_DEBUG)printf("\r\nwc_DsaVerify: (%d): %d",ret,answer);


    }
}


