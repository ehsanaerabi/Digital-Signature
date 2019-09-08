/*
Ehsan Aerabi 
2019
ECDSA-384
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
#define RSA_TEST_BYTES 128 /* 256 bytes * 8 = 2048-bit key length */
#define AES_KEY_SZ 32 /* 32*8 = 256-bit AES KEY */
#define HEAP_HINT NULL
#include <wolfssl/wolfcrypt/ecc.h>
#include <wolfssl/wolfcrypt/error-crypt.h>
#define out_size 2048
#define in_size 128
#define HEAP_HINT NULL


int main(void)
{
	    uint32_t err_code;
	   int    ret,state;
ecc_key key;
RNG rng;
int check_result;
char errorString[25];	
const byte in[48] = "Thisismyfakeaeskeythatis32bytes!";
byte out[RSA_TEST_BYTES];
byte plain[RSA_TEST_BYTES];
word32 outSz   = RSA_TEST_BYTES;	
word32 plainSz = RSA_TEST_BYTES;
	
wc_ecc_init(&key);
wc_InitRng(&rng);
check_result = wc_ecc_make_key(&rng, 32, &key);
//check_result = wc_ecc_check_key(&key);


if (check_result == MP_OKAY)
{
   if(PRINTF_DEBUG)printf("\r\nKey successfully generated.");
}
else
{
      if(PRINTF_DEBUG)printf("\r\nKey generation failed!");
}
	

		////////////////////////////////////////////////////////////////////////////
	if(PRINTF_DEBUG)printf("test");
    while (true)
    {
			ret = wc_ecc_sign_hash(in,sizeof(in) , out, &outSz,&rng ,&key);
			wc_ErrorString(ret,errorString);
			if(PRINTF_DEBUG)printf("\r\nError: (%s): ",errorString);
			if(PRINTF_DEBUG)printf("\r\n\r\nSigned (%d): ",ret);		
			for(int i=0; i<outSz; i++){if(PRINTF_DEBUG)printf("%x",out[i]);}
			wc_FreeRng(&rng);
			wc_InitRng(&rng);

			ret = wc_ecc_verify_hash( out, outSz,plain,plainSz ,&state ,&key);
			wc_ErrorString(ret,errorString);
			if(PRINTF_DEBUG)printf("\r\nError: (%s): ",errorString);
			if(PRINTF_DEBUG)printf("\r\nVerified: (%d): ",state);		
			for(int i=0; i<plainSz; i++){if(PRINTF_DEBUG)printf("%c",plain[i]);}	



    }
}

