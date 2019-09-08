/*
Ehsan Aerabi 
2019
ED25519-256 Signature
*/
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
//#define WOLFSSL_USER_SETTINGS 
//#include <wolfssl/wolfcrypt/rsa.h>

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
#include <wolfssl/wolfcrypt/ed25519.h>
#include <wolfssl/wolfcrypt/error-crypt.h>
#define out_size 2048
#define in_size 128
#define HEAP_HINT NULL


int main(void)
{
	    uint32_t err_code;
char errorString[25];
  int ret = -1000;
    int verify;
    ed25519_key edKey;
    //ed25519_key edPrivateKey;
		RNG rng;	
    byte message[32] = "Thisismyfakeaeskeythatis32bytes!";
    byte sigOut[ED25519_SIG_SIZE];
    word32 sigOutSz = sizeof(sigOut);
		byte plain[32];
		//word32 outSz   = RSA_TEST_BYTES;	
		word32 plainSz = 32;



/*--------------- INIT KEYS ---------------------*/
    ret = wc_ed25519_init(&edKey);
   // ret = wc_ed25519_init(&edPrivateKey);
		wc_InitRng(&rng);
    if (ret != 0) {
        if(PRINTF_DEBUG)printf("Error: wc_ed25519_init: %d\n", ret);
    }

/*--------------- IMPORT KEYS FROM HEADER ---------------------*/
 //ret = wc_ed25519_import_public(ed_pub_key_der_32, sizeof_ed_pub_key_der_32,
																																	//  &edPublicKey);
		
		ret=wc_ed25519_make_key(&rng,32,&edKey);
    if (ret != 0) if(PRINTF_DEBUG)printf("Error: ED public key import failed: %d", ret);

 //   ret = wc_ed25519_import_private_key(ed_priv_key_der_64,
//                                        ED25519_KEY_SIZE,
  //                                      ed_priv_key_der_64 + ED25519_KEY_SIZE,
 //                                       ED25519_KEY_SIZE, &edPrivateKey);
    //if (ret != 0)  if(PRINTF_DEBUG)printf("Error: ED private key import failed: %d", ret);

	

 
		////////////////////////////////////////////////////////////////////////////
	if(PRINTF_DEBUG)printf("test");


    while (true)
    {
			ret = wc_ed25519_sign_msg(message, sizeof(message), sigOut, &sigOutSz,&edKey);
			wc_ErrorString(ret,errorString);
			if(PRINTF_DEBUG)printf("\r\nError: (%s): ",errorString);
			if(PRINTF_DEBUG)printf("\r\n\r\nSigniture (%d): ",ret);		
			for(int i=0; i<sigOutSz; i++){if(PRINTF_DEBUG)printf("%x",sigOut[i]);}
			
			
			ret = wc_ed25519_verify_msg(sigOut, sigOutSz, plain, sizeof(plain),&verify, &edKey);
			wc_ErrorString(ret,errorString);
			if(PRINTF_DEBUG)printf("\r\nError: (%s): ",errorString);
			if(PRINTF_DEBUG)printf("\r\nVerify: (%d): ",verify);		
			for(int i=0; i<sizeof(plain); i++){if(PRINTF_DEBUG)printf("%c",plain[i]);}	



    }
}


/** @} */
