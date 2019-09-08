/*
Ehsan Aerabi 
2019
RSA-PSS-2048
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
#define USE_CERT_BUFFERS_2048
#ifdef USE_CERT_BUFFERS_2048
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
#include <wolfssl/wolfcrypt/rsa.h>
#include <wolfssl/wolfcrypt/error-crypt.h>
#include <wolfssl/wolfcrypt/sha.h>
#define out_size 2048
#define in_size 128
#define HEAP_HINT NULL


int main(void)
{
	    uint32_t err_code;
	   int    ret;
  //  byte*  der = NULL;
//    byte*  pem = NULL;
    size_t bytes;
    WC_RNG rng;
		//Sha    sha;
    RsaKey key;
    word32 idx = 0;
//    byte*  res;
    word32 outSz   = RSA_TEST_BYTES;
    const word32 plainSz = RSA_TEST_BYTES;
    const byte in[] = "Thisismyfakeaeskeythatis32bytes!";
//		byte   hash[SHA_DIGEST_SIZE];
    word32 inLen = XSTRLEN((const char*)in);
		
 //   byte tmp[sizeof_client_key_der_1024];
		const unsigned char* tmp = client_key_der_2048; 
		bytes = (size_t)sizeof_client_key_der_2048;
    byte out[RSA_TEST_BYTES];
    byte plain[RSA_TEST_BYTES];
	
	char errorString[80];
    /* initialize stack structures */
    XMEMSET(&key, 0, sizeof(key));
    XMEMSET(&out, 0, sizeof(out));
    XMEMSET(&plain, 0, sizeof(plain));
		


    /* Copy in existing Public RSA key into "tmp" to use for decrypting */
//    XMEMCPY(tmp, client_keypub_der_1024, (size_t)sizeof_client_key_der_1024);
		//wc_InitSha(&sha);

		//wc_ShaUpdate(&sha, in, sizeof(in));
	//	wc_ShaFinal(&sha, hash);
    /* Initialize the RSA key structure */
//    ret = wc_InitRsaKey(&key, HEAP_HINT);
//    check_ret(ret, "wc_InitRsaKey_ex");
	 // if(PRINTF_DEBUG)printf("\r\n wc_InitRsaKey Error (%d): %s ",ret,errorString);
		
		ret = wc_InitRng(&rng);
    check_ret(ret, "wc_InitRng");																	
    
		/* Decode the public key from buffer "tmp" into RsaKey stucture "key"  */
//    ret = wc_RsaPublicKeyDecode(tmp, &idx, &key, (word32)bytes);
//    check_ret(ret, "wc_RsaPublicKeyDecode");	
 	 // if(PRINTF_DEBUG)printf("\r\n wc_RsaPublicKeyDecode Error (%d): %s ",ret,errorString);
		
    ret = wc_InitRsaKey(&key, HEAP_HINT);
    check_ret(ret, "wc_InitRsaKey_ex");
/* Copy in existing Client RSA key into "tmp" to use for decrypting */
   // XMEMCPY(tmp, rsa_key_der_1024, (size_t)sizeof_rsa_key_der_1024);
    ret = wc_RsaPrivateKeyDecode(tmp, &idx, &key, (word32)bytes);
    check_ret(ret, "wc_RsaPrivateKeyDecode");	
 	  //if(PRINTF_DEBUG)printf("\r\n wc_RsaPrivateKeyDecode Error (%d): %s ",ret,errorString);
		



		////////////////////////////////////////////////////////////////////////////
		if(PRINTF_DEBUG)printf("test");
		
		// Sign

		
			outSz = wc_RsaPSS_Sign(in, inLen, out, outSz,WC_HASH_TYPE_SHA, WC_MGF1SHA1, &key, &rng);
			wc_ErrorString(outSz,errorString);
			if(PRINTF_DEBUG)printf("\r\nwc_RSA  Sign: (%d): %s\r\n",outSz,errorString);		
			for(int i=0; i<ret; i++){if(PRINTF_DEBUG)printf("%x",out[i]);}
			
    while (true)
    {

			
			ret =wc_RsaPSS_Verify(out, outSz, plain, plainSz, WC_HASH_TYPE_SHA, WC_MGF1SHA1, &key);
			wc_ErrorString(ret,errorString);
			if(PRINTF_DEBUG)printf("\r\nwc_RSA  Verfiy: (%d): %s\r\n",ret,errorString);		
			for(int i=0; i<plainSz; i++){if(PRINTF_DEBUG)printf("%x",plain[i]);}


    }
}


/** @} */
