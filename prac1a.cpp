#include <string.h>
#include <stdio.h>
#include <ctype.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/hmac.h>
#include <openssl/x509v3.h>

using namespace std;


int OpenSSL_Cipher(const char *ciphername, int dir, const unsigned char *aKey, 
		const unsigned char * iVec, const unsigned char *in, int inlen, unsigned char
		*out, int *poutlen)
{
	int rv = 0, n = 0, tmplen =0;
	char szErr[1024];

	const EVP_CIPHER *cipher = NULL;
	EVP_CIPHER_CTX ctx;

	/*初始化对称加密的上下文*/
	EVP_CIPHER_CTX_init(&ctx);

    /*根据名称获取CIPHER对象*/
	cipher = EVP_get_cipherbyname(ciphername);
	if (NULL == cipher)
	{
		fprintf(stderr, "OpenSSL_Cipher: Cipher for %s is NULL\n", ciphername);
		
		rv = -1;
		goto err;
	}

	/*
	 * 初始化算法：设置算法密钥，IV，以及加解密标志位dir
	 * 如果使用Engine，此时会调用其实现的EVP_CIPHER->init回调函数
	 */
	if (!EVP_CipherInit_ex(&ctx, cipher, NULL, aKey, iVec, dir))  //最后一个参数，1表示加密，0表示解密
	{
		n = ERR_get_error();
		ERR_error_string(n, szErr);
		fprintf(stderr, "OpenSSL_Cipher: EVP_CipherInit failed: \nopenssl return %d, %s\n", n, szErr);

		rv = -2;
		goto err;
	}

    /*
	 * 对数据进行加/解密(如果使用Engine，此时会调用其实现的EVP_CIPHER->do_cipher回调函数)
	 * 对于连续数据流，CipherUpdate一般会被调用多次
	 */

	if (!EVP_CipherUpdate(&ctx, out, poutlen, in, inlen)) 
	{
		n = ERR_get_error();
		fprintf(stderr, "OpenSSL_Cipher: EVP_CipherInit failed: \nopenssl return %d, %s\n", n, szErr);

		rv = -3;
		goto err;
	}

	/**
	*输出最后一块数据（块加密时，数据将被padding到block长度的整数倍，因此会产生额外的最后一段数据）
	*注意：如果使用Engine，此时会触发其实现的EVP_CIPHER->do_cipher，而不是EVP_CIPHER->cleanup
	*这点上与EVP_DigestFinal/EVP_SignFinal/EVP_VerifyFinal是完全不同的
	*/	
	if (!EVP_CipherFinal(&ctx, out + *poutlen, &tmplen)) 
	{
		n  = ERR_get_error();
		ERR_error_string( n, szErr );

		fprintf( stderr, "OpenSSL_Cipher: EVP_CipherInit failed: \nopenssl return %d, %s\n", n, szErr );

		rv = -4;
		goto err;
	}

	*poutlen += tmplen;
				
err:	
	/* 释放上下文（如果使用Engine，此时会调用其实现的EVP_CIPHER->cleanup回调函数） */	
	EVP_CIPHER_CTX_cleanup(&ctx);

	return rv;

}

int OpenSSL_Digest(  const char *digestname, 
                            const unsigned char *in, int inlen,
                            unsigned char *out, unsigned int *poutlen)
{
    int rv = 0, n = 0;
    char szErr[1024];

    EVP_MD_CTX ctx;
    const EVP_MD *md = NULL;

    /* 初始化摘要计算上下文 */
    EVP_MD_CTX_init(&ctx);

    /* 根据摘要算法名称（如md5，sha1）获取摘要对象，使用openssl dgst -h命令可以查看支持的摘要算法名） */
    md = EVP_get_digestbyname(digestname);
    if (NULL == md) {
        fprintf( stderr, "OpenSSL_Digest: Digest for %s is NULL\n", digestname );

        rv = -1;
        goto err;
    }

    /* 初始化摘要算法（如果使用Engine，此时会触发其实现的EVP_MD->init回调函数） */
    if (!EVP_DigestInit(&ctx, md)) {
        n  = ERR_get_error();
        ERR_error_string( n, szErr );

        fprintf( stderr, "OpenSSL_Cipher: EVP_DigestInit failed: \nopenssl return %d, %s\n", n, szErr );

        rv = -2;
        goto err;
    }

    /**
 *      * 计算摘要（如果使用Engine，此时会触发其实现的EVP_MD->update回调函数）
 *           * 对于连续的数据流，EVP_DigestUpdate一般会被调用多次 
 *                */
    if (!EVP_DigestUpdate(&ctx, in, inlen)) {
        n  = ERR_get_error();
        ERR_error_string( n, szErr );

        fprintf( stderr, "OpenSSL_Cipher: EVP_DigestUpdate failed: \nopenssl return %d, %s\n", n, szErr );

        rv = -3;
            goto err;
    }

    /* 输出摘要计算结果（如果使用Engine，此时会触发其实现的EVP_MD->cleanup回调函数） */
    if (!EVP_DigestFinal(&ctx, out, poutlen)) {
        n  = ERR_get_error();
        ERR_error_string( n, szErr );

        fprintf( stderr, "OpenSSL_Cipher: EVP_DigestFinal failed: \nopenssl return %d, %s\n", n, szErr );

        rv = -4;
            goto err;
    }

err:    
    /* 释放摘要计算上下文 */
    EVP_MD_CTX_cleanup(&ctx);

    return rv;
}

int OpenSSL_HMAC(const char *algor, const unsigned char * key,
	 const unsigned char *input, unsigned int inlen,
	 unsigned  char *output, unsigned int *poutlen)
{
    int rv = 0, n =0;
    const EVP_MD *digest = NULL;
    char szErr[1024];
    HMAC_CTX ctx;  
    HMAC_CTX_init(&ctx);    
    digest = EVP_get_digestbyname(algor);
    if (NULL == digest) 
    {
        fprintf( stderr, "OpenSSL_HMAC: Digest for %s is NULL\n", digest );
        rv = -1;
        goto err;
    }
    printf("key length:%d\n", strlen((const char*)key));
    if (!HMAC_Init_ex(&ctx, key, strlen((const char*)key), digest, NULL)) 
    {
        n  = ERR_get_error();
        ERR_error_string( n, szErr );
        fprintf( stderr, "OpenSSL_HMAC: HMAC_Init_ex failed: \nopenssl return %d, %s\n", n, szErr );

        rv = -2;
        goto err;
    }
 
   if (!HMAC_Update(&ctx, input, inlen)) 
   {
        n  = ERR_get_error();
        ERR_error_string( n, szErr );

        fprintf( stderr, "OpenSSL_HMAC: HMAC_Update failed: \nopenssl return %d, %s\n", n, szErr );

        rv = -3;
        goto err;
    }

    if (!HMAC_Final(&ctx, output, poutlen)) 
    {
        n  = ERR_get_error();
        ERR_error_string( n, szErr );

        fprintf( stderr, "OpenSSL_HMAC: HMAC_Final failed: \nopenssl return %d, %s\n", n, szErr );

        rv = -4;
        goto err;
    }


err:
    HMAC_CTX_cleanup(&ctx);
    return rv;
}

unsigned char *Byte2Hex (const unsigned char* input, int inlen, bool with_new_line)
{
	int rv = 0;
	int i = 0, j = 0;
	unsigned char tmp = 0;
    unsigned char *output = NULL;
    int outlen = 0;
/*	if (outlen - 1 < inlen * 2)
	{
		fprintf(stderr, "Byte2Hex: output length(%d) is to short!", outlen);
		rv = -1;
		goto err;
	}
*/
    if (!input)
	{
       	fprintf(stderr, "Byte2Hex: input null pointer!");
	    goto err;
	}
	
	if (!with_new_line)
	    outlen = inlen * 2 + 1;
	else 
        outlen = inlen * 2 + inlen / 32 + 1 + ((inlen * 2 ) % 64 != 0);
	

	if (!(output = (unsigned char*)malloc(outlen)))
	{
        fprintf(stderr, "Byte2Hex: function malloc fail");
		goto err;
	}	
	for (; i < inlen; ++i) 
    {
		tmp = (input[i] & 0xF0) >> 4;
		if(tmp < 10)
            output[j++] = tmp + '0';
		else
			output[j++] = tmp - 0x0A + 'A';
		
		tmp = (input[i] & 0x0F);
	    if(tmp < 10)
		    output[j++] = tmp + '0';
		else
	 	    output[j++] = tmp - 0x0A + 'A';
        if (with_new_line)
		{
            if (0 == (j+1) % 65)    //every 64-character, new line
               output[j++] = '\n';
		}
	}
	if (with_new_line && j % 65 != 0)
	    output[j++] = '\n';
	output[j] = '\0';

err:
    return output;
}

//Note: piolen is a input&output para
unsigned char *Hex2Byte (const unsigned char* input, int *piolen, bool with_new_line)
{
    int i = 0, j = 0;
	unsigned char tmp = 0;
    unsigned char *output = NULL;
    int outlen = 0;
    int reallen = *piolen - *piolen / 65 - (*piolen % 65 != 0);
         if (!input)
	{
       	    fprintf(stderr, "Hex2Byte: input null pointer!");
	    goto err;
	}
        if (!with_new_line)
	{
            if (*piolen % 2 == 1)
            {
 		fprintf(stderr, "Hex2Byte: intput length error!");
		goto err;
	    }
	}
	else
	{
	     if (reallen % 2 == 1)
            {
 		fprintf(stderr, "Hex2Byte: intput length error!");
		goto err;
	    } 
	}
/*	if (outlen - 1  < inlen / 2)
	{
	    fprintf(stderr, "Hex2Byte: output length(%d) is to short!", outlen);
	    rv = -1;
		goto err;
	 }
*/	 
	if (!with_new_line)
		outlen = *piolen / 2;
	else
		outlen = reallen / 2;

    if (!(output = (unsigned char*)malloc(outlen)))
	{
        fprintf(stderr, "Hex2Byte: function malloc fail");
		goto err;
	}
        if (with_new_line && *piolen % 65 != 0)  //ignore the last ‘\n’
		--(*piolen); 
	for (; i < *piolen; i += 2, ++j)
	{
        tmp = input[i];
		if (tmp >= '0' && tmp <= '9')
		{
			tmp -= '0';
		}
		else if (tmp >= 'a' && tmp <='z' || tmp >= 'A' && tmp <= 'Z')
		{
			tmp = (unsigned char)toupper((int)tmp) - 'A' + 0x0A;
		}
		else
		{
			fprintf(stderr, "Hex2Byte: input format error!");
                        free(output);
			output = NULL;
			goto err;
		}
		output[j] = (tmp << 4);

		tmp = input[i+1];
	    if (tmp >= '0' && tmp <= '9')
	    {
			tmp -= '0';
		}
	    else if (tmp >= 'a' && tmp <='z' || tmp >= 'A' && tmp <= 'Z')
	    {
			tmp = (unsigned char)toupper((int)tmp) - 'A' + 0x0A;
		}
        else
		{
		    fprintf(stderr, "Hex2Byte: input format error!");
		    free(output);
		    output = NULL;
		    goto err;
	    }
		output[j] |= tmp;
        
		if(with_new_line)    //skip '\n'
		{
		    if (0 == (i + 3) % 65)
			    ++i;	
		}
	}
        *piolen = outlen;
//dont need anymore
//	output[j] = '\0';

err:
	return output;
}	

unsigned char * Base64Encode(const unsigned char * input, int length, bool with_new_line)  
{  
    BIO * bmem = NULL;  
    BIO * b64 = NULL;  
    BUF_MEM * bptr = NULL;  
    unsigned char *buff = NULL;
    if(!input)
    {	
       	fprintf(stderr, "Base64Encode: input is null pointer!");
	goto err;
    }

    b64 = BIO_new(BIO_f_base64());  
    if (!with_new_line)
   	{  
	        BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);  
	}  
    bmem = BIO_new(BIO_s_mem());  
    b64 = BIO_push(b64, bmem);  //形成BIO链
    BIO_write(b64, input, length);  
    BIO_flush(b64);  
    BIO_get_mem_ptr(b64, &bptr);  
  
    if (!(buff = (unsigned char *)malloc(bptr->length + 1))) 
    {
        fprintf(stderr, "Hex2Byte: function malloc fail");
        BIO_free_all(b64);
		goto err;
    }
    memcpy(buff, bptr->data, bptr->length);  
    buff[bptr->length] = 0;  
    
    BIO_free_all(b64);  
err:  
    return buff;  
}  	

//Note: piolen is a input&output para
unsigned char* Base64Decode(const unsigned char *input, int* piolen, bool with_new_line)
{
	BIO *b64 = NULL;
	BIO *bmem =NULL;
    int outlen = 0;
	unsigned char *buffer = NULL;
    int reallen = *piolen - *piolen / 65 - (*piolen % 65 != 0);
    if(!input)
	{	
       	fprintf(stderr, "Base64Decode: input null pointer!");
		goto err;
    }
    if (!with_new_line)
	{
        if (*piolen % 4 != 0)
        {
 		    fprintf(stderr, "Base64Decode: intput length error!");
		    goto err;
	    }
	}
	else
	{
	    if (reallen  % 4 != 0)
        {
 		    fprintf(stderr, "Base64Decode: intput length error!");
		    goto err;
	    } 
	}

    if (!with_new_line)
    {
        outlen = *piolen / 4 * 3;
        if ('=' == input[*piolen -1])
        {
            --outlen;
		    if ('=' == input[*piolen - 2])
		    --outlen;
        }
    }
	else
	{
	    outlen = reallen / 4 * 3;
	    if ('\n' == input[*piolen -1])
	    {
	    	if ('=' == input[*piolen -2])
		{
		    --outlen;
		    if('=' == input[*piolen - 3])
			--outlen;
		}
	    }
	    else if ('=' == input[*piolen -1])
	    {
		    --outlen;
		    if('=' == input[*piolen - 2])
		    --outlen;
	    }
    }
         //malloc size can not be too small
    if(!(buffer =(unsigned char*) malloc(outlen)))
    {
        fprintf(stderr, "Base64Decode: function malloc fail");
	    goto err;
	}
    memset(buffer, 0, outlen);

	b64 = BIO_new(BIO_f_base64());
    if (!with_new_line)
	{
		BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
	}
	bmem = BIO_new_mem_buf(input, *piolen);
    b64 = BIO_push(b64, bmem);  //
        //之前由于把最后一个空格干掉了，导致b64转换错误
  	BIO_read(b64, buffer, outlen);
    
	BIO_free_all(b64);
    *piolen = outlen;
err:	
	return buffer;
}


void Test_Cipher(const char *ciphername, const unsigned char *mess, int messlen,  bool with_new_line)
{
	const char *cipher = ciphername;
    const unsigned char *szMess =  mess;
	unsigned char aKey[64];
    for(int i=0 ; i<64; ++i)
	    aKey[i] = 63-i;
	const unsigned char iVec[16] = {0};

	int inlen = messlen;
	unsigned char encData[1024] = {0};
	unsigned char decData[1024] = {0};
    int enclen = 0;
    int declen = 0;
    unsigned char *hexEncode = NULL;
 	unsigned char *base64Encode = NULL;
   	unsigned char *hexDecode = NULL;
    unsigned char *base64Decode = NULL;
    int hexlen = 0;
    int base64len = 0;
   
    if (OpenSSL_Cipher(cipher, 1, aKey, iVec, szMess, inlen, encData, &enclen))
        return;
    
//	unsigned char *enchex = string_to_hex((const char*)encData, (long*)&enclen);
   
    if (!(hexEncode = Byte2Hex(encData, enclen, with_new_line)))
        return;
	
	if (!(base64Encode = Base64Encode(encData, enclen, with_new_line)))
        goto err;
	printf("\nciphername: %s\nmessage:%s\nmeslen:%d\n", cipher, szMess, inlen);
	printf("-------------------encrypto-------------------------\n");
    printf("crypto text len(in byte): %d\n",  enclen);
	printf("crypto text with hex:\n%s\n", hexEncode);
	printf("crypto text with base64:\n%s\n",base64Encode);
    printf("after transform:%d %d\n",strlen((const char*)hexEncode), strlen((const char*)base64Encode));
   
	
    hexlen = strlen((const char*)hexEncode);
	if (!(hexDecode = Hex2Byte (hexEncode, &hexlen, with_new_line)))
	    goto err;
       
    
    base64len = strlen((const char*)base64Encode);
	if (!(base64Decode = Base64Decode(base64Encode, &base64len, with_new_line)))
	    goto err; 
	printf("after recover:%d %d\n", hexlen, base64len);
       
    if (OpenSSL_Cipher(cipher, 0, aKey, iVec, hexDecode, hexlen, decData, &declen))
	    goto err;
	printf("-------------------decrypto-------------------------\n");
	printf("plain text decoded by hex: \n%s\nplain text len: %d\n", decData, declen);
    
    if(OpenSSL_Cipher(cipher, 0, aKey, iVec, base64Decode, base64len, decData, &declen))
	    goto err;
	printf("plain text decoded by base64: \n%s\nplain text len: %d\n", decData, declen);
    
err:
    if(!hexEncode)
	    free(hexEncode);
	if(!hexDecode)
	    free(hexDecode);
	if(!base64Encode)
	    free(base64Encode);
	if(!base64Decode)
	    free(base64Decode);
}

void Test_Digest(const char *digestname, const unsigned char *mess, int messlen, bool with_new_line)
{
    const char *digest = digestname;
    const unsigned char *szMess =  mess;
	int inlen = messlen;
	unsigned char encData[1024] = {0};
    unsigned int enclen = 0;
    unsigned char *hexEncode = NULL;
 	unsigned char *base64Encode = NULL;
   	  

    if ( OpenSSL_Digest(digest, szMess, inlen, encData, &enclen))
 	   return;
	printf("\ndigestname: %s\nmessage:%s\nmeslen:%d\n", digest, szMess, inlen);
        if (!(hexEncode = Byte2Hex(encData, enclen, with_new_line)))
            return;
	
	if (!(base64Encode = Base64Encode(encData, enclen, with_new_line)))
        goto err;
	
    printf("digest len(in byte): %d\n",  enclen);
	printf("digest with format of hex :\n%s\n", hexEncode);
	printf("cro with format of  base64:\n%s\n",base64Encode);
    printf("digest len(hex&&base64):%d %d\n",strlen((const char*)hexEncode), strlen((const char*)base64Encode));
   
err:
    if(!hexEncode)
	    free(hexEncode);
	if(!base64Encode)
	    free(base64Encode);
	
}

void Test_HMAC(const char *algor, const unsigned char *mess, int messlen, bool with_new_line)
{
    const char *digest = algor;
    const unsigned char *szMess =  mess;
	int inlen = messlen;
	unsigned char aKey[65];
    for(int i=0 ; i<65; ++i)
	    aKey[i] = 64 - i;
	unsigned char encData[1024] = {0};
    unsigned int enclen = 0;
    unsigned char *hexEncode = NULL;
 	unsigned char *base64Encode = NULL;
   	  

    if ( OpenSSL_HMAC(digest, aKey, szMess, inlen, encData, &enclen))
 	    return;
	printf("\ndigestname: %s\nmessage:%s\nmeslen:%d\n", digest, szMess, inlen);
    if (!(hexEncode = Byte2Hex(encData, enclen, with_new_line)))
        return;
	
	if (!(base64Encode = Base64Encode(encData, enclen, with_new_line)))
        goto err;
	
    printf("hmac len(in byte): %d\n",  enclen);
	printf("hmac with format of hex :\n%s\n", hexEncode);
	printf("hmac with format of  base64:\n%s\n",base64Encode);
    printf("hmac len(hex&&base64):%d %d\n",strlen((const char*)hexEncode), strlen((const char*)base64Encode));
   
err:
    if(!hexEncode)
	    free(hexEncode);
	if(!base64Encode)
	    free(base64Encode);
	
}

void TestCore(const unsigned char* szMess)
{
	OpenSSL_add_all_algorithms();
	printf("\n----------------------without new line!-----------------------\n"); 
    Test_Cipher("des-ede-cbc", szMess, strlen((const char*)szMess), 0);
    Test_Cipher("aes-128-ofb", szMess, strlen((const char*)szMess), 0);
    Test_Cipher("rc4", szMess, strlen((const char*)szMess), 0);
	Test_Digest("md5", szMess, strlen((const char*)szMess), 0);
	Test_Digest("sha1", szMess, strlen((const char*)szMess), 0);
	Test_HMAC("md5", szMess, strlen((const char*)szMess), 0);
    Test_HMAC("sha1", szMess, strlen((const char*)szMess), 0);
        
	printf("\n-----------------------with new line!-------------------------\n"); 
    Test_Cipher("des-ede-cbc", szMess, strlen((const char*)szMess), 1);
    Test_Cipher("aes-128-ofb", szMess, strlen((const char*)szMess), 1);
    Test_Cipher("rc4", szMess, strlen((const char*)szMess), 1);
	Test_Digest("md5", szMess, strlen((const char*)szMess), 1);
	Test_Digest("sha1", szMess, strlen((const char*)szMess), 1);  
    Test_HMAC("md5", szMess, strlen((const char*)szMess), 1);
    Test_HMAC("sha1", szMess, strlen((const char*)szMess), 1);
    
   //与OpenSSl_add_all_algorithms正好相反
	EVP_cleanup();
}
void Tests1()
{ 
	printf("\n-----------------------------------------------------------------------\n");  
    printf("----------------------------Tests1 start!------------------------------\n");  
    printf("-----------------------------------------------------------------------\n"); 
	const unsigned char szMess[] = "";
	TestCore(szMess);
	
	printf("-----------------------------------------------------------------------\n");
    printf("-----------------------------Tests1 end!-------------------------------\n");
    printf("-----------------------------------------------------------------------\n\n");       
}
void Tests2()
{  	
	printf("\n-----------------------------------------------------------------------\n");  
    printf("----------------------------Tests2 start!------------------------------\n");  
    printf("-----------------------------------------------------------------------\n"); 
	
	const unsigned char szMess[] = "T";
	TestCore(szMess);
	printf("-----------------------------------------------------------------------\n");
    printf("-----------------------------Tests2 end!-------------------------------\n");
    printf("-----------------------------------------------------------------------\n\n");  
}
void Tests3()
{  	
	printf("\n-----------------------------------------------------------------------\n");  
    printf("----------------------------Tests3 start!------------------------------\n");  
    printf("-----------------------------------------------------------------------\n"); 
	
	const unsigned char szMess[] = "Th";
	TestCore(szMess);
	printf("-----------------------------------------------------------------------\n");
    printf("-----------------------------Tests3 end!-------------------------------\n");
    printf("-----------------------------------------------------------------------\n\n");  
}

void Tests4()
{  
	printf("\n----------------------------------------------------------------------\n");  
    printf("----------------------------Tests4 start!------------------------------\n");  
    printf("-----------------------------------------------------------------------\n"); 
	
	const unsigned char szMess[] = "This is a test!This is a test!This is a test!This is a test!This is a test!This is a test!This ";	
	TestCore(szMess);
	printf("-----------------------------------------------------------------------\n");
    printf("-----------------------------Tests4 end!-------------------------------\n");
    printf("-----------------------------------------------------------------------\n\n");  
}

void Tests5()
{  
	printf("\n----------------------------------------------------------------------\n");  
    printf("----------------------------Tests5 start!------------------------------\n");  
    printf("-----------------------------------------------------------------------\n"); 
	
	const unsigned char szMess[] = "This is a test!This is a test!This is a test!This is a test!This is a test!This is a test!This i";
	TestCore(szMess);
	printf("-----------------------------------------------------------------------\n");
    printf("-----------------------------Tests5 end!-------------------------------\n");
    printf("-----------------------------------------------------------------------\n\n");
}


void Tests6()
{  
	printf("\n----------------------------------------------------------------------\n");  
    printf("----------------------------Tests6 start!------------------------------\n");  
    printf("-----------------------------------------------------------------------\n"); 
	
	const unsigned char szMess[] = "This is a test!This is a test!This is a test!This is a test!This is a test!This is a test!This is";
	TestCore(szMess);
	printf("-----------------------------------------------------------------------\n");
    printf("-----------------------------Tests6 end!-------------------------------\n");
    printf("-----------------------------------------------------------------------\n\n");

}


int main()
{
    Tests1();
    Tests2();
	Tests3();
    Tests4();	
    Tests5();
    Tests6();
	return 0;
}
