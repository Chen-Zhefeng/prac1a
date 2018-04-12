#include <string.h>
#include <stdio.h>
#include <ctype.h>
#include <openssl/evp.h>
#include <openssl/err.h>
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

unsigned char *Byte2Hex (const unsigned char* input, int inlen, bool with_new_line)
{
	int rv = 0;
	int i = 0, j = 0;
	unsigned char tmp = 0;
/*	if (outlen - 1 < inlen * 2)
	{
		fprintf(stderr, "Byte2Hex: output length(%d) is to short!", outlen);
		rv = -1;
		goto err;
	}
*/
	int outlen = 0;
	if (!with_new_line)
		outlen = inlen * 2 + 1;
	else
		outlen = inlen + inlen / 32 + 1;
	unsigned char *output = NULL;
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
	output[j] = '\0';

err:
    return output;
}

unsigned char *Hex2Byte (const unsigned char* input, int inlen, bool with_new_line)
{
    int i = 0, j = 0;
	unsigned char tmp = 0;
/*	if (outlen - 1  < inlen / 2)
	{
	    fprintf(stderr, "Hex2Byte: output length(%d) is to short!", outlen);
	    rv = -1;
		goto err;
	 }
*/	 
	int outlen = 0;
	if (!with_new_line)
		outlen = inlen / 2 + 1;
	else
		outlen = (inlen - (inlen / 65)) / 2 + 1;
	unsigned char *output = NULL;	
    if (!(output = (unsigned char*)malloc(outlen)))
	{
        fprintf(stderr, "Hex2Byte: function malloc fail");
		goto err;
	}
	for (; i < inlen; i += 2, ++j)
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
		    goto err;
	    }
		output[j] |= tmp;
        
		if(with_new_line)    //skip '\n'
		{
		    if (0 == (i + 3) % 65)
			    ++i;	
		}
	}
	output[j] = '\0';

err:
	return output;
}	

unsigned char * Base64Encode(const unsigned char * input, int length, bool with_new_line)  
{  
    BIO * bmem = NULL;  
    BIO * b64 = NULL;  
    BUF_MEM * bptr = NULL;  
  
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
  
    unsigned char * buff = (unsigned char *)malloc(bptr->length + 1);  
    memcpy(buff, bptr->data, bptr->length);  
    buff[bptr->length] = 0;  
  
    BIO_free_all(b64);  
  
    return buff;  
}  	

unsigned char* Base64Decode(const unsigned char *input, int length, bool with_new_line)
{
	BIO *b64 = NULL;
	BIO *bmem =NULL;
	unsigned char *buffer =(unsigned char*) malloc(length);
	memset(buffer, 0, length);

	b64 = BIO_new(BIO_f_base64());
    if (!with_new_line)
	{
		BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
	}
	bmem = BIO_new_mem_buf(input, length);
    bmem = BIO_push(b64, bmem);  //
	BIO_read(bmem, buffer, length);
    
	BIO_free_all(bmem);
	return buffer;
}


void Test_Cipher(const char *ciphername, const unsigned char *mess, int messlen)
{
	const char *cipher = ciphername;
    const unsigned char *szMess =  mess;
	const unsigned char aKey[32] = {1};
	const unsigned char iVec[16] = {0};

	int inlen = messlen;
	unsigned char encData[1024];
	int enclen = 0;
    int declen = 0;

    OpenSSL_Cipher(cipher, 1, aKey, iVec, szMess, inlen, encData, &enclen);
    
//	unsigned char *enchex = string_to_hex((const char*)encData, (long*)&enclen);
    unsigned char *hexEncode = NULL;
    if (!(hexEncode = Byte2Hex(encData, enclen, 0)))
        return;
	unsigned char *base64Encode = NULL;
	if (!(base64Encode = Base64Encode(encData, enclen, 0)))
		return;
	printf("\nciphername: %s\nmessage:%s\nmeslen:%d\n", ciphername, szMess, inlen);
	printf("-------------------encrypto-------------------------\n");
    printf("crypto text len(in byte): %d\n",  enclen);
	printf("crypto text with hex:\n0x%s\n", hexEncode);
	printf("crypto text with base64:\n%s\n",base64Encode);

	unsigned char *hexDecode = NULL;
	if (!(hexDecode = Hex2Byte (hexEncode, strlen((const char*)hexEncode), 0)))
		return;
    unsigned char *base64Decode = NULL;
	if (!(base64Decode = Base64Decode(base64Encode, strlen((const char*)base64Encode), 0)))
		return;
    unsigned char decData[1024];
    OpenSSL_Cipher(cipher, 0, aKey, iVec, hexDecode, strlen((const char*)hexDecode), decData, &declen);
	printf("-------------------decrypto-------------------------\n");
	printf("plain text decoded by hex: \n%s\nplain text len: %d\n", decData, declen);
    
	OpenSSL_Cipher(cipher, 0, aKey, iVec, base64Decode, strlen((const char*)base64Decode), decData, &declen);
	printf("plain text decoded by base64: \n%s\nplain text len: %d\n", decData, declen);
    
	free(hexEncode);
	free(hexDecode);
	free(base64Encode);
	free(base64Decode);
}



int main()
{
	OpenSSL_add_all_algorithms();
	const unsigned char szMess[] = "This is a test!This is a test!This is a test!This is a test!This is a test!This is a test!This is a test!";
	printf("Tests start!\n");
    Test_Cipher("des-ede-cbc", szMess, sizeof(szMess));
    Test_Cipher("aes-128-ofb", szMess, sizeof(szMess));
    Test_Cipher("rc4", szMess, sizeof(szMess));	
    //与OpenSSl_add_all_algorithms正好相反
	EVP_cleanup();
	printf("Tests end!\n");
	return 0;
}
