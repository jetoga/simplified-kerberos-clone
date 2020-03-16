#include "rsa.h"

int public_encrypt(void* source, int length, void* res)
{
	char public_key[1024];
	int result;
	int fd = open("public.pem", O_RDONLY);
	RSA* key = NULL;
	BIO* bio;
	
	if(fd < 0) return -1;
	if(read(fd, public_key, 1024) < 0) return -1;
	close(fd);
	
	bio = BIO_new_mem_buf(public_key, -1);
	if(bio == NULL)
		return 0;
	
	key = PEM_read_bio_RSA_PUBKEY(bio, NULL, NULL, NULL);
	
	result = RSA_public_encrypt(length, (const unsigned char*)source, (unsigned char*)res, key, RSA_PKCS1_PADDING);
	RSA_free(key);
	return result;
}

int private_decrypt(void* source, int length, void* res)
{
	char private_key[1024];
	int result;
	int fd = open("private.pem", O_RDONLY);
	RSA* key = NULL;
	BIO* bio;
	
	if(fd < 0) return -1;
	if(read(fd, private_key, 1024) < 0) return -1;
	close(fd);
	
	bio = BIO_new_mem_buf(private_key, -1);
	if(bio == NULL)
		return 0;
	
	key = PEM_read_bio_RSAPrivateKey(bio, NULL, NULL, NULL);
	
	result = RSA_private_decrypt(length, (const unsigned char*)source, (unsigned char*)res, key, RSA_PKCS1_PADDING);
	RSA_free(key);
	return result;
}

int sign(void* source, int length, void* res)
{
	char private_key[1024];
	int result;
	int fd = open("private.pem", O_RDONLY);
	RSA* key = NULL;
	BIO* bio;
	
	if(fd < 0) return -1;
	if(read(fd, private_key, 1024) < 0) return -1;
	close(fd);
	
	bio = BIO_new_mem_buf(private_key, -1);
	if(bio == NULL)
		return 0;
	
	key = PEM_read_bio_RSAPrivateKey(bio, NULL, NULL, NULL);
	
	result = RSA_private_encrypt(length, (const unsigned char*)source, (unsigned char*)res, key, RSA_PKCS1_PADDING);
	RSA_free(key);
	return result;
}

int verify(void* source, int length, void* res)
{
	char public_key[1024];
	int result;
	int fd = open("public.pem", O_RDONLY);
	RSA* key = NULL;
	BIO* bio;
	
	if(fd < 0) return -1;
	if(read(fd, public_key, 1024) < 0) return -1;
	close(fd);
	
	bio = BIO_new_mem_buf(public_key, -1);
	if(bio == NULL)
		return 0;
	
	key = PEM_read_bio_RSA_PUBKEY(bio, NULL, NULL, NULL);
	
	result = RSA_public_decrypt(length, (const unsigned char*)source, (unsigned char*)res, key, RSA_PKCS1_PADDING);
	RSA_free(key);
	return result;
}