#ifndef RSA_H
#define RSA_H

#include <unistd.h>
#include <fcntl.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/rsa.h>
#include <openssl/evp.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <stdio.h>

int public_encrypt(void* source, int length, void* res);

int private_decrypt(void* source, int length, void* res);

int sign(void* source, int length, void* res);

int verify(void* source, int length, void* res);

#endif
