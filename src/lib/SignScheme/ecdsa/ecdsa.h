#ifndef ECDSA_H
#define ECDSA_H

// https://docs.openssl.org/3.0/man7/EVP_SIGNATURE-ECDSA/

#ifdef __cplusplus
extern "C"
{
#endif

#include <stdlib.h>
#include <string.h>
#include "ff.h"        
#include "diskio.h"
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/ec.h>
#include "helper/util_sign.h"
#include "helper/helper.h"
#include "helper/io.h" 

int key_gen_ecdsa(const char *secret_name, const char *public_name);
pki_t read_key_ecdsa(char load_type, const char *file_name);

int verify_ecdsa(uint8_t *msg_raw, uint8_t *msg_signed, int total_len, pki_t public_key);
int sign_ecdsa(uint8_t *msg_signed, uint8_t *msg_raw, unsigned int msg_len, pki_t secret_key);

#ifdef __cplusplus
}
#endif

#endif // ECDSA_H