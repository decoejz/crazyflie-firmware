// https://docs.openssl.org/3.2/man3/EVP_PKEY_new/#description#include <openssl/evp.h>

#include "eddsa.h"

int key_gen_eddsa(const char *secret_name, const char *public_name)
{
    FIL pk_file, sk_file;
    EVP_PKEY *pkey = NULL;
    EVP_PKEY_CTX *pctx = NULL;
    FRESULT fr;

    pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_ED25519, NULL);
    if (!pctx)
    {
        log_error("EVP_PKEY_CTX_new_id failed\n");
        return -1;
    }

    if (EVP_PKEY_keygen_init(pctx) <= 0)
    {
        log_error("EVP_PKEY_keygen_init failed\n");
        return -1;
    }

    // Generate keys
    if (EVP_PKEY_keygen(pctx, &pkey) <= 0)
    {
        log_error("EVP_PKEY_keygen failed\n");
        return -1;
    }

    // Write secret key
    fr = f_open(&sk_file, secret_name, FA_WRITE | FA_CREATE_ALWAYS); // secret key file
    if (fr == FR_OK)
    {
        BIO *bio = BIO_new(BIO_s_mem());
        if (!bio || !PEM_write_bio_PrivateKey(bio, pkey, NULL, NULL, 0, NULL, NULL)) {
            log_error("PEM_write_bio_PrivateKey failed");
        } else {
            char *data;
            long len = BIO_get_mem_data(bio, &data);
            UINT bw;
            f_write(&sk_file, data, len, &bw);
        }
        BIO_free(bio);
        f_close(&sk_file);
    }
    else
    {
        log_error("Could not open secret key file");
        EVP_PKEY_free(pkey);
        EVP_PKEY_CTX_free(pctx);
        return -1;
    }

    // Write Public key
    fr = f_open(&pk_file, public_name, FA_WRITE | FA_CREATE_ALWAYS); // public key file
    if (fr == FR_OK)
    {
        BIO *bio = BIO_new(BIO_s_mem());
        if (!bio || !PEM_write_bio_PUBKEY(bio, pkey)) {
            log_error("PEM_write_bio_PUBKEY failed");
        } else {
            char *data;
            long len = BIO_get_mem_data(bio, &data);
            UINT bw;
            f_write(&pk_file, data, len, &bw);
        }
        BIO_free(bio);
        f_close(&pk_file);
    }
    else
    {
        log_error("Could not open public key file");
        EVP_PKEY_free(pkey);
        EVP_PKEY_CTX_free(pctx);
        return -1;
    }

    // End program
    EVP_PKEY_free(pkey);
    EVP_PKEY_CTX_free(pctx);
    EVP_cleanup();

    return 1;
}