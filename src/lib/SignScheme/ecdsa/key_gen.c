// https://docs.openssl.org/3.0/man7/EVP_PKEY-EC/

#include "ecdsa.h"

int key_gen_ecdsa(const char *secret_name, const char *public_name)
{
    FIL pk_file, sk_file;
    FRESULT fr;

    // Generate keys
    EVP_PKEY *pkey = EVP_EC_gen("P-256");
    if (pkey == NULL)
    {
        log_error("ECDSA key generation failed");
        return 0;
    }

    // Write secret key
    fr = f_open(&sk_file, secret_name, FA_WRITE | FA_CREATE_ALWAYS); // secret key file
    if (fr == FR_OK)
    {
        if (!PEM_write_PrivateKey_FIL(&sk_file, pkey)) {
            log_error("Failed to write private key");
        }
        f_close(&sk_file);
    }
    else
    {
        log_error("Could not open secret key file");
        EVP_PKEY_free(pkey);
        return 0;
    }

    // Write Public key
    fr = f_open(&pk_file, public_name, FA_WRITE | FA_CREATE_ALWAYS); // public key file
    if (fr == FR_OK)
    {
        if (!PEM_write_PUBKEY_FIL(&pk_file, pkey)) {
            log_error("Failed to write public key");
        }
        f_close(&pk_file);
    }
    else
    {
        log_error("Could not open public key file");
        EVP_PKEY_free(pkey);
        return 0;
    }

    // End program
    EVP_PKEY_free(pkey);
    return 1;
}