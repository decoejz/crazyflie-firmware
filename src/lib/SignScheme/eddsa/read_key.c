#include "eddsa.h"

pki_t read_key_eddsa(char load_type, const char *file_name)
{
    pki_t key_res;
    FIL file;
    FRESULT fr;

    EVP_PKEY *key = NULL;
    fr = f_open(&file, file_name, FA_READ);
    if (fr != FR_OK)
    {
        log_error("Read key error: Cannot open the file");
        exit(EXIT_FAILURE); // TODO remove it or change handle
    }

    UINT br;
    char buffer[EDDSA_SIGN_MAX_LEN];
    memset(buffer, 0, sizeof(buffer));
    fr = f_read(&file, buffer, sizeof(buffer) - 1, &br);  // deixar 1 byte para '\0'
    f_close(&file);

    if (fr != FR_OK || br == 0)
    {
        log_error("Read key error: Cannot read file contents");
        exit(EXIT_FAILURE); // TODO remove it or change handle
    }

    BIO *bio = BIO_new_mem_buf(buffer, br);
    if (!bio)
    {
        log_error("Read key error: BIO allocation failed");
        exit(EXIT_FAILURE);
    }

    if (load_type == PRIVATE_KEY)
    {
        key = PEM_read_bio_PrivateKey(bio, NULL, NULL, NULL);
    }
    else if (load_type == PUBLIC_KEY)
    {
        key = PEM_read_bio_PUBKEY(bio, NULL, NULL, NULL);
    }
    else
    {
        log_error("Read key error: Invalid input");
    }

    BIO_free(bio);

    if (!key)
    {
        char msg[128];
        snprintf(msg, sizeof(msg), "Read key error: Unable to load key from file %s", file_name);
        log_error(msg);
    }

    key_res.openssl_key = key;
    return key_res;
}