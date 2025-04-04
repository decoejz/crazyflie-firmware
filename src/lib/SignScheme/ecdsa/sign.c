#include "ecdsa.h"

// Res:
// 0 => ERROR
// else => Success (msg total len)
int sign_ecdsa(uint8_t *msg_signed, uint8_t *msg_raw, unsigned int msg_len, pki_t secret_key)
{
    if (secret_key.openssl_key == NULL)
    {
        log_error("sign_ecdsa: Secret key is NULL");
        return 0;
    }

    // Create a context
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(secret_key.openssl_key, NULL);
    if (!ctx)
    {
        log_error("sign_ecdsa: Failed to create EVP_PKEY_CTX");
        return 0;
    } 

    // Initialize signing
    if (EVP_PKEY_sign_init(ctx) <= 0)
    {
        log_error("sign_ecdsa: EVP_PKEY_sign_init failed");
        EVP_PKEY_CTX_free(ctx);
        return 0;
    }

    uint8_t sigma[ECDSA_SIGN_MAX_LEN]; // Signature var
    size_t siglen = ECDSA_SIGN_MAX_LEN;
    if (EVP_PKEY_sign(ctx, sigma, &siglen, msg_raw, (size_t)msg_len) <= 0)
    {
        log_error("sign_ecdsa: EVP_PKEY_sign failed");
        EVP_PKEY_CTX_free(ctx);
        return 0;
    }
    EVP_PKEY_CTX_free(ctx);

    // * Concatenate sign with message to send (siglen (int) + msg + sigma)
    uint8_t siglen_size[4];
    int2uc(siglen_size, (int)siglen);

    memmove(msg_signed, siglen_size, ECDSA_SIGN_HEADER_SIZE);
    memmove(msg_signed + ECDSA_SIGN_HEADER_SIZE, msg_raw, msg_len);
    memmove(msg_signed + ECDSA_SIGN_HEADER_SIZE + msg_len, (uint8_t *)sigma, siglen);

    return ECDSA_SIGN_HEADER_SIZE + msg_len + siglen;
}