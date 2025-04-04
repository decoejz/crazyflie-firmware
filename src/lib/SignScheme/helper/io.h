#include <stdbool.h>
#include <stdint.h>

#include "ff.h"
#include <openssl/pem.h>
#include <openssl/evp.h>

#define END_BUFFER '\0'
#define BREAK_LINE "\n"

char *getcfg (const char *attr);
bool sdcard_mount(void);

FRESULT log_info(const char *info);
FRESULT log_error(const char *error);
int PEM_write_PUBKEY_FIL(FIL *file, EVP_PKEY *pkey);
int PEM_write_PrivateKey_FIL(FIL *file, EVP_PKEY *pkey);
