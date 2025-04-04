#include "io.h"

static FATFS fs;
static const char *cfg_path_file = "sign_scheme.cfg"; 
static bool fs_mounted = false;

char *getcfg (const char *attr)
{
    if (!cfg_path_file || strstr(cfg_path_file, ".cfg") == NULL) return NULL;
    if (!sdcard_mount()) return NULL;

    FIL file;
    FRESULT res = f_open(&file, cfg_path_file, FA_READ);
    if (res != FR_OK) {
        log_error("sign_scheme.cfg not found");
        return NULL;
    } else {        
        log_error("sign_scheme.cfg found");
    }

    UINT bytes_read;
    static char buffer[1024];  // or malloc + free later
    res = f_read(&file, buffer, sizeof(buffer) - 1, &bytes_read);
    if (res != FR_OK) {
        f_close(&file);
        return NULL;
    }

    buffer[bytes_read] = '\0';
    f_close(&file);

    // Parse for attr=...
    char *line = strtok(buffer, BREAK_LINE);
    while (line != NULL) {
        if (line[0] == '#') {
            line = strtok(NULL, BREAK_LINE);
            continue;
        }

        char *eq = strchr(line, '=');
        if (!eq) {
            line = strtok(NULL, BREAK_LINE);
            continue;
        }

        *eq = '\0';
        char *key = line;
        char *value = eq + 1;

        if (strcmp(attr, key) == 0) {
            return value;
        }

        line = strtok(NULL, BREAK_LINE);
    }

    char msg[128];
    snprintf(msg, sizeof(msg), "%s not found", attr);
    log_error(msg);

    return NULL; // not found
}

FRESULT log_info(const char *info) {
    FIL file;
    FRESULT fr;

    fr = f_open(&file, "log_info.txt", FA_WRITE | FA_CREATE_ALWAYS);
    if (fr == FR_OK) {
        f_printf(&file, info);
        f_close(&file); 
    }
    return fr;
}

FRESULT log_error(const char *error) {
    FIL file;
    FRESULT fr;

    fr = f_open(&file, "log_error.txt", FA_WRITE | FA_CREATE_ALWAYS);
    if (fr == FR_OK) {
        f_printf(&file, error);
        f_close(&file);  
    }
    return fr;
}

int PEM_write_PUBKEY_FIL(FIL *file, EVP_PKEY *pkey) {
    BIO *bio = BIO_new(BIO_s_mem());
    if (!bio)
        return 0;

    if (!PEM_write_bio_PUBKEY(bio, pkey)) {
        BIO_free(bio);
        return 0;
    }

    char *data;
    long len = BIO_get_mem_data(bio, &data);
    UINT bw;
    FRESULT fr = f_write(file, data, len, &bw);

    BIO_free(bio);
    return (fr == FR_OK && bw == len);
}

int PEM_write_PrivateKey_FIL(FIL *file, EVP_PKEY *pkey) {
    BIO *bio = BIO_new(BIO_s_mem());
    if (!bio) return 0;

    if (!PEM_write_bio_PrivateKey(bio, pkey, NULL, NULL, 0, NULL, NULL)) {
        BIO_free(bio);
        return 0;
    }

    char *data;
    long len = BIO_get_mem_data(bio, &data);
    UINT bw;
    FRESULT fr = f_write(file, data, len, &bw);
    BIO_free(bio);
    return (fr == FR_OK && bw == len);
}

bool sdcard_mount(void) 
{
    if (!fs_mounted) {
        if (f_mount(&fs, "", 1) == FR_OK) {
            fs_mounted = true;
        }
    }
    return fs_mounted;
}