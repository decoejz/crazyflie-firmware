#include "signEngine.h"
#include "sign_scheme.h"
#include "util_sign.h"
#include "ff.h"                // FatFS
#include "FreeRTOS.h"
#include "semphr.h"
#include "debug.h"            // DEBUG_PRINT


#define CERT_BUFFER_SIZE 2048

static ConfigEntry configEntries[MAX_CONFIGS];
static int configCount = 0;

static SemaphoreHandle_t sdMutex = NULL;

static pki_t secretCert;
static pki_t publicCert;

static bool cfgLoaded = false;
static bool certsLoaded = false;
static bool signReady = false;

static void trim(char* str) {
    char* end;
    while (*str == ' ' || *str == '\t') str++;
    end = str + strlen(str) - 1;
    while (end > str && (*end == '\r' || *end == '\n' || *end == ' ')) end--;
    *(end + 1) = '\0';
}

// Inicializa e carrega o arquivo .cfg
void readCfgInit(const char* cfg_file_name) {
    if (xSemaphoreTake(sdMutex, pdMS_TO_TICKS(200)) == pdTRUE) {
        FIL file;
        FRESULT fr = f_open(&file, cfg_file_name, FA_READ);
        if (fr != FR_OK) {
            DEBUG_PRINT("signCfg: Erro ao abrir %s (%d)\n", cfg_file_name, fr);
            cfgLoaded = false;
            xSemaphoreGive(sdMutex);
            return;
        }

        char line[128];
        while (f_gets(line, sizeof(line), &file) && configCount < MAX_CONFIGS) {
            char* equalSign = strchr(line, '=');
            if (equalSign) {
                *equalSign = '\0';
                char* key = line;
                char* value = equalSign + 1;
                trim(key);
                trim(value);
                strncpy(configEntries[configCount].key, key, MAX_KEY_LEN);
                strncpy(configEntries[configCount].value, value, MAX_VAL_LEN);
                configCount++;
            }
        }

        f_close(&file);
        DEBUG_PRINT("signCfg: %d entradas carregadas.\n", configCount);
        cfgLoaded = true;
        xSemaphoreGive(sdMutex);
    } else {
        DEBUG_PRINT("signCfg: Timeout ao tentar ler config.\n");
    }
}

// Recupera valor por chave
char* getCfg(char* key) {
    if (!cfgLoaded || !key || !sdMutex) return NULL;

    if (xSemaphoreTake(sdMutex, pdMS_TO_TICKS(100)) == pdTRUE) {
        for (int i = 0; i < configCount; ++i) {
            if (strncmp(configEntries[i].key, key, MAX_KEY_LEN) == 0) {
                xSemaphoreGive(sdMutex);
                return configEntries[i].value;
            }
        }
        xSemaphoreGive(sdMutex);
    }
    return NULL;
}

void readCertsInit(void) {
    if(!cfgLoaded){
        DEBUG_PRINT("signCfg:Configuração no lida.\n");
        certsLoaded = false;
        return;
    }
    if (xSemaphoreTake(sdMutex, pdMS_TO_TICKS(200)) == pdTRUE) {
        if (!certsLoaded) {
            memset(&secretCert, 0, sizeof(pki_t));
            memset(&publicCert, 0, sizeof(pki_t));
            char* secretKey = getCfg("SECRET_KEY_PATH");
            secretCert = read_key(PRIVATE_KEY, secretKey);

            char* publicKey = getCfg("PUBLIC_KEY_PATH");
            publicCert = read_key(PUBLIC_KEY, publicKey);

            if (secretCert.char_key && secretCert.openssl_key &&
                publicCert.char_key && publicCert.openssl_key) {
                certsLoaded = true;
                DEBUG_PRINT("signCfg:Certificados carregados com sucesso.\n");
            } else {
                DEBUG_PRINT("signCfg:Falha ao carregar certificados.\n");
            }
        }
        xSemaphoreGive(sdMutex);
    }
}

const pki_t *signCert_getSecret(void) {
    if (!certsLoaded || !sdMutex) return NULL;
    if (xSemaphoreTake(sdMutex, pdMS_TO_TICKS(100)) == pdTRUE) {
        const pki_t *ref = &secretCert;
        xSemaphoreGive(sdMutex);
        return ref;
    }
    return NULL;
}

const pki_t *signCert_getPublic(void) {
    if (!certsLoaded || !sdMutex) return NULL;
    if (xSemaphoreTake(sdMutex, pdMS_TO_TICKS(100)) == pdTRUE) {
        const pki_t *ref = &publicCert;
        xSemaphoreGive(sdMutex);
        return ref;
    }
    return NULL;
}

// Inicializa o driver e cria o mutex
void signEngineInit(const char* cfg_file_name) {
    if (!sdMutex) {
        sdMutex = xSemaphoreCreateMutex();
        if (sdMutex == NULL) {
            DEBUG_PRINT("signSD: Falha ao criar mutex.\n");
            return;
        }

        readCfgInit(cfg_file_name);
        readCertsInit();

        DEBUG_PRINT("signSD: init_sign_scheme\n");
        char* appName = getCfg("APP_NAME");
        char* scheme = getCfg("SIGN_SCHEME");
        init_sign_scheme(appName, scheme);
        DEBUG_PRINT("signSD: end init_sign_scheme.\n");

        signReady = true;
    }
}

// Escrita segura no SD Card
bool signEngineTest(const char* filename, const char* content) {
    if (!signReady || !filename || !content) {
        DEBUG_PRINT("signSD: Driver não inicializado ou parâmetros inválidos.\n");
        return false;
    }

    if (xSemaphoreTake(sdMutex, pdMS_TO_TICKS(100)) == pdTRUE) {
        FIL file;
        FRESULT fr = f_open(&file, filename, FA_WRITE | FA_CREATE_ALWAYS);
        if (fr == FR_OK) {
            UINT bw;
            fr = f_write(&file, content, strlen(content), &bw);
            f_close(&file);
            xSemaphoreGive(sdMutex);
            if (fr == FR_OK && bw == strlen(content)) {
                DEBUG_PRINT("signSD: Escrita OK em %s.\n", filename);
                return true;
            } else {
                DEBUG_PRINT("signSD: Falha na escrita (%d).\n", fr);
                return false;
            }
        } else {
            DEBUG_PRINT("signSD: Falha ao abrir arquivo (%d).\n", fr);
            xSemaphoreGive(sdMutex);
            return false;
        }
    } else {
        DEBUG_PRINT("signSD: Timeout esperando mutex.\n");
        return false;
    }
}

bool signEngineIsReady(void) {
    return signReady;
}