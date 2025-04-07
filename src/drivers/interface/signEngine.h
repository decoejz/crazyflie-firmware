#ifndef __SIGNENGINE_H__
#define __SIGNENGINE_H__

#include <string.h>
#include <stdbool.h>
#include <openssl/pem.h>

#define MAX_CONFIGS 4
#define MAX_KEY_LEN 32
#define MAX_VAL_LEN 64

/*const char *fresult_messages[] = {
    "OK", "Disk error", "Internal error", "Not ready", "No file", "No path", "Invalid name",
    "Access denied", "Exists", "Invalid object", "Write protected", "Invalid drive",
    "Not enabled", "No filesystem", "Mkfs aborted", "Timeout", "Locked", "No memory",
    "Too many files", "Invalid parameter"
  };*/

typedef struct {
    char key[MAX_KEY_LEN];
    char value[MAX_VAL_LEN];
} ConfigEntry;

void signEngineInit(const char* cfg_file_name);
char* getCfg(char* key);
bool signEngineTest(const char* filename, const char* content);

#endif //__SIGNENGINE_H__