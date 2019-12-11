#ifndef STFU_h
#define STFU_h

typedef struct {
    uint32_t type;
    uint32_t size;
    uint8_t hash[32]; //sha256
    uint8_t signature[64]; //secp256k1
    char name[96];
} FUFile; //200 bytes

typedef struct {
    char magic[4];  //"STFU" signed transfer firmware update
    uint32_t numFiles;
} FUHeader;

#endif