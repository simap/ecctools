#ifndef STFU_h
#define STFU_h

typedef struct {
    uint32_t type;
    uint32_t size;
    char name[92];
} FUFileHeader; //100 bytes

typedef struct {
	uint8_t hash[32]; //sha256 of the header + payload
	uint8_t signature[64]; //secp256k1 signature of the hash
} FUFileFooter; //96 bytes

typedef struct {
    char magic[4];  //"STFU" signed transfer firmware update
    uint32_t numFiles;
} FUHeader;

#endif