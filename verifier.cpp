#include <uECC.h>
#include "SHA256.h"
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <libgen.h>
#include <stdlib.h>
#include "stfu.h"

int main(int argc, char ** argv) {
  const struct uECC_Curve_t * curve = uECC_secp256k1();

  if (argc != 3) {
    fprintf(stderr, "Need a public key and archive\n");
    return -1;
  }

  // uint8_t private1[32];
  uint8_t public1[64];
  char tmp[100];
  FILE *fp, *fpin;


  sprintf(tmp, "%s.pub", argv[1]);
  fp = fopen(tmp, "rb");
  int nread = fread(public1, 1, sizeof(public1), fp);
  fclose(fp);
  if (nread != sizeof(public1)) {
    fprintf(stderr, "can't read key %s\n", tmp);
    return -1;
  }

  fpin = fopen(argv[2], "rb");
  FUHeader header = {0};
  nread = fread(&header, 1, sizeof(FUHeader), fpin);
  if (nread != sizeof(FUHeader) || strncmp("STFU", header.magic, 4) != 0) {
    fprintf(stderr, "can't read magic and header\n");
    return -1;
  }

  for (int fileNum = 0; fileNum < header.numFiles; fileNum++) {
    FUFileHeader header = {0};
    nread = fread(&header, 1, sizeof(header), fpin);
    if (nread != sizeof(header)) {
      fprintf(stderr, "unable to read header\n");
      return -1;
    }

    printf("Scanning type:%d size:%d name:%s\n", header.type, header.size, header.name);

    int bytesRemaining = header.size;

    //hash it
    uint8_t buf[512];
    SHA256 sha;
    sha.update(&header, sizeof(header));
    while (bytesRemaining > 0) {
      int nread = fread(buf, 1, bytesRemaining < 512 ? bytesRemaining : 512, fpin);
      if (nread > 0) {
        bytesRemaining -= nread;
        sha.update(buf, nread);
      } else {
        break;
      }
    }
    if (bytesRemaining) {
      fprintf(stderr, "had trouble reading file for hash, %d bytes more wanted\n", bytesRemaining);
      return -1;
    }

    FUFileFooter footer = {0};
    nread = fread(&footer, 1, sizeof(footer), fpin);
    if (nread != sizeof(footer)) {
      fprintf(stderr, "unable to read footer\n");
      return -1;
    }

    uint8_t hash[32];
    sha.finalize(hash, 32);
    if (memcmp(hash, footer.hash, 32) != 0) {
      fprintf(stderr, "hash mismatch!\n");
      return -1; 
    }

    int signatureOK = uECC_verify(public1, hash, 32, footer.signature, curve);
    if (!signatureOK) {
      fprintf(stderr, "signature invalid!\n");
      return -1;
    }
  }
  fclose(fpin);
  printf("signed transfer file update verification complete!\n");
}

