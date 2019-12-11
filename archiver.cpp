#include <uECC.h>
#include "SHA256.h"
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <libgen.h>
#include <stdlib.h>
#include "stfu.h"


off_t fsize(const char *filename) {
    struct stat st; 
    if (stat(filename, &st) == 0)
        return st.st_size;
    return -1; 
}


int main(int argc, char ** argv) {
  const struct uECC_Curve_t * curve = uECC_secp256k1();

  if (argc < 4) {
    fprintf(stderr, "Need a key, at least one input file, and an output file\n");
    return -1;
  }

  uint32_t numFiles = argc - 3;
  char ** fileNames = &argv[2];

  //check all files first
  for (int fileNum = 0; fileNum < numFiles; fileNum++) {
    int filesize = fsize(fileNames[fileNum]);
    if (filesize < 1) {
      fprintf(stderr, "Can't stat file: %s\n", fileNames[fileNum]);
      return -1;      
    }
  }

  uint8_t privateKey[32];
  char tmp[200];
  FILE * fp, *fpout;
  int nread;

  sprintf(tmp, "%s.key", argv[1]);
  fp = fopen(tmp, "rb");
  nread = fread(privateKey, 1, sizeof(privateKey), fp);
  fclose(fp);
  if (nread != sizeof(privateKey)) {
    fprintf(stderr, "can't read key %s\n", tmp);
    return -1;
  }

  fpout = fopen(argv[argc-1], "wb");
  fwrite("STFU", 4, 1, fpout);
  fwrite(&numFiles, sizeof(numFiles), 1, fpout);

  for (int fileNum = 0; fileNum < numFiles; fileNum++) {
    char * fileName = fileNames[fileNum];
    int bytesRemaining = fsize(fileName);
    fp = fopen(fileName, "rb");

    //do header
    FUFileHeader header = {0};
    FUFileFooter footer = {0};
    header.type = 1;
    header.size = bytesRemaining;
    {
      char * fileBaseName = strdup(fileName);
      strncpy(header.name, basename(fileBaseName), sizeof(header.name)-1);
      free(fileBaseName);
    }
    fwrite(&header, sizeof(header), 1, fpout);

    //hash header + file, and copy to archive
    uint8_t buf[512];
    SHA256 sha;
    sha.update(&header, sizeof(header));
    while (bytesRemaining > 0) {
      int nread = fread(buf, 1, 512, fp);
      if (nread > 0) {
        bytesRemaining -= nread;
        fwrite(buf, 1, nread, fpout);
        sha.update(buf, nread);
      } else {
        break;
      }
    }
    if (bytesRemaining) {
      fprintf(stderr, "had trouble reading file for hash %s\n", fileName);
      return -1;
    }
    fclose(fp);

    //hash, sign, and write out footer
    sha.finalize(footer.hash, 32);
    uECC_sign(privateKey, footer.hash, 32, footer.signature, curve);
    fwrite(&footer, sizeof(footer), 1, fpout);

  }
  fclose(fpout);
  printf("signed transfer file update archive complete!\n");
}
