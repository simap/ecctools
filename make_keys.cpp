#include <uECC.h>
#include "SHA256.h"
#include <stdio.h>
#include <string.h>

void printHex(uint8_t * data, int len) {
  int i;
  printf("{\n\t");
  for(i=0; i<len-1; ++i) {
    printf("0x%02X, ", data[i]);
    if ((i+1) % 11 == 0)
      printf("\n\t");
  }
  printf("0x%02X};\n", data[i]);
}

int main(int argc, char ** argv) {
  if (argc < 2) {
    fprintf(stderr, "Need a key file name\n");
    return -1;
  }

  if (uECC_get_rng() == NULL) {
    fprintf(stderr, "Compiled without a random number generator!\n");
  }


  const struct uECC_Curve_t * curve = uECC_secp256k1();
  uint8_t private1[32];
  uint8_t public1[64];
  
  uECC_make_key(public1, private1, curve);


  char tmp[100];
  FILE * fp;

  sprintf(tmp, "%s.pub", argv[1]);
  fp = fopen (tmp, "wb");
  fwrite(public1, 64, 1, fp);
  fclose(fp);

  sprintf(tmp, "%s.key", argv[1]);
  fp = fopen (tmp, "wb");
  fwrite(private1, 32, 1, fp);
  fclose(fp);


  printf("const uint8_t private_key[] = ");
  printHex(private1, 32);

  printf("const uint8_t public_key[] = ");
  printHex(public1, 64);
}
