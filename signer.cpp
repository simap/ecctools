#include <uECC.h>
#include "SHA256.h"
#include <stdio.h>
#include <string.h>

void printHex(uint8_t * data, int len) {
  for(int i=0; i<len; ++i)
    printf("%02X", data[i]);
  printf("\n");
}

int main(int argc, char ** argv) {
  printf("hello, g_rng_function: %x\n", uECC_get_rng());


  const struct uECC_Curve_t * curve = uECC_secp256k1();
  uint8_t private1[32];
  uint8_t public1[64];

  uint8_t signature[64]; //twice key len

  uint8_t hash[32];


  SHA256 sha;

  char * text = "this is a test of something";
  sha.update(text, strlen(text));
  sha.finalize(hash, 32);

  printf("hash: ");
  printHex(hash, 32);
  
  uECC_make_key(public1, private1, curve);

  printf("private: ");
  printHex(private1, 32);

  printf("public: ");
  printHex(public1, 64);


  uECC_sign(private1, hash, 32, signature, curve);


  printf("signature: ");
  printHex(signature, 64);


  int res = uECC_verify(public1, hash, 32, signature, curve);
  
  printf("uECC_verify = %d\n", res);

}
