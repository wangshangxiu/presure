#ifndef A_AES_H
#define A_AES_H
#ifdef __cplusplus
extern "C" {
#endif
int aes_encrypt(unsigned char *plaintext, int plaintext_len, unsigned char *key,
  unsigned char *iv, unsigned char *ciphertext);
 
int aes_decrypt(unsigned char *ciphertext, int ciphertext_len, unsigned char *key,
  unsigned char *iv, unsigned char *plaintext);

void aesDemoTest();
#ifdef __cplusplus
}
#endif
#endif
