

#ifndef COMMN_H_
#define COMMN_H_


#ifdef __cplusplus
extern "C" {
#endif

// base64 ½âÂë
char * base64Decode(char *input, int length);//, bool newLine)
// base64 ±àÂë
char * base64Encode(const char *buffer, int length);//, bool newLine)
char* hex2Str(char *sSrc, int nSrcLen, char *sDest);
int hexStrToByte(char* source, int sourceLen, unsigned char* dest);

#ifdef __cplusplus
}
#endif

#endif  