#include <emp-tool/emp-tool.h>
#include "emp-ag2pc/emp-ag2pc.h"
#include <stdio.h>
#include <ctype.h>

#include "test/single_execution.h"
void testInput(char* str, int length) {

  /* 2 PC */
  EMP_SHA256_CONTEXT sha;
  Integer err = SHA256_Reset(&sha);

  Integer input[length];
  for (int i = 0; i < length; i++) {
    input[i] = Integer(8, str[i], ALICE);
  }
  err = SHA256_Input(&sha, input, length);
  Integer Message_Digest_Buf[SHA256HashSize];
  Integer *Message_Digest = Message_Digest_Buf;

  err = SHA256_Result(&sha, Message_Digest);

  /* OpenSSL */
  uint8_t digest[32];
  Hash::hash_once(&digest, str, length);
  bool success = compareHash(digest, Message_Digest);
  if(!success) {
    cout << "Failed test with str: " << str << endl;
  }
  
}

int main() {

  setup_plain_prot(false, "sha256-test.circuit.txt");

  // char allChars[512];
  // for (int thisChar = 0; thisChar < 512; thisChar++) {
  //   allChars[thisChar] = thisChar%256;
  // }
  // testInput((char*)"abc", 3);
  // testInput((char*)"Hello, world!", 12);
  // testInput(allChars, 256);

  // int num = 32;
  // for (int len = num; len <= num; len++) {
  //   char input[len];
  //   for (int j = 0; j < len; j++) {
  //     input[j] = '1';
  //   }
  //   //testHmac((char*) input, num, (char*) input, num);
  //   // testInput(input, len);
  // }

//   testHmac((char*)"abcdefghabcdefghabcdefghabcdefgh", 32, (char*)"abcdefghabcdefghabcdefghabcdefgh", 32);
   //testHmac(allChars, 512, allChars, 512);
   testInput((char*)"0", 1);

  // testInput(allChars, 512);

  finalize_plain_prot();  
  return 0;
}