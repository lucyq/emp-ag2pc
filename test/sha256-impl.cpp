#include <emp-tool/emp-tool.h>
#include "emp-ag2pc/emp-ag2pc.h"
#include "sha.h"
#include "sha-private.h"
#include <bitset>

using namespace emp;
using namespace std;


// #include <string.h>

/* Define the SHA shift, rotate left, and rotate right macros */
#define SHA256_SHR(bits,word)      ((word) >> (bits))
#define SHA256_ROTL(bits,word)                         \
  (((word) << (bits)) | ((word) >> (32-(bits))))
#define SHA256_ROTR(bits,word)                         \
  (((word) >> (bits)) | ((word) << (32-(bits))))

/* Define the SHA SIGMA and sigma macros */
#define SHA256_SIGMA0(word)   \
  (SHA256_ROTR( 2,word) ^ SHA256_ROTR(13,word) ^ SHA256_ROTR(22,word))
#define SHA256_SIGMA1(word)   \
  (SHA256_ROTR( 6,word) ^ SHA256_ROTR(11,word) ^ SHA256_ROTR(25,word))
#define SHA256_sigma0(word)   \
  (SHA256_ROTR( 7,word) ^ SHA256_ROTR(18,word) ^ SHA256_SHR( 3,word))
#define SHA256_sigma1(word)   \
  (SHA256_ROTR(17,word) ^ SHA256_ROTR(19,word) ^ SHA256_SHR(10,word))

/*
 * Add "length" to the length.
 * Set Corrupted when overflow has occurred.
 */
// static uint32_t addTemp;
// #define SHA224_256AddLength(context, length)               \
//   (addTemp = (context)->Length_Low, (context)->Corrupted = \
//     (((context)->Length_Low += (length)) < addTemp) &&     \
//     (++(context)->Length_High == 0) ? shaInputTooLong :    \
//                                       (context)->Corrupted )





/* Local Function Prototypes */

static int SHA224_256Reset(SHA256Context *context, uint32_t *H0);
static void SHA224_256ProcessMessageBlock(SHA256Context *context);
static void SHA224_256Finalize(SHA256Context *context,
  uint8_t Pad_Byte);
static void SHA224_256PadMessage(SHA256Context *context,
  uint8_t Pad_Byte);
static int SHA224_256ResultN(SHA256Context *context,
  uint8_t Message_Digest[ ], int HashSize);
/* Initial Hash Values: FIPS 180-3 section 5.3.3 */
static uint32_t SHA256_H0[SHA256HashSize/4] = {
  0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A,
  0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19
};



void print_uint8_t(uint8_t n) {
  bitset<8> x(n);
  cout << x;
}

void print_uint16_t(uint16_t n) {
  bitset<16> x(n);
  cout << x;
}

void print_uint32_t(uint32_t n) {
  bitset<32> x(n);
  cout << x;
}

void printConstIntegerArray(const uint8_t* intToPrint, int arraySize) {
  for(int i = 0; i < arraySize; i++) {
    cout << intToPrint[i] << ", ";
  }
  cout << endl;
  return;
}
void printIntegerArray(uint8_t* intToPrint, int arraySize) {
  for(int i = 0; i < arraySize; i++) {
    print_uint8_t(intToPrint[i]);
    cout << ", ";
  }
  cout << endl;
  return;
}

void printIntegerArray32(uint32_t* intToPrint, int arraySize) {
  for(int i = 0; i < arraySize; i++) {
    print_uint32_t(intToPrint[i]);
    cout << ", ";
  }
  cout << endl;
  return;
}

static int ALL = 0;
static int Msg_Block = 1;
static int Msg_Block_Index = 2;
static int Msg_Interemdiate_Hash = 4;

static int INTERMEDIATE_HASH_LEN = SHA256HashSize/4;

void printContext(SHA256Context *context, int flag, string debugMsg) {
  cout << debugMsg << endl;
  if (flag == ALL || flag == Msg_Interemdiate_Hash) {
    cout << "Interemdiate Hash " << endl;
    printIntegerArray32(context->Intermediate_Hash, INTERMEDIATE_HASH_LEN);
  }
  if (flag == ALL) {
    cout << "Length high " << endl;
    print_uint32_t(context->Length_High);
    cout << endl;
  }
  if (flag == ALL) {
    cout << "Length low " << endl;
    print_uint32_t(context->Length_Low);
    cout << endl;
  }  
  if (flag == ALL || flag == Msg_Block_Index) { 
    cout << "Message block index " << endl;
    print_uint16_t(context->Message_Block_Index);
    cout << endl;
  }
  if (flag == ALL || flag == Msg_Block) {
    cout << "Message block contents " << endl;
    printIntegerArray(context->Message_Block, SHA256_Message_Block_Size);
  }
}


// static uint32_t addTemp;
// #define SHA224_256AddLength(context, length)               \
//   (addTemp = (context)->Length_Low, (context)->Corrupted = \
//     (((context)->Length_Low += (length)) < addTemp) &&     \
//     (++(context)->Length_High == 0) ? shaInputTooLong :    \
//                                       (context)->Corrupted )
int SHA224_256AddLength(SHA256Context *context, int length) {
  uint32_t addTemp = context->Length_Low;
  // context->Corrupted = context->Length_Low + length

  // context->Length_High += 1;
  context->Length_Low += length;


  if (context->Length_Low < addTemp) {
    context->Length_High++;
    if (context->Length_High == 0) {
      return context->Corrupted = shaInputTooLong;
    }
  } 
  return context->Corrupted;
}

/*
 * SHA256Reset
 *
 * Description:
 *   This function will initialize the SHA256Context in preparation
 *   for computing a new SHA256 message digest.
 *
 * Parameters:
 *   context: [in/out]
 *     The context to reset.
 *
 * Returns:
 *   sha Error Code.
 */
int SHA256Reset(SHA256Context *context)
{
  return SHA224_256Reset(context, SHA256_H0);
}
/*
 * SHA256Input
 *
 * Description:
 *   This function accepts an array of octets as the next portion
 *   of the message.

  *   length: [in]
 *     The length of the message in message_array.
 *
 * Returns:
 *   sha Error Code.
 */
int SHA256Input(SHA256Context *context, const uint8_t *message_array,
    unsigned int length)
{
  if (!context) return shaNull;
  if (!length) return shaSuccess;
  if (!message_array) return shaNull;
  if (context->Computed) return context->Corrupted = shaStateError;
  if (context->Corrupted) return context->Corrupted;
  while (length--) {
    context->Message_Block[context->Message_Block_Index++] =
            *message_array;
   if ((SHA224_256AddLength(context, 8) == shaSuccess) &&
      (context->Message_Block_Index == SHA256_Message_Block_Size)) {
      SHA224_256ProcessMessageBlock(context);
    }
    message_array++;
  }
  return context->Corrupted;
}
/*
 * SHA256FinalBits
 *
 * Description:
 *   This function will add in any final bits of the message.
 *
 * Parameters:
 * Returns:
 *   sha Error Code.
  */
int SHA256FinalBits(SHA256Context *context,
                    uint8_t message_bits, unsigned int length)
{
  static uint8_t masks[8] = {
      /* 0 0b00000000 */ 0x00, /* 1 0b10000000 */ 0x80,
      /* 2 0b11000000 */ 0xC0, /* 3 0b11100000 */ 0xE0,
      /* 4 0b11110000 */ 0xF0, /* 5 0b11111000 */ 0xF8,
      /* 6 0b11111100 */ 0xFC, /* 7 0b11111110 */ 0xFE
  };
  static uint8_t markbit[8] = {
      /* 0 0b10000000 */ 0x80, /* 1 0b01000000 */ 0x40,
      /* 2 0b00100000 */ 0x20, /* 3 0b00010000 */ 0x10,
      /* 4 0b00001000 */ 0x08, /* 5 0b00000100 */ 0x04,
      /* 6 0b00000010 */ 0x02, /* 7 0b00000001 */ 0x01
};
  if (!context) return shaNull;
  if (!length) return shaSuccess;
  if (context->Corrupted) return context->Corrupted;
  if (context->Computed) return context->Corrupted = shaStateError;
  if (length >= 8) return context->Corrupted = shaBadParam;
  SHA224_256AddLength(context, length);
  SHA224_256Finalize(context, (uint8_t)
    ((message_bits & masks[length]) | markbit[length]));
  return context->Corrupted;
}
/*
 * SHA256Result
 *
 * Description:
 *   This function will return the 256-bit message digest
 *   into the Message_Digest array provided by the caller.
 *   NOTE:
 *    The first octet of hash is stored in the element with index 0,
 *    the last octet of hash in the element with index 31.
 *
 * Parameters:
*
*
*
*
*
* Returns:
*   sha Error Code.
context: [in/out]
  The context to use to calculate the SHA hash.
Message_Digest[ ]: [out]
  Where the digest i
 */
int SHA256Result(SHA256Context *context,
                 uint8_t Message_Digest[SHA256HashSize])
{
  return SHA224_256ResultN(context, Message_Digest, SHA256HashSize);
}
/*
 * SHA224_256Reset
 *
 * Description:
 *   This helper function will initialize the SHA256Context in
 *   preparation for computing a new SHA-224 or SHA-256 message digest.
 *
 * Parameters:
*
*
*
*
*
* Returns:
*   sha Error Code.
*/
// context: [in/out]
//   The context to reset.
// H0[ ]: [in]
//   The initial hash value array to use.
static int SHA224_256Reset(SHA256Context *context, uint32_t *H0)
{
  if (!context) return shaNull;
  
  for (int i = 0; i < SHA256_Message_Block_Size; i++) {
    context->Message_Block[i] = 0;
  }
  
  context->Length_High = context->Length_Low = 0;
  context->Message_Block_Index  = 0;
  context->Intermediate_Hash[0] = H0[0];
  context->Intermediate_Hash[1] = H0[1];
  context->Intermediate_Hash[2] = H0[2];
  context->Intermediate_Hash[3] = H0[3];
  context->Intermediate_Hash[4] = H0[4];
  context->Intermediate_Hash[5] = H0[5];
  context->Intermediate_Hash[6] = H0[6];
  context->Intermediate_Hash[7] = H0[7];
  context->Computed  = 0;
  context->Corrupted = shaSuccess;
  return shaSuccess;
}
/*
 * SHA224_256ProcessMessageBlock
 *

* Description:
 *   This helper function will process the next 512 bits of the
 *   message stored in the Message_Block array.
 *
 * Parameters:
 *   context: [in/out]
 *     The SHA context to update.
 *
 * Returns:
 *   Nothing.
 *
 * Comments:
 *   Many of the variable names in this code, especially the
 *   single character names, were used because those were the
 *   names used in the Secure Hash Standard.
 */
static void SHA224_256ProcessMessageBlock(SHA256Context *context)
{
  /* Constants defined in FIPS 180-3, section 4.2.2 */
  static const uint32_t K[64] = {
      0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b,
      0x59f111f1, 0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01,
      0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7,
      0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
      0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152,
      0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147,
      0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc,
      0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
      0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819,
      0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116, 0x1e376c08,
      0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f,
      0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
      0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
  };

  int        t, t4;                   /* Loop counter */
  uint32_t   temp1, temp2;            /* Temporary word value */
  uint32_t   W[64];                   /* Word sequence */
  uint32_t   A, B, C, D, E, F, G, H;  /* Word buffers */

  /*
   * Initialize the first 16 words in the array W
   */
  for (t = t4 = 0; t < 16; t++, t4 += 4)
    W[t] = (((uint32_t)context->Message_Block[t4]) << 24) |
           (((uint32_t)context->Message_Block[t4 + 1]) << 16) |
           (((uint32_t)context->Message_Block[t4 + 2]) << 8) |
           (((uint32_t)context->Message_Block[t4 + 3]));
for (t = 16; t < 64; t++)
    W[t] = SHA256_sigma1(W[t-2]) + W[t-7] +
        SHA256_sigma0(W[t-15]) + W[t-16];
  A = context->Intermediate_Hash[0];
  B = context->Intermediate_Hash[1];
  C = context->Intermediate_Hash[2];
  D = context->Intermediate_Hash[3];
  E = context->Intermediate_Hash[4];
  F = context->Intermediate_Hash[5];
  G = context->Intermediate_Hash[6];
  H = context->Intermediate_Hash[7];

  for (t = 0; t < 64; t++) {
    temp1 = H + SHA256_SIGMA1(E) + SHA_Ch(E,F,G) + K[t] + W[t];
    temp2 = SHA256_SIGMA0(A) + SHA_Maj(A,B,C);
    H = G;
    G = F;
    F = E;
    E = D + temp1;
    D = C;
    C = B;
    B = A;
    A = temp1 + temp2;
  }

  context->Intermediate_Hash[0] += A;
  context->Intermediate_Hash[1] += B;
  context->Intermediate_Hash[2] += C;
  context->Intermediate_Hash[3] += D;
  context->Intermediate_Hash[4] += E;
  context->Intermediate_Hash[5] += F;
  context->Intermediate_Hash[6] += G;
  context->Intermediate_Hash[7] += H;
  context->Message_Block_Index = 0;
}
/*
 * SHA224_256Finalize
 *
 * Description:
 *   This helper function finishes off the digest calculations.
 *
 * Parameters:
* * *
context: [in/out]
  The SHA context to update.
Pad_Byte: [in]
 *     The last byte to add to the message block before the 0-padding
 *     and length.  This will contain the last bits of the message
 *     followed by another single bit.  If the message was an
 *     exact multiple of 8-bits long, Pad_Byte will be 0x80.
*
* Returns:
 *   sha Error Code.
 */
static void SHA224_256Finalize(SHA256Context *context,
    uint8_t Pad_Byte)
{
int i;
  SHA224_256PadMessage(context, Pad_Byte);
  /* message may be sensitive, so clear it out */
  for (i = 0; i < SHA256_Message_Block_Size; ++i)
    context->Message_Block[i] = 0;
  context->Length_High = 0;
  context->Length_Low = 0;
  context->Computed = 1;
}
/* and clear length */
/*
 * SHA224_256PadMessage
 *
 * Description:
 *   According to the standard, the message must be padded to the next
 *   even multiple of 512 bits.  The first padding bit must be a ’1’.
 *   The last 64 bits represent the length of the original message.
 *   All bits in between should be 0.  This helper function will pad
 *   the message according to those rules by filling the
 *   Message_Block array accordingly.  When it returns, it can be
 *   assumed that the message digest has been computed.
 *
 * Parameters:
*
*
*
*
*
*
*
*
* Returns:
*   Nothing.
*/
// context: [in/out]
//   The context to pad.
// Pad_Byte: [in]
//   The last byte to add to the message block before the 0-padding
//   and length.  This will contain the last bits of the message
//   followed by another single bit.  If the message was an
//   exact multiple of 8-bits long, Pad_Byte will be 0x80.
static void SHA224_256PadMessage(SHA256Context *context,
    uint8_t Pad_Byte)
{
    /*
   * Check to see if the current message block is too small to hold
   * the initial padding bits and length.  If so, we will pad the
   * block, process it, and then continue padding into a second
   * block.
   */
  if (context->Message_Block_Index >= (SHA256_Message_Block_Size-8)) {
    context->Message_Block[context->Message_Block_Index++] = Pad_Byte;
    while (context->Message_Block_Index < SHA256_Message_Block_Size)
      context->Message_Block[context->Message_Block_Index++] = 0;
    // TO BE TESTED DEBUG
    SHA224_256ProcessMessageBlock(context);
  } else
    context->Message_Block[context->Message_Block_Index++] = Pad_Byte;
  while (context->Message_Block_Index < (SHA256_Message_Block_Size-8))
    context->Message_Block[context->Message_Block_Index++] = 0;
  /*
   * Store the message length as the last 8 octets
   */
  context->Message_Block[56] = (uint8_t)(context->Length_High >> 24);
  context->Message_Block[57] = (uint8_t)(context->Length_High >> 16);
  context->Message_Block[58] = (uint8_t)(context->Length_High >> 8);
  context->Message_Block[59] = (uint8_t)(context->Length_High);
  context->Message_Block[60] = (uint8_t)(context->Length_Low >> 24);
  context->Message_Block[61] = (uint8_t)(context->Length_Low >> 16);
  context->Message_Block[62] = (uint8_t)(context->Length_Low >> 8);
  context->Message_Block[63] = (uint8_t)(context->Length_Low);
  SHA224_256ProcessMessageBlock(context);
}
/*
 * SHA224_256ResultN
 *
 * Description:
 *   This helper function will return the 224-bit or 256-bit message
 *   digest into the Message_Digest array provided by the caller.
 *   NOTE:
 *    The first octet of hash is stored in the element with index 0,
 *    the last octet of hash in the element with index 27/31.
 *
 * Parameters:
* * * * *
context: [in/out]
  The context to use to calculate the SHA hash.
Message_Digest[ ]: [out]
  Where the digest is returned.
HashSize: [in]*/


static int SHA224_256ResultN(SHA256Context *context,
    uint8_t Message_Digest[ ], int HashSize)
{
int i;
  if (!context) return shaNull;
  if (!Message_Digest) return shaNull;

  if (context->Corrupted) return context->Corrupted;
  if (!context->Computed) {
    SHA224_256Finalize(context, 0x80);
  }
  // printContext(context, ALL, "After finalize");
  for (i = 0; i < HashSize; ++i)
    Message_Digest[i] = (uint8_t)
      (context->Intermediate_Hash[i>>2] >> 8 * ( 3 - ( i & 0x03 ) ));
  // cout << "Interemdiate hash of context at result after FINALIZE and LOOP \n";
  // printIntegerArray(Message_Digest, 64);
  return shaSuccess;
}


/*
 * Print the string, converting non-printable characters to "."
 */
void printstr(const char *str, int len)
{
  for ( ; len-- > 0; str++)
    putchar(isprint((unsigned char)*str) ? *str : '.');
}


void testInput(const char* inputArray, char* outputArray, int inputLen) {
  static const char hexdigits[ ] = "0123456789ABCDEF";

  uint8_t Message_Digest_Buf[USHAMaxHashSize];
  uint8_t *Message_Digest = Message_Digest_Buf;
  SHA256Context sha;
  int err;
  char hashResult[64];
  int count = 0;

  // initialize
  SHA256Reset(&sha);

  // input
  err = SHA256Input(&sha, (const uint8_t*)inputArray, inputLen);
  if (err != shaSuccess) {
    printf("Error: input!\n");
  }

  // finalize
  err = SHA256Result(&sha, Message_Digest);

  if (err != shaSuccess) {
    printf("Error: result!\n");
  }

  // test result

  // for(int i = 0; i < 32; i++) {
  //   putchar(hexdigits[(Message_Digest[i] >> 4) & 0xF]);
  //   hashResult[count] = hexdigits[(Message_Digest[i] >> 4) & 0xF];
  //   count++;
  //   putchar(hexdigits[Message_Digest[i] & 0xF]);
  //   hashResult[count] = hexdigits[Message_Digest[i] & 0xF];
  //   count++;
  // }
  printf("Output binary \n");
  printIntegerArray(Message_Digest, 32);
  printf("\n");


  // for (int i = 0; i < 64; i++) {
  //   if (outputArray[i] != hashResult[i]) {
  //     printf("OUTPUT ERROR!!!!!\n");
  //     return;
  //   }
  // }

  // printf("Output was correct!\n");
  return;
}

int main() {

	// char char_array[64];

	// printf("testing: %s\n", "TESTING!\n");
	// string output = "1CFFE26786771001CF767FC7C0CE1C3029060238D3225EA0C9EDE740954EA892";
	// strcpy(char_array, output.c_str());
	// testInput("TESTING!", (char*)char_array, 8);
  int inputLength = 56;
  char in[inputLength];
  char* input = in;
  for (int i = 0; i < inputLength; i++) {
    input[i] = '1';
  }

	char char_array2[64];
	// printf("testing: %s\n", input->c_str());
	string output2 = "BA7816BF8F01CFEA414140DE5DAE2223B00361A396177A9CB410FF61F20015AD";
	strcpy(char_array2, output2.c_str());
	testInput(input, (char*)char_array2, inputLength);

  return 0;
}