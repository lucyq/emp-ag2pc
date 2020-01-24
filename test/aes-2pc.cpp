#include <emp-tool/emp-tool.h>
#include "emp-ag2pc/emp-ag2pc.h"

using namespace std;
using namespace emp;

const int BLOCK_BITS = 128;
const int KEY_LENGTH = 128;
const int BLOCK_BYTES = 16;
const int BYTE_BITS = 8;

const string circuit_file_location = macro_xstr(EMP_CIRCUIT_PATH);
void test(int party, NetIO* io, string name, bool* in, bool* result, string check_output = "") {
	string file = name;//circuit_file_location + name;
	CircuitFile cf(file.c_str());
	auto t1 = clock_start();
	C2PC twopc(io, party, &cf);
	io->flush();
	cout << "one time:\t"<<party<<"\t" <<time_from(t1)<<endl;

	t1 = clock_start();
	twopc.function_independent();
	io->flush();
	cout << "inde:\t"<<party<<"\t"<<time_from(t1)<<endl;

	t1 = clock_start();
	twopc.function_dependent();
	io->flush();
	cout << "dep:\t"<<party<<"\t"<<time_from(t1)<<endl;

	cout << "Input size: " << max(cf.n1, cf.n2) << endl;
	
	t1 = clock_start();
	twopc.online(in, result);
	cout << "online:\t"<<party<<"\t"<<time_from(t1)<<endl;
}

// Bob inputs the IV and Message
int runAsBob(char** argv) {
	PRG prg;
	int party, port;
	char* inputVal = argv[3];
	int inputLength = atoi(argv[4]);
	if(inputLength % BYTE_BITS != 0) {
		cout << "Input length needs to be full bytes, instead is length " << inputLength << endl;
		return 0;
	}
	
	// pad length is set to make input bits divisible by block bits
	int padLength = BLOCK_BYTES - ((inputLength/BYTE_BITS) % BLOCK_BYTES);

	// Do not create extra block for inputs that don't need padding
	// (different than standard AES padding since number of blocks is shared between parties)
	if(padLength == BLOCK_BYTES) {
		padLength = 0;
	}

	cout << "pad length in bits " << padLength*BYTE_BITS << " input length in bits " << inputLength << endl;

	int inputBitLength = inputLength+(padLength*BYTE_BITS);
	bool* inputBits = new bool[inputBitLength];

	if(inputBitLength % BLOCK_BITS != 0) {
		cout << "error woth padding, total input bit length is not divisible by 128, is " << inputBitLength << endl;
		return 0;
	}

	// Parse input as binary
	for (int i = 0; i < inputLength; i++) {
		inputBits[i] = inputVal[i] == '1';
	}

	// To add the padding, input the padding length for each character in the padding.
	bitset<8> padValue((char)padLength);
	for(int i = inputLength; i < inputBitLength; i+=BYTE_BITS) {
		for(int j = 0; j < BYTE_BITS; j++) {
			inputBits[i + j] = padValue.test(j);
		}
	}

	cout << "Full message bits: " << endl;
	for (int i = 0; i < inputBitLength; i++) {
		cout << inputBits[i];
	}
	cout << endl;

	// First fill the result array with the randomly generated IV values
	bool* result = new bool[BLOCK_BITS];

	prg.random_bool(result, BLOCK_BITS);
	cout << "IV bits: " << endl;
	for (int i = 0; i < BLOCK_BITS; i++) {
		cout << result[i];
	}
	cout << endl;
	
	parse_party_and_port(argv, &party, &port);

	bool* xoredInput = new bool[BLOCK_BITS];
	int numIterations = inputBitLength / BLOCK_BITS;
	for (int iteration = 0; iteration < numIterations; iteration++) {
		NetIO* io = new NetIO(nullptr, port);
		io->set_nodelay();
		for(int i = 0; i < BLOCK_BITS; i++) {
			xoredInput[i] = result[i] ^ inputBits[BLOCK_BITS*iteration + i];
		}
		memset(result, false, BLOCK_BITS);
		test(party, io, "../emp-tool/emp-tool/circuits/files/AES-non-expanded.txt", xoredInput, result);
		// test(party, io, "aes_256.txt", inputBits, result);
		string res = "";
		for(int i = 0; i < BLOCK_BITS; ++i)
			res += (result[i]?"1":"0");
		cout << "result: " << res <<endl;
		delete io;
	}
	delete[] xoredInput;
	delete[] result;
	return 0;
}

// Alice gets the KEY
int runAsAlice(char** argv) {
	int party, port;
	char* inputVal = argv[3];
	int inputLength = atoi(argv[4]);
	
	if(inputLength != KEY_LENGTH) {
		cout << "Error, requires 128 bit key got " << inputLength << endl;
		return 0;
	}

	bool* inputBits = new bool[inputLength];

	for (int i = 0; i < inputLength; i++) {
		inputBits[i] = inputVal[i] == '1';
	}

	cout << "Full key bits: " << endl;
	for (int i = 0; i < inputLength; i++) {
		cout << inputBits[i];
	}
	cout << endl;

	// k = 256 bits
	// input = variable length

	// in a for loop, needs size of message

	parse_party_and_port(argv, &party, &port);
	bool* result = new bool[BLOCK_BITS];
	for (int i = 0; i < 2 /* needs to be numIterations depending on message legnth */; i++) {
		NetIO* io = new NetIO(IP, port);
		io->set_nodelay();
		test(party, io, "../emp-tool/emp-tool/circuits/files/AES-non-expanded.txt", inputBits, result);
		// test(party, io, "aes_256.txt", inputBits, result);
		delete io;
	}
	delete[] inputBits;
	delete[] result;
	return 0;
}

int main(int argc, char** argv) {
	int party, port;
	parse_party_and_port(argv, &party, &port);
	if(party == ALICE) {
		runAsAlice(argv);
	} else {
		runAsBob(argv);
	}
}

//11111111111100001111000011110000111100001111000011110000111100001111000011110000111100001111000011110000111100001111000011110000
