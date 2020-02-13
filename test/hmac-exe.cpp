#include <emp-tool/emp-tool.h>
#include "emp-ag2pc/emp-ag2pc.h"

using namespace std;
using namespace emp;

static int BITMASK_LENGTH = 32;

const string circuit_file_location = macro_xstr(EMP_CIRCUIT_PATH);

void test(int party, NetIO* io, string name, bool* in, string check_output = "") {
	string file = name; //circuit_file_location + name;
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

	// bool *in = new bool[max(cf.n1, cf.n2)];
	bool * out = new bool[cf.n3];
	cout << "Input size: " << max(cf.n1, cf.n2) << endl;
	// memset(in, false, max(cf.n1, cf.n2));
	memset(out, false, cf.n3);
	t1 = clock_start();
	twopc.online(in, out);
	cout << "online:\t"<<party<<"\t"<<time_from(t1)<<endl;
	
	string res = "";
	for(int i = 0; i < cf.n3; ++i)
		res += (out[i]?"1":"0");
	cout << "result: " << res <<endl;

	delete[] in;
	delete[] out;
}

int main(int argc, char** argv) {
	int party, port;
	char* inputVal = argv[3];
	int inputLength = atoi(argv[4]);
	bool* inputBits = new bool[inputLength * 8 + BITMASK_LENGTH * 8];
	parse_party_and_port(argv, &party, &port);
	
	// if(party == ALICE) {
		PRG prg;
		bool* mask = new bool[BITMASK_LENGTH * 8]; // Should be a constant
		
		prg.random_bool(mask, BITMASK_LENGTH * 8);

		// for(int i =0; i < BITMASK_LENGTH * 8; i ++) {
		// 	mask[i] = false;
		// }

		cout << "Output bitmask: ";
		for (int i = 0; i < BITMASK_LENGTH * 8; i++) {
			inputBits[inputLength*8 + i] = mask[i];
			cout << mask[i];
		}
		cout << endl;
	// } else {
	// 	for (int i = 0; i < BITMASK_LENGTH * 8; i++) {
	// 		inputBits[inputLength*8 + i] = false;
	// 	}
	// }

	for (int i = 0; i < inputLength; i++) {
		bitset<8> x(inputVal[i]);
		for(int j = 0; j < 8; j++) {
			inputBits[i*8 + j] = x.test(j);
		}
	}

	cout << "Full input bits: ";
	for (int i = 0; i < inputLength * 8; i++) {
		cout << inputBits[i];
	}
	// if (party == ALICE) {
		for (int i = 0; i < BITMASK_LENGTH * 8; i++) {
			cout << inputBits[inputLength*8 + i];
		}
	// }
	cout << endl;


	NetIO* io = new NetIO(party==ALICE ? nullptr:IP, port);
	io->set_nodelay();
	test(party, io, "gc-hmac.circuit.txt", inputBits);
	delete io;
	return 0;
}