#include <emp-tool/emp-tool.h>
#include "test/gr.h"
using namespace std;
using namespace emp;

int main(int argc, char** argv) {
	int party, port;
	parse_party_and_port(argv, &party, &port);
	NetIO* io = new NetIO(party==ALICE ? nullptr:IP, port);
	io->set_nodelay();
	test(party, io, circuit_file_location+"AES-non-expanded.txt");
	delete io;
	return 0;
}