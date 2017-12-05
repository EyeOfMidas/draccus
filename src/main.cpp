#include "main.h"

int main() {
	SshServer* server = new SshServer();
	return server->Start();
}

