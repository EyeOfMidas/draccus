#include "main.h"
#include <libssh/server.h>
#include <iostream>
#include <thread>

void task1() {
	std::cout << "task running" << std::endl;
}


int main() {
	std::cout << "Draccus MUD v0.1" << std::endl;

	ssh_init();
	ssh_bind sshbind;
	sshbind = ssh_bind_new();

	ssh_bind_options_set(sshbind, SSH_BIND_OPTIONS_BINDADDR, "0.0.0.0");
	ssh_bind_options_set(sshbind, SSH_BIND_OPTIONS_BINDPORT_STR, "4000");

	ssh_bind_options_set(sshbind, SSH_BIND_OPTIONS_RSAKEY, "./ssh_host/ssh_host_rsa_key");
	ssh_bind_options_set(sshbind, SSH_BIND_OPTIONS_DSAKEY, "./ssh_host/ssh_host_dsa_key");

	// Use for debugging issues
	//ssh_bind_options_set(sshbind, SSH_BIND_OPTIONS_LOG_VERBOSITY_STR, "3");

	std::cout << "Listening" << std::endl;
	if(ssh_bind_listen(sshbind) < 0) {
		std::cerr << "\t" << ssh_get_error(sshbind) << std::endl;
		return 1;
	}

	ssh_session session;
	std::cout << "Waiting for new connections" << std::endl;
	while(1) {
		session = ssh_new();
		if(session == NULL) {
			std::cerr << "\t" << "Failed to allocated session" << std::endl;
		}

		if(ssh_bind_accept(sshbind, session) != SSH_ERROR) {
			std::thread t1(task1);
			t1.join();
		}
	}


	ssh_bind_free(sshbind);
	ssh_finalize();
	return 0;
}

