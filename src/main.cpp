#include "main.h"

void endSession(ssh_event event, ssh_session session) {
	ssh_event_free(event);
	ssh_disconnect(session);
	ssh_free(session);
}

void sessionHandler(ssh_event event, ssh_session session) {
	std::cout << "Negotiating keys" << std::endl;
	if (ssh_handle_key_exchange(session) != SSH_OK) {
		std::cerr << "\t" << ssh_get_error(session) << std::endl;
		endSession(event, session);
		return;
	}

	ssh_set_auth_methods(session, SSH_AUTH_METHOD_PASSWORD);
	ssh_event_add_session(event, session);

	int timeoutCounter = 0;
	bool isAuthenticated = false;
	int authAttempts = 0;

	while (!isAuthenticated) {
		if (authAttempts >= 3) {
			std::cerr << "\t" << "Too many failed auth attempts" << std::endl;
			endSession(event, session);
		}

		if(timeoutCounter >= 100) {
			std::cerr << "\t" << "Did not receive a response" << std::endl;
			endSession(event, session);
			return;
		}

		if (ssh_event_dopoll(event, 100) == SSH_ERROR) {
			std::cerr << "\t" << ssh_get_error(session) << std::endl;
			endSession(event, session);
			return;
		}
		timeoutCounter++;
	}


	endSession(event, session);
}


int main() {
	std::cout << "Draccus MUD Server v0.1" << std::endl;

	const char* address = "0.0.0.0";
	const char* port = "4000";

	ssh_init();
	ssh_bind sshbind;
	sshbind = ssh_bind_new();

	ssh_bind_options_set(sshbind, SSH_BIND_OPTIONS_BINDADDR, address);
	ssh_bind_options_set(sshbind, SSH_BIND_OPTIONS_BINDPORT_STR, port);

	ssh_bind_options_set(sshbind, SSH_BIND_OPTIONS_RSAKEY, "./ssh_host/ssh_host_rsa_key");
	ssh_bind_options_set(sshbind, SSH_BIND_OPTIONS_DSAKEY, "./ssh_host/ssh_host_dsa_key");

	// Use for debugging issues
	//ssh_bind_options_set(sshbind, SSH_BIND_OPTIONS_LOG_VERBOSITY_STR, "3");

	std::cout << "Server start listening " << address << ":" << port << std::endl;
	if(ssh_bind_listen(sshbind) < 0) {
		std::cerr << "\t" << ssh_get_error(sshbind) << std::endl;
		return 1;
	}

	ssh_session session;
	ssh_event event;
	std::cout << "Waiting for new connections" << std::endl;
	while(1) {
		session = ssh_new();
		if(session == NULL) {
			std::cerr << "\t" << "Failed to allocate session" << std::endl;
		}

		if(ssh_bind_accept(sshbind, session) != SSH_ERROR) {
			std::cout << "New connection attempt" << std::endl;
			event = ssh_event_new();
			if(event != NULL) {
				std::cout << "Spawning connection thread process" << std::endl;
				std::thread threadHandler(sessionHandler, event, session);
				threadHandler.join();
			} else {
				std::cerr << "\t" << "Could not create polling context" << std::endl;
			}
		} else {
			std::cerr << "\t" << ssh_get_error(sshbind) << std::endl;
		}
	}

	ssh_bind_free(sshbind);
	ssh_finalize();
	return 0;
}

