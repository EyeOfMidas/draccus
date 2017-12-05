#include "main.h"

extern "C" {
static int auth_password(ssh_session session, const char *user, const char *pass, void *userdata) {
	session_data_struct *sdata = (session_data_struct *) userdata;

	(void) session;

	if (strcmp(user, "user") == 0 && strcmp(pass, "password") == 0) {
		sdata->authenticated = true;
		return SSH_AUTH_SUCCESS;
	}

	sdata->auth_attempts++;
	return SSH_AUTH_DENIED;
}

static int auth_pubkey(ssh_session session, const char *user, ssh_key_struct* pubkey, char signature_state, void *userdata) {

	std::cout << "using " << user << " pubkey" << std::endl;
	session_data_struct *sdata = (session_data_struct *) userdata;

	(void) user;
	(void) session;

	if (signature_state == SSH_PUBLICKEY_STATE_NONE) {
		std::cout << "\tno public key" << std::endl;
		return SSH_AUTH_SUCCESS;
	}

	if (signature_state != SSH_PUBLICKEY_STATE_VALID) {
		std::cout << "\tinvalid public key state" << std::endl;
		return SSH_AUTH_DENIED;
	}

	sdata->authenticated = false;
	ssh_key key;
	int result;
	char authorizedkeys[256];
	sprintf(authorizedkeys, "./authorized_keys/%s.pub", user);
	struct stat buf;    

	if (stat(authorizedkeys, &buf) == 0) {
		result = ssh_pki_import_pubkey_file( authorizedkeys, &key );
		if ((result != SSH_OK) || (key == NULL)) {
			std::cerr <<"\tUnable to import public key file" << std::endl;
		} else {
			result = ssh_key_cmp( key, pubkey, SSH_KEY_CMP_PUBLIC );
			ssh_key_free(key);
			if (result == 0) {
				sdata->authenticated = true;
				return SSH_AUTH_SUCCESS;
			}
		}
	}
	
	return SSH_AUTH_DENIED;
}

static ssh_channel channel_open(ssh_session session, void *userdata) {
	session_data_struct *sdata = (session_data_struct *) userdata;

	sdata->channel = ssh_channel_new(session);
	return sdata->channel;
}
} //end extern "C"


void endSession(ssh_event event, ssh_session session) {
	ssh_event_free(event);
	ssh_disconnect(session);
	ssh_free(session);
}

void spawnMudSession(ssh_event event, ssh_session session) {
	int loopCounter = 0;
	while(loopCounter < 300) {
		loopCounter++;
	}
	std::cout << "Thank you for playing!" << std::endl;
}

void sessionHandler(ssh_event event, ssh_session session) {
	std::cout << "Negotiating keys" << std::endl;
	if (ssh_handle_key_exchange(session) != SSH_OK) {
		std::cerr << "\t" << ssh_get_error(session) << std::endl;
		endSession(event, session);
		return;
	}

	std::cout << "setting auth methods" << std::endl;
	ssh_set_auth_methods(session, SSH_AUTH_METHOD_PUBLICKEY | SSH_AUTH_METHOD_PASSWORD);

	ssh_event_add_session(event, session);

	int timeoutCounter = 0;

	//Structure for storing the pty size. 
	winsize wsize;
	wsize.ws_row = 0;
	wsize.ws_col = 0;
	wsize.ws_xpixel = 0;
	wsize.ws_ypixel = 0;

	// Our struct holding information about the channel. 
	channel_data_struct cdata;
	cdata.pid = 0;
	cdata.pty_master = -1;
	cdata.pty_slave = -1;
	cdata.child_stdin = -1;
	cdata.child_stdout = -1;
	cdata.child_stderr = -1;
	cdata.event = NULL;
	cdata.wsize = &wsize;

	// Our struct holding information about the session.
	session_data_struct sdata;
	sdata.channel = NULL;
	sdata.auth_attempts = 0;
	sdata.authenticated = false;

	ssh_channel_callbacks_struct channel_cb;
	channel_cb.userdata = &cdata;

	ssh_server_callbacks_struct server_cb;
	server_cb.userdata = &sdata;
	server_cb.auth_password_function = auth_password;
	server_cb.auth_pubkey_function = auth_pubkey;
	server_cb.channel_open_request_session_function = channel_open;

	ssh_callbacks_init(&server_cb);
	ssh_callbacks_init(&channel_cb);

	ssh_set_server_callbacks(session, &server_cb);


	while (!sdata.authenticated) {
		if (sdata.auth_attempts >= 3) {
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

	std::cout << "session authenticated" << std::endl;
	spawnMudSession(event, session);
	endSession(event, session);
}


int main() {
	std::cout << "Draccus MUD v0.1" << std::endl;

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
	ssh_bind_options_set(sshbind, SSH_BIND_OPTIONS_LOG_VERBOSITY_STR, "4");

	std::cout << "Server start listening " << address << ":" << port << std::endl;
	if(ssh_bind_listen(sshbind) < 0) {
		std::cerr << "\t" << ssh_get_error(sshbind) << std::endl;
		return 1;
	}

	ssh_session session;
	ssh_event event;
	while(1) {
		std::cout << "Waiting for new connections" << std::endl;
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

