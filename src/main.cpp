#include "main.h"


static int data_function(ssh_session session, ssh_channel channel, void *data,
                         uint32_t len, int is_stderr, void *userdata) {
    struct channel_data_struct *cdata = (struct channel_data_struct *) userdata;

    (void) session;
    (void) channel;
    (void) is_stderr;

    if (len == 0 || cdata->pid < 1 || kill(cdata->pid, 0) < 0) {
        return 0;
    }

    return write(cdata->child_stdin, (char *) data, len);
}

static int pty_request(ssh_session session, ssh_channel channel,
                       const char *term, int cols, int rows, int py, int px,
                       void *userdata) {
    struct channel_data_struct *cdata = (struct channel_data_struct *)userdata;

    (void) session;
    (void) channel;
    (void) term;

    cdata->winsize->ws_row = rows;
    cdata->winsize->ws_col = cols;
    cdata->winsize->ws_xpixel = px;
    cdata->winsize->ws_ypixel = py;

    if (openpty(&cdata->pty_master, &cdata->pty_slave, NULL, NULL,
                cdata->winsize) != 0) {
        fprintf(stderr, "Failed to open pty\n");
        return SSH_ERROR;
    }
    return SSH_OK;
}

static int pty_resize(ssh_session session, ssh_channel channel, int cols,
                      int rows, int py, int px, void *userdata) {
    struct channel_data_struct *cdata = (struct channel_data_struct *)userdata;

    (void) session;
    (void) channel;

    cdata->winsize->ws_row = rows;
    cdata->winsize->ws_col = cols;
    cdata->winsize->ws_xpixel = px;
    cdata->winsize->ws_ypixel = py;

    if (cdata->pty_master != -1) {
        return ioctl(cdata->pty_master, TIOCSWINSZ, cdata->winsize);
    }

    return SSH_ERROR;
}

static int exec_pty(const char *mode, const char *command,
                    struct channel_data_struct *cdata) {
    switch(cdata->pid = fork()) {
        case -1:
            close(cdata->pty_master);
            close(cdata->pty_slave);
            fprintf(stderr, "Failed to fork\n");
            return SSH_ERROR;
        case 0:
            close(cdata->pty_master);
            if (login_tty(cdata->pty_slave) != 0) {
                exit(1);
            }
            execl("/bin/sh", "sh", mode, command, NULL);
            exit(0);
        default:
            close(cdata->pty_slave);
            /* pty fd is bi-directional */
            cdata->child_stdout = cdata->child_stdin = cdata->pty_master;
    }
    return SSH_OK;
}

static int exec_nopty(const char *command, struct channel_data_struct *cdata) {
    int in[2], out[2], err[2];

    /* Do the plumbing to be able to talk with the child process. */
    if (pipe(in) != 0) {
        goto stdin_failed;
    }
    if (pipe(out) != 0) {
        goto stdout_failed;
    }
    if (pipe(err) != 0) {
        goto stderr_failed;
    }

    switch(cdata->pid = fork()) {
        case -1:
            goto fork_failed;
        case 0:
            /* Finish the plumbing in the child process. */
            close(in[1]);
            close(out[0]);
            close(err[0]);
            dup2(in[0], STDIN_FILENO);
            dup2(out[1], STDOUT_FILENO);
            dup2(err[1], STDERR_FILENO);
            close(in[0]);
            close(out[1]);
            close(err[1]);
            /* exec the requested command. */
            execl("/bin/sh", "sh", "-c", command, NULL);
            exit(0);
    }

    close(in[0]);
    close(out[1]);
    close(err[1]);

    cdata->child_stdin = in[1];
    cdata->child_stdout = out[0];
    cdata->child_stderr = err[0];

    return SSH_OK;

fork_failed:
    close(err[0]);
    close(err[1]);
stderr_failed:
    close(out[0]);
    close(out[1]);
stdout_failed:
    close(in[0]);
    close(in[1]);
stdin_failed:
    return SSH_ERROR;
}

static int exec_request(ssh_session session, ssh_channel channel,
                        const char *command, void *userdata) {
    struct channel_data_struct *cdata = (struct channel_data_struct *) userdata;


    (void) session;
    (void) channel;

    if(cdata->pid > 0) {
        return SSH_ERROR;
    }

    if (cdata->pty_master != -1 && cdata->pty_slave != -1) {
        return exec_pty("-c", command, cdata);
    }
    return exec_nopty(command, cdata);
}

static int shell_request(ssh_session session, ssh_channel channel,
                         void *userdata) {
    channel_data_struct *cdata = (channel_data_struct *) userdata;

    (void) session;
    (void) channel;

    if(cdata->pid > 0) {
        return SSH_ERROR;
    }

    if (cdata->pty_master != -1 && cdata->pty_slave != -1) {
        return exec_pty("-l", NULL, cdata);
    }
    /* Client requested a shell without a pty, let's pretend we allow that */
    return SSH_OK;
}

static int subsystem_request(ssh_session session, ssh_channel channel,
                             const char *subsystem, void *userdata) {
    /* subsystem requests behave simillarly to exec requests. */
    if (strcmp(subsystem, "sftp") == 0) {
    	//Disabled for now
        //return exec_request(session, channel, SFTP_SERVER_PATH, userdata);
    }
    return SSH_ERROR;
}

static int auth_password(ssh_session session, const char *user,
                         const char *pass, void *userdata) {
    session_data_struct *sdata = (session_data_struct *) userdata;

    (void) session;

    if (strcmp(user, "user") == 0 && strcmp(pass, "password") == 0) {
        sdata->authenticated = 1;
        return SSH_AUTH_SUCCESS;
    }

    sdata->auth_attempts++;
    return SSH_AUTH_DENIED;
}

static ssh_channel channel_open(ssh_session session, void *userdata) {
    session_data_struct *sdata = (session_data_struct *) userdata;

    sdata->channel = ssh_channel_new(session);
    return sdata->channel;
}


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
		sdata.authenticated = 0;

	ssh_channel_callbacks_struct channel_cb;

		channel_cb.userdata = &cdata;
		channel_cb.channel_pty_request_function = pty_request;
		channel_cb.channel_pty_window_change_function = pty_resize;
		channel_cb.channel_shell_request_function = shell_request;
		channel_cb.channel_exec_request_function = exec_request;
		channel_cb.channel_data_function = data_function;
		channel_cb.channel_subsystem_request_function = subsystem_request;

	ssh_server_callbacks_struct server_cb;
		server_cb.userdata = &sdata;
		server_cb.auth_password_function = auth_password;
		server_cb.channel_open_request_session_function = channel_open;

	ssh_callbacks_init(&server_cb);
	ssh_callbacks_init(&channel_cb);

	ssh_set_server_callbacks(session, &server_cb);


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

