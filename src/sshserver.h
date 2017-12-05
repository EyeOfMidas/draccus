#ifndef SSHSERVER_H
#define SSHSERVER_H

#include <libssh/server.h>
#include <libssh/callbacks.h>
#include <libssh/libssh.h>
#include <iostream>
#include <thread>
#include <sys/stat.h>

typedef struct {
	int ws_row;
	int ws_col;
	int ws_xpixel;
	int ws_ypixel;
} winsize;

typedef struct {
	pid_t pid;
	socket_t pty_master;
	socket_t pty_slave;
	socket_t child_stdin;
	socket_t child_stdout;
	socket_t child_stderr;
	ssh_event event;
	winsize *wsize;
} channel_data_struct;

typedef struct  {
	ssh_channel channel;
	int auth_attempts;
	bool authenticated;
} session_data_struct;

class SshServer
{
	public:
		SshServer();
		~SshServer();

		int Start();
		void SessionHandler(ssh_event, ssh_session);

		void SpawnMudSession(ssh_event, ssh_session);
	private:
		int AuthPubkey(ssh_session, const char*, ssh_key_struct*, char, void*);

		const char* address;
		const char* port;
};
#endif
