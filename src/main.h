#ifndef MAIN_H
#define MAIN_H

#include <libssh/server.h>
#include <libssh/callbacks.h>
#include <libssh/libssh.h>
#include <iostream>
#include <thread>

typedef struct {
	int ws_row;
	int ws_col;
	int ws_xpixel;
	int ws_ypixel;
}  winsize;

typedef struct {

		/* pid of the child process the channel will spawn. */
	pid_t pid;
		/* For PTY allocation */
	socket_t pty_master;
	socket_t pty_slave;
		/* For communication with the child process. */
	socket_t child_stdin;
	socket_t child_stdout;
		/* Only used for subsystem and exec requests. */
	socket_t child_stderr;
		/* Event which is used to poll the above descriptors. */
	ssh_event event;
		/* Terminal size struct. */
	winsize *wsize;
}  channel_data_struct;

/* A userdata struct for session. */
typedef struct  {
	/* Pointer to the channel the session will allocate. */
	ssh_channel channel;
	int auth_attempts;
	int authenticated;
} session_data_struct;

// typedef struct  {
// 	size_t size;
// 	void *userdata;
// 	ssh_channel_data_callback channel_data_function;
// 	ssh_channel_eof_callback channel_eof_function;
// 	ssh_channel_close_callback channel_close_function;
// 	ssh_channel_signal_callback channel_signal_function;
// 	ssh_channel_exit_status_callback channel_exit_status_function;
// 	ssh_channel_exit_signal_callback channel_exit_signal_function;
// 	ssh_channel_pty_request_callback channel_pty_request_function;
// 	ssh_channel_shell_request_callback channel_shell_request_function;
// 	ssh_channel_auth_agent_req_callback channel_auth_agent_req_function;
// 	ssh_channel_x11_req_callback channel_x11_req_function;
// 	ssh_channel_pty_window_change_callback channel_pty_window_change_function;
// 	ssh_channel_exec_request_callback channel_exec_request_function;
// 	ssh_channel_env_request_callback channel_env_request_function;
// 	ssh_channel_subsystem_request_callback channel_subsystem_request_function;
// } ssh_channel_callbacks_struct;

// typedef struct  {
// 	size_t size;
// 	void *userdata;
// 	ssh_auth_password_callback auth_password_function;
// 	ssh_auth_none_callback auth_none_function;
// 	ssh_auth_gssapi_mic_callback auth_gssapi_mic_function;
// 	ssh_auth_pubkey_callback auth_pubkey_function;
// 	ssh_service_request_callback service_request_function;
// 	ssh_channel_open_request_session_callback channel_open_request_session_function;
// 	ssh_gssapi_select_oid_callback gssapi_select_oid_function;
// 	ssh_gssapi_accept_sec_ctx_callback gssapi_accept_sec_ctx_function;
// 	 /* This function will be called when a MIC needs to be verified.
// 	  */
// 	ssh_gssapi_verify_mic_callback gssapi_verify_mic_function;
// } ssh_server_callbacks_struct;

#endif
