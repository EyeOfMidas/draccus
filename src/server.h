#ifndef SERVER_H
#define SERVER_H

#include <libssh/libssh.h>
#include <iostream>
#include "server.h"

class Server
{
	public:
		Server();
		~Server();
	private:
		int port;
};
#endif
