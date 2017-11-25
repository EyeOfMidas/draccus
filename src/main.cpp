// my first program in C++
#include <libssh/libssh.h>
#include <iostream>
#include <cstdlib>
#include "main.h"

int main()
{
	std::cout << "Draccus MUD v0.1" << std::endl;
	ssh_session my_ssh_session = ssh_new();
	if (my_ssh_session == NULL)
	{
		exit(-1);
	}
	ssh_free(my_ssh_session);
}
