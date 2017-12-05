# draccus
A C++ based MUD client that uses SSH.

## Dependencies
You will need libssh-dev
    sudo apt-get install libssh-dev

## To compile
    make


## To run
    ./draccus


## To reset/clean
    make distclean


##Upcoming Features
* SSH connectivity
* Web-based character management
  * password, email and pubkey management
  * character inventory management

* builder tools
  * like wiki pages (builder mode: You tried to go "east" but that room doesn't exist. Create it?) 
  * create races, classes
  * quest building system

* Cross-MUD portaling
  * MUD server spins up telnet thread to another server, has auto-login features

