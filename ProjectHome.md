only enough of SOCKS4 and SOCK5 to use the built-in OpenSSH (e.g. `ssh -D <local_port> <gateway>`), or Tor local SOCKS proxy with Linux (gmake
-f GNUMakefile) or BSD systems (including MacOS X - just use 'bsdmake').

set LD\_PRELOAD/DYLD\_INSERT\_LIBRARIES to load this library to wrap a client app, or use the dsocks{-torify}.sh scripts. this only works for dynamically-linked binaries. to prevent DNS leaks while using Tor with statically-linked binaries, use the tor-dns-proxy.py script.