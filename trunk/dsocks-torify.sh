#!/bin/sh

# local TOR proxy server (tor)
export DSOCKS_VERSION="Tor"
export DSOCKS_PROXY="127.0.0.1:9050"

# you probably want to run tor-dns-proxy.py also...

# for MacOS X...
#LIBDSOCKS=/usr/local/lib/libdsocks.dylib
#DYLD_INSERT_LIBRARIES=$LIBDSOCKS DYLD_FORCE_FLAT_NAMESPACE=1 exec "$@"

LIBDSOCKS=/usr/local/lib/libdsocks.so.1.0
LD_PRELOAD=$LIBDSOCKS exec "$@"
