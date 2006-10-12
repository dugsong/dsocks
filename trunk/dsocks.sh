#!/bin/sh

# local SOCKS4 proxy server
#export DSOCKS_PROXY="127.0.0.1:10080"

# internal nameservice
#export DSOCKS_NAMESERVER="10.0.0.1"
#export LOCALDOMAIN="int.example.com"

# for MacOS X...
#LIBDSOCKS=/usr/local/lib/libdsocks.dylib
#DYLD_INSERT_LIBRARIES=$LIBDSOCKS DYLD_FORCE_FLAT_NAMESPACE=1 exec "$@"

LIBDSOCKS=/usr/local/lib/libdsocks.so.1.0
LD_PRELOAD=$LIBDSOCKS exec "$@"
