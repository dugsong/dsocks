#!/bin/sh

# not much uses SOCKS5 except browsers (see SwitchProxy for Firefox,
# and set network.proxy.socks_remote_dns in about:config - you don't
# need dsocks for this, though ;-)
#export DSOCKS_VERSION=5
#export DSOCKS_VERSION="Tor"

# local SOCKS4 proxy server - e.g. ssh -D10080 example.com
export DSOCKS_PROXY="127.0.0.1:10080"

# internal nameservice
#export DSOCKS_NAMESERVER="10.0.0.1"
#export LOCALDOMAIN="int.example.com"

if [ `uname -s` = "Darwin" ]; then
  # for MacOS X...
  LIBDSOCKS=/usr/local/lib/libdsocks.dylib
  DYLD_INSERT_LIBRARIES=$LIBDSOCKS DYLD_FORCE_FLAT_NAMESPACE=1 exec "$@"
else
  LIBDSOCKS=/usr/local/lib/libdsocks.so.1.0
  LD_PRELOAD=$LIBDSOCKS exec "$@"
fi

