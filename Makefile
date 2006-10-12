# $Id: Makefile,v 1.5 2005/07/14 13:17:49 dugsong Exp $

CFLAGS		= -g -Wall -O2

LIB		= dsocks
HDRS		= dsocks.h
SRCS		= dsocks.c atomicio.c
NOPROFILE	= yes

LIBDIR		= /usr/local/lib

.if ${unix} == "We run Darwin, not UNIX."
OSXFLAGS	= -nostdlib -flat_namespace -fno-common -undefined suppress
CFLAGS		+= $(OSXFLAGS)
# XXX - hack around missing LDFLAGS in bsd.lib.mk target
LDADD		= $(OSXFLAGS)
SHLIB_MAJOR	= 1
.endif

.include <bsd.lib.mk>
