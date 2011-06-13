/*
 * dsocks.h
 *
 * Copyright (c) 2003 Dug Song <dugsong@monkey.org>
 *
 * $Id: dsocks.h,v 1.6 2006/10/07 06:32:36 dugsong Exp $
 */

#ifndef DSOCKS_H
#define DSOCKS_H

#ifndef __GNUC__
# ifndef __attribute__
#  define __attribute__(x)
# endif
# pragma pack(1)
#endif

struct dsocks4_hdr {
	uint8_t			vn;	/* version number */
	uint8_t			cd;	/* command code */
	uint16_t		dport;	/* destination port */
	uint32_t		dst;	/* destination IP */
} __attribute__((__packed__));

#define DSOCKS4_HDR_LEN		8

#define DSOCKS4_VN_REQUEST	4
#define DSOCKS4_CD_CONNECT	1	/* hdr + userid + null */

#define DSOCKS4_VN_REPLY	0
#define DSOCKS4_CD_OK		90
#define DSOCKS4_CD_FAIL		91
#define DSOCKS4_CD_NOIDENT	92
#define DSOCKS4_CD_BADUSER	93

/* RFC 1928 */
struct dsocks5_auth {
	uint8_t			ver;	/* version number */
	uint8_t			nmeths;	/* number of methods */
	uint8_t			method;	/* XXX - no auth */
} __attribute__((__packed__));

struct dsocks5_msg {
	uint8_t			ver;	/* version number */
	uint8_t			cmd;	/* command code */
	uint8_t			rsv;	/* reserved - 0x00 */
	uint8_t			atyp;	/* address type (IPv4 - 0x01) */
	uint32_t		dst;	/* destination IP */
	uint16_t		dport;	/* destination port */
} __attribute__((__packed__));

#define DSOCKS5_MSG_LEN		10

#define DSOCKS5_METHOD_NOAUTH	0x00
#define DSOCKS5_METHOD_NONE	0xff

#define DSOCKS5_CMD_CONNECT	0x01
#define DSOCKS5_ATYP_IPV4	0x01

#define DSOCKS5_REP_SUCCESS	0x00
#define DSOCKS5_REP_FAILURE	0x01
#define DSOCKS5_REP_NOTALLOWED	0x02
#define DSOCKS5_REP_NETUNREACH	0x03
#define DSOCKS5_REP_HOSTUNREACH	0x04
#define DSOCKS5_REP_CONNREFUSED	0x05
#define DSOCKS5_REP_TTLEXPIRED	0x06
#define DSOCKS5_REP_CMDNOTSUPP	0x07
#define DSOCKS5_REP_AFNOTSUPP	0x08

#ifdef __APPLE__
# define DSOCKS_PATH_LIBC	"libc.dylib"
#elif defined(__linux__)
# define DSOCKS_PATH_LIBC	"libc.so.6"
#else
# define DSOCKS_PATH_LIBC	"libc.so"
#endif
#define DSOCKS_SYM_CONNECT	"connect"
#define DSOCKS_SYM_GETADDRINFO	"getaddrinfo"
#define DSOCKS_SYM_GETHOSTBYNAME "gethostbyname"

#define DSOCKS_ENV_VERSION	"DSOCKS_VERSION"
#define DSOCKS_ENV_PROXY	"DSOCKS_PROXY"
#define DSOCKS_ENV_TOR		"DSOCKS_TOR"
#define DSOCKS_ENV_NAMESERVER	"DSOCKS_NAMESERVER"

void	_dsocks_init(void) __attribute__((constructor));

#endif /* DSOCKS_H */
