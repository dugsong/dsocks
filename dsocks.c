/*
 * dsocks.c
 *
 * Copyright (c) 2003 Dug Song <dugsong@monkey.org>
 *
 * $Id: dsocks.c,v 1.13 2006/10/07 06:32:36 dugsong Exp $
 */

#define BIND_8_COMPAT	1

#include <sys/param.h>
#include <sys/types.h>
#include <sys/socket.h>

#include <netinet/in.h>
#include <arpa/inet.h>
#include <arpa/nameser.h>

#ifdef __APPLE__
/* XXX - hack around __DARWIN_LDBL_COMPAT mangling in err.h, stdio.h */
# define __DARWIN_LDBL_COMPAT(x) /* nothing */
#endif
#include <dlfcn.h>
#include <err.h>
#include <errno.h>
#include <netdb.h>
#include <pwd.h>
#include <resolv.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "atomicio.h"
#include "dsocks.h"

#ifdef __linux__
size_t	strlcpy(char *dst, const char *src, size_t siz);
#endif

typedef int (*connect_fn)(int, const struct sockaddr *, socklen_t);
typedef int (*getaddrinfo_fn)(const char *, const char *,
                              const struct addrinfo *, struct addrinfo **);
typedef struct hostent *(*gethostbyname_fn)(const char *name);

static int		  _dsocks_tor;
static struct sockaddr_in _dsocks_sin, _dsocks_ns;
static char		  _dsocks_user[8 + 1];
static char		  _dsocks_host[MAXHOSTNAMELEN + 1];
static connect_fn	  _dsocks_connect, _sys_connect;
static getaddrinfo_fn	  _sys_getaddrinfo;
static gethostbyname_fn	  _sys_gethostbyname;

#define IS_LOOPBACK(sa)	(((struct sockaddr_in *)sa)->sin_addr.s_addr == \
			 htonl(INADDR_LOOPBACK))

static int
_sin_aton(const char *str, struct sockaddr_in *sin, int default_port)
{
	uint32_t ip;
	uint16_t port;
	char *p, *tmp;
	int ret = -1;
	
	if ((p = tmp = strdup(str)) != NULL) {
		ip = inet_addr(strsep(&p, ":"));
		port = p ? atoi(p) : default_port;
		if (ip != -1 && port != 0) {
			sin->sin_family = AF_INET;
#ifndef __linux__
			sin->sin_len = sizeof(sin);
#endif
			sin->sin_addr.s_addr = ip;
			sin->sin_port = htons(port);
			ret = 0;
		}
		free(tmp);
	}
	return (ret);
}

static const char *
_sin_ntoa(struct sockaddr_in *sin)
{
	static char buf[128];
	snprintf(buf, sizeof(buf), "%s:%d", inet_ntoa(sin->sin_addr),
	    ntohs(sin->sin_port));
	return (buf);
}

static int
_dsocks4_connect(int fd, const struct sockaddr *sa, socklen_t slen)
{
	struct sockaddr_in *sin = (struct sockaddr_in *)sa;
	struct dsocks4_hdr *ds4;
	char buf[sizeof(*ds4) + sizeof(_dsocks_user) + sizeof(_dsocks_host)];
	int len;

	ds4 = (struct dsocks4_hdr *)buf;
	ds4->vn = DSOCKS4_VN_REQUEST;
	ds4->cd = DSOCKS4_CD_CONNECT;
	ds4->dport = sin->sin_port;
	ds4->dst = sin->sin_addr.s_addr;
	len = sizeof(*ds4);
	len += strlcpy(buf + len, _dsocks_user, sizeof(_dsocks_user)) + 1;
	/* XXX - hidden service at 0.0.0.2 */
	if (sin->sin_addr.s_addr == htonl(2)) {
		len += strlcpy(buf + len, _dsocks_host,
		    sizeof(_dsocks_host)) + 1;
		_dsocks_host[0] = '\0';
	}
	if (atomicio(write, fd, buf, len) != len) {
		warn("(dsocks4) error sending request");
	} else if (atomicio(read, fd, buf, DSOCKS4_HDR_LEN) !=
	    DSOCKS4_HDR_LEN) {
		warn("(dsocks4) error reading reply");
	} else if (ds4->vn != DSOCKS4_VN_REPLY) {
		warnx("(dsocks4) invalid reply");
	} else if (ds4->cd != DSOCKS4_CD_OK) {
		warnx("(dsocks4) proxy connection refused");
	} else
		return (0);
	
	return (-1);
}

static int
_dsocks5_error(int rep)
{
	if (rep == DSOCKS5_REP_SUCCESS) {
		return (0);
	}
	if (rep == DSOCKS5_REP_NOTALLOWED) {
		errno = ECONNRESET;
	} else if (rep == DSOCKS5_REP_NETUNREACH) {
		errno = ENETUNREACH;
	} else if (rep == DSOCKS5_REP_HOSTUNREACH) {
		errno = EHOSTUNREACH;
	} else if (rep == DSOCKS5_REP_CONNREFUSED) {
		errno = ECONNREFUSED;
	} else if (DSOCKS5_REP_TTLEXPIRED) {
		errno = ETIMEDOUT;
	} else {
		errno = ECONNABORTED;
	}
	return (1);
}

static int
_dsocks5_connect(int fd, const struct sockaddr *sa, socklen_t slen)
{
	struct sockaddr_in *sin = (struct sockaddr_in *)sa;
	struct dsocks5_auth auth[1];
	struct dsocks5_msg msg[1];
	int len;

	auth->ver = 5;
	auth->nmeths = 1;
	auth->method = DSOCKS5_METHOD_NOAUTH;
	
	msg->ver = 5;
	msg->cmd = DSOCKS5_CMD_CONNECT;
	msg->rsv = 0;
	msg->atyp = DSOCKS5_ATYP_IPV4;
	msg->dst = sin->sin_addr.s_addr;
	msg->dport = sin->sin_port;
	len = DSOCKS5_MSG_LEN;

	if (atomicio(write, fd, (char *)auth, 3) != 3) {
		warn("(dsocks5) error sending auth request");
		return (-1);
	} 
	if (atomicio(read, fd, (char *)auth, 2) != 2) {
		warn("(dsocks5) error reading auth reply");
		return (-1);
	}
	if (auth->ver != 5) {
		warnx("(dsocks5) invalid auth reply: version = %d", auth->ver);
		return (-1);
	}
	if (auth->nmeths != DSOCKS5_METHOD_NOAUTH) {
		warnx("(dsocks5) authentication required");
		return (-1);
	}
	if (atomicio(write, fd, (char *)msg, len) != len) {
		warn("(dsocks5) error sending connect request");
		return (-1);
	} 
	if (atomicio(read, fd, (char *)msg, len) != len) {
		warn("(dsocks5) error reading connect reply");
		return (-1);
	} 
	if (_dsocks5_error(msg->cmd)) {
		warn("(dsocks5) unknown SOCKS5 error code: %d", msg->cmd);
		return (-1);
	}
	return (0);
}
	
int
connect(int fd, const struct sockaddr *sa, socklen_t len)
{
	struct sockaddr_in sin;
	int oval;
	socklen_t olen = sizeof(oval);
	fd_set wfds;
	struct timeval tv = {0, 0};
	int n;
	
	if (getsockopt(fd, SOL_SOCKET, SO_TYPE, &oval, &olen) < 0) {
		return (-1);
	}
	/* Only handle non-loopback, Internet stream sockets. */
	if (sa->sa_family != AF_INET || len != sizeof(sin) ||
	    IS_LOOPBACK(sa) || oval != SOCK_STREAM) {
		return ((*_sys_connect)(fd, sa, len));
	}
	if ((*_sys_connect)(fd, (struct sockaddr *)&_dsocks_sin,
		sizeof(_dsocks_sin)) == -1) {
		if (errno != EINPROGRESS) {
			goto CONNECT_FAILED;
		} else {
			FD_ZERO(&wfds);
			FD_SET(fd, &wfds);
			tv.tv_sec = 30;	/* Wait for 30 seconds */
			n = select(fd + 1, NULL, &wfds, NULL, &tv);
			if (n < 0) {
				goto CONNECT_FAILED;
			} else if (n == 0) {
				errno = ETIMEDOUT;
				goto CONNECT_FAILED;
			} else {
        		getsockopt(fd, SOL_SOCKET, SO_ERROR, &n, (socklen_t*)&len);
        		if (n != 0) {
	        		errno = n;
	        		goto CONNECT_FAILED;
        		}
			}
		}
	}
	memcpy(&sin, sa, sizeof(sin));
	return ((*_dsocks_connect)(fd, (struct sockaddr *)&sin, sizeof(sin)));

CONNECT_FAILED:
	warnx("(dsocks) couldn't connect to proxy at %s, error: %s",
	    _sin_ntoa(&_dsocks_sin), strerror(errno));
	return (-1);
}

static int
_send_recv_timeout(int fd, int secs, void *ibuf, size_t ilen,
    void *obuf, size_t olen)
{
	struct timeval tv = { 0, 0 };
	fd_set rfds;
	int n;
	
	if ((n = send(fd, ibuf, ilen, 0)) == ilen) {
		tv.tv_sec = secs;
		FD_ZERO(&rfds);
		FD_SET(fd, &rfds);
		
		if ((n = select(fd + 1, &rfds, NULL, NULL, &tv)) > 0)
			n = recv(fd, obuf, olen, 0);
	}
	return (n);
}

/* getanswer() ported from OpenBSD resolver */
typedef union {
	int32_t al;
	char ac;
} align;

#define MAXALIASES      35
#define MAXADDRS        35

static char *h_addr_ptrs[MAXADDRS + 1];
static struct hostent host;
static char *host_aliases[MAXALIASES];
static char hostbuf[BUFSIZ+1];

#ifdef NS_GET16
#define _getshort ns_get16
#endif

static struct hostent *
_getanswer(const u_char *answer, int anslen, const char *qname, int qtype)
{
	const HEADER *hp;
	const u_char *cp, *eom;
	char tbuf[MAXDNAME];
	char *bp, **ap, **hap, *ep;
	int type, class, ancount, qdcount, n;
	int haveanswer, had_error, toobig = 0;
	const char *tname;
	
	tname = qname;
	host.h_name = NULL;
	eom = answer + anslen;
	switch (qtype) {
	case T_A:
	case T_PTR:
		break;
	default:
		return (NULL);
	}
	/*
	 * find first satisfactory answer
	 */
	hp = (HEADER *)answer;
	ancount = ntohs(hp->ancount);
	qdcount = ntohs(hp->qdcount);
	bp = hostbuf;
	ep = hostbuf + sizeof hostbuf;
	cp = answer + HFIXEDSZ;
	if (qdcount != 1) {
		h_errno = NO_RECOVERY;
		return (NULL);
	}
	n = dn_expand(answer, eom, cp, bp, ep - bp);
	if (n < 0) {
		h_errno = NO_RECOVERY;
		return (NULL);
	}
	cp += n + QFIXEDSZ;
	if (qtype == T_A) {
		/* res_send() has already verified that the query name is the
		 * same as the one we sent; this just gets the expanded name
		 * (i.e., with the succeeding search-domain tacked on).
		 */
		n = strlen(bp) + 1;		/* for the \0 */
		host.h_name = bp;
		bp += n;
		/* The qname can be abbreviated, but h_name is now absolute. */
		qname = host.h_name;
	}
	ap = host_aliases;
	*ap = NULL;
	host.h_aliases = host_aliases;
	hap = h_addr_ptrs;
	*hap = NULL;
	host.h_addr_list = h_addr_ptrs;
	haveanswer = 0;
	had_error = 0;
	while (ancount-- > 0 && cp < eom && !had_error) {
		n = dn_expand(answer, eom, cp, bp, ep - bp);
		if (n < 0) {
			had_error++;
			continue;
		}
		cp += n;			/* name */
		if (cp >= eom)
			break;
		type = _getshort(cp);
		cp += INT16SZ;			/* type */
		if (cp >= eom)
			break;
		class = _getshort(cp);
 		cp += INT16SZ + INT32SZ;	/* class, TTL */
		if (cp >= eom)
			break;
		n = _getshort(cp);
		cp += INT16SZ;			/* len */
		if (cp >= eom)
			break;
		if (type == T_SIG) {
			/* XXX - ignore signatures as we don't use them yet */
			cp += n;
			continue;
		}
		if (class != C_IN) {
			/* XXX - debug? syslog? */
			cp += n;
			continue;		/* XXX - had_error++ ? */
		}
		if (qtype == T_A && type == T_CNAME) {
			if (ap >= &host_aliases[MAXALIASES-1])
				continue;
			n = dn_expand(answer, eom, cp, tbuf, sizeof tbuf);
			if (n < 0) {
				had_error++;
				continue;
			}
			cp += n;
			/* Store alias. */
			*ap++ = bp;
			n = strlen(bp) + 1;	/* for the \0 */
			bp += n;
			/* Get canonical name. */
			n = strlen(tbuf) + 1;	/* for the \0 */
			if (n > ep - bp) {
				had_error++;
				continue;
			}
			strlcpy(bp, tbuf, ep - bp);
			host.h_name = bp;
			bp += n;
			continue;
		}
		if (qtype == T_PTR && type == T_CNAME) {
			n = dn_expand(answer, eom, cp, tbuf, sizeof tbuf);
			if (n < 0) {
				had_error++;
				continue;
			}
			cp += n;
			/* Get canonical name. */
			n = strlen(tbuf) + 1;	/* for the \0 */
			if (n > ep - bp) {
				had_error++;
				continue;
			}
			strlcpy(bp, tbuf, ep - bp);
			tname = bp;
			bp += n;
			continue;
		}
		if (type != qtype) {
			cp += n;
			continue;		/* XXX - had_error++ ? */
		}
		switch (type) {
		case T_PTR:
			if (strcasecmp(tname, bp) != 0) {
				cp += n;
				continue;	/* XXX - had_error++ ? */
			}
			n = dn_expand(answer, eom, cp, bp, ep - bp);
			if (n < 0) {
				had_error++;
				break;
			}
			cp += n;
			if (!haveanswer)
				host.h_name = bp;
			else if (ap < &host_aliases[MAXALIASES-1])
				*ap++ = bp;
			else
				n = -1;
			if (n != -1) {
				n = strlen(bp) + 1;	/* for the \0 */
				bp += n;
			}
			break;
		case T_A:
			if (strcasecmp(host.h_name, bp) != 0) {
				cp += n;
				continue;	/* XXX - had_error++ ? */
			}
			if (n != host.h_length) {
				cp += n;
				continue;
			}
			if (!haveanswer) {
				int nn;

				host.h_name = bp;
				nn = strlen(bp) + 1;	/* for the \0 */
				bp += nn;
			}

			bp += sizeof(align) - ((u_long)bp % sizeof(align));

			if (bp + n >= &hostbuf[sizeof hostbuf]) {
				had_error++;
				continue;
			}
			if (hap >= &h_addr_ptrs[MAXADDRS-1]) {
				if (!toobig++)
				cp += n;
				continue;
			}
			bcopy(cp, *hap++ = bp, n);
			bp += n;
			cp += n;
			break;
		}
		if (!had_error)
			haveanswer++;
	}
	if (haveanswer) {
		*ap = NULL;
		*hap = NULL;
		if (!host.h_name) {
			n = strlen(qname) + 1;	/* for the \0 */
			if (n > ep - bp)
				goto try_again;
			strlcpy(bp, qname, ep - bp);
			host.h_name = bp;
			bp += n;
		}
		h_errno = NETDB_SUCCESS;
		return (&host);
	}
 try_again:
	h_errno = TRY_AGAIN;
	return (NULL);
}

static struct hostent *
_socks_gethostbyname(const char *name)
{
	struct hostent *hp = NULL;
	u_char buf[BUFSIZ];
	int fd, n;
	
	if ((n = res_mkquery(QUERY, name, C_IN, T_A, NULL, 0,
		 NULL, buf + 2, sizeof(buf) - 2)) < 0)
		return (NULL);
	*(u_int16_t *)buf = htons(n);
	
	if ((fd = socket(AF_INET, SOCK_STREAM, 0)) != -1) {
		if (connect(fd, (struct sockaddr *)&_dsocks_ns,
			sizeof(_dsocks_ns)) != -1) {
			if ((n = _send_recv_timeout(fd, RES_TIMEOUT,
				 buf, 2 + n, buf, sizeof(buf))) > 0) {
				if (ntohs(*(u_int16_t *)buf) == n - 2) {
					host.h_length = 4;
					hp = _getanswer(buf + 2, n - 2,
					    name, T_A);
				} else
					warnx("short read from nameserver %s",
					    _sin_ntoa(&_dsocks_ns));
			} else
				warnx("no answer from nameserver %s",
				    _sin_ntoa(&_dsocks_ns));
		}
		close(fd);
	}
	return (hp);
}

struct tor_req {
	u_int8_t	v;
	u_int8_t	cmd;
	u_int16_t	port;
	u_int32_t	ip;
};

static struct hostent *
_fake_hostent(const char *name, u_int32_t ip)
{
	memcpy(hostbuf, &ip, 4);
	strlcpy(hostbuf + 4, name, sizeof(hostbuf) - 4);
	host.h_name = hostbuf + 4;
	host_aliases[0] = NULL;
	host.h_aliases = host_aliases;
	host.h_addrtype = AF_INET;
	host.h_length = 4;
	h_addr_ptrs[0] = hostbuf;
	h_addr_ptrs[1] = NULL;
	host.h_addr_list = h_addr_ptrs;
	return (&host);
}

static struct hostent *
_tor_gethostbyname(const char *name)
{
	struct tor_req *req;
	struct hostent *hp = NULL;
	char *p, buf[sizeof(*req) + 1 + MAXHOSTNAMELEN];
	int fd;

	if ((p = strrchr(name, '.')) != NULL) {
		if (strcmp(p, ".onion") == 0) {
			/* XXX - hidden service request */
			strlcpy(_dsocks_host, name, sizeof(_dsocks_host));
			return (_fake_hostent(name, htonl(2))); /* 0.0.0.2 */
		}
	}
	/* Redirect name lookups to local Tor proxy. */
	req = (struct tor_req *)buf;
	req->v = 4;
	req->cmd = 0xF0;	/* resolve */
	req->port = 0;
	req->ip = htonl(1);	/* 0.0.0.1 */
	p = buf + sizeof(*req);
	*p++ = '\0';
	strlcpy(p, name, MAXHOSTNAMELEN);
	p += strlen(p) + 1;
	
	if ((fd = socket(AF_INET, SOCK_STREAM, 0)) != -1) {
		if ((*_sys_connect)(fd, (struct sockaddr *)&_dsocks_sin,
			sizeof(_dsocks_sin)) != -1) {
			if (_send_recv_timeout(fd, RES_TIMEOUT, buf, p - buf,
				buf, sizeof(buf)) == 8) {
				if (req->cmd == 90) {
					hp = _fake_hostent(name, req->ip);
				}
			}
		} else {
			warnx("(dsocks) couldn't connect to proxy at %s",
			    _sin_ntoa(&_dsocks_sin));
		}
		close(fd);
	}
	return (hp);
}

struct hostent *
gethostbyname(const char *name)
{
	if (_dsocks_tor) {
		return (_tor_gethostbyname(name));
	} else if (_dsocks_ns.sin_addr.s_addr != 0) {
		return (_socks_gethostbyname(name));
	}
	return (_sys_gethostbyname(name));
}

int
getaddrinfo(const char *hostname, const char *servname,
    const struct addrinfo *hints, struct addrinfo **res)
{
	struct hostent *hp;

	if (hostname != NULL) {
		if (_dsocks_tor) {
			if ((hp = _tor_gethostbyname(hostname)) != NULL)
				hostname = inet_ntoa(*(struct in_addr *)hp->h_addr);
		} else if (_dsocks_ns.sin_addr.s_addr != 0) {
			if ((hp = _socks_gethostbyname(hostname)) != NULL)
				hostname = inet_ntoa(*(struct in_addr *)hp->h_addr);
		}
	}
	return (_sys_getaddrinfo(hostname, servname, hints, res));
}

void
_dsocks_init(void)
{
	struct passwd *pw;
	char *env;
	void *libc;

	_dsocks_connect = _dsocks4_connect;
	
	if ((env = getenv(DSOCKS_ENV_VERSION)) != NULL) {
		if (strcmp(env, "5") == 0) {
			_dsocks_connect = _dsocks5_connect;
		} else if (strcasecmp(env, "tor") == 0) {
			_dsocks_tor = 1;
		} else if (strcmp(env, "4") != 0)
			errx(1, "(dsocks) unsupported version %s", env);
	}
	/* XXX - backward compatibility */
	if (getenv(DSOCKS_ENV_TOR) != NULL) {
		_dsocks_tor = 1;
	}
	if ((env = getenv(DSOCKS_ENV_PROXY)) != NULL) {
		if (_sin_aton(env, &_dsocks_sin, 1080) < 0)
			errx(1, "(dsocks) invalid proxy: %s", env);
	} else
		_sin_aton("127.0.0.1", &_dsocks_sin, 1080);
	
	if ((env = getenv(DSOCKS_ENV_NAMESERVER)) != NULL) {
		if (_sin_aton(env, &_dsocks_ns, 53) < 0)
			errx(1, "(dsocks) invalid nameserver: %s", env);
	}
	if ((pw = getpwuid(getuid())) != NULL) {
		strlcpy(_dsocks_user, pw->pw_name, sizeof(_dsocks_user));
	} else {
		/* XXX - getpwuid() actually fails on MacOS X Leopard! */
		strlcpy(_dsocks_user, getenv("USER"), sizeof(_dsocks_user));
	}
#ifndef DL_LAZY
# define DL_LAZY RTLD_LAZY
#endif
	if (!(libc = dlopen(DSOCKS_PATH_LIBC, DL_LAZY)))
		err(1, "(dsocks) couldn't dlopen %s", DSOCKS_PATH_LIBC);
	else if (!(_sys_connect = dlsym(libc, DSOCKS_SYM_CONNECT)))
		err(1, "(dsocks) couldn't dlsym '%s'", DSOCKS_SYM_CONNECT);
	else if (!(_sys_gethostbyname = dlsym(libc, DSOCKS_SYM_GETHOSTBYNAME)))
		err(1, "(dsocks) couldn't dlsym '%s'", DSOCKS_SYM_GETHOSTBYNAME);
	else if (!(_sys_getaddrinfo = dlsym(libc, DSOCKS_SYM_GETADDRINFO)))
		err(1, "(dsocks) couldn't dlsym '%s'", DSOCKS_SYM_GETADDRINFO);
}
