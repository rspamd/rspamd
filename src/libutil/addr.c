/*-
 * Copyright 2016 Vsevolod Stakhov
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#include "config.h"
#include "addr.h"
#include "util.h"
#include "logger.h"
#include "cryptobox.h"
#include "radix.h"
#include "unix-std.h"
/* pwd and grp */
#ifdef HAVE_PWD_H
#include <pwd.h>
#endif

#ifdef HAVE_GRP_H
#include <grp.h>
#endif

static radix_compressed_t *local_addrs;

enum {
	RSPAMD_IPV6_UNDEFINED = 0,
	RSPAMD_IPV6_SUPPORTED,
	RSPAMD_IPV6_UNSUPPORTED
} ipv6_status = RSPAMD_IPV6_UNDEFINED;

/**
 * Union that is used for storing sockaddrs
 */
union sa_union {
	struct sockaddr sa;
	struct sockaddr_in s4;
	struct sockaddr_in6 s6;
	struct sockaddr_un su;
	struct sockaddr_storage ss;
};

union sa_inet {
	struct sockaddr sa;
	struct sockaddr_in s4;
	struct sockaddr_in6 s6;
};

struct rspamd_addr_unix {
	struct sockaddr_un addr;
	gint mode;
	uid_t owner;
	gid_t group;
};

struct rspamd_addr_inet {
	union sa_inet addr;
};

struct rspamd_inet_addr_s {
	union {
		struct rspamd_addr_inet in;
		struct rspamd_addr_unix *un;
	} u;
	gint af;
	socklen_t slen;
};

static void
rspamd_ip_validate_af (rspamd_inet_addr_t *addr)
{
	if (addr->af != AF_UNIX) {
		if (addr->u.in.addr.sa.sa_family != addr->af) {
			addr->u.in.addr.sa.sa_family = addr->af;
		}
	}
	else {
		addr->u.un->addr.sun_family = AF_UNIX;
	}

	if (addr->af == AF_INET) {
		addr->slen = sizeof (struct sockaddr_in);
	}
	else if (addr->af == AF_INET6) {
		addr->slen = sizeof (struct sockaddr_in6);
	}
	else if (addr->af == AF_UNIX) {
#ifdef SUN_LEN
		addr->slen = SUN_LEN (&addr->u.un->addr);
#else
		addr->slen = sizeof (addr->u.un->addr);
#endif
#if defined(FREEBSD) || defined(__APPLE__)
		addr->u.un->addr.sun_len = addr->slen;
#endif
	}
}


static rspamd_inet_addr_t *
rspamd_inet_addr_create (gint af)
{
	rspamd_inet_addr_t *addr;

	addr = g_slice_alloc0 (sizeof (rspamd_inet_addr_t));

	if (af == AF_UNIX) {
		addr->u.un = g_slice_alloc (sizeof (*addr->u.un));
		addr->slen = sizeof (addr->u.un->addr);
		/* Zero terminate to avoid issues with SUN_LEN */
		addr->u.un->addr.sun_path[0] = '\0';
	}

	addr->af = af;

	rspamd_ip_validate_af (addr);

	return addr;
}

void
rspamd_inet_address_destroy (rspamd_inet_addr_t *addr)
{
	if (addr) {
		if (addr->af == AF_UNIX) {
			if (addr->u.un) {
				g_slice_free1 (sizeof (*addr->u.un), addr->u.un);
			}
		}
		g_slice_free1 (sizeof (rspamd_inet_addr_t), addr);
	}
}

static void
rspamd_ip_check_ipv6 (void)
{
	if (ipv6_status == RSPAMD_IPV6_UNDEFINED) {
		gint s, r;
		struct sockaddr_in6 sin6;
		const struct in6_addr ip6_local = IN6ADDR_LOOPBACK_INIT;

		s = socket (AF_INET6, SOCK_STREAM, 0);
		if (s == -1) {
			ipv6_status = RSPAMD_IPV6_UNSUPPORTED;
		}
		else {
			/*
			 * Some systems allow ipv6 sockets creating but not binding,
			 * so here we try to bind to some local address and check, whether it
			 * is possible
			 */
			memset (&sin6, 0, sizeof (sin6));
			sin6.sin6_family = AF_INET6;
			sin6.sin6_port = g_random_int_range (20000, 60000);
			sin6.sin6_addr = ip6_local;

			r = bind (s, (struct sockaddr *)&sin6, sizeof (sin6));
			if (r == -1 && errno != EADDRINUSE) {
				ipv6_status = RSPAMD_IPV6_UNSUPPORTED;
			}
			else {
				ipv6_status = RSPAMD_IPV6_SUPPORTED;
			}
			close (s);
		}
	}
}

gboolean
rspamd_ip_is_valid (const rspamd_inet_addr_t *addr)
{
	const struct in_addr ip4_any = { INADDR_ANY }, ip4_none = { INADDR_NONE };
	const struct in6_addr ip6_any = IN6ADDR_ANY_INIT;
	gboolean ret = FALSE;

	if (G_LIKELY (addr->af == AF_INET)) {
		if (memcmp (&addr->u.in.addr.s4.sin_addr, &ip4_any,
			sizeof (struct in_addr)) != 0 &&
			memcmp (&addr->u.in.addr.s4.sin_addr, &ip4_none,
			sizeof (struct in_addr)) != 0) {
			ret = TRUE;
		}
	}
	else if (G_UNLIKELY (addr->af == AF_INET6)) {
		if (memcmp (&addr->u.in.addr.s6.sin6_addr, &ip6_any,
			sizeof (struct in6_addr)) != 0) {
			ret = TRUE;
		}
	}

	return ret;
}

static void
rspamd_enable_accept_event (gint fd, short what, gpointer d)
{
	struct event *events = d;

	event_del (&events[1]);
	event_add (&events[0], NULL);
}

static void
rspamd_disable_accept_events (gint sock, GList *accept_events)
{
	GList *cur;
	struct event *events;
	const gdouble throttling = 0.5;
	struct timeval tv;
	struct event_base *ev_base;

	double_to_tv (throttling, &tv);

	for (cur = accept_events; cur != NULL; cur = g_list_next (cur)) {
		events = cur->data;

		ev_base = event_get_base (&events[0]);
		event_del (&events[0]);
		event_set (&events[1], sock, EV_TIMEOUT, rspamd_enable_accept_event,
				events);
		event_base_set (ev_base, &events[1]);
		event_add (&events[1], &tv);
	}
}

gint
rspamd_accept_from_socket (gint sock, rspamd_inet_addr_t **target,
		GList *accept_events)
{
	gint nfd, serrno;
	union sa_union su;
	socklen_t len = sizeof (su);
	rspamd_inet_addr_t *addr = NULL;

	if ((nfd = accept (sock, &su.sa, &len)) == -1) {
		if (target) {
			*target = NULL;
		}

		if (errno == EAGAIN || errno == EINTR || errno == EWOULDBLOCK) {
			return 0;
		}
		else if (errno == EMFILE || errno == ENFILE) {
			/* Temporary disable accept event */
			rspamd_disable_accept_events (sock, accept_events);

			return 0;
		}

		return -1;
	}

	addr = rspamd_inet_addr_create (su.sa.sa_family);
	addr->slen = len;

	if (addr->af == AF_UNIX) {
		addr->u.un = g_slice_alloc0 (sizeof (*addr->u.un));
		/* Get name from the listening socket */
		len = sizeof (su);

		if (getsockname (sock, &su.sa, &len) != -1) {
			memcpy (&addr->u.un->addr, &su.su, MIN (len,
					sizeof (struct sockaddr_un)));
		}
		else {
			/* Just copy socket address */
			memcpy (&addr->u.un->addr, &su.sa, sizeof (struct sockaddr));
		}
	}
	else {
		memcpy (&addr->u.in.addr, &su, MIN (len, sizeof (addr->u.in.addr)));
	}

	if (rspamd_socket_nonblocking (nfd) < 0) {
		goto out;
	}

	/* Set close on exec */
	if (fcntl (nfd, F_SETFD, FD_CLOEXEC) == -1) {
		msg_warn ("fcntl failed: %d, '%s'", errno, strerror (errno));
		goto out;
	}

	if (target) {
		*target = addr;
	}
	else {
		/* Avoid leak */
		rspamd_inet_address_destroy (addr);
	}

	return (nfd);

out:
	serrno = errno;
	close (nfd);
	errno = serrno;
	rspamd_inet_address_destroy (addr);

	return (-1);

}

static gboolean
rspamd_parse_unix_path (rspamd_inet_addr_t **target, const char *src)
{
	gchar **tokens, **cur_tok, *p, *pwbuf;
	glong pwlen;
	struct passwd pw, *ppw;
	struct group gr, *pgr;
	rspamd_inet_addr_t *addr;

	tokens = g_strsplit_set (src, " ", -1);

	addr = rspamd_inet_addr_create (AF_UNIX);

	rspamd_strlcpy (addr->u.un->addr.sun_path, tokens[0],
			sizeof (addr->u.un->addr.sun_path));
	#if defined(FREEBSD) || defined(__APPLE__)
	addr->u.un->addr.sun_len = SUN_LEN (&addr->u.un->addr);
	#endif

	addr->u.un->mode = 00644;
	addr->u.un->owner = (uid_t)-1;
	addr->u.un->group = (gid_t)-1;

	cur_tok = &tokens[1];
#ifdef _SC_GETPW_R_SIZE_MAX
	pwlen = sysconf (_SC_GETPW_R_SIZE_MAX);
	if (pwlen <= 0) {
		pwlen = 8192;
	}
#else
	pwlen = 8192;
#endif

	pwbuf = g_alloca (pwlen);

	while (*cur_tok) {
		if (g_ascii_strncasecmp (*cur_tok, "mode=", sizeof ("mode=") - 1) == 0) {
			p = strchr (*cur_tok, '=');
			/* XXX: add error check */
			addr->u.un->mode = strtoul (p + 1, NULL, 0);

			if (addr->u.un->mode == 0) {
				msg_err ("bad mode: %s", p + 1);
				errno = EINVAL;
				goto err;
			}
		}
		else if (g_ascii_strncasecmp (*cur_tok, "owner=",
				sizeof ("owner=") - 1) == 0) {
			p = strchr (*cur_tok, '=');

			if (getpwnam_r (p + 1, &pw, pwbuf, pwlen, &ppw) != 0 || ppw == NULL) {
				msg_err ("bad user: %s", p + 1);
				if (ppw == NULL) {
					errno = ENOENT;
				}
				goto err;
			}
			addr->u.un->owner = pw.pw_uid;
			addr->u.un->group = pw.pw_gid;
		}
		else if (g_ascii_strncasecmp (*cur_tok, "group=",
				sizeof ("group=") - 1) == 0) {
			p = strchr (*cur_tok, '=');

			if (getgrnam_r (p + 1, &gr, pwbuf, pwlen, &pgr) != 0 || pgr == NULL) {
				msg_err ("bad group: %s", p + 1);
				if (pgr == NULL) {
					errno = ENOENT;
				}
				goto err;
			}
			addr->u.un->group = gr.gr_gid;
		}
		cur_tok ++;
	}

	if (target) {
		rspamd_ip_validate_af (addr);
		*target = addr;
	}
	else {
		rspamd_inet_address_destroy (addr);
	}

	return TRUE;

err:

	rspamd_inet_address_destroy (addr);
	return FALSE;
}

gboolean
rspamd_parse_inet_address_ip4 (const guchar *text, gsize len, gpointer target)
{
	const guchar *p;
	guchar c;
	guint32 addr = 0, *addrptr = target;
	guint octet = 0, n = 0;

	g_assert (text != NULL);
	g_assert (target != NULL);

	if (len == 0) {
		len = strlen (text);
	}

	for (p = text; p < text + len; p++) {
		c = *p;

		if (c >= '0' && c <= '9') {
			octet = octet * 10 + (c - '0');

			if (octet > 255) {
				return FALSE;
			}

			continue;
		}

		if (c == '.') {
			addr = (addr << 8) + octet;
			octet = 0;
			n++;
			continue;
		}

		return FALSE;
	}

	if (n == 3) {
		addr = (addr << 8) + octet;
		*addrptr = ntohl (addr);

		return TRUE;
	}

	return FALSE;
}

gboolean
rspamd_parse_inet_address_ip6 (const guchar *text, gsize len, gpointer target)
{
	guchar t, *zero = NULL, *s, *d,  *addr = target;
	const guchar *p, *digit = NULL;
	gsize len4 = 0;
	guint n = 8, nibbles = 0, word = 0;

	g_assert (text != NULL);
	g_assert (target != NULL);

	if (len == 0) {
		len = strlen (text);
	}

	/* Ignore trailing semicolon */
	if (text[0] == ':') {
		p = text + 1;
		len--;
	}
	else {
		p = text;
	}

	for (/* void */; len; len--) {
		t = *p++;

		if (t == ':') {
			if (nibbles) {
				digit = p;
				len4 = len;
				*addr++ = (u_char) (word >> 8);
				*addr++ = (u_char) (word & 0xff);

				if (--n) {
					nibbles = 0;
					word = 0;
					continue;
				}
			} else {
				if (zero == NULL) {
					digit = p;
					len4 = len;
					zero = addr;
					continue;
				}
			}

			return FALSE;
		}

		if (t == '.' && nibbles) {
			if (n < 2 || digit == NULL) {
				return FALSE;
			}

			/* IPv4 encoded in IPv6 */
			if (!rspamd_parse_inet_address_ip4 (digit, len4 - 1, &word)) {
				return FALSE;
			}

			word = ntohl (word);
			*addr++ = (guchar) ((word >> 24) & 0xff);
			*addr++ = (guchar) ((word >> 16) & 0xff);
			n--;
			break;
		}

		if (++nibbles > 4) {
			/* Too many dots */
			return FALSE;
		}

		/* Restore from hex */
		if (t >= '0' && t <= '9') {
			word = word * 16 + (t - '0');
			continue;
		}

		t |= 0x20;

		if (t >= 'a' && t <= 'f') {
			word = word * 16 + (t - 'a') + 10;
			continue;
		}

		return FALSE;
	}

	if (nibbles == 0 && zero == NULL) {
		return FALSE;
	}

	*addr++ = (guchar) (word >> 8);
	*addr++ = (guchar) (word & 0xff);

	if (--n) {
		if (zero) {
			n *= 2;
			s = addr - 1;
			d = s + n;
			while (s >= zero) {
				*d-- = *s--;
			}
			memset (zero, 0, n);

			return TRUE;
		}

	} else {
		if (zero == NULL) {
			return TRUE;
		}
	}

	return FALSE;
}

gboolean
rspamd_parse_inet_address (rspamd_inet_addr_t **target,
		const char *src,
		gsize srclen)
{
	gboolean ret = FALSE;
	rspamd_inet_addr_t *addr = NULL;
	union sa_inet su;
	const char *end;
	char ipbuf[INET6_ADDRSTRLEN + 1];
	guint iplen;
	gulong portnum;

	g_assert (src != NULL);
	g_assert (target != NULL);

	if (srclen == 0) {
		srclen = strlen (src);
	}

	rspamd_ip_check_ipv6 ();

	if (src[0] == '/' || src[0] == '.') {
		return rspamd_parse_unix_path (target, src);
	}

	if (src[0] == '[') {
		/* Ipv6 address in format [::1]:port or just [::1] */
		end = memchr (src + 1, ']', srclen - 1);

		if (end == NULL) {
			return FALSE;
		}

		iplen = end - src - 1;

		if (iplen == 0 || iplen >= sizeof (ipbuf)) {
			return FALSE;
		}

		rspamd_strlcpy (ipbuf, src + 1, iplen + 1);

		if (ipv6_status == RSPAMD_IPV6_SUPPORTED &&
				rspamd_parse_inet_address_ip6 (ipbuf, iplen,
						&su.s6.sin6_addr)) {
			addr = rspamd_inet_addr_create (AF_INET6);
			memcpy (&addr->u.in.addr.s6.sin6_addr, &su.s6.sin6_addr,
					sizeof (struct in6_addr));
			ret = TRUE;
		}

		if (ret && end[1] == ':') {
			/* Port part */
			rspamd_strtoul (end + 1, srclen - iplen - 3, &portnum);
			rspamd_inet_address_set_port (addr, portnum);
		}
	}
	else {

		if ((end = memchr (src, ':', srclen)) != NULL) {
			/* This is either port number and ipv4 addr or ipv6 addr */
			/* Search for another semicolon */
			if (memchr (end + 1, ':', srclen - (end - src + 1)) &&
					ipv6_status == RSPAMD_IPV6_SUPPORTED &&
					rspamd_parse_inet_address_ip6 (src, srclen, &su.s6.sin6_addr)) {
				addr = rspamd_inet_addr_create (AF_INET6);
				memcpy (&addr->u.in.addr.s6.sin6_addr, &su.s6.sin6_addr,
						sizeof (struct in6_addr));
				ret = TRUE;
			}
			else {
				/* Not ipv6, so try ip:port */
				iplen = end - src;

				if (iplen >= sizeof (ipbuf) || iplen <= 1) {
					return FALSE;
				}
				else {
					rspamd_strlcpy (ipbuf, src, iplen + 1);
				}

				if (rspamd_parse_inet_address_ip4 (ipbuf, iplen,
						&su.s4.sin_addr)) {
					addr = rspamd_inet_addr_create (AF_INET);
					memcpy (&addr->u.in.addr.s4.sin_addr, &su.s4.sin_addr,
							sizeof (struct in_addr));
					rspamd_strtoul (end + 1, srclen - iplen - 1, &portnum);
					rspamd_inet_address_set_port (addr, portnum);
					ret = TRUE;
				}
			}
		}
		else {
			if (rspamd_parse_inet_address_ip4 (src, srclen, &su.s4.sin_addr)) {
				addr = rspamd_inet_addr_create (AF_INET);
				memcpy (&addr->u.in.addr.s4.sin_addr, &su.s4.sin_addr,
						sizeof (struct in_addr));
				ret = TRUE;
			}
			else if (ipv6_status == RSPAMD_IPV6_SUPPORTED &&
					rspamd_parse_inet_address_ip6 (src, srclen, &su.s6.sin6_addr)) {
				addr = rspamd_inet_addr_create (AF_INET6);
				memcpy (&addr->u.in.addr.s6.sin6_addr, &su.s6.sin6_addr,
						sizeof (struct in6_addr));
				ret = TRUE;
			}
		}
	}

	if (ret && target) {
		*target = addr;
	}

	return ret;
}

const char *
rspamd_inet_address_to_string (const rspamd_inet_addr_t *addr)
{
	static char addr_str[INET6_ADDRSTRLEN + 1];

	if (addr == NULL) {
		return "<empty inet address>";
	}

	switch (addr->af) {
	case AF_INET:
		return inet_ntop (addr->af, &addr->u.in.addr.s4.sin_addr, addr_str,
				   sizeof (addr_str));
	case AF_INET6:
		return inet_ntop (addr->af, &addr->u.in.addr.s6.sin6_addr, addr_str,
				   sizeof (addr_str));
	case AF_UNIX:
		return addr->u.un->addr.sun_path;
	}

	return "undefined";
}

const char *
rspamd_inet_address_to_string_pretty (const rspamd_inet_addr_t *addr)
{
	static char addr_str[PATH_MAX + 5];

	if (addr == NULL) {
		return "<empty inet address>";
	}

	switch (addr->af) {
	case AF_INET:
		rspamd_snprintf (addr_str, sizeof (addr_str), "%s:%d",
				rspamd_inet_address_to_string (addr),
				rspamd_inet_address_get_port (addr));
		break;
	case AF_INET6:
		rspamd_snprintf (addr_str, sizeof (addr_str), "[%s]:%d",
				rspamd_inet_address_to_string (addr),
				rspamd_inet_address_get_port (addr));
		break;
	case AF_UNIX:
		rspamd_snprintf (addr_str, sizeof (addr_str), "unix:%s",
				rspamd_inet_address_to_string (addr),
				rspamd_inet_address_get_port (addr));
		break;
	}

	return addr_str;
}

uint16_t
rspamd_inet_address_get_port (const rspamd_inet_addr_t *addr)
{
	switch (addr->af) {
	case AF_INET:
		return ntohs (addr->u.in.addr.s4.sin_port);
	case AF_INET6:
		return ntohs (addr->u.in.addr.s6.sin6_port);
	}

	return 0;
}

void
rspamd_inet_address_set_port (rspamd_inet_addr_t *addr, uint16_t port)
{
	switch (addr->af) {
	case AF_INET:
		addr->u.in.addr.s4.sin_port = htons (port);
		break;
	case AF_INET6:
		addr->u.in.addr.s6.sin6_port = htons (port);
		break;
	}
}

int
rspamd_inet_address_connect (const rspamd_inet_addr_t *addr, gint type,
		gboolean async)
{
	int fd, r;
	const struct sockaddr *sa;

	if (addr == NULL) {
		return -1;
	}

	fd = rspamd_socket_create (addr->af, type, 0, async);
	if (fd == -1) {
		return -1;
	}

	if (addr->af == AF_UNIX) {
		sa = (const struct sockaddr *)&addr->u.un->addr;
	}
	else {
		sa = &addr->u.in.addr.sa;
	}

	r = connect (fd, sa, addr->slen);

	if (r == -1) {
		if (!async || errno != EINPROGRESS) {
			close (fd);
			msg_warn ("connect failed: %d, '%s'", errno,
						strerror (errno));
			return -1;
		}
	}

	return fd;
}

int
rspamd_inet_address_listen (const rspamd_inet_addr_t *addr, gint type,
		gboolean async)
{
	gint fd, r;
	gint on = 1;
	const struct sockaddr *sa;
	const char *path;

	if (addr == NULL) {
		return -1;
	}

	fd = rspamd_socket_create (addr->af, type, 0, async);
	if (fd == -1) {
		return -1;
	}

	if (addr->af == AF_UNIX && access (addr->u.un->addr.sun_path, W_OK) != -1) {
		/* Unlink old socket */
		(void)unlink (addr->u.un->addr.sun_path);
	}

	if (addr->af == AF_UNIX) {
		sa = (const struct sockaddr *)&addr->u.un->addr;
	}
	else {
		sa = &addr->u.in.addr.sa;
	}

	(void)setsockopt (fd, SOL_SOCKET, SO_REUSEADDR, (const void *)&on, sizeof (gint));

#ifdef HAVE_IPV6_V6ONLY
	if (addr->af == AF_INET6) {
		/* We need to set this flag to avoid errors */
		on = 1;
#ifdef SOL_IPV6
		(void)setsockopt (fd, SOL_IPV6, IPV6_V6ONLY, (const void *)&on, sizeof (gint));
#elif defined(IPPROTO_IPV6)
		(void)setsockopt (fd, IPPROTO_IPV6, IPV6_V6ONLY, (const void *)&on, sizeof (gint));
#endif
	}
#endif

	r = bind (fd, sa, addr->slen);
	if (r == -1) {
		if (!async || errno != EINPROGRESS) {
			close (fd);
			msg_warn ("bind failed: %d, '%s'", errno,
						strerror (errno));
			return -1;
		}
	}

	if (type != SOCK_DGRAM) {

		if (addr->af == AF_UNIX) {
			path = addr->u.un->addr.sun_path;
			/* Try to set mode and owner */

			if (addr->u.un->owner != (uid_t)-1 || addr->u.un->group != (gid_t)-1) {
				if (chown (path, addr->u.un->owner, addr->u.un->group) == -1) {
					msg_info ("cannot change owner for %s to %d:%d: %s",
							path, addr->u.un->owner, addr->u.un->group,
							strerror (errno));
				}
			}

			if (chmod (path, addr->u.un->mode) == -1) {
				msg_info ("cannot change mode for %s to %od %s",
						path, addr->u.un->mode, strerror (errno));
			}
		}
		r = listen (fd, -1);

		if (r == -1) {
			msg_warn ("listen failed: %d, '%s'", errno, strerror (errno));
			close (fd);
			return -1;
		}
	}

	return fd;
}

gssize
rspamd_inet_address_recvfrom (gint fd, void *buf, gsize len, gint fl,
		rspamd_inet_addr_t **target)
{
	gssize ret;
	union sa_union su;
	socklen_t slen = sizeof (su);
	rspamd_inet_addr_t *addr = NULL;

	if ((ret = recvfrom (fd, buf, len, fl, &su.sa, &slen)) == -1) {
		if (target) {
			*target = NULL;
		}

		return -1;
	}

	if (target) {
		addr = rspamd_inet_addr_create (su.sa.sa_family);
		addr->slen = slen;

		if (addr->af == AF_UNIX) {
			addr->u.un = g_slice_alloc (sizeof (*addr->u.un));
			memcpy (&addr->u.un->addr, &su.su, sizeof (struct sockaddr_un));
		}
		else {
			memcpy (&addr->u.in.addr, &su.sa, MIN (slen, sizeof (addr->u.in.addr)));
		}

		*target = addr;
	}

	return (ret);
}

gssize
rspamd_inet_address_sendto (gint fd, const void *buf, gsize len, gint fl,
		const rspamd_inet_addr_t *addr)
{
	gssize r;
	const struct sockaddr *sa;

	if (addr == NULL) {
		return -1;
	}

	if (addr->af == AF_UNIX) {
		sa = (struct sockaddr *)&addr->u.un->addr;
	}
	else {
		sa = &addr->u.in.addr.sa;
	}

	r = sendto (fd, buf, len, fl, sa, addr->slen);

	return r;
}

static gboolean
rspamd_check_port_priority (const char *line, guint default_port,
		guint *priority, gchar *out,
		gsize outlen, rspamd_mempool_t *pool)
{
	guint real_port = default_port, real_priority = 0;
	gchar *err_str, *err_str_prio;

	if (line && line[0] == ':') {
		errno = 0;
		real_port = strtoul (line + 1, &err_str, 10);

		if (err_str && *err_str == ':') {
			/* We have priority */
			real_priority = strtoul (err_str + 1, &err_str_prio, 10);

			if (err_str_prio && *err_str_prio != '\0') {
				msg_err_pool_check (
						"cannot parse priority: %s, at symbol %c, error: %s",
						line,
						*err_str_prio,
						strerror (errno));

				return FALSE;
			}
		}
		else if (err_str && *err_str != '\0') {
			msg_err_pool_check (
					"cannot parse port: %s, at symbol %c, error: %s",
					line,
					*err_str,
					strerror (errno));

			return FALSE;
		}
	}

	if (priority) {
		*priority = real_priority;
	}

	rspamd_snprintf (out, outlen, "%ud", real_port);

	return TRUE;
}

static gboolean
rspamd_resolve_addrs (const char *begin, size_t len, GPtrArray **addrs,
		const gchar *portbuf, gint flags,
		rspamd_mempool_t *pool)
{
	struct addrinfo hints, *res, *cur;
	rspamd_inet_addr_t *cur_addr = NULL;
	gint r, addr_cnt;
	gchar *addr_cpy = NULL;

	rspamd_ip_check_ipv6 ();
	memset (&hints, 0, sizeof (hints));
	hints.ai_socktype = SOCK_STREAM; /* Type of the socket */
	hints.ai_flags = AI_NUMERICSERV|flags;

	if (len > 0) {
		addr_cpy = g_malloc (len + 1);
		rspamd_strlcpy (addr_cpy, begin, len + 1);
	}
	/* Otherwise it will be NULL */

	if (ipv6_status == RSPAMD_IPV6_SUPPORTED) {
		hints.ai_family = AF_UNSPEC;
	}
	else {
		hints.ai_family = AF_INET;
	}

	if ((r = getaddrinfo (addr_cpy, portbuf, &hints, &res)) == 0) {
		/* Now copy up to max_addrs of addresses */
		addr_cnt = 0;
		cur = res;
		while (cur) {
			cur = cur->ai_next;
			addr_cnt ++;
		}

		if (*addrs == NULL) {
			*addrs = g_ptr_array_new_full (addr_cnt,
					(GDestroyNotify)rspamd_inet_address_destroy);

			if (pool != NULL) {
				rspamd_mempool_add_destructor (pool,
						rspamd_ptr_array_free_hard, *addrs);
			}
		}

		cur = res;
		while (cur) {
			cur_addr = rspamd_inet_address_from_sa (cur->ai_addr,
					cur->ai_addrlen);

			if (cur_addr != NULL) {
				g_ptr_array_add (*addrs, cur_addr);
			}
			cur = cur->ai_next;
		}

		freeaddrinfo (res);
	}
	else if (addr_cpy) {
		msg_err_pool_check ("address resolution for %s failed: %s",
				addr_cpy,
				gai_strerror (r));
		g_free (addr_cpy);

		return FALSE;
	}
	else {
		/* Should never ever happen */
		g_assert (0);
	}

	return TRUE;
}

gboolean
rspamd_parse_host_port_priority (const gchar *str,
	GPtrArray **addrs,
	guint *priority,
	gchar **name_ptr,
	guint default_port,
	rspamd_mempool_t *pool)
{
	gchar portbuf[8];
	const gchar *p, *name = NULL;
	gsize namelen;
	rspamd_inet_addr_t *cur_addr = NULL;

	/*
	 * In this function, we can have several possibilities:
	 * 1) Unix socket: check for '.' or '/' at the begin of string
	 * 2) \[ipv6\]: check for '[' at the beginning
	 * 3) '*': means listening on any address
	 * 4) ip|host[:port[:priority]]
	 */

	if (str[0] == '*') {
		if (!rspamd_check_port_priority (str + 1, default_port, priority,
				portbuf, sizeof (portbuf), pool)) {
			return FALSE;
		}

		if (!rspamd_resolve_addrs (str, 0, addrs, portbuf, AI_PASSIVE, pool)) {
			return FALSE;
		}

		name = "*";
		namelen = 1;
	}
	else if (str[0] == '[') {
		/* This is braced IPv6 address */
		p = strchr (str, ']');

		if (p == NULL) {
			msg_err_pool_check ("cannot parse address definition %s: %s",
					str,
					strerror (EINVAL));

			return FALSE;
		}

		name = str + 1;
		namelen = p - str - 1;

		if (!rspamd_check_port_priority (p + 1, default_port, priority, portbuf,
				sizeof (portbuf), pool)) {
			return FALSE;
		}

		if (!rspamd_resolve_addrs (name, namelen, addrs,
				portbuf, 0, pool)) {
			return FALSE;
		}
	}
	else if (str[0] == '/' || str[0] == '.') {
		/* Special case of unix socket, as getaddrinfo cannot deal with them */
		if (*addrs == NULL) {
			*addrs = g_ptr_array_new_full (1,
					(GDestroyNotify)rspamd_inet_address_destroy);

			if (pool != NULL) {
				rspamd_mempool_add_destructor (pool,
						rspamd_ptr_array_free_hard, *addrs);
			}
		}

		if (!rspamd_parse_inet_address (&cur_addr, str, 0)) {
			msg_err_pool_check ("cannot parse unix socket definition %s: %s",
					str,
					strerror (errno));

			return FALSE;
		}

		g_ptr_array_add (*addrs, cur_addr);
		name = str;
		namelen = strlen (str);
	}
	else {
		p = strchr (str, ':');

		if (p == NULL) {
			/* Just address or IP */
			name = str;
			namelen = strlen (str);
			rspamd_check_port_priority ("", default_port, priority, portbuf,
					sizeof (portbuf), pool);

			if (!rspamd_resolve_addrs (name, namelen, addrs,
					portbuf, 0, pool)) {
				return FALSE;
			}
		}
		else {
			name = str;
			namelen = p - str;

			if (!rspamd_check_port_priority (p, default_port, priority, portbuf,
					sizeof (portbuf), pool)) {
				return FALSE;
			}

			if (!rspamd_resolve_addrs (str, p - str, addrs,
					portbuf, 0, pool)) {
				return FALSE;
			}
		}
	}

	if (name_ptr != NULL) {
		if (pool) {
			*name_ptr = rspamd_mempool_alloc (pool, namelen + 1);
		}
		else {
			*name_ptr = g_malloc (namelen + 1);
		}

		rspamd_strlcpy (*name_ptr, name, namelen + 1);
	}

	return TRUE;
}

guchar*
rspamd_inet_address_get_radix_key (const rspamd_inet_addr_t *addr, guint *klen)
{
	guchar *res = NULL;
	static struct in_addr local = {INADDR_LOOPBACK};

	g_assert (addr != NULL);
	g_assert (klen != NULL);

	if (addr->af == AF_INET) {
		*klen = sizeof (struct in_addr);
		res = (guchar *)&addr->u.in.addr.s4.sin_addr;
	}
	else if (addr->af == AF_INET6) {
		*klen = sizeof (struct in6_addr);
		res = (guchar *)&addr->u.in.addr.s6.sin6_addr;
	}
	else if (addr->af == AF_UNIX) {
		*klen = sizeof (struct in_addr);
		res = (guchar *)&local;
	}

	return res;
}


rspamd_inet_addr_t *
rspamd_inet_address_new (int af, const void *init)
{
	rspamd_inet_addr_t *addr;

	addr = rspamd_inet_addr_create (af);

	if (init != NULL) {
		if (af == AF_UNIX) {
			/* Init is a path */
			rspamd_strlcpy (addr->u.un->addr.sun_path, init,
					sizeof (addr->u.un->addr.sun_path));
#if defined(FREEBSD) || defined(__APPLE__)
			addr->u.un->addr.sun_len = SUN_LEN (&addr->u.un->addr);
#endif
		}
		else if (af == AF_INET) {
			memcpy (&addr->u.in.addr.s4.sin_addr, init, sizeof (struct in_addr));
		}
		else if (af == AF_INET6) {
			memcpy (&addr->u.in.addr.s6.sin6_addr, init, sizeof (struct in6_addr));
		}
	}

	return addr;
}

rspamd_inet_addr_t *
rspamd_inet_address_from_sa (const struct sockaddr *sa, socklen_t slen)
{
	rspamd_inet_addr_t *addr;

	g_assert (sa != NULL);
	g_assert (slen >= sizeof (struct sockaddr));

	addr = rspamd_inet_addr_create (sa->sa_family);

	if (sa->sa_family == AF_UNIX) {
		/* Init is a path */
		const struct sockaddr_un *un = (const struct sockaddr_un *)sa;

		g_assert (slen >= SUN_LEN (un));

		rspamd_strlcpy (addr->u.un->addr.sun_path, un->sun_path,
				sizeof (addr->u.un->addr.sun_path));
#if defined(FREEBSD) || defined(__APPLE__)
		addr->u.un->addr.sun_len = un->sun_len;
#endif
	}
	else if (sa->sa_family == AF_INET) {
		g_assert (slen >= sizeof (struct sockaddr_in));
		memcpy (&addr->u.in.addr.s4, sa, sizeof (struct sockaddr_in));
	}
	else if (sa->sa_family == AF_INET6) {
		g_assert (slen >= sizeof (struct sockaddr_in6));
		memcpy (&addr->u.in.addr.s6, sa, sizeof (struct sockaddr_in6));
	}
	else {
		/* XXX: currently we cannot deal with other AF */
		g_assert (0);
	}

	return addr;
}

rspamd_inet_addr_t *
rspamd_inet_address_from_rnds (const struct rdns_reply_entry *rep)
{
	rspamd_inet_addr_t *addr = NULL;

	g_assert (rep != NULL);

	if (rep->type == RDNS_REQUEST_A) {
		addr = rspamd_inet_addr_create (AF_INET);
		memcpy (&addr->u.in.addr.s4.sin_addr, &rep->content.a.addr,
				sizeof (struct in_addr));
	}
	else if (rep->type == RDNS_REQUEST_AAAA) {
		addr = rspamd_inet_addr_create (AF_INET6);
		memcpy (&addr->u.in.addr.s6.sin6_addr, &rep->content.aaa.addr,
						sizeof (struct in6_addr));
	}

	return addr;
}

void
rspamd_inet_address_apply_mask (rspamd_inet_addr_t *addr, guint mask)
{
	guint32 umsk, *p;

	if (mask > 0 && addr != NULL) {
		if (addr->af == AF_INET && mask <= 32) {
			umsk = htonl (G_MAXUINT32 << (32 - mask));
			addr->u.in.addr.s4.sin_addr.s_addr &= umsk;
		}
		else if (addr->af == AF_INET6 && mask <= 128) {
			p = (uint32_t *)&addr->u.in.addr.s6.sin6_addr;
			p += 3;
			while (mask > 0) {
				umsk = htonl (G_MAXUINT32 << (32 - (mask > 32 ? 32 : mask)));
				*p &= umsk;
				p --;
				mask -= 32;
			}
		}
	}
}

static gint
rspamd_inet_address_af_order (const rspamd_inet_addr_t *addr)
{
	int ret;

	switch (addr->af) {
	case AF_UNIX:
		ret = 2;
		break;
	case AF_INET:
		ret = 1;
		break;
	default:
		ret = 0;
		break;
	}

	return ret;
}

gint
rspamd_inet_address_compare (const rspamd_inet_addr_t *a1,
		const rspamd_inet_addr_t *a2)
{
	g_assert (a1 != NULL);
	g_assert (a2 != NULL);

	if (a1->af != a2->af) {
		return (rspamd_inet_address_af_order (a2) -
				rspamd_inet_address_af_order (a1));
	}
	else {
		switch (a1->af) {
		case AF_INET:
			return memcmp (&a1->u.in.addr.s4.sin_addr,
					&a2->u.in.addr.s4.sin_addr, sizeof (struct in_addr));
		case AF_INET6:
			return memcmp (&a1->u.in.addr.s6.sin6_addr,
				&a2->u.in.addr.s6.sin6_addr, sizeof (struct in6_addr));
		case AF_UNIX:
			return strncmp (a1->u.un->addr.sun_path,
				a2->u.un->addr.sun_path, sizeof (a1->u.un->addr.sun_path));
		default:
			return memcmp (&a1->u.in, &a2->u.in, sizeof (a1->u.in));
		}
	}

	return 0;
}

gint
rspamd_inet_address_compare_ptr (gconstpointer a1,
		gconstpointer a2)
{
	const rspamd_inet_addr_t **i1 = (const rspamd_inet_addr_t **)a1,
			**i2 = (const rspamd_inet_addr_t **)a2;

	return rspamd_inet_address_compare (*i1, *i2);
}

rspamd_inet_addr_t *
rspamd_inet_address_copy (const rspamd_inet_addr_t *addr)
{
	rspamd_inet_addr_t *n;

	if (addr == NULL) {
		return NULL;
	}

	n = rspamd_inet_addr_create (addr->af);

	if (n->af == AF_UNIX) {
		memcpy (n->u.un, addr->u.un, sizeof (*addr->u.un));
	}
	else {
		memcpy (&n->u.in, &addr->u.in, sizeof (addr->u.in));
	}

	return n;
}

gint
rspamd_inet_address_get_af (const rspamd_inet_addr_t *addr)
{
	g_assert (addr != NULL);

	return addr->af;
}


guint
rspamd_inet_address_hash (gconstpointer a)
{
	const rspamd_inet_addr_t *addr = a;
	rspamd_cryptobox_fast_hash_state_t st;

	rspamd_cryptobox_fast_hash_init (&st, rspamd_hash_seed ());
	rspamd_cryptobox_fast_hash_update (&st, &addr->af, sizeof (addr->af));


	if (addr->af == AF_UNIX && addr->u.un) {
		rspamd_cryptobox_fast_hash_update (&st, addr->u.un, sizeof (*addr->u.un));
	}
	else {
		/* We ignore port part here */
		if (addr->af == AF_INET) {
			rspamd_cryptobox_fast_hash_update (&st, &addr->u.in.addr.s4.sin_addr,
					sizeof (addr->u.in.addr.s4.sin_addr));
		}
		else {
			rspamd_cryptobox_fast_hash_update (&st, &addr->u.in.addr.s6.sin6_addr,
					sizeof (addr->u.in.addr.s6.sin6_addr));
		}
	}

	return rspamd_cryptobox_fast_hash_final (&st);
}

gboolean
rspamd_inet_address_equal (gconstpointer a, gconstpointer b)
{
	const rspamd_inet_addr_t *a1 = a, *a2 = b;

	return rspamd_inet_address_compare (a1, a2) == 0;
}

#ifndef IN6_IS_ADDR_LOOPBACK
#define	IN6_IS_ADDR_LOOPBACK(a)		\
	((*(const __uint32_t *)(const void *)(&(a)->s6_addr[0]) == 0) && \
	(*(const __uint32_t *)(const void *)(&(a)->s6_addr[4]) == 0) && \
	(*(const __uint32_t *)(const void *)(&(a)->s6_addr[8]) == 0) && \
	(*(const __uint32_t *)(const void *)(&(a)->s6_addr[12]) == ntohl(1)))
#endif
#ifndef IN6_IS_ADDR_LINKLOCAL
#define IN6_IS_ADDR_LINKLOCAL(a)	\
	(((a)->s6_addr[0] == 0xfe) && (((a)->s6_addr[1] & 0xc0) == 0x80))
#endif
#ifndef IN6_IS_ADDR_SITELOCAL
#define IN6_IS_ADDR_SITELOCAL(a)	\
	(((a)->s6_addr[0] == 0xfe) && (((a)->s6_addr[1] & 0xc0) == 0xc0))
#endif

gboolean
rspamd_inet_address_is_local (const rspamd_inet_addr_t *addr)
{
	if (addr == NULL) {
		return FALSE;
	}

	if (addr->af == AF_UNIX) {
		/* Always true for unix sockets */
		return TRUE;
	}
	else {
		if (addr->af == AF_INET) {
			if ((ntohl (addr->u.in.addr.s4.sin_addr.s_addr) & 0xff000000)
					== 0x7f000000) {
				return TRUE;
			}
		}
		else if (addr->af == AF_INET6) {
			if (IN6_IS_ADDR_LOOPBACK (&addr->u.in.addr.s6.sin6_addr) ||
						IN6_IS_ADDR_LINKLOCAL (&addr->u.in.addr.s6.sin6_addr) ||
						IN6_IS_ADDR_SITELOCAL (&addr->u.in.addr.s6.sin6_addr)) {
				return TRUE;
			}
		}

		if (local_addrs) {
			if (radix_find_compressed_addr (local_addrs, addr) != RADIX_NO_VALUE) {
				return TRUE;
			}
		}
	}

	return FALSE;
}

radix_compressed_t **
rspamd_inet_library_init (void)
{
	return &local_addrs;
}

void
rspamd_inet_library_destroy (void)
{
	if (local_addrs != NULL) {
		radix_destroy_compressed (local_addrs);
	}
}
