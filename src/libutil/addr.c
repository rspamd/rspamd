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
#include "unix-std.h"
/* pwd and grp */
#ifdef HAVE_PWD_H
#include <pwd.h>
#endif

#ifdef HAVE_GRP_H
#include <grp.h>
#endif

static void *local_addrs;

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

#define RSPAMD_MAYBE_ALLOC_POOL(pool, sz) \
	(pool != NULL) ? rspamd_mempool_alloc((pool), (sz)) : g_malloc(sz)
#define RSPAMD_MAYBE_ALLOC0_POOL(pool, sz) \
	(pool != NULL) ? rspamd_mempool_alloc0((pool), (sz)) : g_malloc0(sz)

static rspamd_inet_addr_t *
rspamd_inet_addr_create (gint af, rspamd_mempool_t *pool)
{
	rspamd_inet_addr_t *addr;

	addr = RSPAMD_MAYBE_ALLOC0_POOL (pool, sizeof(*addr));

	addr->af = af;

	if (af == AF_UNIX) {
		addr->u.un = RSPAMD_MAYBE_ALLOC0_POOL(pool, sizeof (*addr->u.un));
		addr->slen = sizeof (addr->u.un->addr);
	}
	else {
		rspamd_ip_validate_af (addr);
	}

	return addr;
}

void
rspamd_inet_address_free (rspamd_inet_addr_t *addr)
{
	if (addr) {
		if (addr->af == AF_UNIX) {
			if (addr->u.un) {
				g_free (addr->u.un);
			}
		}
		g_free (addr);
	}
}

static void
rspamd_ip_check_ipv6 (void)
{
	if (ipv6_status == RSPAMD_IPV6_UNDEFINED) {
		gint s;

		s = socket (AF_INET6, SOCK_STREAM, 0);

		if (s == -1) {
			ipv6_status = RSPAMD_IPV6_UNSUPPORTED;
		}
		else {
			/*
			 * Try to check /proc if we are on Linux (the common case)
			 */
			struct stat st;

			close (s);

			if (stat ("/proc/net/dev", &st) != -1) {
				if (stat ("/proc/net/if_inet6", &st) != -1) {
					ipv6_status = RSPAMD_IPV6_SUPPORTED;
				}
				else {
					ipv6_status = RSPAMD_IPV6_UNSUPPORTED;
				}
			}
			else {
				/* Not a Linux, so we assume it supports ipv6 somehow... */
				ipv6_status = RSPAMD_IPV6_SUPPORTED;
			}
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

gint
rspamd_accept_from_socket (gint sock, rspamd_inet_addr_t **target,
						   rspamd_accept_throttling_handler hdl,
						   void *hdl_data)
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
			if (hdl) {
				hdl (sock, hdl_data);
			}

			return 0;
		}

		return -1;
	}

	if (su.sa.sa_family == AF_INET6) {
		/* Deal with bloody v4 mapped to v6 addresses */

		static const guint8 mask[] = {
				0, 0, 0, 0, 0, 0, 0, 0, 0, 0
		};
		const guint8 *p;

		if (memcmp ((const guint8 *)&su.s6.sin6_addr, mask, sizeof (mask)) == 0) {
			p = (const guint8 *)&su.s6.sin6_addr;

			if ((p[10] == 0xff && p[11] == 0xff)) {
				addr = rspamd_inet_addr_create (AF_INET, NULL);
				memcpy (&addr->u.in.addr.s4.sin_addr, &p[12],
						sizeof (struct in_addr));
				addr->u.in.addr.s4.sin_port = su.s6.sin6_port;
			}
			else {
				/* Something strange but not mapped v4 address */
				addr = rspamd_inet_addr_create (AF_INET6, NULL);
				memcpy (&addr->u.in.addr.s6, &su.s6,
						sizeof (struct sockaddr_in6));
			}
		}
		else {
			addr = rspamd_inet_addr_create (AF_INET6, NULL);
			memcpy (&addr->u.in.addr.s6, &su.s6,
					sizeof (struct sockaddr_in6));
		}

	}
	else {
		addr = rspamd_inet_addr_create (su.sa.sa_family, NULL);
		addr->slen = len;

		if (addr->af == AF_UNIX) {
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
		rspamd_inet_address_free (addr);
	}

	return (nfd);

out:
	serrno = errno;
	close (nfd);
	errno = serrno;
	rspamd_inet_address_free (addr);

	return (-1);

}

static gboolean
rspamd_parse_unix_path (rspamd_inet_addr_t **target,
						const char *src, gsize len,
						rspamd_mempool_t *pool,
						enum rspamd_inet_address_parse_flags how)
{
	gchar **tokens, **cur_tok, *p, *pwbuf;
	glong pwlen;
	struct passwd pw, *ppw;
	struct group gr, *pgr;
	rspamd_inet_addr_t *addr;
	bool has_group = false;

	addr = rspamd_inet_addr_create (AF_UNIX, pool);

	addr->u.un->mode = 00644;
	addr->u.un->owner = (uid_t)-1;
	addr->u.un->group = (gid_t)-1;

	if (!(how & RSPAMD_INET_ADDRESS_PARSE_REMOTE)) {
		tokens = rspamd_string_len_split (src, len, " ,", -1, pool);

		if (tokens[0] == NULL) {

			if (!pool) {
				rspamd_inet_address_free(addr);
				g_strfreev (tokens);
			}

			return FALSE;
		}

		rspamd_strlcpy (addr->u.un->addr.sun_path, tokens[0],
				sizeof (addr->u.un->addr.sun_path));
#if defined(FREEBSD) || defined(__APPLE__)
		addr->u.un->addr.sun_len = SUN_LEN (&addr->u.un->addr);
#endif
	}
	else {
		rspamd_strlcpy (addr->u.un->addr.sun_path, src,
				MIN (len + 1, sizeof (addr->u.un->addr.sun_path)));
#if defined(FREEBSD) || defined(__APPLE__)
		addr->u.un->addr.sun_len = SUN_LEN (&addr->u.un->addr);
#endif

		if (target) {
			rspamd_ip_validate_af (addr);
			*target = addr;
		}
		else {
			if (!pool) {
				rspamd_inet_address_free(addr);
			}
		}

		return TRUE;
	}

	/* Skip for remote */
	cur_tok = &tokens[1];
#ifdef _SC_GETPW_R_SIZE_MAX
	pwlen = sysconf (_SC_GETPW_R_SIZE_MAX);
	if (pwlen <= 0) {
		pwlen = 8192;
	}
#else
	pwlen = 8192;
#endif

	pwbuf = g_malloc0 (pwlen);

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

			if (!has_group) {
				addr->u.un->group = pw.pw_gid;
			}
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

			has_group = true;
			addr->u.un->group = gr.gr_gid;
		}
		cur_tok ++;
	}

	g_free (pwbuf);

	if (!pool) {
		g_strfreev(tokens);
	}

	if (target) {
		rspamd_ip_validate_af (addr);
		*target = addr;
	}
	else {
		if (!pool) {
			rspamd_inet_address_free(addr);
		}
	}

	return TRUE;

err:

	g_free (pwbuf);

	if (!pool) {
		g_strfreev(tokens);
		rspamd_inet_address_free (addr);
	}

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
	const guchar *p, *digit = NULL, *percent;
	gsize len4 = 0;
	guint n = 8, nibbles = 0, word = 0;

	g_assert (text != NULL);
	g_assert (target != NULL);

	p = text;
	if (len == 0) {
		len = strlen (text);
	}

	/* Check IPv6 scope */
	if ((percent = memchr (p, '%', len)) != NULL && percent > p) {
		len = percent - p; /* Ignore scope */
	}

	if (len > sizeof ("IPv6:") - 1 &&
		g_ascii_strncasecmp (p, "IPv6:", sizeof ("IPv6:") - 1) == 0) {
		/* Special case, SMTP conformant IPv6 address */
		p += sizeof ("IPv6:") - 1;
		len -= sizeof ("IPv6:") - 1;
	}

	if (*p == '[' && len > 1 && p[len - 1] == ']') {
		/* Strip [] as well */
		p ++;
		len -= 2;
	}

	/* Ignore leading colon */
	if (len > 0 && *p == ':') {
		p++;
		len--;
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
			/* Too many digits */
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

/* Checks for ipv6 mapped address */
static rspamd_inet_addr_t *
rspamd_inet_address_v6_maybe_map (const struct sockaddr_in6 *sin6,
		rspamd_mempool_t *pool)
{
	rspamd_inet_addr_t *addr = NULL;
	/* 10 zero bytes or 80 bits */
	static const guint8 mask[] = {
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0
	};
	const guint8 *p;

	if (memcmp ((const guint8 *)&sin6->sin6_addr, mask, sizeof (mask)) == 0) {
		p = (const guint8 *)&sin6->sin6_addr;

		if ((p[10] == 0xff && p[11] == 0xff)) {
			addr = rspamd_inet_addr_create (AF_INET, pool);
			memcpy (&addr->u.in.addr.s4.sin_addr, &p[12],
					sizeof (struct in_addr));
		}
		else {
			/* Something strange but not mapped v4 address */
			addr = rspamd_inet_addr_create (AF_INET6, pool);
			memcpy (&addr->u.in.addr.s6.sin6_addr, &sin6->sin6_addr,
					sizeof (struct in6_addr));
		}
	}
	else {
		addr = rspamd_inet_addr_create (AF_INET6, pool);
		memcpy (&addr->u.in.addr.s6.sin6_addr, &sin6->sin6_addr,
				sizeof (struct in6_addr));
	}

	return addr;
}

static void
rspamd_inet_address_v6_maybe_map_static (const struct sockaddr_in6 *sin6,
		rspamd_inet_addr_t *addr)
{
	/* 10 zero bytes or 80 bits */
	static const guint8 mask[] = {
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0
	};
	const guint8 *p;

	if (memcmp ((const guint8 *)&sin6->sin6_addr, mask, sizeof (mask)) == 0) {
		p = (const guint8 *)&sin6->sin6_addr;

		if ((p[10] == 0xff && p[11] == 0xff)) {
			memcpy (&addr->u.in.addr.s4.sin_addr, &p[12],
					sizeof (struct in_addr));
			addr->af = AF_INET;
			addr->slen = sizeof (addr->u.in.addr.s4);
		}
		else {
			/* Something strange but not mapped v4 address */
			memcpy (&addr->u.in.addr.s6.sin6_addr, &sin6->sin6_addr,
					sizeof (struct in6_addr));
			addr->af = AF_INET6;
			addr->slen = sizeof (addr->u.in.addr.s6);
		}
	}
	else {
		memcpy (&addr->u.in.addr.s6.sin6_addr, &sin6->sin6_addr,
				sizeof (struct in6_addr));
		addr->af = AF_INET6;
		addr->slen = sizeof (addr->u.in.addr.s6);
	}
}

static gboolean
rspamd_parse_inet_address_common (rspamd_inet_addr_t **target,
								  const char *src,
								  gsize srclen,
								  rspamd_mempool_t *pool,
								  enum rspamd_inet_address_parse_flags how)
{
	gboolean ret = FALSE;
	rspamd_inet_addr_t *addr = NULL;
	union sa_inet su;
	const char *end = NULL;
	char ipbuf[INET6_ADDRSTRLEN + 1];
	guint iplen;
	gulong portnum;

	if (srclen == 0) {
		return FALSE;
	}

	g_assert (src != NULL);
	g_assert (target != NULL);

	rspamd_ip_check_ipv6 ();

	if (!(how & RSPAMD_INET_ADDRESS_PARSE_NO_UNIX) &&
		(src[0] == '/' || src[0] == '.')) {
		return rspamd_parse_unix_path (target, src, srclen, pool, how);
	}

	if (src[0] == '[') {
		const gchar *ip_start;
		/* Ipv6 address in format [::1]:port or just [::1] */
		end = memchr (src + 1, ']', srclen - 1);

		if (end == NULL) {
			return FALSE;
		}

		iplen = end - src - 1;

		if (iplen == 0 || iplen >= sizeof (ipbuf)) {
			return FALSE;
		}

		ip_start = src + 1;
		rspamd_strlcpy (ipbuf, ip_start, iplen + 1);

		if (rspamd_parse_inet_address_ip6 (ipbuf, iplen,
						&su.s6.sin6_addr)) {
			addr = rspamd_inet_address_v6_maybe_map (&su.s6, pool);
			ret = TRUE;
		}

		if (!(how & RSPAMD_INET_ADDRESS_PARSE_NO_PORT) && ret && end[1] == ':') {
			/* Port part */
			rspamd_strtoul (end + 1, srclen - iplen - 3, &portnum);
			rspamd_inet_address_set_port (addr, portnum);
		}
	}
	else {

		if (!(how & RSPAMD_INET_ADDRESS_PARSE_NO_PORT) &&
			(end = memchr (src, ':', srclen)) != NULL) {
			/* This is either port number and ipv4 addr or ipv6 addr */
			/* Search for another semicolon */
			if (memchr (end + 1, ':', srclen - (end - src + 1)) &&
					rspamd_parse_inet_address_ip6 (src, srclen,
							&su.s6.sin6_addr)) {
				addr = rspamd_inet_address_v6_maybe_map (&su.s6, pool);
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
					addr = rspamd_inet_addr_create (AF_INET, pool);
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
				addr = rspamd_inet_addr_create (AF_INET, pool);
				memcpy (&addr->u.in.addr.s4.sin_addr, &su.s4.sin_addr,
						sizeof (struct in_addr));
				ret = TRUE;
			}
			else if (rspamd_parse_inet_address_ip6 (src, srclen, &su.s6.sin6_addr)) {
				addr = rspamd_inet_address_v6_maybe_map (&su.s6, pool);
				ret = TRUE;
			}
		}
	}

	if (ret && target) {
		*target = addr;
	}

	return ret;
}

gboolean
rspamd_parse_inet_address (rspamd_inet_addr_t **target,
						   const char *src,
						   gsize srclen,
						   enum rspamd_inet_address_parse_flags how)
{
	return rspamd_parse_inet_address_common (target, src, srclen, NULL, how);
}

rspamd_inet_addr_t *
rspamd_parse_inet_address_pool (const char *src,
								gsize srclen,
								rspamd_mempool_t *pool,
								enum rspamd_inet_address_parse_flags how)
{
	rspamd_inet_addr_t *ret = NULL;

	if (!rspamd_parse_inet_address_common (&ret, src, srclen, pool, how)) {
		return NULL;
	}

	return ret;
}

gboolean
rspamd_parse_inet_address_ip (const char *src, gsize srclen,
		rspamd_inet_addr_t *target)
{
	const char *end;
	char ipbuf[INET6_ADDRSTRLEN + 1];
	guint iplen;
	gulong portnum;
	gboolean ret = FALSE;
	union sa_inet su;

	g_assert (target != NULL);
	g_assert (src != NULL);

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

		if (rspamd_parse_inet_address_ip6 (ipbuf, iplen,
						&su.s6.sin6_addr)) {
			rspamd_inet_address_v6_maybe_map_static (&su.s6, target);
			ret = TRUE;
		}

		if (ret && end[1] == ':') {
			/* Port part */
			rspamd_strtoul (end + 1, srclen - iplen - 3, &portnum);
			rspamd_inet_address_set_port (target, portnum);
		}
	}
	else {

		if ((end = memchr (src, ':', srclen)) != NULL) {
			/* This is either port number and ipv4 addr or ipv6 addr */
			/* Search for another semicolon */
			if (memchr (end + 1, ':', srclen - (end - src + 1)) &&
					rspamd_parse_inet_address_ip6 (src, srclen, &su.s6.sin6_addr)) {
				rspamd_inet_address_v6_maybe_map_static (&su.s6, target);
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
					memcpy (&target->u.in.addr.s4.sin_addr, &su.s4.sin_addr,
							sizeof (struct in_addr));
					target->af = AF_INET;
					target->slen = sizeof (target->u.in.addr.s4);
					rspamd_strtoul (end + 1, srclen - iplen - 1, &portnum);
					rspamd_inet_address_set_port (target, portnum);
					ret = TRUE;
				}
			}
		}
		else {
			if (rspamd_parse_inet_address_ip4 (src, srclen, &su.s4.sin_addr)) {
				memcpy (&target->u.in.addr.s4.sin_addr, &su.s4.sin_addr,
						sizeof (struct in_addr));
				target->af = AF_INET;
				target->slen = sizeof (target->u.in.addr.s4);
				ret = TRUE;
			}
			else if (rspamd_parse_inet_address_ip6 (src, srclen,
					&su.s6.sin6_addr)) {
				rspamd_inet_address_v6_maybe_map_static (&su.s6, target);
				ret = TRUE;
			}
		}
	}

	return ret;
}

/*
 * This is used to allow rspamd_inet_address_to_string to be used several times
 * at the same function invocation, like printf("%s -> %s", f(ip1), f(ip2));
 * Yes, it is bad but it helps to utilise this function without temporary buffers
 * for up to 5 simultaneous invocations.
 */
#define NADDR_BUFS 5

const char *
rspamd_inet_address_to_string (const rspamd_inet_addr_t *addr)
{
	static char addr_str[NADDR_BUFS][INET6_ADDRSTRLEN + 1];
	static guint cur_addr = 0;
	char *addr_buf;

	if (addr == NULL) {
		return "<empty inet address>";
	}

	addr_buf = addr_str[cur_addr++ % NADDR_BUFS];

	switch (addr->af) {
	case AF_INET:
		return inet_ntop (addr->af, &addr->u.in.addr.s4.sin_addr, addr_buf,
				INET6_ADDRSTRLEN + 1);
	case AF_INET6:
		return inet_ntop (addr->af, &addr->u.in.addr.s6.sin6_addr, addr_buf,
				INET6_ADDRSTRLEN + 1);
	case AF_UNIX:
		return addr->u.un->addr.sun_path;
	}

	return "undefined";
}

#define PRETTY_IP_BUFSIZE 128

const char *
rspamd_inet_address_to_string_pretty (const rspamd_inet_addr_t *addr)
{
	static char addr_str[NADDR_BUFS][PRETTY_IP_BUFSIZE];
	static guint cur_addr = 0;
	char *addr_buf;

	if (addr == NULL) {
		return "<empty inet address>";
	}

	addr_buf = addr_str[cur_addr++ % NADDR_BUFS];

	switch (addr->af) {
	case AF_INET:
		rspamd_snprintf (addr_buf, PRETTY_IP_BUFSIZE, "%s:%d",
				rspamd_inet_address_to_string (addr),
				rspamd_inet_address_get_port (addr));
		break;
	case AF_INET6:
		rspamd_snprintf (addr_buf, PRETTY_IP_BUFSIZE, "[%s]:%d",
				rspamd_inet_address_to_string (addr),
				rspamd_inet_address_get_port (addr));
		break;
	case AF_UNIX:
		rspamd_snprintf (addr_buf, PRETTY_IP_BUFSIZE, "unix:%s",
				rspamd_inet_address_to_string (addr));
		break;
	}

	return addr_buf;
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
			msg_info ("connect %s failed: %d, '%s'",
					rspamd_inet_address_to_string_pretty (addr),
					errno, strerror (errno));
			return -1;
		}
	}

	return fd;
}

int
rspamd_inet_address_listen (const rspamd_inet_addr_t *addr, gint type,
							enum rspamd_inet_address_listen_opts opts,
							gint listen_queue)
{
	gint fd, r;
	gint on = 1, serrno;
	const struct sockaddr *sa;
	const char *path;

	if (addr == NULL) {
		return -1;
	}

	fd = rspamd_socket_create (addr->af, type, 0,
			(opts & RSPAMD_INET_ADDRESS_LISTEN_ASYNC));
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

#if defined(SO_REUSEADDR)
	if (setsockopt (fd, SOL_SOCKET, SO_REUSEADDR, (const void *)&on, sizeof (gint)) == -1) {
		msg_err ("cannot set SO_REUSEADDR on %s (fd=%d): %s",
				rspamd_inet_address_to_string_pretty (addr),
				fd, strerror (errno));
		goto err;
	}
#endif

#if defined(SO_REUSEPORT) && defined(LINUX)
	if (opts & RSPAMD_INET_ADDRESS_LISTEN_REUSEPORT) {
		on = 1;

		if (setsockopt (fd, SOL_SOCKET, SO_REUSEPORT, (const void *)&on, sizeof (gint)) == -1) {
			msg_err ("cannot set SO_REUSEPORT on %s (fd=%d): %s",
					rspamd_inet_address_to_string_pretty (addr),
					fd, strerror (errno));
			goto err;
		}
	}
#endif

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
		if (!(opts & RSPAMD_INET_ADDRESS_LISTEN_ASYNC) || errno != EINPROGRESS) {
			msg_warn ("bind %s failed: %d, '%s'",
					rspamd_inet_address_to_string_pretty (addr),
					errno,
					strerror (errno));

			goto err;
		}
	}

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

	if (type != (int)SOCK_DGRAM) {

		if (!(opts & RSPAMD_INET_ADDRESS_LISTEN_NOLISTEN)) {
			r = listen (fd, listen_queue);

			if (r == -1) {
				msg_warn ("listen %s failed: %d, '%s'",
						rspamd_inet_address_to_string_pretty (addr),
						errno, strerror (errno));

				goto err;
			}
		}
	}

	return fd;

err:
	/* Error path */
	serrno = errno;

	if (fd != -1) {
		close (fd);
	}

	errno = serrno;

	return -1;
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
		addr = rspamd_inet_addr_create (su.sa.sa_family, NULL);
		addr->slen = slen;

		if (addr->af == AF_UNIX) {
			addr->u.un = g_malloc (sizeof (*addr->u.un));
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

static enum rspamd_parse_host_port_result
rspamd_resolve_addrs (const char *begin, size_t len, GPtrArray **addrs,
		const gchar *portbuf, gint flags,
		rspamd_mempool_t *pool)
{
	struct addrinfo hints, *res, *cur;
	rspamd_inet_addr_t *cur_addr = NULL;
	gint r, addr_cnt;
	gchar *addr_cpy = NULL;
	enum rspamd_parse_host_port_result ret = RSPAMD_PARSE_ADDR_FAIL;

	rspamd_ip_check_ipv6 ();

	if (rspamd_parse_inet_address (&cur_addr,
			begin, len, RSPAMD_INET_ADDRESS_PARSE_DEFAULT) && cur_addr != NULL) {
		if (*addrs == NULL) {
			*addrs = g_ptr_array_new_full (1,
					(GDestroyNotify) rspamd_inet_address_free);

			if (pool != NULL) {
				rspamd_mempool_add_destructor (pool,
						rspamd_ptr_array_free_hard, *addrs);
			}
		}

		rspamd_inet_address_set_port (cur_addr, strtoul (portbuf, NULL, 10));
		g_ptr_array_add (*addrs, cur_addr);
		ret = RSPAMD_PARSE_ADDR_NUMERIC;
	}
	else {
		memset (&hints, 0, sizeof (hints));
		hints.ai_socktype = SOCK_STREAM; /* Type of the socket */
		hints.ai_flags = AI_NUMERICSERV|flags;

		if (len > 0) {
			if (pool) {
				addr_cpy = rspamd_mempool_alloc (pool, len + 1);
			}
			else {
				addr_cpy = g_malloc (len + 1);
			}

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
						(GDestroyNotify) rspamd_inet_address_free);

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
			ret = RSPAMD_PARSE_ADDR_RESOLVED;
		}
		else if (addr_cpy) {
			msg_err_pool_check ("address resolution for %s failed: %s",
					addr_cpy,
					gai_strerror (r));

			if (pool == NULL) {
				g_free (addr_cpy);
			}

			return RSPAMD_PARSE_ADDR_FAIL;
		}
		else {
			/* Should never ever happen */
			g_assert (0);
		}
	}

	if (pool == NULL) {
		g_free (addr_cpy);
	}

	return ret;
}

enum rspamd_parse_host_port_result
rspamd_parse_host_port_priority (const gchar *str,
								 GPtrArray **addrs,
								 guint *priority,
								 gchar **name_ptr,
								 guint default_port,
								 gboolean allow_listen,
								 rspamd_mempool_t *pool)
{
	gchar portbuf[8];
	const gchar *p, *name = NULL;
	gsize namelen;
	rspamd_inet_addr_t *cur_addr = NULL;
	enum rspamd_parse_host_port_result ret = RSPAMD_PARSE_ADDR_FAIL;
	union sa_union su;

	/*
	 * In this function, we can have several possibilities:
	 * 1) Unix socket: check for '.' or '/' at the begin of string
	 * 2) \[ipv6\]: check for '[' at the beginning
	 * 3) '*': means listening on any address
	 * 4) ip|host[:port[:priority]]
	 */

	if (allow_listen && str[0] == '*') {
		bool v4_any = true, v6_any = true;

		p = &str[1];

		if (g_ascii_strncasecmp (p, "v4", 2) == 0) {
			p += 2;
			name = "*v4";
			v6_any = false;
		}
		else if (g_ascii_strncasecmp (p, "v6", 2) == 0) {
			p += 2;
			name = "*v6";
			v4_any = false;
		}
		else {
			name = "*";
		}

		if (!rspamd_check_port_priority (p, default_port, priority,
				portbuf, sizeof (portbuf), pool)) {
			return ret;
		}

		if (*addrs == NULL) {
			*addrs = g_ptr_array_new_full (1,
					(GDestroyNotify) rspamd_inet_address_free);

			if (pool != NULL) {
				rspamd_mempool_add_destructor (pool,
						rspamd_ptr_array_free_hard, *addrs);
			}
		}

		if (v4_any) {
			cur_addr = rspamd_inet_addr_create (AF_INET, pool);
			rspamd_parse_inet_address_ip4 ("0.0.0.0",
					sizeof ("0.0.0.0") - 1, &su.s4.sin_addr);
			memcpy (&cur_addr->u.in.addr.s4.sin_addr, &su.s4.sin_addr,
					sizeof (struct in_addr));
			rspamd_inet_address_set_port (cur_addr,
					strtoul (portbuf, NULL, 10));
			g_ptr_array_add (*addrs, cur_addr);
		}
		if (v6_any) {
			cur_addr = rspamd_inet_addr_create (AF_INET6, pool);
			rspamd_parse_inet_address_ip6 ("::",
					sizeof ("::") - 1, &su.s6.sin6_addr);
			memcpy (&cur_addr->u.in.addr.s6.sin6_addr, &su.s6.sin6_addr,
					sizeof (struct in6_addr));
			rspamd_inet_address_set_port (cur_addr,
					strtoul (portbuf, NULL, 10));
			g_ptr_array_add (*addrs, cur_addr);
		}

		namelen = strlen (name);
		ret = RSPAMD_PARSE_ADDR_NUMERIC; /* No resolution here */
	}
	else if (str[0] == '[') {
		/* This is braced IPv6 address */
		p = strchr (str, ']');

		if (p == NULL) {
			msg_err_pool_check ("cannot parse address definition %s: %s",
					str,
					strerror (EINVAL));

			return ret;
		}

		name = str + 1;
		namelen = p - str - 1;

		if (!rspamd_check_port_priority (p + 1, default_port, priority, portbuf,
				sizeof (portbuf), pool)) {
			return ret;
		}

		ret = rspamd_resolve_addrs (name, namelen, addrs, portbuf, 0, pool);
	}
	else if (str[0] == '/' || str[0] == '.') {
		/* Special case of unix socket, as getaddrinfo cannot deal with them */
		if (*addrs == NULL) {
			*addrs = g_ptr_array_new_full (1,
					(GDestroyNotify) rspamd_inet_address_free);

			if (pool != NULL) {
				rspamd_mempool_add_destructor (pool,
						rspamd_ptr_array_free_hard, *addrs);
			}
		}

		if (!rspamd_parse_inet_address (&cur_addr,
				str, strlen (str), RSPAMD_INET_ADDRESS_PARSE_DEFAULT)) {
			msg_err_pool_check ("cannot parse unix socket definition %s: %s",
					str,
					strerror (errno));

			return ret;
		}

		g_ptr_array_add (*addrs, cur_addr);
		name = str;
		namelen = strlen (str);
		ret = RSPAMD_PARSE_ADDR_NUMERIC; /* No resolution here: unix socket */
	}
	else {
		p = strchr (str, ':');

		if (p == NULL) {
			/* Just address or IP */
			name = str;
			namelen = strlen (str);
			rspamd_check_port_priority ("", default_port, priority, portbuf,
					sizeof (portbuf), pool);

			ret = rspamd_resolve_addrs (name, namelen, addrs,
					portbuf, 0, pool);
		}
		else {
			const gchar *second_semicolon = strchr (p + 1, ':');

			name = str;

			if (second_semicolon) {
				/* name + port part excluding priority */
				namelen = second_semicolon - str;
			}
			else {
				/* Full ip/name + port */
				namelen = strlen (str);
			}

			if (!rspamd_check_port_priority (p, default_port, priority, portbuf,
					sizeof (portbuf), pool)) {
				return ret;
			}

			ret = rspamd_resolve_addrs (str, p - str, addrs,
					portbuf, 0, pool);
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

	return ret;
}

guchar*
rspamd_inet_address_get_hash_key (const rspamd_inet_addr_t *addr, guint *klen)
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
	else {
		*klen = 0;
		res = NULL;
	}

	return res;
}


rspamd_inet_addr_t *
rspamd_inet_address_new (int af, const void *init)
{
	rspamd_inet_addr_t *addr;

	addr = rspamd_inet_addr_create (af, NULL);

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

	addr = rspamd_inet_addr_create (sa->sa_family, NULL);

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
		addr = rspamd_inet_addr_create (AF_INET, NULL);
		memcpy (&addr->u.in.addr.s4.sin_addr, &rep->content.a.addr,
				sizeof (struct in_addr));
	}
	else if (rep->type == RDNS_REQUEST_AAAA) {
		addr = rspamd_inet_addr_create (AF_INET6, NULL);
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
			mask = 128 - mask;
			p += 3;

			for (;;) {
				if (mask >= 32) {
					mask -= 32;
					*p = 0;
				}
				else {
					umsk = htonl (G_MAXUINT32 << mask);
					*p &= umsk;
					break;
				}

				p --;
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
		const rspamd_inet_addr_t *a2, gboolean compare_ports)
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
			if (!compare_ports) {
				return memcmp (&a1->u.in.addr.s4.sin_addr,
						&a2->u.in.addr.s4.sin_addr, sizeof (struct in_addr));
			}
			else {
				if (a1->u.in.addr.s4.sin_port == a2->u.in.addr.s4.sin_port) {
					return memcmp (&a1->u.in.addr.s4.sin_addr,
							&a2->u.in.addr.s4.sin_addr, sizeof (struct in_addr));
				}
				else {
					return a1->u.in.addr.s4.sin_port - a2->u.in.addr.s4.sin_port;
				}
			}
		case AF_INET6:
			if (!compare_ports) {
				return memcmp (&a1->u.in.addr.s6.sin6_addr,
						&a2->u.in.addr.s6.sin6_addr, sizeof (struct in6_addr));
			}
			else {
				if (a1->u.in.addr.s6.sin6_port == a2->u.in.addr.s6.sin6_port) {
					return memcmp (&a1->u.in.addr.s6.sin6_addr,
							&a2->u.in.addr.s6.sin6_addr, sizeof (struct in6_addr));
				}
				else {
					return a1->u.in.addr.s6.sin6_port - a2->u.in.addr.s6.sin6_port;
				}
			}
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

	return rspamd_inet_address_compare (*i1, *i2, FALSE);
}

rspamd_inet_addr_t *
rspamd_inet_address_copy (const rspamd_inet_addr_t *addr)
{
	rspamd_inet_addr_t *n;

	if (addr == NULL) {
		return NULL;
	}

	n = rspamd_inet_addr_create (addr->af, NULL);

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

struct sockaddr*
rspamd_inet_address_get_sa (const rspamd_inet_addr_t *addr,
							socklen_t *sz)
{
	g_assert (addr != NULL);

	if (addr->af == AF_UNIX) {
		*sz = addr->slen;
		return (struct sockaddr *)&addr->u.un->addr;
	}
	else {
		*sz = addr->slen;
		return (struct sockaddr *)&addr->u.in.addr.sa;
	}
}


guint
rspamd_inet_address_hash (gconstpointer a)
{
	const rspamd_inet_addr_t *addr = a;
	struct {
		gchar buf[sizeof(struct in6_addr)]; /* 16 bytes */
		int af;
	} layout;

	gint32 k;

	if (addr->af == AF_UNIX && addr->u.un) {
		rspamd_cryptobox_fast_hash_state_t st;

		rspamd_cryptobox_fast_hash_init (&st, rspamd_hash_seed ());
		rspamd_cryptobox_fast_hash_update (&st, &addr->af, sizeof (addr->af));
		rspamd_cryptobox_fast_hash_update (&st, addr->u.un, sizeof (*addr->u.un));

		return rspamd_cryptobox_fast_hash_final (&st);
	}
	else {
		memset (&layout, 0, sizeof (layout));
		layout.af = addr->af;

		/* We ignore port part here */
		if (addr->af == AF_INET) {
			memcpy (layout.buf, &addr->u.in.addr.s4.sin_addr,
					sizeof (addr->u.in.addr.s4.sin_addr));
		}
		else {
			memcpy (layout.buf, &addr->u.in.addr.s6.sin6_addr,
					sizeof (addr->u.in.addr.s6.sin6_addr));
		}

		k = rspamd_cryptobox_fast_hash (&layout, sizeof (layout),
				rspamd_hash_seed ());
	}

	return k;
}

guint
rspamd_inet_address_port_hash (gconstpointer a)
{
	const rspamd_inet_addr_t *addr = a;
	struct {
		gchar buf[sizeof(struct in6_addr)]; /* 16 bytes */
		int port;
		int af;
	} layout;

	gint32 k;

	if (addr->af == AF_UNIX && addr->u.un) {
		rspamd_cryptobox_fast_hash_state_t st;

		rspamd_cryptobox_fast_hash_init (&st, rspamd_hash_seed ());
		rspamd_cryptobox_fast_hash_update (&st, &addr->af, sizeof (addr->af));
		rspamd_cryptobox_fast_hash_update (&st, addr->u.un, sizeof (*addr->u.un));

		return rspamd_cryptobox_fast_hash_final (&st);
	}
	else {
		memset (&layout, 0, sizeof (layout));
		layout.af = addr->af;

		/* We consider port part here */
		if (addr->af == AF_INET) {
			memcpy (layout.buf, &addr->u.in.addr.s4.sin_addr,
					sizeof (addr->u.in.addr.s4.sin_addr));
			layout.port = addr->u.in.addr.s4.sin_port;
		}
		else {
			memcpy (layout.buf, &addr->u.in.addr.s6.sin6_addr,
					sizeof (addr->u.in.addr.s6.sin6_addr));
			layout.port = addr->u.in.addr.s6.sin6_port;
		}

		k = rspamd_cryptobox_fast_hash (&layout, sizeof (layout),
				rspamd_hash_seed ());
	}

	return k;
}

gboolean
rspamd_inet_address_equal (gconstpointer a, gconstpointer b)
{
	const rspamd_inet_addr_t *a1 = a, *a2 = b;

	return rspamd_inet_address_compare (a1, a2, FALSE) == 0;
}

gboolean
rspamd_inet_address_port_equal (gconstpointer a, gconstpointer b)
{
	const rspamd_inet_addr_t *a1 = a, *a2 = b;

	return rspamd_inet_address_compare (a1, a2, TRUE) == 0;
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
	}

	return FALSE;
}

void **
rspamd_inet_library_init (void)
{
	return &local_addrs;
}

void *
rspamd_inet_library_get_lib_ctx (void)
{
	return local_addrs;
}

void
rspamd_inet_library_destroy (void)
{
	/* Ugly: local_addrs will actually be freed by config object */
}

gsize
rspamd_inet_address_storage_size (void)
{
	return sizeof (rspamd_inet_addr_t);
}
