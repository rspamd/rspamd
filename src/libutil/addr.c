/* Copyright (c) 2014, Vsevolod Stakhov
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *       * Redistributions of source code must retain the above copyright
 *         notice, this list of conditions and the following disclaimer.
 *       * Redistributions in binary form must reproduce the above copyright
 *         notice, this list of conditions and the following disclaimer in the
 *         documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED ''AS IS'' AND ANY
 * EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL AUTHOR BE LIABLE FOR ANY
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include "config.h"
#include "addr.h"
#include "util.h"
#include "logger.h"

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

	addr = g_slice_alloc (sizeof (rspamd_inet_addr_t));

	if (af == AF_UNIX) {
		addr->u.un = g_slice_alloc (sizeof (*addr->u.un));
		addr->slen = sizeof (addr->u.un->addr);
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

gint
rspamd_accept_from_socket (gint sock, rspamd_inet_addr_t **target)
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
		return -1;
	}

	addr = rspamd_inet_addr_create (su.sa.sa_family);
	addr->slen = len;

	if (addr->af == AF_UNIX) {
		addr->u.un = g_slice_alloc (sizeof (*addr->u.un));
		memcpy (&addr->u.un->addr, &su.su, sizeof (struct sockaddr_un));
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
	gint pwlen;
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
	addr->u.un->mode = 0;
	addr->u.un->group = 0;

	cur_tok = &tokens[1];
	pwlen = sysconf (_SC_GETPW_R_SIZE_MAX);
	g_assert (pwlen > 0);
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
rspamd_parse_inet_address (rspamd_inet_addr_t **target, const char *src)
{
	gboolean ret = FALSE;
	rspamd_inet_addr_t *addr = NULL;
	union sa_inet su;

	g_assert (src != NULL);
	g_assert (target != NULL);

	rspamd_ip_check_ipv6 ();

	if (src[0] == '/' || src[0] == '.') {
		return rspamd_parse_unix_path (target, src);
	}
	else if (ipv6_status == RSPAMD_IPV6_SUPPORTED &&
			inet_pton (AF_INET6, src, &su.s6.sin6_addr) == 1) {
		addr = rspamd_inet_addr_create (AF_INET6);
		memcpy (&addr->u.in.addr.s6.sin6_addr, &su.s6.sin6_addr,
				sizeof (struct in6_addr));
		ret = TRUE;
	}
	else if (inet_pton (AF_INET, src, &su.s4.sin_addr) == 1) {
		addr = rspamd_inet_addr_create (AF_INET6);
		memcpy (&addr->u.in.addr.s4.sin_addr, &su.s4.sin_addr,
				sizeof (struct in_addr));
		ret = TRUE;
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

	setsockopt (fd, SOL_SOCKET, SO_REUSEADDR, (const void *)&on, sizeof (gint));
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
			if (chown (path, addr->u.un->owner, addr->u.un->group) == -1) {
				msg_info ("cannot change owner for %s to %d:%d: %s",
						path, addr->u.un->owner, addr->u.un->group,
						strerror (errno));
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
		addr->slen = len;

		if (addr->af == AF_UNIX) {
			addr->u.un = g_slice_alloc (sizeof (*addr->u.un));
			memcpy (&addr->u.un->addr, &su.su, sizeof (struct sockaddr_un));
		}
		else {
			memcpy (&addr->u.in.addr, &su, MIN (len, sizeof (addr->u.in.addr)));
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

gboolean
rspamd_parse_host_port_priority_strv (gchar **tokens,
	GPtrArray **addrs,
	guint *priority,
	gchar **name,
	guint default_port,
	rspamd_mempool_t *pool)
{
	gchar *err_str, portbuf[8];
	const gchar *cur_tok, *cur_port;
	struct addrinfo hints, *res, *cur;
	rspamd_inet_addr_t *cur_addr;
	guint addr_cnt;
	guint port_parsed, priority_parsed, saved_errno = errno;
	gint r;

	rspamd_ip_check_ipv6 ();
	/* Now try to parse host and write address to ina */
	memset (&hints, 0, sizeof (hints));
	hints.ai_socktype = SOCK_STREAM; /* Type of the socket */
	hints.ai_flags = AI_NUMERICSERV;

	cur_tok = tokens[0];

	if (strcmp (cur_tok, "*") == 0) {
		hints.ai_flags |= AI_PASSIVE;
		cur_tok = NULL;
	}

	if (ipv6_status == RSPAMD_IPV6_SUPPORTED) {
		hints.ai_family = AF_UNSPEC;
	}
	else {
		hints.ai_family = AF_INET;
	}

	if (tokens[1] != NULL) {
		/* Port part */
		rspamd_strlcpy (portbuf, tokens[1], sizeof (portbuf));
		cur_port = portbuf;
		errno = 0;
		port_parsed = strtoul (tokens[1], &err_str, 10);
		if (*err_str != '\0' || errno != 0) {
			msg_warn ("cannot parse port: %s, at symbol %c, error: %s",
					tokens[1],
					*err_str,
					strerror (errno));
			hints.ai_flags ^= AI_NUMERICSERV;
		}
		else if (port_parsed > G_MAXUINT16) {
			errno = ERANGE;
			msg_warn ("cannot parse port: %s, error: %s",
					tokens[1],
					*err_str,
					strerror (errno));
			hints.ai_flags ^= AI_NUMERICSERV;
		}
		if (priority != NULL) {
			const gchar *tok;

			tok = tokens[2];
			if (tok != NULL) {
				/* Priority part */
				errno = 0;
				priority_parsed = strtoul (tok, &err_str, 10);
				if (*err_str != '\0' || errno != 0) {
					msg_warn (
						"cannot parse priority: %s, at symbol %c, error: %s",
						tok,
						*err_str,
						strerror (errno));
				}
				else {
					*priority = priority_parsed;
				}
			}
		}
	}
	else if (default_port != 0) {
		rspamd_snprintf (portbuf, sizeof (portbuf), "%ud", default_port);
		cur_port = portbuf;
	}
	else {
		cur_port = NULL;
	}

	if (*tokens[0] != '/') {
		if ((r = getaddrinfo (cur_tok, cur_port, &hints, &res)) == 0) {
			/* Now copy up to max_addrs of addresses */
			addr_cnt = 0;
			cur = res;
			while (cur) {
				cur = cur->ai_next;
				addr_cnt ++;
			}

			*addrs = g_ptr_array_new_full (addr_cnt,
						(GDestroyNotify)rspamd_inet_address_destroy);

			if (pool != NULL) {
				rspamd_mempool_add_destructor (pool,
						rspamd_ptr_array_free_hard, *addrs);
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
		else {
			msg_err ("address resolution for %s failed: %s",
					tokens[0],
					gai_strerror (r));
			goto err;
		}
	}
	else {
		/* Special case of unix socket, as getaddrinfo cannot deal with them */
		*addrs = g_ptr_array_new_full (1,
				(GDestroyNotify)rspamd_inet_address_destroy);

		if (pool != NULL) {
			rspamd_mempool_add_destructor (pool,
					rspamd_ptr_array_free_hard, *addrs);
		}

		if (!rspamd_parse_inet_address (&cur_addr, tokens[0])) {
			msg_err ("cannot parse unix socket definition %s: %s",
					tokens[0],
					strerror (errno));
			goto err;
		}

		g_ptr_array_add (*addrs, cur_addr);
	}

	/* Restore errno */
	if (name != NULL) {
		if (pool == NULL) {
			*name = g_strdup (tokens[0]);
		}
		else {
			*name = rspamd_mempool_strdup (pool, tokens[0]);
		}
	}
	errno = saved_errno;
	return TRUE;

err:
	errno = saved_errno;
	return FALSE;
}

gboolean
rspamd_parse_host_port_priority (
	const gchar *str,
	GPtrArray **addrs,
	guint *priority,
	gchar **name,
	guint default_port,
	rspamd_mempool_t *pool)
{
	gchar **tokens;
	gboolean ret;

	tokens = g_strsplit_set (str, ":", 0);
	if (!tokens || !tokens[0]) {
		return FALSE;
	}

	ret = rspamd_parse_host_port_priority_strv (tokens, addrs,
			priority, name, default_port, pool);

	g_strfreev (tokens);

	return ret;
}

gboolean
rspamd_parse_host_port (const gchar *str,
	GPtrArray **addrs,
	gchar **name,
	guint default_port,
	rspamd_mempool_t *pool)
{
	return rspamd_parse_host_port_priority (str, addrs, NULL,
			name, default_port, pool);
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

void
rspamd_inet_address_apply_mask (rspamd_inet_addr_t *addr, guint mask)
{
	guint32 umsk, *p;

	if (mask > 0 && addr != NULL) {
		if (addr->af == AF_INET && mask <= 32) {
			umsk = htonl (G_MAXUINT32 << (32 - mask));
			addr->u.in.addr.s4.sin_addr.s_addr &= umsk;
		}
		else if (addr->af == AF_INET && mask <= 128) {
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
		return (rspamd_inet_address_af_order (a1) -
				rspamd_inet_address_af_order (a2));
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
