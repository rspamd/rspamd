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


static void
rspamd_ip_validate_af (rspamd_inet_addr_t *addr)
{
	if (addr->addr.sa.sa_family != addr->af) {
		addr->addr.sa.sa_family = addr->af;
	}
	if (addr->af == AF_INET) {
		addr->slen = sizeof (addr->addr.s4);
	}
	else if (addr->af == AF_INET6) {
		addr->slen = sizeof (addr->addr.s6);
	}
	else if (addr->af == AF_UNIX) {
#ifdef SUN_LEN
		addr->slen = SUN_LEN (&addr->addr.su);
#else
		addr->slen = sizeof (addr->addr.su);
#endif
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
		if (s == -1 && errno == EAFNOSUPPORT) {
			ipv6_status = RSPAMD_IPV6_UNSUPPORTED;
		}
		else {
			/*
			 * Some systems allow ipv6 sockets creating but not binding,
			 * so here we try to bind to some local address and check, whether it
			 * is possible
			 */
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
rspamd_ip_is_valid (rspamd_inet_addr_t *addr)
{
	const struct in_addr ip4_any = { INADDR_ANY }, ip4_none = { INADDR_NONE };
	const struct in6_addr ip6_any = IN6ADDR_ANY_INIT;
	gboolean ret = FALSE;

	if (G_LIKELY (addr->af == AF_INET)) {
		if (memcmp (&addr->addr.s4.sin_addr, &ip4_any,
			sizeof (struct in_addr)) != 0 &&
			memcmp (&addr->addr.s4.sin_addr, &ip4_none,
			sizeof (struct in_addr)) != 0) {
			ret = TRUE;
		}
	}
	else if (G_UNLIKELY (addr->af == AF_INET6)) {
		if (memcmp (&addr->addr.s6.sin6_addr, &ip6_any,
			sizeof (struct in6_addr)) != 0) {
			ret = TRUE;
		}
	}

	return ret;
}

gint
rspamd_accept_from_socket (gint sock, rspamd_inet_addr_t *addr)
{
	gint nfd, serrno;
	socklen_t len = sizeof (addr->addr.ss);

	if ((nfd = accept (sock, &addr->addr.sa, &len)) == -1) {
		if (errno == EAGAIN || errno == EINTR || errno == EWOULDBLOCK) {
			return 0;
		}
		return -1;
	}

	addr->slen = len;
	addr->af = addr->addr.sa.sa_family;

	if (rspamd_socket_nonblocking (nfd) < 0) {
		goto out;
	}

	/* Set close on exec */
	if (fcntl (nfd, F_SETFD, FD_CLOEXEC) == -1) {
		msg_warn ("fcntl failed: %d, '%s'", errno, strerror (errno));
		goto out;
	}

	return (nfd);

out:
	serrno = errno;
	close (nfd);
	errno = serrno;
	return (-1);

}

gboolean
rspamd_parse_inet_address (rspamd_inet_addr_t *target, const char *src)
{
	gboolean ret = FALSE;

	rspamd_ip_check_ipv6 ();

	if (src[0] == '/' || src[0] == '.') {
		target->af = AF_UNIX;
		target->slen = sizeof (target->addr.su);
		rspamd_strlcpy (target->addr.su.sun_path, src,
				sizeof (target->addr.su.sun_path));
#ifdef FREEBSD
		target->addr.su.sun_len = SUN_LEN (&target->addr.su);
#endif
	}
	else if (ipv6_status == RSPAMD_IPV6_SUPPORTED &&
			inet_pton (AF_INET6, src, &target->addr.s6.sin6_addr) == 1) {
		target->af = AF_INET6;
		target->slen = sizeof (target->addr.s6);
		ret = TRUE;
	}
	else if (inet_pton (AF_INET, src, &target->addr.s4.sin_addr) == 1) {
		target->af = AF_INET;
		target->slen = sizeof (target->addr.s4);
		ret = TRUE;
	}

	target->addr.sa.sa_family = target->af;

	return ret;
}

const char *
rspamd_inet_address_to_string (rspamd_inet_addr_t *addr)
{
	static char addr_str[INET6_ADDRSTRLEN + 1];

	switch (addr->af) {
	case AF_INET:
		return inet_ntop (addr->af, &addr->addr.s4.sin_addr, addr_str,
				   sizeof (addr_str));
	case AF_INET6:
		return inet_ntop (addr->af, &addr->addr.s6.sin6_addr, addr_str,
				   sizeof (addr_str));
	case AF_UNIX:
		return addr->addr.su.sun_path;
	}

	return "undefined";
}

uint16_t
rspamd_inet_address_get_port (rspamd_inet_addr_t *addr)
{
	switch (addr->af) {
	case AF_INET:
		return ntohs (addr->addr.s4.sin_port);
	case AF_INET6:
		return ntohs (addr->addr.s6.sin6_port);
	}

	return 0;
}

void
rspamd_inet_address_set_port (rspamd_inet_addr_t *addr, uint16_t port)
{
	switch (addr->af) {
	case AF_INET:
		addr->addr.s4.sin_port = htons (port);
		break;
	case AF_INET6:
		addr->addr.s6.sin6_port = htons (port);
		break;
	}
}

int
rspamd_inet_address_connect (rspamd_inet_addr_t *addr, gint type,
		gboolean async)
{
	int fd, r;

	if (addr == NULL) {
		return -1;
	}

	rspamd_ip_validate_af (addr);

	fd = rspamd_socket_create (addr->af, type, 0, async);
	if (fd == -1) {
		return -1;
	}

	r = connect (fd, &addr->addr.sa, addr->slen);

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
rspamd_inet_address_listen (rspamd_inet_addr_t *addr, gint type,
		gboolean async)
{
	gint fd, r;
	gint on = 1;

	if (addr == NULL) {
		return -1;
	}

	rspamd_ip_validate_af (addr);
	fd = rspamd_socket_create (addr->af, type, 0, async);
	if (fd == -1) {
		return -1;
	}

	setsockopt (fd, SOL_SOCKET, SO_REUSEADDR, (const void *)&on, sizeof (gint));
	r = bind (fd, &addr->addr.sa, addr->slen);
	if (r == -1) {
		if (!async || errno != EINPROGRESS) {
			close (fd);
			msg_warn ("bind failed: %d, '%s'", errno,
						strerror (errno));
			return -1;
		}
	}

	if (type != SOCK_DGRAM) {
		r = listen (fd, -1);

		if (r == -1) {
			msg_warn ("listen failed: %d, '%s'", errno, strerror (errno));
			close (fd);
			return -1;
		}
	}

	return fd;
}

gboolean
rspamd_parse_host_port_priority_strv (gchar **tokens,
	rspamd_inet_addr_t **addr,
	guint *max_addrs,
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

	if ((r = getaddrinfo (cur_tok, cur_port, &hints, &res)) == 0) {
		/* Now copy up to max_addrs of addresses */
		addr_cnt = 0;
		cur = res;
		while (cur && addr_cnt < *max_addrs) {
			cur = cur->ai_next;
			addr_cnt ++;
		}

		if (pool == NULL) {
			*addr = g_new (rspamd_inet_addr_t, addr_cnt);
		}
		else {
			*addr = rspamd_mempool_alloc (pool, addr_cnt *
					sizeof (rspamd_inet_addr_t));
		}

		cur = res;
		addr_cnt = 0;
		while (cur && addr_cnt < *max_addrs) {
			cur_addr = &(*addr)[addr_cnt];
			memcpy (&cur_addr->addr, cur->ai_addr,
					MIN (sizeof (cur_addr->addr), cur->ai_addrlen));
			cur_addr->af = cur->ai_family;
			rspamd_ip_validate_af (cur_addr);
			cur_addr->slen = cur->ai_addrlen;
			cur = cur->ai_next;
			addr_cnt ++;
		}

		*max_addrs = addr_cnt;

		freeaddrinfo (res);
	}
	else {
		msg_err ("address resolution for %s failed: %s",
			tokens[0],
			gai_strerror (r));
		goto err;
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
	rspamd_inet_addr_t **addr,
	guint *max_addrs,
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

	ret = rspamd_parse_host_port_priority_strv (tokens, addr, max_addrs,
			priority, name, default_port, pool);

	g_strfreev (tokens);

	return ret;
}

gboolean
rspamd_parse_host_port (const gchar *str,
	rspamd_inet_addr_t **addr,
	guint *max_addrs,
	gchar **name,
	guint default_port,
	rspamd_mempool_t *pool)
{
	return rspamd_parse_host_port_priority (str, addr, max_addrs, NULL,
			name, default_port, pool);
}
