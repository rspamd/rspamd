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

	if (make_socket_nonblocking (nfd) < 0) {
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

	if (inet_pton (AF_INET6, src, &target->addr.s6.sin6_addr) == 1) {
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
