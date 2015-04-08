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

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/un.h>
#include <sys/stat.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <netdb.h>
#include <fcntl.h>
#include <ctype.h>

#include "ottery.h"
#include "util.h"
#include "logger.h"

static int
rdns_make_socket_nonblocking (int fd)
{
	int                            ofl;

	ofl = fcntl (fd, F_GETFL, 0);

	if (fcntl (fd, F_SETFL, ofl | O_NONBLOCK) == -1) {
		return -1;
	}
	return 0;
}

static int
rdns_make_inet_socket (int type, struct addrinfo *addr)
{
	int fd, r, s_error;
	socklen_t optlen;
	struct addrinfo *cur;

	cur = addr;
	while (cur) {
		/* Create socket */
		fd = socket (cur->ai_family, type, 0);
		if (fd == -1) {
			goto out;
		}

		if (rdns_make_socket_nonblocking (fd) < 0) {
			goto out;
		}

		/* Set close on exec */
		if (fcntl (fd, F_SETFD, FD_CLOEXEC) == -1) {
			goto out;
		}

		r = connect (fd, cur->ai_addr, cur->ai_addrlen);

		if (r == -1) {
			if (errno != EINPROGRESS) {
				goto out;
			}
		}
		else {
			/* Still need to check SO_ERROR on socket */
			optlen = sizeof (s_error);
			getsockopt (fd, SOL_SOCKET, SO_ERROR, (void *)&s_error, &optlen);
			if (s_error) {
				errno = s_error;
				goto out;
			}
		}
		break;
out:
		if (fd != -1) {
			close (fd);
		}
		fd = -1;
		cur = cur->ai_next;
	}
	return (fd);
}

static int
rdns_make_unix_socket (const char *path, struct sockaddr_un *addr, int type)
{
	int fd = -1, s_error, r, serrno;
	socklen_t optlen;

	if (path == NULL) {
		return -1;
	}

	addr->sun_family = AF_UNIX;

	memset (addr->sun_path, 0, sizeof (addr->sun_path));
	memccpy (addr->sun_path, path, 0, sizeof (addr->sun_path) - 1);
#ifdef FREEBSD
	addr->sun_len = SUN_LEN (addr);
#endif

	fd = socket (PF_LOCAL, type, 0);

	if (fd == -1) {
		return -1;
	}

	if (rdns_make_socket_nonblocking (fd) < 0) {
		goto out;
	}

	/* Set close on exec */
	if (fcntl (fd, F_SETFD, FD_CLOEXEC) == -1) {
		goto out;
	}

	r = connect (fd, (struct sockaddr *)addr, SUN_LEN (addr));

	if (r == -1) {
		if (errno != EINPROGRESS) {
			goto out;
		}
	}
	else {
		/* Still need to check SO_ERROR on socket */
		optlen = sizeof (s_error);
		getsockopt (fd, SOL_SOCKET, SO_ERROR, (void *)&s_error, &optlen);
		if (s_error) {
			errno = s_error;
			goto out;
		}
	}

	return (fd);

  out:
	serrno = errno;
	if (fd != -1) {
		close (fd);
	}
	errno = serrno;
	return (-1);
}

/**
 * Make a universal socket
 * @param credits host, ip or path to unix socket
 * @param port port (used for network sockets)
 * @param async make this socket asynced
 * @param is_server make this socket as server socket
 * @param try_resolve try name resolution for a socket (BLOCKING)
 */
int
rdns_make_client_socket (const char *credits, uint16_t port,
		int type)
{
	struct sockaddr_un              un;
	struct stat                     st;
	struct addrinfo                 hints, *res;
	int                             r;
	char                            portbuf[8];

	if (*credits == '/') {
		r = stat (credits, &st);
		if (r == -1) {
			/* Unix socket doesn't exists it must be created first */
			errno = ENOENT;
			return -1;
		}
		else {
			if ((st.st_mode & S_IFSOCK) == 0) {
				/* Path is not valid socket */
				errno = EINVAL;
				return -1;
			}
			else {
				return rdns_make_unix_socket (credits, &un, type);
			}
		}
	}
	else {
		/* TCP related part */
		memset (&hints, 0, sizeof (hints));
		hints.ai_family = AF_UNSPEC;     /* Allow IPv4 or IPv6 */
		hints.ai_socktype = type; /* Type of the socket */
		hints.ai_flags = 0;
		hints.ai_protocol = 0;           /* Any protocol */
		hints.ai_canonname = NULL;
		hints.ai_addr = NULL;
		hints.ai_next = NULL;

		hints.ai_flags |= AI_NUMERICHOST | AI_NUMERICSERV;

		snprintf (portbuf, sizeof (portbuf), "%d", (int)port);
		if ((r = getaddrinfo (credits, portbuf, &hints, &res)) == 0) {
			r = rdns_make_inet_socket (type, res);
			freeaddrinfo (res);
			return r;
		}
		else {
			return -1;
		}
	}

	/* Not reached */
	return -1;
}

const char *
rdns_strerror (enum dns_rcode rcode)
{
	rcode &= 0xf;
	static char numbuf[16];

	if ('\0' == dns_rcodes[rcode][0]) {
		snprintf (numbuf, sizeof (numbuf), "UNKNOWN: %d", (int)rcode);
		return numbuf;
	}
	return dns_rcodes[rcode];
}

const char *
rdns_strtype (enum rdns_request_type type)
{
	return dns_types[type];
}

uint16_t
rdns_permutor_generate_id (void)
{
	uint16_t id;

	id = ottery_rand_unsigned ();

	return id;
}


void
rdns_reply_free (struct rdns_reply *rep)
{
	struct rdns_reply_entry *entry, *tmp;

	LL_FOREACH_SAFE (rep->entries, entry, tmp) {
		switch (entry->type) {
		case RDNS_REQUEST_PTR:
			free (entry->content.ptr.name);
			break;
		case RDNS_REQUEST_NS:
			free (entry->content.ns.name);
			break;
		case RDNS_REQUEST_MX:
			free (entry->content.mx.name);
			break;
		case RDNS_REQUEST_TXT:
		case RDNS_REQUEST_SPF:
			free (entry->content.txt.data);
			break;
		case RDNS_REQUEST_SRV:
			free (entry->content.srv.target);
			break;
		case RDNS_REQUEST_TLSA:
			free (entry->content.tlsa.data);
			break;
		case RDNS_REQUEST_SOA:
			free (entry->content.soa.mname);
			free (entry->content.soa.admin);
			break;
		}
		free (entry);
	}
	free (rep);
}

void
rdns_request_free (struct rdns_request *req)
{
	unsigned int i;

	if (req != NULL) {
		if (req->packet != NULL) {
			free (req->packet);
		}
		for (i = 0; i < req->qcount; i ++) {
			free (req->requested_names[i].name);
		}
		if (req->requested_names != NULL) {
			free (req->requested_names);
		}
		if (req->reply != NULL) {
			rdns_reply_free (req->reply);
		}
		if (req->state >= RDNS_REQUEST_SENT &&
				req->state < RDNS_REQUEST_REPLIED) {
			/* Remove timer */
			req->async->del_timer (req->async->data,
					req->async_event);
			/* Remove from id hashes */
			HASH_DEL (req->io->requests, req);
		}
		else if (req->state == RDNS_REQUEST_REGISTERED) {
			/* Remove retransmit event */
			req->async->del_write (req->async->data,
					req->async_event);
		}
#ifdef TWEETNACL
		if (req->curve_plugin_data != NULL) {
			req->resolver->curve_plugin->cb.curve_plugin.finish_cb (
					req, req->resolver->curve_plugin->data);
		}
#endif
		if (req->io != NULL && req->state > RDNS_REQUEST_NEW) {
			REF_RELEASE (req->io);
			REF_RELEASE (req->resolver);
		}

		free (req);
	}
}

void
rdns_ioc_free (struct rdns_io_channel *ioc)
{
	struct rdns_request *req, *rtmp;

	HASH_ITER (hh, ioc->requests, req, rtmp) {
		REF_RELEASE (req);
	}
	ioc->resolver->async->del_read (ioc->resolver->async->data,
			ioc->async_io);
	close (ioc->sock);
	free (ioc);
}

void
rdns_resolver_release (struct rdns_resolver *resolver)
{
	REF_RELEASE (resolver);
}

struct rdns_request*
rdns_request_retain (struct rdns_request *req)
{
	REF_RETAIN (req);
	return req;
}

void
rdns_request_release (struct rdns_request *req)
{
	REF_RELEASE (req);
}

static bool
rdns_resolver_conf_process_line (struct rdns_resolver *resolver, char *line)
{
	char *p, *c;
	bool has_obrace = false;
	unsigned int port = dns_port;

	if (strncmp (line, "nameserver", sizeof ("nameserver") - 1) == 0) {
		p = line + sizeof ("nameserver") - 1;
		/* Skip spaces */
		while (*p == ' ' || *p == '\t') {
			p ++;
		}
		if (*p == '[') {
			has_obrace = true;
			p ++;
		}
		if (isxdigit (*p) || *p == ':') {
			c = p;
			while (isxdigit (*p) || *p == ':' || *p == '.') {
				p ++;
			}
			if (has_obrace && *p != ']') {
				return false;
			}
			else if (*p != '\0' && !isspace (*p) && *p != '#') {
				return false;
			}
			*p = '\0';
			if (has_obrace) {
				p ++;
				if (*p == ':') {
					/* Maybe we have a port definition */
					port = strtoul (p + 1, NULL, 10);
					if (port == 0 || port > UINT16_MAX) {
						return false;
					}
				}
			}

			return rdns_resolver_add_server (resolver, c, port, 0, default_io_cnt);
		}
		else {
			return false;
		}
	}
	/* XXX: skip unknown resolv.conf lines */

	return true;
}

bool
rdns_resolver_parse_resolv_conf (struct rdns_resolver *resolver, const char *path)
{
	FILE *in;
	char buf[BUFSIZ];

	in = fopen (path, "r");

	if (in == NULL) {
		return false;
	}

	while (!feof (in)) {
		if (fgets (buf, sizeof (buf), in) == NULL) {
			break;
		}
		if (!rdns_resolver_conf_process_line (resolver, buf)) {
			rdns_warn ("rdns_resolver_parse_resolv_conf: cannot parse line: %s", buf);
			fclose (in);
			return false;
		}
	}

	fclose (in);
	return true;
}

bool
rdns_request_has_type (struct rdns_request *req, enum rdns_request_type type)
{
	unsigned int i;

	for (i = 0; i < req->qcount; i ++) {
		if (req->requested_names[i].type == type) {
			return true;
		}
	}

	return false;
}

const struct rdns_request_name *
rdns_request_get_name (struct rdns_request *req, unsigned int *count)
{

	if (count != NULL) {
		*count = req->qcount;
	}
	return req->requested_names;
}

char *
rdns_generate_ptr_from_str (const char *str)
{
	union {
		struct in_addr v4;
		struct in6_addr v6;
	} addr;
	char *res = NULL;
	unsigned char *bytes;
	size_t len;

	if (inet_pton (AF_INET, str, &addr.v4) == 1) {
		bytes = (unsigned char *)&addr.v4;

		len = 4 * 4 + sizeof ("in-addr.arpa");
		res = malloc (len);
		if (res) {
			snprintf (res, len, "%u.%u.%u.%u.in-addr.arpa",
					(unsigned)bytes[3]&0xFF,
					(unsigned)bytes[2]&0xFF,
					(unsigned)bytes[1]&0xFF,
					(unsigned)bytes[0]&0xFF);
		}
	}
	else if (inet_pton (AF_INET6, str, &addr.v6) == 1) {
		bytes = (unsigned char *)&addr.v6;

		len = 2*32 + sizeof ("ip6.arpa");
		res = malloc (len);
		if (res) {
			snprintf(res, len,
					"%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x."
					"%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.ip6.arpa",
					bytes[15]&0xF, bytes[15] >> 4, bytes[14]&0xF, bytes[14] >> 4,
					bytes[13]&0xF, bytes[13] >> 4, bytes[12]&0xF, bytes[12] >> 4,
					bytes[11]&0xF, bytes[11] >> 4, bytes[10]&0xF, bytes[10] >> 4,
					bytes[9]&0xF, bytes[9] >> 4, bytes[8]&0xF, bytes[8] >> 4,
					bytes[7]&0xF, bytes[7] >> 4, bytes[6]&0xF, bytes[6] >> 4,
					bytes[5]&0xF, bytes[5] >> 4, bytes[4]&0xF, bytes[4] >> 4,
					bytes[3]&0xF, bytes[3] >> 4, bytes[2]&0xF, bytes[2] >> 4,
					bytes[1]&0xF, bytes[1] >> 4, bytes[0]&0xF, bytes[0] >> 4);
		}
	}

	return res;
}
