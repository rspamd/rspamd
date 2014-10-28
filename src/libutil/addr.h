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
#ifndef ADDR_H_
#define ADDR_H_

#include "config.h"

/**
 * Union that is used for storing sockaddrs
 */
union sa_union {
	struct sockaddr_storage ss;
	struct sockaddr sa;
	struct sockaddr_in s4;
	struct sockaddr_in6 s6;
	struct sockaddr_un su;
};

typedef struct _rspamd_inet_addr_s {
	union sa_union addr;
	socklen_t slen;
	int af;
} rspamd_inet_addr_t;

/**
 * Try to parse address from string
 * @param target target to fill
 * @param src IP string representation
 * @return TRUE if addr has been parsed
 */
gboolean rspamd_parse_inet_address (rspamd_inet_addr_t *target,
	const char *src);

/**
 * Returns string representation of inet address
 * @param addr
 * @return statically allocated string pointer (not thread safe)
 */
const char * rspamd_inet_address_to_string (rspamd_inet_addr_t *addr);

/**
 * Returns port number for the specified inet address in host byte order
 * @param addr
 * @return
 */
uint16_t rspamd_inet_address_get_port (rspamd_inet_addr_t *addr);

/**
 * Set port for inet address
 */
void rspamd_inet_address_set_port (rspamd_inet_addr_t *addr, uint16_t port);

/**
 * Connect to inet_addr address
 * @param addr
 * @param async perform operations asynchronously
 * @return newly created and connected socket
 */
int rspamd_inet_address_connect (rspamd_inet_addr_t *addr, gint type,
	gboolean async);

/**
 * Check whether specified ip is valid (not INADDR_ANY or INADDR_NONE) for ipv4 or ipv6
 * @param ptr pointer to struct in_addr or struct in6_addr
 * @param af address family (AF_INET or AF_INET6)
 * @return TRUE if the address is valid
 */
gboolean rspamd_ip_is_valid (rspamd_inet_addr_t *addr);

/**
 * Accept from listening socket filling addr structure
 * @param sock listening socket
 * @param addr
 * @return
 */
gint rspamd_accept_from_socket (gint sock, rspamd_inet_addr_t *addr);

gboolean rspamd_parse_host_port_priority_strv (gchar **tokens,
	rspamd_inet_addr_t *addr, guint *priority, gchar **name, guint default_port);

/**
 * Parse host[:port[:priority]] line
 * @param ina host address
 * @param port port
 * @param priority priority
 * @return TRUE if string was parsed
 */
gboolean rspamd_parse_host_port_priority (const gchar *str,
		rspamd_inet_addr_t *addr, guint *priority, gchar **name, guint default_port);

/**
 * Parse host:port line
 * @param ina host address
 * @param port port
 * @return TRUE if string was parsed
 */
gboolean rspamd_parse_host_port (const gchar *str,
	rspamd_inet_addr_t *addr, gchar **name, guint default_port);


#endif /* ADDR_H_ */
