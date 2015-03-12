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
#include "mem_pool.h"

/**
 * Opaque structure
 */
typedef struct rspamd_inet_addr_s rspamd_inet_addr_t;

/**
 * Create new inet address structure based on the address familiy and opaque init pointer
 * @param af
 * @param init
 * @return new inet addr
 */
rspamd_inet_addr_t * rspamd_inet_address_new (int af, const void *init);

/**
 * Create new inet address structure from struct sockaddr
 * @param sa
 * @param slen
 * @return
 */
rspamd_inet_addr_t * rspamd_inet_address_from_sa (const struct sockaddr *sa,
		socklen_t slen);

/**
 * Try to parse address from string
 * @param target target to fill
 * @param src IP string representation
 * @return TRUE if addr has been parsed
 */
gboolean rspamd_parse_inet_address (rspamd_inet_addr_t **target,
	const char *src);

/**
 * Returns string representation of inet address
 * @param addr
 * @return statically allocated string pointer (not thread safe)
 */
const char * rspamd_inet_address_to_string (const rspamd_inet_addr_t *addr);

/**
 * Returns port number for the specified inet address in host byte order
 * @param addr
 * @return
 */
uint16_t rspamd_inet_address_get_port (const rspamd_inet_addr_t *addr);

/**
 * Returns address family of inet address
 * @param addr
 * @return
 */
gint rspamd_inet_address_get_af (const rspamd_inet_addr_t *addr);


/**
 * Makes a radix key from inet address
 * @param addr
 * @param klen
 * @return
 */
guchar * rspamd_inet_address_get_radix_key (const rspamd_inet_addr_t *addr, guint *klen);

/**
 * Receive data from an unconnected socket and fill the inet_addr structure if needed
 * @param fd
 * @param buf
 * @param len
 * @param target
 * @return same as recvfrom(2)
 */
gssize rspamd_inet_address_recvfrom (gint fd, void *buf, gsize len, gint fl,
		rspamd_inet_addr_t **target);

/**
 * Send data via unconnected socket using the specified inet_addr structure
 * @param fd
 * @param buf
 * @param len
 * @param target
 * @return
 */
gssize rspamd_inet_address_sendto (gint fd, const void *buf, gsize len, gint fl,
		const rspamd_inet_addr_t *addr);

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
int rspamd_inet_address_connect (const rspamd_inet_addr_t *addr, gint type,
	gboolean async);

/**
 * Listen on a specified inet address
 * @param addr
 * @param type
 * @param async
 * @return
 */
int rspamd_inet_address_listen (const rspamd_inet_addr_t *addr, gint type,
	gboolean async);
/**
 * Check whether specified ip is valid (not INADDR_ANY or INADDR_NONE) for ipv4 or ipv6
 * @param ptr pointer to struct in_addr or struct in6_addr
 * @param af address family (AF_INET or AF_INET6)
 * @return TRUE if the address is valid
 */
gboolean rspamd_ip_is_valid (const rspamd_inet_addr_t *addr);

/**
 * Accept from listening socket filling addr structure
 * @param sock listening socket
 * @param addr allocated inet addr structur
 * @return
 */
gint rspamd_accept_from_socket (gint sock, rspamd_inet_addr_t **addr);

gboolean rspamd_parse_host_port_priority_strv (gchar **tokens,
	GPtrArray **addrs, guint *priority,
	gchar **name, guint default_port, rspamd_mempool_t *pool);

/**
 * Parse host[:port[:priority]] line
 * @param ina host address
 * @param port port
 * @param priority priority
 * @return TRUE if string was parsed
 */
gboolean rspamd_parse_host_port_priority (const gchar *str,
		GPtrArray **addrs,
		guint *priority, gchar **name, guint default_port,
		rspamd_mempool_t *pool);

/**
 * Parse host:port line
 * @param ina host address
 * @param port port
 * @return TRUE if string was parsed
 */
gboolean rspamd_parse_host_port (const gchar *str,
		GPtrArray **addrs,
	gchar **name, guint default_port, rspamd_mempool_t *pool);

/**
 * Destroy the specified IP address
 * @param addr
 */
void rspamd_inet_address_destroy (rspamd_inet_addr_t *addr);

/**
 * Apply the specified mask to an address (ignored for AF_UNIX)
 * @param addr
 * @param mask
 */
void rspamd_inet_address_apply_mask (rspamd_inet_addr_t *addr, guint mask);

/**
 * Compare a1 and a2 and return value >0, ==0 and <0 if a1 is more, equal or less than a2 correspondingly
 * @param a1
 * @param a2
 * @return
 */
gint rspamd_inet_address_compare (const rspamd_inet_addr_t *a1,
		const rspamd_inet_addr_t *a2);

/**
 * Performs deep copy of rspamd inet addr
 * @param addr
 * @return
 */
rspamd_inet_addr_t *rspamd_inet_address_copy (const rspamd_inet_addr_t *addr);

#endif /* ADDR_H_ */
