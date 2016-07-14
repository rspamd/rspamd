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
#ifndef ADDR_H_
#define ADDR_H_

#include "config.h"
#include "rdns.h"

#ifdef HAVE_SYS_SOCKET_H
#include <sys/socket.h>
#endif
#ifdef HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif
#ifdef HAVE_ARPA_INET_H
#include <arpa/inet.h>
#endif
/* unix sockets */
#ifdef HAVE_SYS_UN_H
#include <sys/un.h>
#endif

#include "mem_pool.h"

/**
 * Opaque structure
 */
typedef struct rspamd_inet_addr_s rspamd_inet_addr_t;
struct radix_tree_compressed;

struct radix_tree_compressed **rspamd_inet_library_init (void);
void rspamd_inet_library_destroy (void);

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
 * Create new inet address from rdns reply
 * @param rep reply element
 * @return new ipv4 or ipv6 addr (port is NOT set)
 */
rspamd_inet_addr_t * rspamd_inet_address_from_rnds (
		const struct rdns_reply_entry *rep);

/**
 * Parse string with ipv6 address of length `len` to `target` which should be
 * at least sizeof (in6_addr_t)
 * @param text input string
 * @param len lenth of `text` (if 0, then `text` must be zero terminated)
 * @param target target structure
 * @return TRUE if the address has been parsed, otherwise `target` content is undefined
 */
gboolean rspamd_parse_inet_address_ip6 (const guchar *text, gsize len,
		gpointer target);

/**
 * Parse string with ipv4 address of length `len` to `target` which should be
 * at least sizeof (in4_addr_t)
 * @param text input string
 * @param len lenth of `text` (if 0, then `text` must be zero terminated)
 * @param target target structure
 * @return TRUE if the address has been parsed, otherwise `target` content is undefined
 */
gboolean rspamd_parse_inet_address_ip4 (const guchar *text, gsize len,
		gpointer target);

/**
 * Try to parse address from string
 * @param target target to fill
 * @param src IP string representation
 * @return TRUE if addr has been parsed
 */
gboolean rspamd_parse_inet_address (rspamd_inet_addr_t **target,
		const char *src,
		gsize srclen);

/**
 * Returns string representation of inet address
 * @param addr
 * @return statically allocated string pointer (not thread safe)
 */
const char * rspamd_inet_address_to_string (const rspamd_inet_addr_t *addr);

/**
 * Returns pretty string representation of inet address
 * @param addr
 * @return statically allocated string pointer (not thread safe)
 */
const char * rspamd_inet_address_to_string_pretty (const rspamd_inet_addr_t *addr);

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
guchar * rspamd_inet_address_get_hash_key (const rspamd_inet_addr_t *addr, guint *klen);

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
 * @param addr allocated inet addr structure
 * @param accept_events events for accepting new sockets
 * @return
 */
gint rspamd_accept_from_socket (gint sock, rspamd_inet_addr_t **addr,
		GList *accept_events);

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
 * Utility function to compare addresses by in g_ptr_array
 * @param a1
 * @param a2
 * @return
 */
gint rspamd_inet_address_compare_ptr (gconstpointer a1,
		gconstpointer a2);
/**
 * Performs deep copy of rspamd inet addr
 * @param addr
 * @return
 */
rspamd_inet_addr_t *rspamd_inet_address_copy (const rspamd_inet_addr_t *addr);

/**
 * Returns hash for inet address
 */
guint rspamd_inet_address_hash (gconstpointer a);


/**
 * Returns true if two address are equal
 */
gboolean rspamd_inet_address_equal (gconstpointer a, gconstpointer b);

/**
 * Returns TRUE if an address belongs to some local address
 */
gboolean rspamd_inet_address_is_local (const rspamd_inet_addr_t *addr);

#endif /* ADDR_H_ */
