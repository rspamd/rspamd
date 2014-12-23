#ifndef UPSTREAM_H
#define UPSTREAM_H

#include "config.h"
#include "util.h"
#include "rdns.h"
#include "ucl.h"

enum rspamd_upstream_rotation {
	RSPAMD_UPSTREAM_RANDOM,
	RSPAMD_UPSTREAM_HASHED,
	RSPAMD_UPSTREAM_ROUND_ROBIN,
	RSPAMD_UPSTREAM_MASTER_SLAVE,
	RSPAMD_UPSTREAM_SEQUENTIAL
};


struct rspamd_config;
/* Opaque upstream structures */
struct upstream;
struct upstream_list;

/**
 * Init upstreams library
 * @param resolver
 */
void rspamd_upstreams_library_init (struct rdns_resolver *resolver,
		struct event_base *base);

/**
 * Configure attributes of upstreams library
 * @param cfg
 */
void rspamd_upstreams_library_config (struct rspamd_config *cfg);

/**
 * Upstream error logic
 * 1. During error time we count upstream_ok and upstream_fail
 * 2. If failcount is more then maxerrors then we mark upstream as unavailable for dead time
 * 3. After dead time we mark upstream as alive and go to the step 1
 * 4. If all upstreams are dead, marks every upstream as alive
 */

/**
 * Add an error to an upstream
 */
void rspamd_upstream_fail (struct upstream *up);

/**
 * Increase upstream successes count
 */
void rspamd_upstream_ok (struct upstream *up);

/**
 * Create new list of upstreams
 * @return
 */
struct upstream_list* rspamd_upstreams_create (void);
/**
 * Destroy list of upstreams
 * @param ups
 */
void rspamd_upstreams_destroy (struct upstream_list *ups);

/**
 * Returns count of upstreams in a list
 * @param ups
 * @return
 */
gsize rspamd_upstreams_count (struct upstream_list *ups);

/**
 * Returns the number of upstreams in the list
 * @param ups
 * @return
 */
gsize rspamd_upstreams_alive (struct upstream_list *ups);

/**
 * Add upstream from the string
 * @param ups upstream list
 * @param str string in format "name[:port[:priority]]"
 * @param def_port default port number
 * @param data optional userdata
 * @return TRUE if upstream has been added
 */
gboolean rspamd_upstreams_add_upstream (struct upstream_list *ups,
		const gchar *str, guint16 def_port, void *data);

/**
 * Add multiple upstreams from comma, semicolon or space separated line
 * @param ups upstream list
 * @param str string in format "(<ups>([<sep>+]<ups>)*)+"
 * @param def_port default port number
 * @param data optional userdata
 * @return TRUE if **any** of upstreams has been added
 */
gboolean rspamd_upstreams_parse_line (struct upstream_list *ups,
		const gchar *str, guint16 def_port, void *data);


/**
 * Parse upstreams list from the UCL object
 * @param ups
 * @param in
 * @param def_port
 * @param data
 * @return
 */
gboolean rspamd_upstreams_from_ucl (struct upstream_list *ups,
		const ucl_object_t *in, guint16 def_port, void *data);

/**
 * Returns the current IP address of the upstream
 * @param up
 * @return
 */
rspamd_inet_addr_t* rspamd_upstream_addr (struct upstream *up);

/**
 * Add custom address for an upstream
 * @param up
 * @return
 */
gboolean rspamd_upstream_add_addr (struct upstream *up,
		const rspamd_inet_addr_t *addr);

/**
 * Returns the symbolic name of the upstream
 * @param up
 * @return
 */
const gchar* rspamd_upstream_name (struct upstream *up);

/**
 * Get new upstream from the list
 * @param ups upstream list
 * @param type type of rotation algorithm, for `RSPAMD_UPSTREAM_HASHED` it is required to specify `key` and `keylen` as arguments
 * @return
 */
struct upstream* rspamd_upstream_get (struct upstream_list *ups,
		enum rspamd_upstream_rotation type, ...);

#endif /* UPSTREAM_H */
/*
 * vi:ts=4
 */
