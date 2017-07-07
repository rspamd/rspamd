#ifndef RSPAMD_MAP_H
#define RSPAMD_MAP_H

#include "config.h"
#include <event.h>

#include "ucl.h"
#include "mem_pool.h"
#include "radix.h"
#include "dns.h"

/**
 * Maps API is designed to load lists data from different dynamic sources.
 * It monitor files and HTTP locations for modifications and reload them if they are
 * modified.
 */
struct map_cb_data;

/**
 * Callback types
 */
typedef gchar * (*map_cb_t)(gchar *chunk, gint len,
	struct map_cb_data *data, gboolean final);
typedef void (*map_fin_cb_t)(struct map_cb_data *data);

/**
 * Common map object
 */
struct rspamd_config;
struct rspamd_map;

/**
 * Callback data for async load
 */
struct map_cb_data {
	struct rspamd_map *map;
	gint state;
	void *prev_data;
	void *cur_data;
};

/**
 * Returns TRUE if line looks like a map definition
 * @param map_line
 * @return
 */
gboolean rspamd_map_is_map (const gchar *map_line);

/**
 * Add map from line
 */
struct rspamd_map* rspamd_map_add (struct rspamd_config *cfg,
	const gchar *map_line,
	const gchar *description,
	map_cb_t read_callback,
	map_fin_cb_t fin_callback,
	void **user_data);

/**
 * Add map from ucl
 */
struct rspamd_map* rspamd_map_add_from_ucl (struct rspamd_config *cfg,
	const ucl_object_t *obj,
	const gchar *description,
	map_cb_t read_callback,
	map_fin_cb_t fin_callback,
	void **user_data);

/**
 * Start watching of maps by adding events to libevent event loop
 */
void rspamd_map_watch (struct rspamd_config *cfg, struct event_base *ev_base,
		struct rspamd_dns_resolver *resolver, gboolean active_http);

/**
 * Remove all maps watched (remove events)
 */
void rspamd_map_remove_all (struct rspamd_config *cfg);

typedef void (*insert_func) (gpointer st, gconstpointer key,
	gconstpointer value);

/**
 * Common callbacks for frequent types of lists
 */

/**
 * Radix list is a list like ip/mask
 */
gchar * rspamd_radix_read (
	gchar *chunk,
	gint len,
	struct map_cb_data *data,
	gboolean final);
void rspamd_radix_fin (struct map_cb_data *data);

/**
 * Host list is an ordinal list of hosts or domains
 */
gchar * rspamd_hosts_read (
	gchar *chunk,
	gint len,
	struct map_cb_data *data,
	gboolean final);
void rspamd_hosts_fin (struct map_cb_data *data);

/**
 * Kv list is an ordinal list of keys and values separated by whitespace
 */
gchar * rspamd_kv_list_read (
	gchar *chunk,
	gint len,
	struct map_cb_data *data,
	gboolean final);
void rspamd_kv_list_fin (struct map_cb_data *data);

/**
 * Regexp list is a list of regular expressions
 */
struct rspamd_regexp_map;

gchar * rspamd_regexp_list_read_single (
		gchar *chunk,
		gint len,
		struct map_cb_data *data,
		gboolean final);
gchar * rspamd_regexp_list_read_multiple (
		gchar *chunk,
		gint len,
		struct map_cb_data *data,
		gboolean final);
void rspamd_regexp_list_fin (struct map_cb_data *data);

/**
 * FSM for lists parsing (support comments, blank lines and partial replies)
 */
gchar *
rspamd_parse_kv_list (
	gchar * chunk,
	gint len,
	struct map_cb_data *data,
	insert_func func,
	const gchar *default_value,
	gboolean final);

/**
 * Find a single (any) matching regexp for the specified text or NULL if
 * no matches found
 * @param map
 * @param in
 * @param len
 * @return
 */
gpointer rspamd_match_regexp_map_single (struct rspamd_regexp_map *map,
		const gchar *in, gsize len);

/**
 * Find a multiple (all) matching regexp for the specified text or NULL if
 * no matches found. Returns GPtrArray that *must* be freed by a caller if not NULL
 * @param map
 * @param in
 * @param len
 * @return
 */
gpointer rspamd_match_regexp_map_all (struct rspamd_regexp_map *map,
		const gchar *in, gsize len);

#endif
