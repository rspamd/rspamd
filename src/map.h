#ifndef RSPAMD_MAP_H
#define RSPAMD_MAP_H

#include "config.h"
#include "mem_pool.h"
#include "radix.h"

/**
 * Maps API is designed to load lists data from different dynamic sources.
 * It monitor files and HTTP locations for modifications and reload them if they are
 * modified.
 */

enum fetch_proto {
	PROTO_FILE,
	PROTO_HTTP,
};

/**
 * Callback data for async load
 */
struct map_cb_data {
	gint state;
	void *prev_data;
	void *cur_data;
};

/**
 * Data specific to file maps
 */
struct file_map_data {
	const gchar *filename;
	struct stat st;
};

/**
 * Data specific to HTTP maps
 */
struct http_map_data {
	struct in_addr addr;
	guint16 port;
	gchar *path;
	gchar *host;
	time_t last_checked;
	gboolean chunked;
	u_char read_buf[BUFSIZ];
	guint32 rlen;
	guint32 chunk;
	guint32 chunk_read;
};

/**
 * Callback types
 */
typedef u_char* (*map_cb_t)(memory_pool_t *pool, u_char *chunk, size_t len, struct map_cb_data *data);
typedef void (*map_fin_cb_t)(memory_pool_t *pool, struct map_cb_data *data);

/**
 * Common map object
 */
struct rspamd_map {
	memory_pool_t *pool;
	enum fetch_proto protocol;
	map_cb_t read_callback;
	map_fin_cb_t fin_callback;
	void **user_data;
	struct event ev;
	struct timeval tv;
	void *map_data;
};

/**
 * Check map protocol
 */
gboolean check_map_proto (const gchar *map_line, gint *res, const gchar **pos);
/**
 * Add map from line
 */
gboolean add_map (const gchar *map_line, map_cb_t read_callback, map_fin_cb_t fin_callback, void **user_data);

/**
 * Start watching of maps by adding events to libevent event loop
 */
void start_map_watch (void);

/**
 * Remove all maps watched (remove events)
 */
void remove_all_maps (void);

typedef void                    (*insert_func) (gpointer st, gconstpointer key, gpointer value);

/**
 * Common callbacks for frequent types of lists
 */

/**
 * Radix list is a list like ip/mask
 */
u_char* read_radix_list (memory_pool_t *pool, u_char *chunk, size_t len, struct map_cb_data *data);
void fin_radix_list (memory_pool_t *pool, struct map_cb_data *data);

/**
 * Host list is an ordinal list of hosts or domains
 */
u_char* read_host_list (memory_pool_t *pool, u_char *chunk, size_t len, struct map_cb_data *data);
void fin_host_list (memory_pool_t *pool, struct map_cb_data *data);

/**
 * FSM for lists parsing (support comments, blank lines and partial replies)
 */
u_char * abstract_parse_list (memory_pool_t * pool, u_char * chunk, size_t len, struct map_cb_data *data, insert_func func);

#endif
