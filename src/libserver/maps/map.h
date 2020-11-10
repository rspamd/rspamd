#ifndef RSPAMD_MAP_H
#define RSPAMD_MAP_H

#include "config.h"
#include "contrib/libev/ev.h"

#include "ucl.h"
#include "mem_pool.h"
#include "radix.h"
#include "dns.h"

#ifdef  __cplusplus
extern "C" {
#endif

/**
 * Maps API is designed to load lists data from different dynamic sources.
 * It monitor files and HTTP locations for modifications and reload them if they are
 * modified.
 */
struct map_cb_data;
struct rspamd_worker;

/**
 * Callback types
 */
typedef gchar *(*map_cb_t) (gchar *chunk, gint len,
							struct map_cb_data *data, gboolean final);

typedef void (*map_fin_cb_t) (struct map_cb_data *data, void **target);

typedef void (*map_dtor_t) (struct map_cb_data *data);

typedef gboolean (*rspamd_map_traverse_cb) (gconstpointer key,
											gconstpointer value, gsize hits, gpointer ud);

typedef void (*rspamd_map_traverse_function) (void *data,
											  rspamd_map_traverse_cb cb,
											  gpointer cbdata, gboolean reset_hits);

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

enum rspamd_map_flags {
	RSPAMD_MAP_DEFAULT = 0,
	RSPAMD_MAP_FILE_ONLY = 1u << 0u,
	RSPAMD_MAP_FILE_NO_READ = 1u << 1u,
};

/**
 * Add map from line
 */
struct rspamd_map *rspamd_map_add (struct rspamd_config *cfg,
								   const gchar *map_line,
								   const gchar *description,
								   map_cb_t read_callback,
								   map_fin_cb_t fin_callback,
								   map_dtor_t dtor,
								   void **user_data,
								   struct rspamd_worker *worker,
								   int flags);

/**
 * Add map from ucl
 */
struct rspamd_map *rspamd_map_add_from_ucl (struct rspamd_config *cfg,
											const ucl_object_t *obj,
											const gchar *description,
											map_cb_t read_callback,
											map_fin_cb_t fin_callback,
											map_dtor_t dtor,
											void **user_data,
											struct rspamd_worker *worker,
											int flags);

/**
 * Adds a fake map structure (for logging purposes mainly)
 * @param cfg
 * @param description
 * @return
 */
struct rspamd_map *rspamd_map_add_fake (struct rspamd_config *cfg,
								   const gchar *description,
								   const gchar *name);


enum rspamd_map_watch_type {
	RSPAMD_MAP_WATCH_MIN = 9,
	RSPAMD_MAP_WATCH_PRIMARY_CONTROLLER,
	RSPAMD_MAP_WATCH_SCANNER,
	RSPAMD_MAP_WATCH_WORKER,
	RSPAMD_MAP_WATCH_MAX
};

/**
 * Start watching of maps by adding events to libevent event loop
 */
void rspamd_map_watch (struct rspamd_config *cfg,
					   struct ev_loop *event_loop,
					   struct rspamd_dns_resolver *resolver,
					   struct rspamd_worker *worker,
					   enum rspamd_map_watch_type how);

/**
 * Preloads maps where all backends are file
 * @param cfg
 */
void rspamd_map_preload (struct rspamd_config *cfg);

/**
 * Remove all maps watched (remove events)
 */
void rspamd_map_remove_all (struct rspamd_config *cfg);

/**
 * Get traverse function for specific map
 * @param map
 * @return
 */
rspamd_map_traverse_function rspamd_map_get_traverse_function (struct rspamd_map *map);

/**
 * Perform map traverse
 * @param map
 * @param cb
 * @param cbdata
 * @param reset_hits
 * @return
 */
void rspamd_map_traverse (struct rspamd_map *map, rspamd_map_traverse_cb cb,
						  gpointer cbdata, gboolean reset_hits);

#ifdef  __cplusplus
}
#endif

#endif
