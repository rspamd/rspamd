#ifndef RSPAMD_MAP_H
#define RSPAMD_MAP_H

#include "config.h"
#include "mem_pool.h"
#include "radix.h"

enum fetch_proto {
	PROTO_FILE,
	PROTO_HTTP,
};

struct map_cb_data {
	int state;
	void *prev_data;
	void *cur_data;
};

struct file_map_data {
	const char *filename;
	struct stat st;
};

struct http_map_data {
	struct in_addr addr;
	uint16_t port;
	char *path;
	char *host;
	time_t last_checked;
	gboolean chunked;
	uint32_t chunk;
	uint32_t chunk_read;
};

typedef u_char* (*map_cb_t)(memory_pool_t *pool, u_char *chunk, size_t len, struct map_cb_data *data);
typedef void (*map_fin_cb_t)(memory_pool_t *pool, struct map_cb_data *data);

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

gboolean add_map (const char *map_line, map_cb_t read_callback, map_fin_cb_t fin_callback, void **user_data);
void start_map_watch (void);

/* Common callbacks */
u_char* read_radix_list (memory_pool_t *pool, u_char *chunk, size_t len, struct map_cb_data *data);
void fin_radix_list (memory_pool_t *pool, struct map_cb_data *data);
u_char* read_host_list (memory_pool_t *pool, u_char *chunk, size_t len, struct map_cb_data *data);
void fin_host_list (memory_pool_t *pool, struct map_cb_data *data);

#endif
