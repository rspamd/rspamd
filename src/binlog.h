#ifndef RSPAMD_BINLOG_H
#define RSPAMD_BINLOG_H

#include "config.h"
#include "main.h"
#include "statfile.h"

/* How much records are in a single index */
#define BINLOG_IDX_LEN 200
#define METAINDEX_LEN 1024

/* Assume 8 bytes words */
struct rspamd_binlog_header {
	char magic[3];
	char version[2];
	char padding[3];
	uint64_t create_time;
};

struct rspamd_binlog_index {
	uint64_t time;
	uint64_t seek;
	uint32_t len;
};

struct rspamd_index_block {
	struct rspamd_binlog_index indexes[BINLOG_IDX_LEN];
	uint32_t last_index;
};

struct rspamd_binlog_metaindex {
	uint64_t indexes[METAINDEX_LEN];
	uint64_t last_index;
};

struct rspamd_binlog_element {
	uint32_t h1;
	uint32_t h2;
	float value;
} __attribute__((__packed__));

struct rspamd_binlog {
	char *filename;
	time_t rotate_time;
	int rotate_jitter;
	uint64_t cur_seq;
	uint64_t cur_time;
	int fd;
	memory_pool_t *pool;

	struct rspamd_binlog_header header;
	struct rspamd_binlog_metaindex *metaindex;
	struct rspamd_index_block *cur_idx;
};

struct classifier_config;

struct rspamd_binlog* binlog_open (memory_pool_t *pool, const char *path, time_t rotate_time, int rotate_jitter);
struct rspamd_binlog* get_binlog_by_statfile (struct statfile *st);
void binlog_close (struct rspamd_binlog *log);
gboolean binlog_insert (struct rspamd_binlog *log, GTree *nodes);
gboolean binlog_sync (struct rspamd_binlog *log, uint64_t from_rev, uint64_t *from_time, GByteArray **rep);
gboolean maybe_write_binlog (struct classifier_config *ccf, struct statfile *st, stat_file_t *file, GTree *nodes);

#endif
