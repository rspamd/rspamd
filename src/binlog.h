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
	gchar magic[3];
	gchar version[2];
	gchar padding[3];
	guint64 create_time;
};

struct rspamd_binlog_index {
	guint64 time;
	guint64 seek;
	guint32 len;
};

struct rspamd_index_block {
	struct rspamd_binlog_index indexes[BINLOG_IDX_LEN];
	guint32 last_index;
};

struct rspamd_binlog_metaindex {
	guint64 indexes[METAINDEX_LEN];
	guint64 last_index;
};

struct rspamd_binlog_element {
	guint32 h1;
	guint32 h2;
	float value;
} __attribute__((__packed__));

struct rspamd_binlog {
	gchar *filename;
	time_t rotate_time;
	gint rotate_jitter;
	guint64 cur_seq;
	guint64 cur_time;
	gint fd;
	memory_pool_t *pool;

	struct rspamd_binlog_header header;
	struct rspamd_binlog_metaindex *metaindex;
	struct rspamd_index_block *cur_idx;
};

struct classifier_config;

struct rspamd_binlog* binlog_open (memory_pool_t *pool, const gchar *path, time_t rotate_time, gint rotate_jitter);
struct rspamd_binlog* get_binlog_by_statfile (struct statfile *st);
void binlog_close (struct rspamd_binlog *log);
gboolean binlog_insert (struct rspamd_binlog *log, GTree *nodes);
gboolean binlog_sync (struct rspamd_binlog *log, guint64 from_rev, guint64 *from_time, GByteArray **rep);
gboolean maybe_write_binlog (struct classifier_config *ccf, struct statfile *st, stat_file_t *file, GTree *nodes);

#endif
