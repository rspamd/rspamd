#ifndef RSPAMD_FUZZY_STORAGE_H
#define RSPAMD_FUZZY_STORAGE_H

#include "config.h"
#include "main.h"
#include "fuzzy.h"
#include "shingles.h"

#define RSPAMD_FUZZY_VERSION 2

/* Commands for fuzzy storage */
#define FUZZY_CHECK 0
#define FUZZY_WRITE 1
#define FUZZY_DEL 2

struct legacy_fuzzy_cmd {
	u_char cmd;
	guint32 blocksize;
	gint32 value;
	gint32 flag;
	u_char hash[FUZZY_HASHLEN];
};

RSPAMD_PACKED(rspamd_fuzzy_cmd) {
	guint8 version;
	guint8 cmd;
	guint8 shingles_count;
	guint8 flag;
	gint32 value;
	guint32 tag;
	gchar digest[64];
};

RSPAMD_PACKED(rspamd_fuzzy_shingle_cmd) {
	struct rspamd_fuzzy_cmd basic;
	struct rspamd_shingle sgl;
};

RSPAMD_PACKED(rspamd_fuzzy_reply) {
	gint32 value;
	guint32 flag;
	guint32 tag;
	float prob;
};

#endif
