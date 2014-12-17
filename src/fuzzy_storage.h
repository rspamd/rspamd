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

struct rspamd_fuzzy_cmd {
	guint8 version;
	guint8 cmd;
	guint16 size;
	struct rspamd_shingle sh;
};

struct rspamd_fuzzy_reply {
	guint32 code;
	gdouble prob;
};

#endif
