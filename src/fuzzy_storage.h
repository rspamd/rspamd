#ifndef RSPAMD_FUZZY_STORAGE_H
#define RSPAMD_FUZZY_STORAGE_H

#include "config.h"
#include "fuzzy.h"
#include "main.h"

/* Commands for fuzzy storage */
#define FUZZY_CHECK 0
#define FUZZY_WRITE 1
#define FUZZY_DEL 2

struct fuzzy_cmd {
	u_char cmd;
	guint32 blocksize;
	gint32 value;
	gint32 flag;
	u_char hash[FUZZY_HASHLEN];
};

#endif
