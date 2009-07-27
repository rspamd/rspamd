#ifndef RSPAMD_FUZZY_STORAGE_H
#define RSPAMD_FUZZY_STORAGE_H

#include "config.h"
#include "main.h"
#include "fuzzy.h"

/* Commands for fuzzy storage */
#define FUZZY_CHECK 0
#define FUZZY_WRITE 1
#define FUZZY_DEL 2

struct fuzzy_cmd {
	u_char cmd;
	uint32_t blocksize;
	u_char hash[FUZZY_HASHLEN];
};

struct fuzzy_session {
	struct rspamd_worker *worker;
	struct event ev;
	struct fuzzy_cmd cmd;
	struct timeval tv;
	int fd;
	u_char *pos;
};

void start_fuzzy_storage (struct rspamd_worker *worker);

#endif
