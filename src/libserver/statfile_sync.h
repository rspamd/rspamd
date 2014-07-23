#ifndef RSPAMD_STATFILE_SYNC_H
#define RSPAMD_STATFILE_SYNC_H

#include "config.h"
#include "main.h"
#include "statfile.h"
#include "cfg_file.h"

/*
 * Start synchronization of statfiles. Must be called after event_init as it adds events
 */
gboolean start_statfile_sync (statfile_pool_t *pool,
	struct rspamd_config *cfg,
	struct event_base *ev_base);

#endif
