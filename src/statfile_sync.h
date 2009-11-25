#ifndef RSPAMD_STATFILE_SYNC_H
#define RSPAMD_STATFILE_SYNC_H

#include "config.h"
#include "main.h"
#include "statfile.h"
#include "cfg_file.h"

gboolean start_statfile_sync (statfile_pool_t *pool, struct config_file *cfg);

#endif
