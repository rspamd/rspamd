#ifndef RSPAMD_SETTINGS_H
#define RSPAMD_SETTINGS_H

#include "config.h"
#include "main.h"

struct rspamd_settings {
	GHashTable *metric_scores;			/**< hash table of metric scores for this setting		*/
	GHashTable *factors;				/**< hash table of new factors for this setting			*/
	char *statfile_alias;				/**< alias for statfile used							*/
	gboolean want_spam;					/**< if true disable rspamd checks						*/
};


int read_settings (const char *path, struct config_file *cfg, GHashTable *table);

#endif
