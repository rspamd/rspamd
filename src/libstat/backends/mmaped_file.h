/**
 * @file statfile.h
 * Describes common methods for accessing statistics files and caching them in memory
 */

#ifndef RSPAMD_STATFILE_H
#define RSPAMD_STATFILE_H

#include "config.h"


/* Forwarded declarations */
struct rspamd_classifier_config;
struct rspamd_statfile_config;
struct rspamd_config;

gpointer
rspamd_mmaped_file_init(struct rspamd_config *cfg);

#endif
