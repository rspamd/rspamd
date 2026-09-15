/* Internal hooks used by the canonical result insertion path. */
#ifndef RSPAMD_SYMCACHE_CHECKPOINT_H
#define RSPAMD_SYMCACHE_CHECKPOINT_H

#include "config.h"

#ifdef __cplusplus
extern "C" {
#endif

struct rspamd_task;
struct rspamd_scan_result;
struct rspamd_symbol_result;

gboolean rspamd_symcache_is_checkpoint(struct rspamd_task *task);

void rspamd_symcache_checkpoint_insert_begin(struct rspamd_task *task,
											 const char *symbol, double weight, const char *option, unsigned int flags,
											 struct rspamd_scan_result *result);
void rspamd_symcache_checkpoint_insert_end(struct rspamd_task *task,
										   struct rspamd_symbol_result *result);
void rspamd_symcache_checkpoint_option(struct rspamd_task *task,
									   struct rspamd_symbol_result *result, const char *option, gsize len);

void rspamd_symcache_checkpoint_invalidate(struct rspamd_task *task);
void rspamd_symcache_checkpoint_flush_frequencies(struct rspamd_task *task);

#ifdef __cplusplus
}
#endif
#endif
