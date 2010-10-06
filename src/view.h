#ifndef RSPAMD_VIEW_H
#define RSPAMD_VIEW_H

#include "config.h"
#include "main.h"
#include "radix.h"

struct rspamd_view {
	GList *from_re_list;
	GHashTable *from_hash;

	GList *rcpt_re_list;
	GHashTable *rcpt_hash;

	radix_tree_t *ip_tree;
	radix_tree_t *client_ip_tree;

	GHashTable *symbols_hash;
	GList *symbols_re_list;
	gboolean skip_check;

	memory_pool_t *pool;
};

struct rspamd_view* init_view (memory_pool_t *pool);

gboolean add_view_from (struct rspamd_view *view, gchar *line);
gboolean add_view_rcpt (struct rspamd_view *view, gchar *line);
gboolean add_view_ip (struct rspamd_view *view, gchar *line);
gboolean add_view_client_ip (struct rspamd_view *view, gchar *line);
gboolean add_view_symbols (struct rspamd_view *view, gchar *line);

gboolean check_view (GList *views, const gchar *symbol, struct worker_task *task);
gboolean check_skip (GList *views, struct worker_task *task);

#endif
