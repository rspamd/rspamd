/** @file view.h **/

#ifndef RSPAMD_VIEW_H
#define RSPAMD_VIEW_H

#include "config.h"
#include "main.h"
#include "radix.h"

struct config_file;
struct rspamd_view {
	struct config_file *cfg;
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


/**
 * Init a new view
 * @param pool pool for view
 * @return
 */
struct rspamd_view* init_view (struct config_file *cfg, memory_pool_t *pool);

/**
 * Add from option for this view
 * @param view view
 * @param line from line for this view
 * @return
 */
gboolean add_view_from (struct rspamd_view *view, gchar *line);


/**
 * Add recipient for this view
 * @param view view object
 * @param line recipient description
 * @return
 */
gboolean add_view_rcpt (struct rspamd_view *view, gchar *line);

/**
 * Add ip option for this view
 * @param view view object
 * @param line ip description
 * @return
 */
gboolean add_view_ip (struct rspamd_view *view, gchar *line);

/**
 * Add client ip option for this view
 * @param view view object
 * @param line ip description
 * @return
 */
gboolean add_view_client_ip (struct rspamd_view *view, gchar *line);

/**
 * Add symbols option for this view
 * @param view view object
 * @param line symbols description
 * @return
 */
gboolean add_view_symbols (struct rspamd_view *view, gchar *line);

/**
 * Check view for this task for specified symbol
 * @param views list of defined views
 * @param symbol symbol to check
 * @param task task object
 * @return whether to check this symbol for this task
 */
gboolean check_view (GList *views, const gchar *symbol, struct worker_task *task);

/**
 * Check whether this task should be skipped from checks
 * @param views list of defined views
 * @param task task object
 * @return
 */
gboolean check_skip (GList *views, struct worker_task *task);

#endif
