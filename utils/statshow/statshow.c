/* Copyright (c) 2010, Vsevolod Stakhov
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *       * Redistributions of source code must retain the above copyright
 *         notice, this list of conditions and the following disclaimer.
 *       * Redistributions in binary form must reproduce the above copyright
 *         notice, this list of conditions and the following disclaimer in the
 *         documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED ''AS IS'' AND ANY
 * EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL Rambler BE LIABLE FOR ANY
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include "config.h"
#include "main.h"
#include "cfg_file.h"
#include "util.h"
#include "map.h"
#include "cfg_xml.h"
#include "classifiers/classifiers.h"
#include "tokenizers/tokenizers.h"
#include "message.h"
#include "lua/lua_common.h"

module_t                        modules[] = { {NULL, NULL, NULL, NULL} };
struct rspamd_main             *rspamd_main = NULL;
static gchar                   *cfg_name;
extern rspamd_hash_t           *counters;

static GOptionEntry entries[] =
{
  { "config", 'c', 0, G_OPTION_ARG_STRING, &cfg_name, "Specify config file", NULL },
  { NULL, 0, 0, G_OPTION_ARG_NONE, NULL, NULL, NULL }
};

static void
read_cmd_line (gint *argc, gchar ***argv, struct config_file *cfg)
{
	GError                         *error = NULL;
	GOptionContext                 *context;

	context = g_option_context_new ("- run statshow utility");
	g_option_context_set_summary (context, "Summary:\n  Statshow utility version " RVERSION "\n  Release id: " RID);
	g_option_context_add_main_entries (context, entries, NULL);
	if (!g_option_context_parse (context, argc, argv, &error)) {
		fprintf (stderr, "option parsing failed: %s\n", error->message);
		exit (1);
	}
	cfg->cfg_name = cfg_name;
}

static gboolean
load_rspamd_config (struct config_file *cfg)
{
	if (! read_xml_config (cfg, cfg->cfg_name)) {
		return FALSE;
	}

	/* Do post-load actions */
	post_load_config (cfg);

	return TRUE;
}

static void
classifiers_callback (gpointer value, void *arg)
{
	struct worker_task             *task = arg;
	struct classifier_config       *cl = value;
	struct classifier_ctx          *ctx;
	struct mime_text_part          *text_part;
	GTree                          *tokens = NULL;
	GList                          *cur;
	f_str_t                         c;
	gchar                           *header = NULL;

	ctx = cl->classifier->init_func (task->task_pool, cl);
	ctx->debug = TRUE;

	cur = g_list_first (task->text_parts);
	if ((tokens = g_hash_table_lookup (task->tokens, cl->tokenizer)) == NULL) {
		while (cur != NULL) {
			if (header) {
				c.len = strlen (cur->data);
				if (c.len > 0) {
					c.begin = cur->data;
					if (!cl->tokenizer->tokenize_func (cl->tokenizer, task->task_pool, &c, &tokens, TRUE)) {
						msg_info ("cannot tokenize input");
						return;
					}
				}
			}
			else {
				text_part = (struct mime_text_part *)cur->data;
				if (text_part->is_empty) {
					cur = g_list_next (cur);
					continue;
				}
				c.begin = text_part->content->data;
				c.len = text_part->content->len;
				/* Tree would be freed at task pool freeing */
				if (!cl->tokenizer->tokenize_func (cl->tokenizer, task->task_pool, &c, &tokens, TRUE)) {
					msg_info ("cannot tokenize input");
					return;
				}
			}
			cur = g_list_next (cur);
		}
		g_hash_table_insert (task->tokens, cl->tokenizer, tokens);
	}

	if (tokens == NULL) {
		return;
	}

	/* Take care of subject */
	tokenize_subject (task, &tokens);
	cl->classifier->classify_func (ctx, task->worker->srv->statfile_pool, tokens, task);
}

static void
process_buffer (gchar *buf, gsize len, struct rspamd_main *rspamd)
{
	struct worker_task              *task;
	struct rspamd_worker            *fake_worker;


	/* Make fake worker for task */
	fake_worker = g_malloc (sizeof (struct rspamd_worker));
	fake_worker->srv = rspamd;

	/* Make task */
	task = construct_task (fake_worker);
	/* Copy message */
	task->msg = memory_pool_alloc (task->task_pool, sizeof (f_str_t));
	task->msg->begin = buf;
	task->msg->len = len;

	/* Process message */
	if (process_message (task) != 0) {
		return;
	}

	g_list_foreach (task->cfg->classifiers, classifiers_callback, task);

	g_free (fake_worker);
}

static void
process_stdin (struct rspamd_main *rspamd)
{
	gchar                           *in_buf;
	gint                             r = 0, len;

	/* Allocate input buffer */
	len = BUFSIZ;
	in_buf = g_malloc (len);

	/* Read stdin */
	while (!feof (stdin)) {
		r += fread (in_buf + r, 1, len - r, stdin);
		if (len - r < len / 2) {
			/* Grow buffer */
			len *= 2;
			in_buf = g_realloc (in_buf, len);
		}
	}

	process_buffer (in_buf, r, rspamd);
	g_free (in_buf);
}

static void
process_file (const gchar *filename, struct rspamd_main *rspamd)
{
	struct stat                     st;
	char                           *in_buf;
	gsize                           r = 0;
	gint                            fd;

	if (stat (filename, &st) == -1) {
		msg_err ("stat failed: %s", strerror (errno));
		return;
	}

	if ((fd = open (filename, O_RDONLY)) == -1) {
		msg_err ("stat failed: %s", strerror (errno));
		return;
	}

	in_buf = g_malloc (st.st_size);

	while (r < st.st_size) {
		r += read (fd, in_buf + r, r - st.st_size);
	}

	process_buffer (in_buf, r, rspamd);
	g_free (in_buf);
}

gint
main (gint argc, gchar **argv, gchar **env)
{
	gchar                          **arg;

	rspamd_main = (struct rspamd_main *)g_malloc (sizeof (struct rspamd_main));
	memset (rspamd_main, 0, sizeof (struct rspamd_main));
	rspamd_main->server_pool = memory_pool_new (memory_pool_get_size ());
	rspamd_main->cfg = (struct config_file *)g_malloc (sizeof (struct config_file));
	if (!rspamd_main || !rspamd_main->cfg) {
		fprintf (stderr, "Cannot allocate memory\n");
		exit (-errno);
	}
	rspamd_main->cfg->modules_num = 0;

	memset (rspamd_main->cfg, 0, sizeof (struct config_file));
	rspamd_main->cfg->cfg_pool = memory_pool_new (memory_pool_get_size ());
	init_defaults (rspamd_main->cfg);

	read_cmd_line (&argc, &argv, rspamd_main->cfg);
	if (rspamd_main->cfg->cfg_name == NULL) {
		rspamd_main->cfg->cfg_name = FIXED_CONFIG_FILE;
	}

	/* First set logger to console logger */
	rspamd_set_logger (RSPAMD_LOG_CONSOLE, TYPE_MAIN, rspamd_main);
	(void)open_log (rspamd_main->logger);
	g_log_set_default_handler (rspamd_glib_log_function, rspamd_main);
	init_lua (rspamd_main->cfg);
	/* Init counters */
	counters = rspamd_hash_new_shared (rspamd_main->server_pool, g_str_hash, g_str_equal, 64);

	/* Init classifiers options */
	register_classifier_opt ("bayes", "min_tokens");
	register_classifier_opt ("winnow", "min_tokens");
	register_classifier_opt ("winnow", "learn_threshold");
	/* Load config */
	if (! load_rspamd_config (rspamd_main->cfg)) {
		exit (EXIT_FAILURE);
	}

	/* Init statfile pool */
	rspamd_main->statfile_pool = statfile_pool_new (rspamd_main->server_pool, rspamd_main->cfg->max_statfile_size);
	g_mime_init (0);
	rspamd_main->cfg->log_extended = FALSE;

	/* Check argc */
	if (argc > 1) {
		arg = &argv[1];
		while (*arg) {
			process_file (*arg, rspamd_main);
			arg ++;
		}
	}
	else {
		process_stdin (rspamd_main);
	}

	return 0;
}
