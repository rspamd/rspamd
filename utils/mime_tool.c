/*-
 * Copyright 2016 Vsevolod Stakhov
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "config.h"
#include "printf.h"
#include "message.h"
#include "util.h"
#include "content_type.h"
#include "task.h"
#include "mime_parser.h"
#include "unix-std.h"

static gdouble total_time = 0.0;

static void
rspamd_show_normal (struct rspamd_mime_part *part)
{
	rspamd_printf ("got normal part %p: parent: %p, type: %T/%T,"
			"length: %z (%z raw)\n",
			part, part->parent_part,
			&part->ct->type, &part->ct->subtype,
			part->parsed_data.len,
			part->raw_data.len);
}

static void
rspamd_show_multipart (struct rspamd_mime_part *part)
{
	struct rspamd_mime_part *cur;
	guint i;

	rspamd_printf ("got multipart part %p, boundary: %T: parent: %p, type: %T/%T, children: [",
			part, &part->ct->boundary,
			part->parent_part,
			&part->ct->type, &part->ct->subtype);

	if (part->children) {
		for (i = 0; i < part->children->len; i ++) {
			cur = g_ptr_array_index (part->children, i);

			if (i != 0) {
				rspamd_printf (", %p{%T/%T}", cur,
						&cur->ct->type, &cur->ct->subtype);
			}
			else {
				rspamd_printf ("%p{%T/%T}", cur,
						&cur->ct->type, &cur->ct->subtype);
			}
		}
	}

	rspamd_printf ("]\n");
}

static void
rspamd_show_message (struct rspamd_mime_part *part)
{
	rspamd_printf ("got message part %p: parent: %p\n",
				part, part->parent_part);
}

static void
rspamd_process_file (struct rspamd_config *cfg, const gchar *fname, gint mode)
{
	struct rspamd_task *task;
	gint fd;
	gpointer map;
	struct stat st;
	GError *err = NULL;
	struct rspamd_mime_part *part;
	guint i;
	gdouble ts1, ts2;

	fd = open (fname, O_RDONLY);

	if (fd == -1) {
		rspamd_fprintf (stderr, "cannot open %s: %s\n", fname, strerror (errno));
		exit (EXIT_FAILURE);
	}

	if (fstat (fd, &st) == -1) {
		rspamd_fprintf (stderr, "cannot stat %s: %s\n", fname, strerror (errno));
		exit (EXIT_FAILURE);
	}

	map = mmap (NULL, st.st_size, PROT_READ, MAP_SHARED, fd, 0);
	close (fd);

	if (map == MAP_FAILED) {
		rspamd_fprintf (stderr, "cannot mmap %s: %s\n", fname, strerror (errno));
		exit (EXIT_FAILURE);
	}

	task = rspamd_task_new (NULL, cfg);
	task->msg.begin = map;
	task->msg.len = st.st_size;

	ts1 = rspamd_get_ticks ();

	if (!rspamd_mime_parse_task (task, &err)) {
		rspamd_fprintf (stderr, "cannot parse %s: %e\n", fname, err);
		g_error_free (err);
	}

	ts2 = rspamd_get_ticks ();
	total_time += ts2 - ts1;

	for (i = 0; i < task->parts->len; i ++) {
		part = g_ptr_array_index (task->parts, i);

		if (part->ct->flags & RSPAMD_CONTENT_TYPE_MULTIPART) {
			rspamd_show_multipart (part);
		}
		else if (part->ct->flags & RSPAMD_CONTENT_TYPE_MESSAGE) {
			rspamd_show_message (part);
		}
		else {
			rspamd_show_normal (part);
		}
	}

	rspamd_task_free (task);
	munmap (map, st.st_size);
}

int
main (int argc, char **argv)
{
	gint i, start = 1;
	struct rspamd_config *cfg;
	rspamd_logger_t *logger = NULL;

	cfg = rspamd_config_new ();
	cfg->libs_ctx = rspamd_init_libs ();
	cfg->log_type = RSPAMD_LOG_CONSOLE;
	rspamd_set_logger (cfg, g_quark_from_static_string ("mime"), &logger, NULL);
	(void) rspamd_log_open (logger);
	g_log_set_default_handler (rspamd_glib_log_function, logger);
	g_set_printerr_handler (rspamd_glib_printerr_function);
	rspamd_config_post_load (cfg,
			RSPAMD_CONFIG_INIT_LIBS|RSPAMD_CONFIG_INIT_URL|RSPAMD_CONFIG_INIT_NO_TLD);

	for (i = start; i < argc; i ++) {
		if (argv[i]) {
			rspamd_process_file (cfg, argv[i], 0);
		}
	}

	rspamd_printf ("Total time parsing: %.4f seconds\n", total_time);

	rspamd_log_close (logger);
	REF_RELEASE (cfg);

	return 0;
}
