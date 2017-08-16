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
#include "smtp_parsers.h"

static gdouble total_time = 0;
static gint total_parsed = 0;
static gint total_valid = 0;
static gint total_real_ip = 0;
static gint total_real_host = 0;
static gint total_known_proto = 0;
static gint total_known_ts = 0;
static gint total_known_for = 0;

static void
rspamd_process_file (const gchar *fname)
{
	struct rspamd_task *task;
	GIOChannel *f;
	GError *err = NULL;
	GString *buf;
	struct received_header rh;
	gdouble t1, t2;

	f = g_io_channel_new_file (fname, "r", &err);

	if (!f) {
		rspamd_fprintf (stderr, "cannot open %s: %e\n", fname, err);
		g_error_free (err);

		return;
	}

	g_io_channel_set_encoding (f, NULL, NULL);
	buf = g_string_sized_new (8192);
	task = g_malloc0 (sizeof (*task));
	task->task_pool = rspamd_mempool_new (rspamd_mempool_suggest_size (), "test");

	while (g_io_channel_read_line_string (f, buf, NULL, &err)
			== G_IO_STATUS_NORMAL) {

		while (buf->len > 0 && g_ascii_isspace (buf->str[buf->len - 1])) {
			buf->len --;
		}

		t1 = rspamd_get_virtual_ticks ();
		rspamd_smtp_received_parse (task, buf->str, buf->len, &rh);
		t2 = rspamd_get_virtual_ticks ();

		total_time += t2 - t1;
		total_parsed ++;

		if (rh.addr) {
			total_real_ip ++;
		}
		if (rh.real_hostname) {
			total_real_host ++;
		}
		if (rh.type != RSPAMD_RECEIVED_UNKNOWN) {
			total_known_proto ++;
		}

		if (rh.by_hostname || rh.timestamp > 0) {
			total_valid ++;
		}

		if (rh.timestamp != 0) {
			total_known_ts ++;
		}

		if (rh.for_mbox) {
			total_known_for ++;
		}
	}

	if (err) {
		rspamd_fprintf (stderr, "cannot read %s: %e\n", fname, err);
		g_error_free (err);
	}

	g_io_channel_unref (f);
	g_string_free (buf, TRUE);
	rspamd_mempool_delete (task->task_pool);
	g_free (task);
}

int
main (int argc, char **argv)
{
	gint i;

	for (i = 1; i < argc; i ++) {
		if (argv[i]) {
			rspamd_process_file (argv[i]);
		}
	}

	rspamd_printf ("Parsed %d received headers in %.3f seconds\n"
			"Total valid (has by part): %d\n"
			"Total real ip: %d\n"
			"Total real host: %d\n"
			"Total known proto: %d\n"
			"Total known timestamp: %d\n"
			"Total known for: %d\n",
			total_parsed, total_time,
			total_valid, total_real_ip,
			total_real_host, total_known_proto,
			total_known_ts,
			total_known_for);

	return 0;
}
