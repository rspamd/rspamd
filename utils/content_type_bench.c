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

static gdouble total_time = 0;
static gint total_parsed = 0;
static gint total_valid = 0;
static gint total_type = 0;
static gint total_subtype = 0;
static gint total_charset = 0;
static gint total_attrs = 0;

static void
rspamd_process_file (const gchar *fname)
{
	rspamd_mempool_t *pool;
	GIOChannel *f;
	GError *err = NULL;
	GString *buf;
	struct rspamd_content_type *ct;
	gdouble t1, t2;

	f = g_io_channel_new_file (fname, "r", &err);

	if (!f) {
		rspamd_fprintf (stderr, "cannot open %s: %e\n", fname, err);
		g_error_free (err);

		return;
	}

	g_io_channel_set_encoding (f, NULL, NULL);
	buf = g_string_sized_new (8192);
	pool = rspamd_mempool_new (rspamd_mempool_suggest_size (), "test");

	while (g_io_channel_read_line_string (f, buf, NULL, &err)
			== G_IO_STATUS_NORMAL) {

		while (buf->len > 0 && g_ascii_isspace (buf->str[buf->len - 1])) {
			buf->len --;
		}

		t1 = rspamd_get_virtual_ticks ();
		ct = rspamd_content_type_parse (buf->str, buf->len, pool);
		t2 = rspamd_get_virtual_ticks ();

		total_time += t2 - t1;
		total_parsed ++;

		if (ct) {
			total_valid ++;

			if (ct->type.len > 0) {
				total_type ++;
			}
			if (ct->subtype.len > 0) {
				total_subtype ++;
			}
			if (ct->charset.len > 0) {
				total_charset ++;
			}
			if (ct->attrs) {
				total_attrs ++;
			}
		}
	}

	if (err) {
		rspamd_fprintf (stderr, "cannot read %s: %e\n", fname, err);
		g_error_free (err);
	}

	g_io_channel_unref (f);
	g_string_free (buf, TRUE);
	rspamd_mempool_delete (pool);
}

int
main (int argc, char **argv)
{
	gint i;

	g_mime_init (0);

	for (i = 1; i < argc; i ++) {
		if (argv[i]) {
			rspamd_process_file (argv[i]);
		}
	}

	rspamd_printf ("Parsed %d received headers in %.3f seconds\n"
			"Total valid (has by part): %d\n"
			"Total known type: %d\n"
			"Total known subtype: %d\n"
			"Total known charset: %d\n"
			"Total has attrs: %d\n",
			total_parsed, total_time,
			total_valid, total_type,
			total_subtype, total_type,
			total_attrs);

	g_mime_shutdown ();

	return 0;
}
