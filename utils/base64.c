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
#include "util.h"
#include "cryptobox.h"
#include "unix-std.h"

static gdouble total_time = 0;


static void
rspamd_process_file (const gchar *fname, gint decode)
{
	gint fd;
	gpointer map;
	struct stat st;
	guint8 *dest;
	gsize destlen;

	fd = open (fname, O_RDONLY);

	if (fd == -1) {
		rspamd_fprintf (stderr, "cannot open %s: %s", fname, strerror (errno));
		exit (EXIT_FAILURE);
	}

	if (fstat (fd, &st) == -1) {
		rspamd_fprintf (stderr, "cannot stat %s: %s", fname, strerror (errno));
		exit (EXIT_FAILURE);
	}

	map = mmap (NULL, st.st_size, PROT_READ, MAP_SHARED, fd, 0);
	close (fd);

	if (map == MAP_FAILED) {
		rspamd_fprintf (stderr, "cannot mmap %s: %s", fname, strerror (errno));
		exit (EXIT_FAILURE);
	}

	if (decode) {
		destlen = st.st_size / 4 * 3 + 10;
		dest = g_malloc (destlen);
		rspamd_cryptobox_base64_decode (map, st.st_size, dest, &destlen);
	}
	else {
		dest = rspamd_encode_base64 (map, st.st_size, 80, &destlen);
	}

	rspamd_printf ("%*s", (gint)destlen, dest);
	g_free (dest);

	munmap (map, st.st_size);
}

int
main (int argc, char **argv)
{
	gint i, start = 1, decode = 0;

	if (argc > 2 && *argv[1] == '-') {
		start = 2;

		if (argv[1][1] == 'd') {
			decode = 1;
		}
	}

	for (i = start; i < argc; i ++) {
		if (argv[i]) {
			rspamd_process_file (argv[i], decode);
		}
	}

	return 0;
}
