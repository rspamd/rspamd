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
#include "message.h"
#include "task.h"
#include "archives.h"

static void
rspamd_archive_dtor (gpointer p)
{
	struct rspamd_archive *arch = p;
	GString *s;
	guint i;

	for (i = 0; i < arch->files->len; i ++) {
		s = g_ptr_array_index (arch->files, i);

		g_string_free (s, TRUE);
	}

	g_ptr_array_free (arch->files, TRUE);
}

static void
rspamd_archive_process_zip (struct rspamd_task *task,
		struct rspamd_mime_part *part)
{
	const guchar *p, *start, *end, *eocd = NULL, *cd;
	const guint32 eocd_magic = 0x06054b50, cd_basic_len = 46;
	const guchar cd_magic[] = {0x50, 0x4b, 0x01, 0x02};
	guint32 cd_offset, cd_size;
	guint16 extra_len, fname_len, comment_len;
	struct rspamd_archive *arch;
	GString *fname;

	/* Zip files have interesting data at the end of archive */
	p = part->content->data + part->content->len - 1;
	start = part->content->data;
	end = p;

	/* Search for EOCD:
	 * 22 bytes is a typical size of eocd without a comment and
	 * end points one byte after the last character
	 */
	p -= 21;

	while (p > start + sizeof (guint32)) {
		guint32 t;

		/* XXX: not an efficient approach */
		memcpy (&t, p, sizeof (t));

		if (GUINT32_FROM_LE (t) == eocd_magic) {
			eocd = p;
			break;
		}

		p --;
	}


	if (eocd == NULL) {
		/* Not a zip file */
		msg_debug_task ("zip archive is invalid (no EOCD): %s", part->filename);

		return;
	}

	if (end - eocd < 21) {
		msg_debug_task ("zip archive is invalid (short EOCD): %s", part->filename);

		return;
	}


	memcpy (&cd_size, eocd + 12, sizeof (cd_size));
	cd_size = GUINT32_FROM_LE (cd_size);
	memcpy (&cd_offset, eocd + 16, sizeof (cd_offset));
	cd_offset = GUINT32_FROM_LE (cd_offset);

	/* We need to check sanity as well */
	if (cd_offset + cd_size != (guint)(eocd - start)) {
		msg_debug_task ("zip archive is invalid (bad size/offset for CD): %s",
				part->filename);

		return;
	}

	cd = start + cd_offset;

	arch = rspamd_mempool_alloc0 (task->task_pool, sizeof (*arch));
	arch->files = g_ptr_array_new ();
	arch->type = RSPAMD_ARCHIVE_ZIP;
	rspamd_mempool_add_destructor (task->task_pool, rspamd_archive_dtor,
			arch);

	while (cd < eocd) {
		/* Read central directory record */
		if (eocd - cd < cd_basic_len ||
				memcmp (cd, cd_magic, sizeof (cd_magic)) != 0) {
			msg_debug_task ("zip archive is invalid (bad cd record): %s",
					part->filename);

			return;
		}

		memcpy (&fname_len, cd + 28, sizeof (fname_len));
		fname_len = GUINT16_FROM_LE (fname_len);
		memcpy (&extra_len, cd + 30, sizeof (extra_len));
		extra_len = GUINT16_FROM_LE (extra_len);
		memcpy (&comment_len, cd + 32, sizeof (comment_len));
		comment_len = GUINT16_FROM_LE (comment_len);

		if (cd + fname_len + comment_len + extra_len + cd_basic_len > eocd) {
			msg_debug_task ("zip archive is invalid (too large cd record): %s",
					part->filename);

			return;
		}

		fname = g_string_new_len (cd + cd_basic_len, fname_len);
		g_ptr_array_add (arch->files, fname);
		msg_debug_task ("found file in zip archive: %v", fname);

		cd += fname_len + comment_len + extra_len + cd_basic_len;
	}

	part->flags |= RSPAMD_MIME_PART_ARCHIVE;
	part->specific_data = arch;
	arch->archive_name = part->filename;
	arch->size = part->content->len;
}

static inline gint
rspamd_archive_rar_read_vint (const guchar *start, gsize remain, guint64 *res)
{
	/*
	 * From http://www.rarlab.com/technote.htm:
	 * Variable length integer. Can include one or more bytes, where
	 * lower 7 bits of every byte contain integer data and highest bit
	 * in every byte is the continuation flag.
	 * If highest bit is 0, this is the last byte in sequence.
	 * So first byte contains 7 least significant bits of integer and
	 * continuation flag. Second byte, if present, contains next 7 bits and so on.
	 */
	guint64 t = 0;
	guint shift = 0;
	const guchar *p = start;

	while (remain > 0 && shift <= 57) {
		if (*p & 0x80) {
			t |= (*p & 0x7f) << shift;
		}
		else {
			t |= (*p & 0x7f) << shift;
			break;
		}

		shift += 7;
		p++;
		remain --;
	}

	if (remain == 0 || shift > 64) {
		return -1;
	}

	*res = GUINT64_FROM_LE (t);

	return p - start;
}

#define RAR_SKIP_BYTES(n) do { \
	if ((n) <= 0) { \
		msg_debug_task ("rar archive is invalid (bad skip value): %s", part->filename); \
		return; \
	} \
	if ((gsize)(end - p) < (n)) { \
		msg_debug_task ("rar archive is invalid (truncated): %s", part->filename); \
		return; \
	} \
	p += (n); \
} while (0)

#define RAR_READ_VINT() do { \
	r = rspamd_archive_rar_read_vint (p, end - p, &vint); \
	if (r == -1) { \
		msg_debug_task ("rar archive is invalid (bad vint): %s", part->filename); \
		return; \
	} \
	else if (r == 0) { \
		msg_debug_task ("rar archive is invalid (BAD vint offset): %s", part->filename); \
		return; \
	}\
} while (0)

#define RAR_READ_VINT_SKIP() do { \
	r = rspamd_archive_rar_read_vint (p, end - p, &vint); \
	if (r == -1) { \
		msg_debug_task ("rar archive is invalid (bad vint): %s", part->filename); \
		return; \
	} \
	p += r; \
} while (0)

static void
rspamd_archive_process_rar (struct rspamd_task *task,
		struct rspamd_mime_part *part)
{
	const guchar *p, *end;
	const guchar rar_v5_magic[] = {0x52, 0x61, 0x72, 0x21, 0x1A, 0x07, 0x01, 0x00},
			rar_v4_magic[] = {0x52, 0x61, 0x72, 0x21, 0x1A, 0x07, 0x00};
	const guint rar_encrypted_header = 4, rar_main_header = 1,
			rar_file_header = 2;
	guint64 vint, sz;
	struct rspamd_archive *arch;
	gint r;

	p = part->content->data;
	end = p + part->content->len;

	if ((gsize)(end - p) <= sizeof (rar_v5_magic)) {
		msg_debug_task ("rar archive is invalid (too small): %s", part->filename);

		return;
	}

	if (memcmp (p, rar_v5_magic, sizeof (rar_v5_magic)) == 0) {
		p += sizeof (rar_v5_magic);
	}
	else if (memcmp (p, rar_v4_magic, sizeof (rar_v4_magic)) == 0) {
		p += sizeof (rar_v4_magic);
	}
	else {
		msg_debug_task ("rar archive is invalid (no rar magic): %s", part->filename);

		return;
	}

	arch = rspamd_mempool_alloc0 (task->task_pool, sizeof (*arch));
	arch->files = g_ptr_array_new ();
	arch->type = RSPAMD_ARCHIVE_RAR;
	rspamd_mempool_add_destructor (task->task_pool, rspamd_archive_dtor,
			arch);

	/* Now we can have either encryption header or archive header */
	/* Crc 32 */
	RAR_SKIP_BYTES (sizeof (guint32));
	/* Size */
	RAR_READ_VINT_SKIP ();
	sz = vint;
	/* Type (not skip) */
	RAR_READ_VINT ();

	if (vint == rar_encrypted_header) {
		/* We can't read any further information as archive is encrypted */
		arch->flags |= RSPAMD_ARCHIVE_ENCRYPTED;
		goto end;
	}
	else if (vint != rar_main_header) {
		msg_debug_task ("rar archive is invalid (bad main header): %s", part->filename);

		return;
	}

	/* Nothing useful in main header */
	RAR_SKIP_BYTES (sz);

	while (p < end) {
		/* Read the next header */
		/* Crc 32 */
		RAR_SKIP_BYTES (sizeof (guint32));
		/* Size */
		RAR_READ_VINT_SKIP ();
		sz = vint;
		/* Type (not skip) */
		RAR_READ_VINT ();

		if (vint != rar_file_header) {
			RAR_SKIP_BYTES (sz);
		}
		else {
			/* We have a file header, go forward */
			const guchar *section_type_start = p;
			guint64 flags, fname_len;
			GString *s;

			p += r; /* Remain from type */
			/* Header flags */
			RAR_READ_VINT_SKIP ();
			flags = vint;

			/* Now we have two optional fields (fuck rar!) */
			if (flags & 0x1) {
				/* Extra flag */
				RAR_READ_VINT_SKIP ();
			}
			if (flags & 0x2) {
				/* Data size */
				RAR_READ_VINT_SKIP ();
			}

			/* File flags */
			RAR_READ_VINT_SKIP ();

			flags = vint;

			/* Unpacked size */
			RAR_READ_VINT_SKIP ();
			/* Attributes */
			RAR_READ_VINT_SKIP ();

			if (flags & 0x2) {
				/* Unix mtime */
				RAR_SKIP_BYTES (sizeof (guint32));
			}
			if (flags & 0x4) {
				/* Crc32 */
				RAR_SKIP_BYTES (sizeof (guint32));
			}

			/* Compression */
			RAR_READ_VINT_SKIP ();
			/* Host OS */
			RAR_READ_VINT_SKIP ();
			/* Filename length (finally!) */
			RAR_READ_VINT_SKIP ();
			fname_len = vint;

			if (fname_len == 0 || fname_len > (gsize)(end - p)) {
				msg_debug_task ("rar archive is invalid (bad fileame size): %s", part->filename);

				return;
			}

			s = g_string_new_len (p, fname_len);
			g_ptr_array_add (arch->files, s);
			/* Restore p to the beginning of the header */
			p = section_type_start;
			RAR_SKIP_BYTES (sz);
		}
	}

	return;
end:
	part->flags |= RSPAMD_MIME_PART_ARCHIVE;
	part->specific_data = arch;
	arch->archive_name = part->filename;
	arch->size = part->content->len;
}

static gboolean
rspamd_archive_cheat_detect (struct rspamd_mime_part *part, const gchar *str)
{
	GMimeContentType *ct;
	const gchar *fname, *p;

	ct = part->type;

	if (ct && ct->type && ct->subtype && strcmp (ct->type,
			"application") == 0) {
		if (rspamd_substring_search_caseless (ct->subtype, strlen (ct->subtype),
				str, strlen (str)) != -1) {
			return TRUE;
		}
	}

	fname = part->filename;

	if (fname && strlen (fname) > strlen (str)) {
		p = fname + strlen (fname) - strlen (str);

		if (rspamd_lc_cmp (p, str, strlen (str)) == 0) {
			if (*(p - 1) == '.') {
				return TRUE;
			}
		}
	}

	return FALSE;
}

void
rspamd_archives_process (struct rspamd_task *task)
{
	guint i;
	struct rspamd_mime_part *part;

	for (i = 0; i < task->parts->len; i ++) {
		part = g_ptr_array_index (task->parts, i);

		if (part->content->len > 0) {
			if (rspamd_archive_cheat_detect (part, "zip")) {
				rspamd_archive_process_zip (task, part);
			}
			else if (rspamd_archive_cheat_detect (part, "rar")) {
				rspamd_archive_process_rar (task, part);
			}
		}
	}
}


const gchar *
rspamd_archive_type_str (enum rspamd_archive_type type)
{
	const gchar *ret = "unknown";

	switch (type) {
	case RSPAMD_ARCHIVE_ZIP:
		ret = "zip";
		break;
	case RSPAMD_ARCHIVE_RAR:
		ret = "rar";
		break;
	}

	return ret;
}
