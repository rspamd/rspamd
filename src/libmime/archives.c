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
#include "libmime/mime_encoding.h"
#include <unicode/uchar.h>
#include <unicode/utf8.h>
#include <unicode/utf16.h>
#include <unicode/ucnv.h>

#define msg_debug_archive(...)  rspamd_conditional_debug_fast (NULL, NULL, \
        rspamd_archive_log_id, "archive", task->task_pool->tag.uid, \
        G_STRFUNC, \
        __VA_ARGS__)

INIT_LOG_MODULE(archive)

static void
rspamd_archive_dtor (gpointer p)
{
	struct rspamd_archive *arch = p;
	struct rspamd_archive_file *f;
	guint i;

	for (i = 0; i < arch->files->len; i ++) {
		f = g_ptr_array_index (arch->files, i);

		if (f->fname) {
			g_string_free (f->fname, TRUE);
		}

		g_free (f);
	}

	g_ptr_array_free (arch->files, TRUE);
}

static GString *
rspamd_archive_file_try_utf (struct rspamd_task *task,
		const gchar *in, gsize inlen)
{
	const gchar *charset = NULL, *p, *end;
	GString *res;

	charset = rspamd_mime_charset_find_by_content (in, inlen, TRUE);

	if (charset) {
		UChar *tmp;
		UErrorCode uc_err = U_ZERO_ERROR;
		gint32 r, clen, dlen;
		struct rspamd_charset_converter *conv;
		UConverter *utf8_converter;

		conv = rspamd_mime_get_converter_cached (charset, task->task_pool,
				TRUE, &uc_err);
		utf8_converter = rspamd_get_utf8_converter ();

		if (conv == NULL) {
			msg_info_task ("cannot open converter for %s: %s",
					charset, u_errorName (uc_err));

			return NULL;
		}

		tmp = g_malloc (sizeof (*tmp) * (inlen + 1));
		r = rspamd_converter_to_uchars (conv, tmp, inlen + 1,
				in, inlen, &uc_err);
		if (!U_SUCCESS (uc_err)) {
			msg_info_task ("cannot convert data to unicode from %s: %s",
					charset, u_errorName (uc_err));
			g_free (tmp);

			return NULL;
		}

		clen = ucnv_getMaxCharSize (utf8_converter);
		dlen = UCNV_GET_MAX_BYTES_FOR_STRING (r, clen);
		res = g_string_sized_new (dlen);
		r = ucnv_fromUChars (utf8_converter, res->str, dlen, tmp, r, &uc_err);

		if (!U_SUCCESS (uc_err)) {
			msg_info_task ("cannot convert data from unicode from %s: %s",
					charset, u_errorName (uc_err));
			g_free (tmp);
			g_string_free (res, TRUE);

			return NULL;
		}

		g_free (tmp);
		res->len = r;

		msg_debug_archive ("converted from %s to UTF-8 inlen: %z, outlen: %d",
				charset, inlen, r);
	}
	else {
		/* Convert unsafe characters to '?' */
		res = g_string_sized_new (inlen);
		p = in;
		end = in + inlen;

		while (p < end) {
			if (g_ascii_isgraph (*p)) {
				g_string_append_c (res, *p);
			}
			else {
				g_string_append_c (res, '?');
			}

			p ++;
		}
	}

	return res;
}

static void
rspamd_archive_process_zip (struct rspamd_task *task,
		struct rspamd_mime_part *part)
{
	const guchar *p, *start, *end, *eocd = NULL, *cd;
	const guint32 eocd_magic = 0x06054b50, cd_basic_len = 46;
	const guchar cd_magic[] = {0x50, 0x4b, 0x01, 0x02};
	const guint max_processed = 1024;
	guint32 cd_offset, cd_size, comp_size, uncomp_size, processed = 0;
	guint16 extra_len, fname_len, comment_len;
	struct rspamd_archive *arch;
	struct rspamd_archive_file *f = NULL;

	/* Zip files have interesting data at the end of archive */
	p = part->parsed_data.begin + part->parsed_data.len - 1;
	start = part->parsed_data.begin;
	end = p;

	/* Search for EOCD:
	 * 22 bytes is a typical size of eocd without a comment and
	 * end points one byte after the last character
	 */
	p -= 21;

	while (p > start + sizeof (guint32)) {
		guint32 t;

		if (processed > max_processed) {
			break;
		}

		/* XXX: not an efficient approach */
		memcpy (&t, p, sizeof (t));

		if (GUINT32_FROM_LE (t) == eocd_magic) {
			eocd = p;
			break;
		}

		p --;
		processed ++;
	}


	if (eocd == NULL) {
		/* Not a zip file */
		msg_info_task ("zip archive is invalid (no EOCD)");

		return;
	}

	if (end - eocd < 21) {
		msg_info_task ("zip archive is invalid (short EOCD)");

		return;
	}


	memcpy (&cd_size, eocd + 12, sizeof (cd_size));
	cd_size = GUINT32_FROM_LE (cd_size);
	memcpy (&cd_offset, eocd + 16, sizeof (cd_offset));
	cd_offset = GUINT32_FROM_LE (cd_offset);

	/* We need to check sanity as well */
	if (cd_offset + cd_size > (guint)(eocd - start)) {
		msg_info_task ("zip archive is invalid (bad size/offset for CD)");

		return;
	}

	cd = start + cd_offset;

	arch = rspamd_mempool_alloc0 (task->task_pool, sizeof (*arch));
	arch->files = g_ptr_array_new ();
	arch->type = RSPAMD_ARCHIVE_ZIP;
	rspamd_mempool_add_destructor (task->task_pool, rspamd_archive_dtor,
			arch);

	while (cd < start + cd_offset + cd_size) {
		guint16 flags;

		/* Read central directory record */
		if (eocd - cd < cd_basic_len ||
				memcmp (cd, cd_magic, sizeof (cd_magic)) != 0) {
			msg_info_task ("zip archive is invalid (bad cd record)");

			return;
		}

		memcpy (&flags, cd + 8, sizeof (guint16));
		flags = GUINT16_FROM_LE (flags);
		memcpy (&comp_size, cd + 20, sizeof (guint32));
		comp_size = GUINT32_FROM_LE (comp_size);
		memcpy (&uncomp_size, cd + 24, sizeof (guint32));
		uncomp_size = GUINT32_FROM_LE (uncomp_size);
		memcpy (&fname_len, cd + 28, sizeof (fname_len));
		fname_len = GUINT16_FROM_LE (fname_len);
		memcpy (&extra_len, cd + 30, sizeof (extra_len));
		extra_len = GUINT16_FROM_LE (extra_len);
		memcpy (&comment_len, cd + 32, sizeof (comment_len));
		comment_len = GUINT16_FROM_LE (comment_len);

		if (cd + fname_len + comment_len + extra_len + cd_basic_len > eocd) {
			msg_info_task ("zip archive is invalid (too large cd record)");

			return;
		}

		f = g_malloc0 (sizeof (*f));
		f->fname = rspamd_archive_file_try_utf (task,
				cd + cd_basic_len, fname_len);
		f->compressed_size = comp_size;
		f->uncompressed_size = uncomp_size;

		if (flags & 0x41u) {
			f->flags |= RSPAMD_ARCHIVE_FILE_ENCRYPTED;
		}

		if (f->fname) {
			g_ptr_array_add (arch->files, f);
			msg_debug_archive ("found file in zip archive: %v", f->fname);
		}
		else {
			g_free (f);

			return;
		}

		/* Process extra fields */
		const guchar *extra = cd + fname_len + cd_basic_len;
		p = extra;

		while (p + sizeof (guint16) * 2 < extra + extra_len) {
			guint16 hid, hlen;

			memcpy (&hid, p, sizeof (guint16));
			hid = GUINT16_FROM_LE (hid);
			memcpy (&hlen, p + sizeof (guint16), sizeof (guint16));
			hlen = GUINT16_FROM_LE (hlen);

			if (hid == 0x0017) {
				f->flags |= RSPAMD_ARCHIVE_FILE_ENCRYPTED;
			}

			p += hlen + sizeof (guint16) * 2;
		}

		cd += fname_len + comment_len + extra_len + cd_basic_len;
	}

	part->part_type = RSPAMD_MIME_PART_ARCHIVE;
	part->specific.arch = arch;

	if (part->cd) {
		arch->archive_name = &part->cd->filename;
	}

	arch->size = part->parsed_data.len;
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
			t |= ((guint64)(*p & 0x7f)) << shift;
		}
		else {
			t |= ((guint64)(*p & 0x7f)) << shift;
			p ++;
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
		msg_debug_archive ("rar archive is invalid (bad skip value)"); \
		return; \
	} \
	if ((gsize)(end - p) < (n)) { \
		msg_debug_archive ("rar archive is invalid (truncated)"); \
		return; \
	} \
	p += (n); \
} while (0)

#define RAR_READ_VINT() do { \
	r = rspamd_archive_rar_read_vint (p, end - p, &vint); \
	if (r == -1) { \
		msg_debug_archive ("rar archive is invalid (bad vint)"); \
		return; \
	} \
	else if (r == 0) { \
		msg_debug_archive ("rar archive is invalid (BAD vint offset)"); \
		return; \
	}\
} while (0)

#define RAR_READ_VINT_SKIP() do { \
	r = rspamd_archive_rar_read_vint (p, end - p, &vint); \
	if (r == -1) { \
		msg_debug_archive ("rar archive is invalid (bad vint)"); \
		return; \
	} \
	p += r; \
} while (0)

#define RAR_READ_UINT16(n) do { \
	if (end - p < (glong)sizeof (guint16)) { \
		msg_debug_archive ("rar archive is invalid (bad int16)"); \
		return; \
	} \
	n = p[0] + (p[1] << 8); \
	p += sizeof (guint16); \
} while (0)

#define RAR_READ_UINT32(n) do { \
	if (end - p < (glong)sizeof (guint32)) { \
		msg_debug_archive ("rar archive is invalid (bad int32)"); \
		return; \
	} \
	n = (guint)p[0] + ((guint)p[1] << 8) + ((guint)p[2] << 16) + ((guint)p[3] << 24); \
	p += sizeof (guint32); \
} while (0)

static void
rspamd_archive_process_rar_v4 (struct rspamd_task *task, const guchar *start,
		const guchar *end, struct rspamd_mime_part *part)
{
	const guchar *p = start, *start_section;
	guint8 type;
	guint flags;
	guint64 sz, comp_sz = 0, uncomp_sz = 0;
	struct rspamd_archive *arch;
	struct rspamd_archive_file *f;

	arch = rspamd_mempool_alloc0 (task->task_pool, sizeof (*arch));
	arch->files = g_ptr_array_new ();
	arch->type = RSPAMD_ARCHIVE_RAR;
	rspamd_mempool_add_destructor (task->task_pool, rspamd_archive_dtor,
			arch);

	while (p < end) {
		/* Crc16 */
		start_section = p;
		RAR_SKIP_BYTES (sizeof (guint16));
		type = *p;
		p ++;
		RAR_READ_UINT16 (flags);

		if (type == 0x73) {
			/* Main header, check for encryption */
			if (flags & 0x80) {
				arch->flags |= RSPAMD_ARCHIVE_ENCRYPTED;
				goto end;
			}
		}

		RAR_READ_UINT16 (sz);

		if (flags & 0x8000) {
			/* We also need to read ADD_SIZE element */
			guint32 tmp;

			RAR_READ_UINT32 (tmp);
			sz += tmp;
			/* This is also used as PACK_SIZE */
			comp_sz = tmp;
		}

		if (sz == 0) {
			/* Zero sized block - error */
			msg_debug_archive ("rar archive is invalid (zero size block)");

			return;
		}

		if (type == 0x74) {
			guint fname_len;

			/* File header */
			/* Uncompressed size */
			RAR_READ_UINT32 (uncomp_sz);
			/* Skip to NAME_SIZE element */
			RAR_SKIP_BYTES (11);
			RAR_READ_UINT16 (fname_len);

			if (fname_len == 0 || fname_len > (gsize)(end - p)) {
				msg_debug_archive ("rar archive is invalid (bad filename size: %d)",
						fname_len);

				return;
			}

			/* Attrs */
			RAR_SKIP_BYTES (4);

			if (flags & 0x100) {
				/* We also need to read HIGH_PACK_SIZE */
				guint32 tmp;

				RAR_READ_UINT32 (tmp);
				sz += tmp;
				comp_sz += tmp;
				/* HIGH_UNP_SIZE  */
				RAR_READ_UINT32 (tmp);
				uncomp_sz += tmp;
			}

			f = g_malloc0 (sizeof (*f));

			if (flags & 0x200) {
				/* We have unicode + normal version */
				guchar *tmp;

				tmp = memchr (p, '\0', fname_len);

				if (tmp != NULL) {
					/* Just use ASCII version */
					f->fname = rspamd_archive_file_try_utf (task, p, tmp - p);
					msg_debug_archive ("found ascii filename in rarv4 archive: %v",
							f->fname);
				}
				else {
					/* We have UTF8 filename, use it as is */
					f->fname = rspamd_archive_file_try_utf (task, p, fname_len);
					msg_debug_archive ("found utf filename in rarv4 archive: %v",
							f->fname);
				}
			}
			else {
				f->fname = rspamd_archive_file_try_utf (task, p, fname_len);
				msg_debug_archive ("found ascii (old) filename in rarv4 archive: %v",
						f->fname);
			}

			f->compressed_size = comp_sz;
			f->uncompressed_size = uncomp_sz;

			if (flags & 0x4) {
				f->flags |= RSPAMD_ARCHIVE_FILE_ENCRYPTED;
			}

			if (f->fname) {
				g_ptr_array_add (arch->files, f);
			}
			else {
				g_free (f);
			}
		}

		p = start_section;
		RAR_SKIP_BYTES (sz);
	}

end:
	part->part_type = RSPAMD_MIME_PART_ARCHIVE;
	part->specific.arch = arch;
	arch->archive_name = &part->cd->filename;
	arch->size = part->parsed_data.len;
}

static void
rspamd_archive_process_rar (struct rspamd_task *task,
		struct rspamd_mime_part *part)
{
	const guchar *p, *end, *section_start;
	const guchar rar_v5_magic[] = {0x52, 0x61, 0x72, 0x21, 0x1A, 0x07, 0x01, 0x00},
			rar_v4_magic[] = {0x52, 0x61, 0x72, 0x21, 0x1A, 0x07, 0x00};
	const guint rar_encrypted_header = 4, rar_main_header = 1,
			rar_file_header = 2;
	guint64 vint, sz, comp_sz = 0, uncomp_sz = 0, flags = 0, type = 0,
			extra_sz = 0;
	struct rspamd_archive *arch;
	struct rspamd_archive_file *f;
	gint r;

	p = part->parsed_data.begin;
	end = p + part->parsed_data.len;

	if ((gsize)(end - p) <= sizeof (rar_v5_magic)) {
		msg_debug_archive ("rar archive is invalid (too small)");

		return;
	}

	if (memcmp (p, rar_v5_magic, sizeof (rar_v5_magic)) == 0) {
		p += sizeof (rar_v5_magic);
	}
	else if (memcmp (p, rar_v4_magic, sizeof (rar_v4_magic)) == 0) {
		p += sizeof (rar_v4_magic);

		rspamd_archive_process_rar_v4 (task, p, end, part);
		return;
	}
	else {
		msg_debug_archive ("rar archive is invalid (no rar magic)");

		return;
	}

	/* Rar v5 format */
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
	/* Type */
	section_start = p;
	RAR_READ_VINT_SKIP ();
	type = vint;
	/* Header flags */
	RAR_READ_VINT_SKIP ();
	flags = vint;

	if (flags & 0x1) {
		/* Have extra zone */
		RAR_READ_VINT_SKIP ();
	}
	if (flags & 0x2) {
		/* Data zone is presented */
		RAR_READ_VINT_SKIP ();
		sz += vint;
	}

	if (type == rar_encrypted_header) {
		/* We can't read any further information as archive is encrypted */
		arch->flags |= RSPAMD_ARCHIVE_ENCRYPTED;
		goto end;
	}
	else if (type != rar_main_header) {
		msg_debug_archive ("rar archive is invalid (bad main header)");

		return;
	}

	/* Nothing useful in main header */
	p = section_start;
	RAR_SKIP_BYTES (sz);

	while (p < end) {
		gboolean has_extra = FALSE;
		/* Read the next header */
		/* Crc 32 */
		RAR_SKIP_BYTES (sizeof (guint32));
		/* Size */
		RAR_READ_VINT_SKIP ();

		sz = vint;
		if (sz == 0) {
			/* Zero sized block - error */
			msg_debug_archive ("rar archive is invalid (zero size block)");

			return;
		}

		section_start = p;
		/* Type */
		RAR_READ_VINT_SKIP ();
		type = vint;
		/* Header flags */
		RAR_READ_VINT_SKIP ();
		flags = vint;

		if (flags & 0x1) {
			/* Have extra zone */
			RAR_READ_VINT_SKIP ();
			extra_sz = vint;
			has_extra = TRUE;
		}

		if (flags & 0x2) {
			/* Data zone is presented */
			RAR_READ_VINT_SKIP ();
			sz += vint;
			comp_sz = vint;
		}

		if (type != rar_file_header) {
			p = section_start;
			RAR_SKIP_BYTES (sz);
		}
		else {
			/* We have a file header, go forward */
			guint64 fname_len;

			/* File header specific flags */
			RAR_READ_VINT_SKIP ();
			flags = vint;

			/* Unpacked size */
			RAR_READ_VINT_SKIP ();
			uncomp_sz = vint;
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
				msg_debug_archive ("rar archive is invalid (bad filename size)");

				return;
			}

			f = g_malloc0 (sizeof (*f));
			f->uncompressed_size = uncomp_sz;
			f->compressed_size = comp_sz;
			f->fname = rspamd_archive_file_try_utf (task, p, fname_len);

			if (f->fname) {
				msg_debug_archive ("added rarv5 file: %v", f->fname);
				g_ptr_array_add (arch->files, f);
			}
			else {
				g_free (f);
				f = NULL;
			}

			if (f && has_extra && extra_sz > 0 &&
				p + fname_len + extra_sz < end) {
				/* Try to find encryption record in extra field */
				const guchar *ex = p + fname_len;

				while (ex < p + extra_sz) {
					const guchar *t;
					gint64 cur_sz = 0, sec_type = 0;

					r = rspamd_archive_rar_read_vint (ex, extra_sz, &cur_sz);
					if (r == -1) {
						msg_debug_archive ("rar archive is invalid (bad vint)");
						return;
					}

					t = ex + r;

					r = rspamd_archive_rar_read_vint (t, extra_sz - r, &sec_type);
					if (r == -1) {
						msg_debug_archive ("rar archive is invalid (bad vint)");
						return;
					}

					if (sec_type == 0x01) {
						f->flags |= RSPAMD_ARCHIVE_FILE_ENCRYPTED;
						arch->flags |= RSPAMD_ARCHIVE_ENCRYPTED;
						break;
					}

					ex += cur_sz;
				}
			}

			/* Restore p to the beginning of the header */
			p = section_start;
			RAR_SKIP_BYTES (sz);
		}
	}

end:
	part->part_type = RSPAMD_MIME_PART_ARCHIVE;
	part->specific.arch = arch;
	if (part->cd != NULL) {
		arch->archive_name = &part->cd->filename;
	}
	arch->size = part->parsed_data.len;
}

static inline gint
rspamd_archive_7zip_read_vint (const guchar *start, gsize remain, guint64 *res)
{
	/*
	 * REAL_UINT64 means real UINT64.
	 * UINT64 means real UINT64 encoded with the following scheme:
	 *
	 * Size of encoding sequence depends from first byte:
	 * First_Byte  Extra_Bytes        Value
	 * (binary)
	 * 0xxxxxxx               : ( xxxxxxx           )
	 * 10xxxxxx    BYTE y[1]  : (  xxxxxx << (8 * 1)) + y
	 * 110xxxxx    BYTE y[2]  : (   xxxxx << (8 * 2)) + y
	 * ...
	 * 1111110x    BYTE y[6]  : (       x << (8 * 6)) + y
	 * 11111110    BYTE y[7]  :                         y
	 * 11111111    BYTE y[8]  :                         y
	 */
	guchar t;

	if (remain == 0) {
		return -1;
	}

	t = *start;

	if (!isset (&t, 7)) {
		/* Trivial case */
		*res = t;
		return 1;
	}
	else if (t == 0xFF) {
		if (remain >= sizeof (guint64) + 1) {
			memcpy (res, start + 1, sizeof (guint64));
			*res = GUINT64_FROM_LE (*res);

			return sizeof (guint64) + 1;
		}
	}
	else {
		gint cur_bit = 6, intlen = 1;
		const guchar bmask = 0xFF;
		guint64 tgt;

		while (cur_bit > 0) {
			if (!isset (&t, cur_bit)) {
				if (remain >= intlen + 1) {
					memcpy (&tgt, start + 1, intlen);
					tgt = GUINT64_FROM_LE (tgt);
					/* Shift back */
					tgt >>= sizeof (tgt) - NBBY * intlen;
					/* Add masked value */
					tgt += (guint64)(t & (bmask >> (NBBY - cur_bit)))
							<< (NBBY * intlen);
					*res = tgt;

					return intlen + 1;
				}
			}
			cur_bit --;
			intlen ++;
		}
	}

	return -1;
}

#define SZ_READ_VINT_SKIP() do { \
	r = rspamd_archive_7zip_read_vint (p, end - p, &vint); \
	if (r == -1) { \
		msg_debug_archive ("7z archive is invalid (bad vint)"); \
		return; \
	} \
	p += r; \
} while (0)
#define SZ_READ_VINT(var) do { \
	int r; \
	r = rspamd_archive_7zip_read_vint (p, end - p, &(var)); \
	if (r == -1) { \
		msg_debug_archive ("7z archive is invalid (bad vint): %s", G_STRLOC); \
		return NULL; \
	} \
	p += r; \
} while (0)

#define SZ_READ_UINT64(n) do { \
	if (end - p < (goffset)sizeof (guint64)) { \
		msg_debug_archive ("7zip archive is invalid (bad uint64): %s", G_STRLOC); \
		return; \
	} \
	memcpy (&(n), p, sizeof (guint64)); \
	n = GUINT64_FROM_LE(n); \
	p += sizeof (guint64); \
} while (0)
#define SZ_SKIP_BYTES(n) do { \
	if (end - p >= (n)) { \
		p += (n); \
	} \
	else { \
		msg_debug_archive ("7zip archive is invalid (truncated); wanted to read %d bytes, %d avail: %s", (gint)(n), (gint)(end - p), G_STRLOC); \
		return NULL; \
	} \
} while (0)

enum rspamd_7zip_header_mark {
	kEnd = 0x00,
	kHeader = 0x01,
	kArchiveProperties = 0x02,
	kAdditionalStreamsInfo = 0x03,
	kMainStreamsInfo = 0x04,
	kFilesInfo = 0x05,
	kPackInfo = 0x06,
	kUnPackInfo = 0x07,
	kSubStreamsInfo = 0x08,
	kSize = 0x09,
	kCRC = 0x0A,
	kFolder = 0x0B,
	kCodersUnPackSize = 0x0C,
	kNumUnPackStream = 0x0D,
	kEmptyStream = 0x0E,
	kEmptyFile = 0x0F,
	kAnti = 0x10,
	kName = 0x11,
	kCTime = 0x12,
	kATime = 0x13,
	kMTime = 0x14,
	kWinAttributes = 0x15,
	kComment = 0x16,
	kEncodedHeader = 0x17,
	kStartPos = 0x18,
	kDummy = 0x19,
};


#define _7Z_CRYPTO_MAIN_ZIP			0x06F10101 /* Main Zip crypto algo */
#define _7Z_CRYPTO_RAR_29			0x06F10303 /* Rar29 AES-128 + (modified SHA-1) */
#define _7Z_CRYPTO_AES_256_SHA_256	0x06F10701 /* AES-256 + SHA-256 */

#define IS_SZ_ENCRYPTED(codec_id) (((codec_id) == _7Z_CRYPTO_MAIN_ZIP) || \
	((codec_id) == _7Z_CRYPTO_RAR_29) || \
	((codec_id) == _7Z_CRYPTO_AES_256_SHA_256))

static const guchar *
rspamd_7zip_read_bits (struct rspamd_task *task,
		const guchar *p, const guchar *end,
		struct rspamd_archive *arch, guint nbits,
		guint *pbits_set)
{
	unsigned mask = 0, avail = 0, i;
	gboolean bit_set = 0;

	for (i = 0; i < nbits; i++) {
		if (mask == 0) {
			avail = *p;
			SZ_SKIP_BYTES(1);
			mask = 0x80;
		}

		bit_set = (avail & mask) ? 1 : 0;

		if (bit_set && pbits_set) {
			(*pbits_set) ++;
		}

		mask >>= 1;
	}

	return p;
}

static const guchar *
rspamd_7zip_read_digest (struct rspamd_task *task,
		const guchar *p, const guchar *end,
		struct rspamd_archive *arch,
		guint64 num_streams,
		guint *pdigest_read)
{
	guchar all_defined = *p;
	guint64 i;
	guint num_defined = 0;
	/*
	 * BYTE AllAreDefined
	 *  if (AllAreDefined == 0)
	 *  {
	 *    for(NumStreams)
	 *    BIT Defined
	 *  }
	 *  UINT32 CRCs[NumDefined]
	 */
	SZ_SKIP_BYTES(1);

	if (all_defined) {
		num_defined = num_streams;
	}
	else {
		if (num_streams > 8192) {
			/* Gah */
			return NULL;
		}

		p = rspamd_7zip_read_bits (task, p, end, arch, num_streams, &num_defined);

		if (p == NULL) {
			return NULL;
		}
	}

	for (i = 0; i < num_defined; i ++) {
		SZ_SKIP_BYTES(sizeof(guint32));
	}

	if (pdigest_read) {
		*pdigest_read = num_defined;
	}

	return p;
}

static const guchar *
rspamd_7zip_read_pack_info (struct rspamd_task *task,
		const guchar *p, const guchar *end,
		struct rspamd_archive *arch)
{
	guint64 pack_pos = 0, pack_streams = 0, i, cur_sz;
	guint num_digests = 0;
	guchar t;
	/*
	 *  UINT64 PackPos
	 *  UINT64 NumPackStreams
	 *
	 *  []
	 *  BYTE NID::kSize    (0x09)
	 *  UINT64 PackSizes[NumPackStreams]
	 *  []
	 *
	 *  []
	 *  BYTE NID::kCRC      (0x0A)
	 *  PackStreamDigests[NumPackStreams]
	 *  []
	 *  BYTE NID::kEnd
	 */

	SZ_READ_VINT(pack_pos);
	SZ_READ_VINT(pack_streams);

	while (p != NULL && p < end) {
		t = *p;
		SZ_SKIP_BYTES(1);
		msg_debug_archive ("7zip: read pack info %xc", t);

		switch (t) {
		case kSize:
			/* We need to skip pack_streams VINTS */
			for (i = 0; i < pack_streams; i++) {
				SZ_READ_VINT(cur_sz);
			}
			break;
		case kCRC:
			/* CRCs are more complicated */
			p = rspamd_7zip_read_digest (task, p, end, arch, pack_streams,
					&num_digests);
			break;
		case kEnd:
			goto end;
			break;
		default:
			p = NULL;
			msg_debug_archive ("bad 7zip type: %xc; %s", t, G_STRLOC);
			goto end;
			break;
		}
	}

end:

	return p;
}

static const guchar *
rspamd_7zip_read_folder (struct rspamd_task *task,
		const guchar *p, const guchar *end,
		struct rspamd_archive *arch, guint *pnstreams, guint *ndigests)
{
	guint64 ncoders = 0, i, j, noutstreams = 0, ninstreams = 0;

	SZ_READ_VINT (ncoders);

	for (i = 0; i < ncoders && p != NULL && p < end; i ++) {
		guint64 sz, tmp;
		guchar t;
		/*
		 * BYTE
		 * {
		 *   0:3 CodecIdSize
		 *   4:  Is Complex Coder
		 *   5:  There Are Attributes
		 *   6:  Reserved
		 *   7:  There are more alternative methods. (Not used anymore, must be 0).
		 * }
		 * BYTE CodecId[CodecIdSize]
		 * if (Is Complex Coder)
		 * {
		 *   UINT64 NumInStreams;
		 *   UINT64 NumOutStreams;
		 * }
		 * if (There Are Attributes)
		 * {
		 *   UINT64 PropertiesSize
		 *   BYTE Properties[PropertiesSize]
		 * }
		 */
		t = *p;
		SZ_SKIP_BYTES (1);
		sz = t & 0xF;
		/* Codec ID */
		tmp = 0;
		for (j = 0; j < sz; j++) {
			tmp <<= 8;
			tmp += p[j];
		}

		msg_debug_archive ("7zip: read codec id: %L", tmp);

		if (IS_SZ_ENCRYPTED (tmp)) {
			arch->flags |= RSPAMD_ARCHIVE_ENCRYPTED;
		}

		SZ_SKIP_BYTES (sz);

		if (t & (1u << 4)) {
			/* Complex */
			SZ_READ_VINT (tmp); /* InStreams */
			ninstreams += tmp;
			SZ_READ_VINT (tmp); /* OutStreams */
			noutstreams += tmp;
		}
		else {
			/* XXX: is it correct ? */
			noutstreams ++;
			ninstreams ++;
		}
		if (t & (1u << 5)) {
			/* Attributes ... */
			SZ_READ_VINT (tmp); /* Size of attrs */
			SZ_SKIP_BYTES (tmp);
		}
	}

	if (noutstreams > 1) {
		/* BindPairs, WTF, huh */
		for (i = 0; i < noutstreams - 1; i ++) {
			guint64 tmp;

			SZ_READ_VINT (tmp);
			SZ_READ_VINT (tmp);
		}
	}

	gint64 npacked = (gint64)ninstreams - (gint64)noutstreams + 1;
	msg_debug_archive ("7zip: instreams=%L, outstreams=%L, packed=%L",
			ninstreams, noutstreams, npacked);

	if (npacked > 1) {
		/* Gah... */
		for (i = 0; i < npacked; i ++) {
			guint64 tmp;

			SZ_READ_VINT (tmp);
		}
	}

	*pnstreams = noutstreams;
	(*ndigests) += npacked;

	return p;
}

static const guchar *
rspamd_7zip_read_coders_info (struct rspamd_task *task,
		const guchar *p, const guchar *end,
		struct rspamd_archive *arch,
		guint *pnum_folders, guint *pnum_nodigest)
{
	guint64 num_folders = 0, i, tmp;
	guchar t;
	guint *folder_nstreams = NULL, num_digests = 0, digests_read = 0;

	while (p != NULL && p < end) {
		/*
		 * BYTE NID::kFolder  (0x0B)
		 *  UINT64 NumFolders
		 *  BYTE External
		 *  switch(External)
		 *  {
		 * 	case 0:
		 * 	  Folders[NumFolders]
		 * 	case 1:
		 * 	  UINT64 DataStreamIndex
		 *   }
		 *   BYTE ID::kCodersUnPackSize  (0x0C)
		 *   for(Folders)
		 * 	for(Folder.NumOutStreams)
		 * 	 UINT64 UnPackSize;
		 *   []
		 *   BYTE NID::kCRC   (0x0A)
		 *   UnPackDigests[NumFolders]
		 *   []
		 *   BYTE NID::kEnd
		 */

		t = *p;
		SZ_SKIP_BYTES(1);
		msg_debug_archive ("7zip: read coders info %xc", t);

		switch (t) {
		case kFolder:
			SZ_READ_VINT (num_folders);
			msg_debug_archive ("7zip: nfolders=%L", num_folders);

			if (*p != 0) {
				/* External folders */
				SZ_SKIP_BYTES(1);
				SZ_READ_VINT (tmp);
			}
			else {
				SZ_SKIP_BYTES(1);

				if (num_folders > 8192) {
					/* Gah */
					return NULL;
				}

				if (folder_nstreams) {
					g_free (folder_nstreams);
				}

				folder_nstreams = g_malloc (sizeof (int) * num_folders);

				for (i = 0; i < num_folders && p != NULL && p < end; i++) {
					p = rspamd_7zip_read_folder (task, p, end, arch,
							&folder_nstreams[i], &num_digests);
				}
			}
			break;
		case kCodersUnPackSize:
			for (i = 0; i < num_folders && p != NULL && p < end; i++) {
				if (folder_nstreams) {
					for (guint j = 0; j < folder_nstreams[i]; j++) {
						SZ_READ_VINT (tmp); /* Unpacked size */
						msg_debug_archive ("7zip: unpacked size "
										   "(folder=%d, stream=%d) = %L",
								(gint)i, j, tmp);
					}
				}
				else {
					msg_err_task ("internal 7zip error");
				}
			}
			break;
		case kCRC:
			/*
			 * Here are dragons. Spec tells that here there could be up
			 * to nfolders digests. However, according to the actual source
			 * code, in case of multiple out streams there should be digests
			 * for all out streams.
			 *
			 * In the real life (tm) it is even more idiotic: all these digests
			 * are in another section! But that section needs number of digests
			 * that are absent here. It is the most stupid thing I've ever seen
			 * in any file format.
			 *
			 * I hope there *WAS* some reason to do such shit...
			 */
			p = rspamd_7zip_read_digest (task, p, end, arch, num_digests,
					&digests_read);
			break;
		case kEnd:
			goto end;
			break;
		default:
			p = NULL;
			msg_debug_archive ("bad 7zip type: %xc; %s", t, G_STRLOC);
			goto end;
			break;
		}
	}

end:

	if (pnum_nodigest) {
		*pnum_nodigest = num_digests - digests_read;
	}
	if (pnum_folders) {
		*pnum_folders = num_folders;
	}

	if (folder_nstreams) {
		g_free (folder_nstreams);
	}

	return p;
}

static const guchar *
rspamd_7zip_read_substreams_info (struct rspamd_task *task,
		const guchar *p, const guchar *end,
		struct rspamd_archive *arch,
		guint num_folders, guint num_nodigest)
{
	guchar t;
	guint i;
	guint64 *folder_nstreams;

	if (num_folders > 8192) {
		/* Gah */
		return NULL;
	}

	folder_nstreams = g_alloca (sizeof (guint64) * num_folders);
	memset (folder_nstreams, 0, sizeof (guint64) * num_folders);

	while (p != NULL && p < end) {
		/*
		 * []
		 *  BYTE NID::kNumUnPackStream; (0x0D)
		 *  UINT64 NumUnPackStreamsInFolders[NumFolders];
		 *  []
		 *
		 *  []
		 *  BYTE NID::kSize  (0x09)
		 *  UINT64 UnPackSizes[??]
		 *  []
		 *
		 *
		 *  []
		 *  BYTE NID::kCRC  (0x0A)
		 *  Digests[Number of streams with unknown CRC]
		 *  []

		 */
		t = *p;
		SZ_SKIP_BYTES(1);

		msg_debug_archive ("7zip: read substream info %xc", t);

		switch (t) {
		case kNumUnPackStream:
			for (i = 0; i < num_folders; i ++) {
				guint64 tmp;

				SZ_READ_VINT (tmp);
				folder_nstreams[i] = tmp;
			}
			break;
		case kCRC:
			/*
			 * Read the comment in the rspamd_7zip_read_coders_info
			 */
			p = rspamd_7zip_read_digest (task, p, end, arch, num_nodigest,
					NULL);
			break;
		case kSize:
			/*
			 * Another brain damaged logic, but we have to support it
			 * as there are no ways to proceed without it.
			 * In fact, it is just absent in the real life...
			 */
			for (i = 0; i < num_folders; i ++) {
				for (guint j = 0; j < folder_nstreams[i]; j++) {
					guint64 tmp;

					SZ_READ_VINT (tmp); /* Who cares indeed */
				}
			}
			break;
		case kEnd:
			goto end;
			break;
		default:
			p = NULL;
			msg_debug_archive ("bad 7zip type: %xc; %s", t, G_STRLOC);
			goto end;
			break;
		}
	}

end:
	return p;
}

static const guchar *
rspamd_7zip_read_main_streams_info (struct rspamd_task *task,
		const guchar *p, const guchar *end,
		struct rspamd_archive *arch)
{
	guchar t;
	guint num_folders = 0, unknown_digests = 0;

	while (p != NULL && p < end) {
		t = *p;
		SZ_SKIP_BYTES(1);
		msg_debug_archive ("7zip: read main streams info %xc", t);

		/*
		 *
		 *  []
		 *  PackInfo
		 *  []

		 *  []
		 *  CodersInfo
		 *  []
		 *
		 *  []
		 *  SubStreamsInfo
		 *  []
		 *
		 *  BYTE NID::kEnd
		 */
		switch (t) {
		case kPackInfo:
			p = rspamd_7zip_read_pack_info (task, p, end, arch);
			break;
		case kUnPackInfo:
			p = rspamd_7zip_read_coders_info (task, p, end, arch, &num_folders,
					&unknown_digests);
			break;
		case kSubStreamsInfo:
			p = rspamd_7zip_read_substreams_info (task, p, end, arch, num_folders,
					unknown_digests);
			break;
			break;
		case kEnd:
			goto end;
			break;
		default:
			p = NULL;
			msg_debug_archive ("bad 7zip type: %xc; %s", t, G_STRLOC);
			goto end;
			break;
		}
	}

end:
	return p;
}

static const guchar *
rspamd_7zip_read_archive_props (struct rspamd_task *task,
		const guchar *p, const guchar *end,
		struct rspamd_archive *arch)
{
	guchar proptype;
	guint64 proplen;

	/*
	 * for (;;)
	 * {
	 *   BYTE PropertyType;
	 *   if (aType == 0)
	 *     break;
	 *   UINT64 PropertySize;
	 *   BYTE PropertyData[PropertySize];
	 * }
	 */

	if (p != NULL) {
		proptype = *p;
		SZ_SKIP_BYTES(1);

		while (proptype != 0) {
			SZ_READ_VINT(proplen);

			if (p + proplen < end) {
				p += proplen;
			}
			else {
				return NULL;
			}

			proptype = *p;
			SZ_SKIP_BYTES(1);
		}
	}

	return p;
}

static GString *
rspamd_7zip_ucs2_to_utf8 (struct rspamd_task *task, const guchar *p,
		const guchar *end)
{
	GString *res;
	goffset dest_pos = 0, src_pos = 0;
	const gsize len = (end - p) / sizeof (guint16);
	guint16 *up;
	UChar32 wc;
	UBool is_error = 0;

	res = g_string_sized_new ((end - p) * 3 / 2 + sizeof (wc) + 1);
	up = (guint16 *)p;

	while (src_pos < len) {
		U16_NEXT (up, src_pos, len, wc);

		if (wc > 0) {
			U8_APPEND (res->str, dest_pos,
					res->allocated_len - 1,
					wc, is_error);
		}

		if (is_error) {
			g_string_free (res, TRUE);

			return NULL;
		}
	}

	g_assert (dest_pos < res->allocated_len);

	res->len = dest_pos;
	res->str[dest_pos] = '\0';

	return res;
}

static const guchar *
rspamd_7zip_read_files_info (struct rspamd_task *task,
		const guchar *p, const guchar *end,
		struct rspamd_archive *arch)
{
	guint64 nfiles = 0, sz, i;
	guchar t, b;
	struct rspamd_archive_file *fentry;

	SZ_READ_VINT (nfiles);

	for (;p != NULL && p < end;) {
		t = *p;
		SZ_SKIP_BYTES (1);

		msg_debug_archive ("7zip: read file data type %xc", t);

		if (t == kEnd) {
			goto end;
		}

		/* This is SO SPECIAL, gah */
		SZ_READ_VINT (sz);

		switch (t) {
		case kEmptyStream:
		case kEmptyFile:
		case kAnti: /* AntiFile, OMFG */
			/* We don't care about these bits */
		case kCTime:
		case kATime:
		case kMTime:
			/* We don't care of these guys, but we still have to parse them, gah */
			if (sz > 0) {
				SZ_SKIP_BYTES (sz);
			}
			break;
		case kName:
			/* The most useful part in this whole bloody format */
			b = *p; /* External flag */
			SZ_SKIP_BYTES (1);

			if (b) {
				/* TODO: for the god sake, do something about external
				 * filenames...
				 */
				guint64 tmp;

				SZ_READ_VINT (tmp);
			}
			else {
				for (i = 0; i < nfiles; i ++) {
					/* Zero terminated wchar_t: happy converting... */
					/* First, find terminator */
					const guchar *fend = NULL, *tp = p;
					GString *res;

					while (tp < end - 1) {
						if (*tp == 0 && *(tp + 1) == 0) {
							fend = tp;
							break;
						}

						tp += 2;
					}

					if (fend == NULL || fend - p == 0) {
						/* Crap instead of fname */
						msg_debug_archive ("bad 7zip name; %s", G_STRLOC);
						goto end;
					}

					res = rspamd_7zip_ucs2_to_utf8 (task, p, fend);

					if (res != NULL) {
						fentry = g_malloc0 (sizeof (*fentry));
						fentry->fname = res;
						g_ptr_array_add (arch->files, fentry);
						msg_debug_archive ("7zip: found file %v", res);
					}
					else {
						msg_debug_archive ("bad 7zip name; %s", G_STRLOC);
					}
					/* Skip zero terminating character */
					p = fend + 2;
				}
			}
			break;
		case kDummy:
		case kWinAttributes:
			if (sz > 0) {
				SZ_SKIP_BYTES (sz);
			}
			break;
		default:
			p = NULL;
			msg_debug_archive ("bad 7zip type: %xc; %s", t, G_STRLOC);
			goto end;
			break;
		}
	}

end:
	return p;
}

static const guchar *
rspamd_7zip_read_next_section (struct rspamd_task *task,
		const guchar *p, const guchar *end,
		struct rspamd_archive *arch)
{
	guchar t = *p;

	SZ_SKIP_BYTES(1);

	msg_debug_archive ("7zip: read section %xc", t);

	switch (t) {
	case kHeader:
		/* We just skip byte and go further */
		break;
	case kEncodedHeader:
		/*
		 * In fact, headers are just packed, but we assume it as
		 * encrypted to distinguish from the normal archives
		 */
		msg_debug_archive ("7zip: encoded header, needs to be uncompressed");
		arch->flags |= RSPAMD_ARCHIVE_CANNOT_READ;
		p = NULL; /* Cannot get anything useful */
		break;
	case kArchiveProperties:
		p = rspamd_7zip_read_archive_props (task, p, end, arch);
		break;
	case kMainStreamsInfo:
		p = rspamd_7zip_read_main_streams_info (task, p, end, arch);
		break;
	case kAdditionalStreamsInfo:
		p = rspamd_7zip_read_main_streams_info (task, p, end, arch);
		break;
	case kFilesInfo:
		p = rspamd_7zip_read_files_info (task, p, end, arch);
		break;
	case kEnd:
		p = NULL;
		msg_debug_archive ("7zip: read final section");
		break;
	default:
		p = NULL;
		msg_debug_archive ("bad 7zip type: %xc; %s", t, G_STRLOC);
		break;
	}

	return p;
}

static void
rspamd_archive_process_7zip (struct rspamd_task *task,
		struct rspamd_mime_part *part)
{
	struct rspamd_archive *arch;
	const guchar *start, *p, *end;
	const guchar sz_magic[] = {'7', 'z', 0xBC, 0xAF, 0x27, 0x1C};
	guint64 section_offset = 0, section_length = 0;

	start = part->parsed_data.begin;
	p = start;
	end = p + part->parsed_data.len;

	if (end - p <= sizeof (guint64) + sizeof (guint32) ||
			memcmp (p, sz_magic, sizeof (sz_magic)) != 0) {
		msg_debug_archive ("7z archive is invalid (no 7z magic)");

		return;
	}

	arch = rspamd_mempool_alloc0 (task->task_pool, sizeof (*arch));
	arch->files = g_ptr_array_new ();
	arch->type = RSPAMD_ARCHIVE_7ZIP;
	rspamd_mempool_add_destructor (task->task_pool, rspamd_archive_dtor,
			arch);

	/* Magic (6 bytes) + version (2 bytes) + crc32 (4 bytes) */
	p += sizeof (guint64) + sizeof (guint32);

	SZ_READ_UINT64(section_offset);
	SZ_READ_UINT64(section_length);

	if (end - p > sizeof (guint32)) {
		p += sizeof (guint32);
	}
	else {
		msg_debug_archive ("7z archive is invalid (truncated crc)");

		return;
	}

	if (end - p > section_offset) {
		p += section_offset;
	}
	else {
		msg_debug_archive ("7z archive is invalid (incorrect section offset)");

		return;
	}

	while ((p = rspamd_7zip_read_next_section (task, p, end, arch)) != NULL);

	part->part_type = RSPAMD_MIME_PART_ARCHIVE;
	part->specific.arch = arch;
	if (part->cd != NULL) {
		arch->archive_name = &part->cd->filename;
	}
	arch->size = part->parsed_data.len;
}

static void
rspamd_archive_process_gzip (struct rspamd_task *task,
							 struct rspamd_mime_part *part) {
	struct rspamd_archive *arch;
	const guchar *start, *p, *end;
	const guchar gz_magic[] = {0x1F, 0x8B};
	guchar flags;

	start = part->parsed_data.begin;
	p = start;
	end = p + part->parsed_data.len;

	if (end - p <= 10 || memcmp (p, gz_magic, sizeof (gz_magic)) != 0) {
		msg_debug_archive ("gzip archive is invalid (no gzip magic)");

		return;
	}

	arch = rspamd_mempool_alloc0 (task->task_pool, sizeof (*arch));
	arch->files = g_ptr_array_sized_new (1);
	arch->type = RSPAMD_ARCHIVE_GZIP;
	rspamd_mempool_add_destructor (task->task_pool, rspamd_archive_dtor,
			arch);

	flags = p[3];

	if (flags & (1u << 5)) {
		arch->flags |= RSPAMD_ARCHIVE_ENCRYPTED;
	}

	if (flags & (1u << 3)) {
		/* We have file name presented in archive, try to use it */
		if (flags & (1u << 1)) {
			/* Multipart */
			p += 12;
		}
		else {
			p += 10;
		}

		if (flags & (1u << 2)) {
			/* Optional section */
			guint16 optlen = 0;

			RAR_READ_UINT16 (optlen);

			if (end <= p + optlen) {
				msg_debug_archive ("gzip archive is invalid, bad extra length: %d",
						(int)optlen);

				return;
			}

			p += optlen;
		}

		/* Read file name */
		const guchar *fname_start = p;

		while (p < end) {
			if (*p == '\0') {
				if (p > fname_start) {
					struct rspamd_archive_file *f;

					f = g_malloc0 (sizeof (*f));
					f->fname = rspamd_archive_file_try_utf (task, fname_start,
							p - fname_start);

					if (f->fname) {
						g_ptr_array_add (arch->files, f);
					}
					else {
						/* Invalid filename, skip */
						g_free (f);
					}

					goto set;
				}
			}

			p ++;
		}

		/* Wrong filename, not zero terminated */
		msg_debug_archive ("gzip archive is invalid, bad filename at pos %d",
				(int)(p - start));

		return;
	}

	/* Fallback, we need to extract file name from archive name if possible */
	if (part->cd && part->cd->filename.len > 0) {
		const gchar *dot_pos, *slash_pos;

		dot_pos = rspamd_memrchr (part->cd->filename.begin, '.',
				part->cd->filename.len);

		if (dot_pos) {
			struct rspamd_archive_file *f;

			slash_pos = rspamd_memrchr (part->cd->filename.begin, '/',
					part->cd->filename.len);

			if (slash_pos && slash_pos < dot_pos) {
				f = g_malloc0 (sizeof (*f));
				f->fname = g_string_sized_new (dot_pos - slash_pos);
				g_string_append_len (f->fname, slash_pos + 1,
						dot_pos - slash_pos - 1);

				msg_debug_archive ("fallback to gzip filename based on cd: %v",
						f->fname);

				g_ptr_array_add (arch->files, f);

				goto set;
			}
			else {
				const gchar *fname_start = part->cd->filename.begin;

				f = g_malloc0 (sizeof (*f));

				if (memchr (fname_start, '.', part->cd->filename.len) != dot_pos) {
					/* Double dots, something like foo.exe.gz */
					f->fname = g_string_sized_new (dot_pos - fname_start);
					g_string_append_len (f->fname, fname_start,
							dot_pos - fname_start);
				}
				else {
					/* Single dot, something like foo.gzz */
					f->fname = g_string_sized_new (part->cd->filename.len);
					g_string_append_len (f->fname, fname_start,
							part->cd->filename.len);
				}

				msg_debug_archive ("fallback to gzip filename based on cd: %v",
						f->fname);

				g_ptr_array_add (arch->files, f);

				goto set;
			}
		}
	}

	return;

set:
	/* Set archive data */
	part->part_type = RSPAMD_MIME_PART_ARCHIVE;
	part->specific.arch = arch;

	if (part->cd) {
		arch->archive_name = &part->cd->filename;
	}

	arch->size = part->parsed_data.len;
}

static gboolean
rspamd_archive_cheat_detect (struct rspamd_mime_part *part, const gchar *str,
		const guchar *magic_start, gsize magic_len)
{
	struct rspamd_content_type *ct;
	const gchar *p;
	rspamd_ftok_t srch, *fname;

	ct = part->ct;
	RSPAMD_FTOK_ASSIGN (&srch, "application");

	if (ct && ct->type.len && ct->subtype.len > 0 && rspamd_ftok_cmp (&ct->type,
			&srch) == 0) {
		if (rspamd_substring_search_caseless (ct->subtype.begin, ct->subtype.len,
				str, strlen (str)) != -1) {
			/* We still need to check magic, see #1848 */
			if (magic_start != NULL) {
				if (part->parsed_data.len > magic_len &&
						memcmp (part->parsed_data.begin,
								magic_start, magic_len) == 0) {
					return TRUE;
				}
				/* No magic, refuse this type of archive */
				return FALSE;
			}
			else {
				return TRUE;
			}
		}
	}

	if (part->cd) {
		fname = &part->cd->filename;

		if (fname && fname->len > strlen (str)) {
			p = fname->begin + fname->len - strlen (str);

			if (rspamd_lc_cmp (p, str, strlen (str)) == 0) {
				if (*(p - 1) == '.') {
					if (magic_start != NULL) {
						if (part->parsed_data.len > magic_len &&
								memcmp (part->parsed_data.begin,
										magic_start, magic_len) == 0) {
							return TRUE;
						}
						/* No magic, refuse this type of archive */
						return FALSE;
					}

					return TRUE;
				}
			}
		}

		if (magic_start != NULL) {
			if (part->parsed_data.len > magic_len &&
				memcmp (part->parsed_data.begin, magic_start, magic_len) == 0) {
				return TRUE;
			}
		}
	}
	else {
		if (magic_start != NULL) {
			if (part->parsed_data.len > magic_len &&
				memcmp (part->parsed_data.begin, magic_start, magic_len) == 0) {
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
	const guchar rar_magic[] = {0x52, 0x61, 0x72, 0x21, 0x1A, 0x07};
	const guchar zip_magic[] = {0x50, 0x4b, 0x03, 0x04};
	const guchar sz_magic[] = {'7', 'z', 0xBC, 0xAF, 0x27, 0x1C};
	const guchar gz_magic[] = {0x1F, 0x8B, 0x08};

	PTR_ARRAY_FOREACH (MESSAGE_FIELD (task, parts), i, part) {
		if (part->part_type == RSPAMD_MIME_PART_UNDEFINED) {
			if (part->parsed_data.len > 0) {
				if (rspamd_archive_cheat_detect (part, "zip",
						zip_magic, sizeof (zip_magic))) {
					rspamd_archive_process_zip (task, part);
				}
				else if (rspamd_archive_cheat_detect (part, "rar",
						rar_magic, sizeof (rar_magic))) {
					rspamd_archive_process_rar (task, part);
				}
				else if (rspamd_archive_cheat_detect (part, "7z",
						sz_magic, sizeof (sz_magic))) {
					rspamd_archive_process_7zip (task, part);
				}
				else if (rspamd_archive_cheat_detect (part, "gz",
						gz_magic, sizeof (gz_magic))) {
					rspamd_archive_process_gzip (task, part);
				}

				if (part->ct && (part->ct->flags & RSPAMD_CONTENT_TYPE_TEXT) &&
						part->part_type == RSPAMD_MIME_PART_ARCHIVE &&
						part->specific.arch) {
					struct rspamd_archive *arch = part->specific.arch;

					msg_info_task ("found %s archive with incorrect content-type: %T/%T",
							rspamd_archive_type_str (arch->type),
							&part->ct->type, &part->ct->subtype);

					if (!(part->ct->flags & RSPAMD_CONTENT_TYPE_MISSING)) {
						part->ct->flags |= RSPAMD_CONTENT_TYPE_BROKEN;
					}
				}
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
	case RSPAMD_ARCHIVE_7ZIP:
		ret = "7z";
		break;
	case RSPAMD_ARCHIVE_GZIP:
		ret = "gz";
		break;
	}

	return ret;
}
