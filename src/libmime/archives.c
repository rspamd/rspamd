/*
 * Copyright 2024 Vsevolod Stakhov
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
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
#include "rspamd_simdutf.h"
#include <unicode/uchar.h>
#include <unicode/utf8.h>
#include <unicode/utf16.h>
#include <unicode/ucnv.h>
#include <unicode/unorm2.h>
#include <unicode/ustring.h>

#include <archive.h>
#include <archive_entry.h>
#ifdef HAVE_USELOCALE
#include <locale.h>
#ifdef __APPLE__
#include <xlocale.h>
#endif
#endif
#include <zlib.h>
#include "ottery.h"

#define msg_debug_archive(...) rspamd_conditional_debug_fast(NULL, NULL,                                                 \
															 rspamd_archive_log_id, "archive", task->task_pool->tag.uid, \
															 G_STRFUNC,                                                  \
															 __VA_ARGS__)
#define msg_debug_archive_taskless(...) rspamd_conditional_debug_fast(NULL, NULL,                             \
																	  rspamd_archive_log_id, "archive", NULL, \
																	  G_STRFUNC,                              \
																	  __VA_ARGS__)

INIT_LOG_MODULE(archive)

static const unsigned int max_archive_files = 100000;

static GQuark
rspamd_archives_err_quark(void)
{
	static GQuark q = 0;
	if (G_UNLIKELY(q == 0)) {
		q = g_quark_from_static_string("archives");
	}

	return q;
}

static void
rspamd_archive_file_free(struct rspamd_archive_file *f)
{
	if (f->fname) {
		g_string_free(f->fname, TRUE);
	}

	g_free(f);
}

static void
rspamd_archive_dtor(gpointer p)
{
	struct rspamd_archive *arch = p;
	struct rspamd_archive_file *f;
	unsigned int i;

	for (i = 0; i < arch->files->len; i++) {
		f = g_ptr_array_index(arch->files, i);
		rspamd_archive_file_free(f);
	}

	g_ptr_array_free(arch->files, TRUE);
}

static gboolean
rspamd_archive_file_limit_check(struct rspamd_task *task,
								struct rspamd_archive *arch)
{
	if (MESSAGE_FIELD(task, narchive_files) >= max_archive_files) {
		arch->flags |= RSPAMD_ARCHIVE_FILES_TRUNCATED;

		if (!MESSAGE_FIELD(task, archive_files_limit_reached)) {
			msg_warn_task("archive file metadata limit of %ud is reached; "
						  "ignoring the remaining entries",
						  max_archive_files);
			MESSAGE_FIELD(task, archive_files_limit_reached) = TRUE;
		}

		return FALSE;
	}

	return TRUE;
}

static gboolean
rspamd_archive_file_add(struct rspamd_task *task,
						struct rspamd_archive *arch,
						struct rspamd_archive_file *f)
{
	if (!rspamd_archive_file_limit_check(task, arch)) {
		rspamd_archive_file_free(f);

		return FALSE;
	}

	MESSAGE_FIELD(task, narchive_files) += 1;
	g_ptr_array_add(arch->files, f);

	return TRUE;
}

static void
rspamd_archive_files_reset(struct rspamd_task *task,
						   struct rspamd_archive *arch)
{
	g_assert(MESSAGE_FIELD(task, narchive_files) >= arch->files->len);
	MESSAGE_FIELD(task, narchive_files) -= arch->files->len;
	rspamd_archive_dtor(arch);
	arch->files = g_ptr_array_new();
	arch->flags &= ~RSPAMD_ARCHIVE_FILES_TRUNCATED;
}

/* Drops the files listed after the first `len` ones */
static void
rspamd_archive_files_truncate(struct rspamd_task *task,
							  struct rspamd_archive *arch,
							  unsigned int len)
{
	while (arch->files->len > len) {
		rspamd_archive_file_free(g_ptr_array_index(arch->files, arch->files->len - 1));
		g_ptr_array_set_size(arch->files, arch->files->len - 1);
		g_assert(MESSAGE_FIELD(task, narchive_files) > 0);
		MESSAGE_FIELD(task, narchive_files) -= 1;
	}
}


static bool
rspamd_archive_file_try_utf(struct rspamd_task *task,
							struct rspamd_archive *arch,
							struct rspamd_archive_file *fentry,
							const char *in, gsize inlen)
{
	const char *charset = NULL, *p, *end;
	GString *res;

	charset = rspamd_mime_charset_find_by_content(in, inlen, TRUE);

	if (charset) {
		UChar *tmp;
		UErrorCode uc_err = U_ZERO_ERROR;
		int32_t r, clen, dlen;
		struct rspamd_charset_converter *conv;
		UConverter *utf8_converter;

		conv = rspamd_mime_get_converter_cached(charset, task->task_pool,
												TRUE, &uc_err);
		utf8_converter = rspamd_get_utf8_converter();

		if (conv == NULL) {
			msg_info_task("cannot open converter for %s: %s",
						  charset, u_errorName(uc_err));
			fentry->flags |= RSPAMD_ARCHIVE_FILE_OBFUSCATED;
			fentry->fname = g_string_new_len(in, inlen);

			return false;
		}

		tmp = g_malloc(sizeof(*tmp) * (inlen + 1));
		r = rspamd_converter_to_uchars(conv, tmp, inlen + 1,
									   in, inlen, &uc_err);
		if (!U_SUCCESS(uc_err)) {
			msg_info_task("cannot convert data to unicode from %s: %s",
						  charset, u_errorName(uc_err));
			g_free(tmp);

			fentry->flags |= RSPAMD_ARCHIVE_FILE_OBFUSCATED;
			fentry->fname = g_string_new_len(in, inlen);

			return false;
		}

		int i = 0;

		while (i < r) {
			UChar32 uc;

			U16_NEXT(tmp, i, r, uc);

			if (IS_ZERO_WIDTH_SPACE(uc) || u_iscntrl(uc)) {
				msg_info_task("control character in archive file name found: 0x%02xd "
							  "(filename=%T)",
							  uc, arch->archive_name);
				fentry->flags |= RSPAMD_ARCHIVE_FILE_OBFUSCATED;
				break;
			}
		}

		clen = ucnv_getMaxCharSize(utf8_converter);
		dlen = UCNV_GET_MAX_BYTES_FOR_STRING(r, clen);
		res = g_string_sized_new(dlen);
		r = ucnv_fromUChars(utf8_converter, res->str, dlen, tmp, r, &uc_err);

		if (!U_SUCCESS(uc_err)) {
			msg_info_task("cannot convert data from unicode from %s: %s",
						  charset, u_errorName(uc_err));
			g_free(tmp);
			g_string_free(res, TRUE);
			fentry->flags |= RSPAMD_ARCHIVE_FILE_OBFUSCATED;
			fentry->fname = g_string_new_len(in, inlen);

			return false;
		}

		g_free(tmp);
		res->len = r;

		msg_debug_archive("converted from %s to UTF-8 inlen: %z, outlen: %d",
						  charset, inlen, r);
		fentry->fname = res;
	}
	else {
		/* Convert unsafe characters to '?' */
		res = g_string_sized_new(inlen);
		p = in;
		end = in + inlen;

		while (p < end) {
			if (g_ascii_isgraph(*p)) {
				g_string_append_c(res, *p);
			}
			else {
				g_string_append_c(res, '?');

				if (*p < 0x7f && (g_ascii_iscntrl(*p) || *p == '\0')) {
					if (!(fentry->flags & RSPAMD_ARCHIVE_FILE_OBFUSCATED)) {
						msg_info_task("suspicious character in archive file name found: 0x%02xd "
									  "(filename=%T)",
									  (int) *p, arch->archive_name);
						fentry->flags |= RSPAMD_ARCHIVE_FILE_OBFUSCATED;
					}
				}
			}

			p++;
		}
		fentry->fname = res;
	}

	return true;
}

/*
 * Another name of a file that readers show, listed after it. FALSE when no
 * more files can be listed
 */
static gboolean
rspamd_archive_file_add_name(struct rspamd_task *task,
							 struct rspamd_archive *arch,
							 const struct rspamd_archive_file *f,
							 const char *name, gsize len)
{
	struct rspamd_archive_file *cf;

	if (len == 0 || f->fname == NULL) {
		return TRUE;
	}

	cf = g_malloc0(sizeof(*cf));
	rspamd_archive_file_try_utf(task, arch, cf, name, len);

	if (cf->fname == NULL || g_string_equal(cf->fname, f->fname)) {
		rspamd_archive_file_free(cf);

		return TRUE;
	}

	cf->compressed_size = f->compressed_size;
	cf->uncompressed_size = f->uncompressed_size;
	cf->flags |= (f->flags & RSPAMD_ARCHIVE_FILE_ENCRYPTED) | RSPAMD_ARCHIVE_FILE_ALIAS |
				 RSPAMD_ARCHIVE_FILE_SAME_ENTRY;

	if (cf->flags & RSPAMD_ARCHIVE_FILE_OBFUSCATED) {
		arch->flags |= RSPAMD_ARCHIVE_HAS_OBFUSCATED_FILES;
	}

	return rspamd_archive_file_add(task, arch, cf);
}

/*
 * Readers that take the name of a file as a C string show it up to its first
 * NUL: that name is listed after the file as another name of it. FALSE when
 * no more files can be listed
 */
static gboolean
rspamd_archive_file_add_cstr_name(struct rspamd_task *task,
								  struct rspamd_archive *arch,
								  const struct rspamd_archive_file *f,
								  const unsigned char *name, gsize len)
{
	const unsigned char *nul = memchr(name, 0, len);

	if (nul == NULL) {
		return TRUE;
	}

	return rspamd_archive_file_add_name(task, arch, f, (const char *) name, nul - name);
}

/*
 * A name as unrar decodes UTF-8, for every rar 5 name and for rar 4 names
 * on macOS: up to the first NUL or the first byte it cannot read, overlong
 * forms (0xC0 0xAE is '.') and surrogates decoded, code points past U+10FFFF
 * dropped. Surrogates are listed as U+FFFD. This name is listed after the
 * file as another name of it. FALSE when no more files can be listed
 */
static gboolean
rspamd_archive_file_add_unrar_utf_name(struct rspamd_task *task,
									   struct rspamd_archive *arch,
									   const struct rspamd_archive_file *f,
									   const unsigned char *name, gsize len)
{
	GString *res;
	gboolean listed, changed = FALSE;
	gsize i = 0;

	res = g_string_sized_new(len);

	while (i < len && name[i] != 0) {
		unsigned int c = name[i], d, n, k;

		if (c < 0x80) {
			d = c;
			n = 1;
		}
		else if ((c >> 5) == 6) {
			d = c & 0x1f;
			n = 2;
		}
		else if ((c >> 4) == 14) {
			d = c & 0x0f;
			n = 3;
		}
		else if ((c >> 3) == 30) {
			d = c & 0x07;
			n = 4;
		}
		else {
			changed = TRUE;
			break;
		}

		for (k = 1; k < n; k++) {
			if (i + k >= len || (name[i + k] & 0xc0) != 0x80) {
				break;
			}

			d = (d << 6) | (name[i + k] & 0x3f);
		}

		if (k < n) {
			/* unrar stops at a sequence cut short */
			changed = TRUE;
			break;
		}

		if (d > 0x10ffff) {
			changed = TRUE;
		}
		else if ((d >= 0xd800 && d <= 0xdfff) || (n > 1 && d < 0x80) ||
				 (n > 2 && d < 0x800) || (n > 3 && d < 0x10000)) {
			/* A surrogate or an overlong form, which UTF-8 does not allow */
			changed = TRUE;

			if (d >= 0xd800 && d <= 0xdfff) {
				d = 0xfffd;
			}
		}

		if (d <= 0x10ffff) {
			char buf[4];
			int blen = 0;

			U8_APPEND_UNSAFE(buf, blen, d);
			g_string_append_len(res, buf, blen);
		}

		i += n;
	}

	/* Only a name that differs from the bytes is listed */
	listed = !changed || rspamd_archive_file_add_name(task, arch, f, res->str, res->len);
	g_string_free(res, TRUE);

	return listed;
}

/* Readers of the Unicode name of a rar 4 file, which stop at different points */
enum rspamd_rar4_unicode_reader {
	RSPAMD_RAR4_UNRAR = 0,
	RSPAMD_RAR4_BSDTAR,
	RSPAMD_RAR4_7ZIP,
	/* unrar copies runs as signed char: bytes from 0x80 on differ */
	RSPAMD_RAR4_UNRAR_WINDOWS, /* U+FF80..U+FFFF in a 16-bit wchar_t */
	RSPAMD_RAR4_UNRAR_MACOS,   /* dropped from the name */
	RSPAMD_RAR4_UNRAR_LINUX,   /* the name stops at them */
	RSPAMD_RAR4_UNICODE_READERS,
};

/*
 * Characters kept of a longer name, from its start and its end (where its
 * extension is): runs over the zeros unrar reads past a header make names of
 * up to 65535 characters of a few bytes
 */
#define RSPAMD_RAR4_NAME_HEAD 768
#define RSPAMD_RAR4_NAME_TAIL 256

/*
 * The UTF-8 of a name in UTF-16 added to `names` unless it is empty or there;
 * `capped` is set when only its start and end are kept
 */
static void
rspamd_archive_rar4_add_unicode(const UChar *s, gsize len, GString **names, unsigned int *nnames,
								gboolean *capped)
{
	UChar kept[RSPAMD_RAR4_NAME_HEAD + 1 + RSPAMD_RAR4_NAME_TAIL];
	UErrorCode err = U_ZERO_ERROR;
	int32_t u8_len;
	GString *res;

	if (len == 0) {
		return;
	}

	if (len > G_N_ELEMENTS(kept)) {
		memcpy(kept, s, RSPAMD_RAR4_NAME_HEAD * sizeof(UChar));
		kept[RSPAMD_RAR4_NAME_HEAD] = 0x2026;
		memcpy(kept + RSPAMD_RAR4_NAME_HEAD + 1, s + len - RSPAMD_RAR4_NAME_TAIL,
			   RSPAMD_RAR4_NAME_TAIL * sizeof(UChar));
		s = kept;
		len = G_N_ELEMENTS(kept);
		*capped = TRUE;
	}

	res = g_string_sized_new(3 * len + 1);
	u_strToUTF8WithSub(res->str, res->allocated_len, &u8_len, s, len, 0xFFFD, NULL, &err);

	if (U_FAILURE(err)) {
		g_string_free(res, TRUE);

		return;
	}

	res->len = u8_len;
	res->str[u8_len] = '\0';

	for (unsigned int i = 0; i < *nnames; i++) {
		if (g_string_equal(names[i], res)) {
			g_string_free(res, TRUE);

			return;
		}
	}

	names[(*nnames)++] = res;
}

/*
 * The Unicode name of a rar 4 file follows the NUL of its name field of `len`
 * bytes, after the name of `ascii_len` bytes; `avail` bytes of the field are
 * in its header, and unrar reads zeros after them. It is encoded against that
 * field: a high byte, then a byte of flags for each four characters, which
 * take a byte, a byte under the high byte, two bytes, or a run of the bytes of
 * the field at the same places (with a correction under the high byte).
 * unrar, bsdtar and 7-Zip decode it alike (EncodeFileName::Decode of unrar 7)
 * and stop at different points (checked with unrar 7.1, bsdtar 3.7, 7-Zip
 * 17.05): unrar goes on to the end of the field; bsdtar and 7-Zip stop at two
 * bytes cut by the end of the field, bsdtar at as many characters as the field
 * has bytes, and 7-Zip one character short of that or of 1024. unrar copies a
 * run without a correction as signed char, so its bytes from 0x80 on are
 * shown otherwise on Windows, macOS and Linux. Each reader shows the name up
 * to its first NUL character, where decoding stops, and unrar and 7-Zip the
 * name before the NUL when nothing follows it. The names they show in UTF-8,
 * distinct, unrar's first; `capped` is set when one is kept in part
 */
static unsigned int
rspamd_archive_rar4_unicode_names(const unsigned char *name, gsize avail, gsize len, gsize ascii_len,
								  GString *names[RSPAMD_RAR4_UNICODE_READERS], gboolean *capped)
{
#define RAR4_NAME_AT(i) ((i) < avail ? name[(i)] : 0)
	gsize enc = ascii_len + 1, dec = 0, size, cut_len = G_MAXSIZE, sevenzip_max = MIN(len, 1024),
		  lens[RSPAMD_RAR4_UNICODE_READERS], nsigned = 0;
	unsigned char high, flags = 0;
	unsigned int bits = 0, nnames = 0, i;
	gboolean nul = FALSE;
	UChar *out, *other;
	unsigned char *as_signed;

	if (enc >= len) {
		return 0;
	}

	size = 2 * MIN(avail, len) + 16;
	out = g_malloc_n(size, sizeof(UChar));
	as_signed = g_malloc(size);
	high = RAR4_NAME_AT(enc);
	enc++;

	/* Each step takes a byte at least, a run at most 129 characters */
	while (enc < len && !nul) {
		unsigned int n = 0, run = 0, step;
		unsigned char correction = 0, run_high = 0;
		gboolean is_run = FALSE, signed_run = FALSE;
		UChar c = 0;

		if (bits == 0) {
			flags = RAR4_NAME_AT(enc);
			enc++;
			bits = 8;
		}

		switch (flags >> 6) {
		case 0:
			if (enc < len) {
				c = RAR4_NAME_AT(enc);
				enc++;
				n = 1;
			}
			break;
		case 1:
			if (enc < len) {
				c = RAR4_NAME_AT(enc) | (high << 8);
				enc++;
				n = 1;
			}
			break;
		case 2:
			if (enc + 1 < len) {
				c = RAR4_NAME_AT(enc) | (RAR4_NAME_AT(enc + 1) << 8);
				enc += 2;
				n = 1;
			}
			else if (cut_len == G_MAXSIZE) {
				/* bsdtar and 7-Zip stop, unrar goes on with the byte left */
				cut_len = dec;
			}
			break;
		default:
			if (enc >= len) {
				break;
			}

			run = RAR4_NAME_AT(enc);
			enc++;

			if (run & 0x80) {
				if (enc >= len) {
					break;
				}

				correction = RAR4_NAME_AT(enc);
				enc++;
				run_high = high;
			}
			else {
				signed_run = TRUE;
			}

			is_run = TRUE;
			n = (run & 0x7f) + 2;
			break;
		}

		if (dec + n > size) {
			size = MAX(size * 2, dec + n);
			out = g_realloc_n(out, size, sizeof(UChar));
			as_signed = g_realloc(as_signed, size);
		}

		for (step = 0; step < n && !nul; step++) {
			if (is_run) {
				unsigned char b;

				if (dec >= len) {
					break;
				}

				b = RAR4_NAME_AT(dec);
				c = ((b + correction) & 0xff) | (run_high << 8);
				as_signed[dec] = signed_run && b >= 0x80;
			}
			else {
				as_signed[dec] = FALSE;
			}

			out[dec++] = c;
			nul = c == 0;
		}

		flags <<= 2;
		bits -= 2;
	}

	lens[RSPAMD_RAR4_UNRAR] = dec;
	lens[RSPAMD_RAR4_BSDTAR] = MIN(MIN(dec, cut_len), len);
	lens[RSPAMD_RAR4_7ZIP] = MIN(MIN(dec, cut_len), sevenzip_max);

	if (lens[RSPAMD_RAR4_7ZIP] == sevenzip_max) {
		/* Its NUL takes the place of the last character */
		lens[RSPAMD_RAR4_7ZIP]--;
	}

	for (i = RSPAMD_RAR4_UNRAR; i <= RSPAMD_RAR4_7ZIP; i++) {
		const UChar *first_nul = u_memchr(out, 0, lens[i]);

		if (first_nul != NULL) {
			lens[i] = first_nul - out;
		}

		rspamd_archive_rar4_add_unicode(out, lens[i], names, &nnames, capped);
	}

	for (gsize k = 0; k < lens[RSPAMD_RAR4_UNRAR]; k++) {
		nsigned += as_signed[k];
	}

	if (nsigned > 0) {
		gsize k, olen;

		other = g_malloc_n(lens[RSPAMD_RAR4_UNRAR], sizeof(UChar));

		for (k = 0; k < lens[RSPAMD_RAR4_UNRAR]; k++) {
			other[k] = as_signed[k] ? (0xFF00 | out[k]) : out[k];
		}

		rspamd_archive_rar4_add_unicode(other, lens[RSPAMD_RAR4_UNRAR], names, &nnames, capped);

		for (k = 0, olen = 0; k < lens[RSPAMD_RAR4_UNRAR]; k++) {
			if (!as_signed[k]) {
				other[olen++] = out[k];
			}
		}

		rspamd_archive_rar4_add_unicode(other, olen, names, &nnames, capped);

		for (k = 0; k < lens[RSPAMD_RAR4_UNRAR] && !as_signed[k]; k++) {
		}

		rspamd_archive_rar4_add_unicode(out, k, names, &nnames, capped);
		g_free(other);
	}

	g_free(out);
	g_free(as_signed);

	return nnames;
#undef RAR4_NAME_AT
}

enum rspamd_zip_eocd_check {
	RSPAMD_ZIP_EOCD_USABLE = 0,
	RSPAMD_ZIP_EOCD_SKIP,
	RSPAMD_ZIP_EOCD_STOP,
};

/* A central directory that an end record describes */
struct rspamd_zip_cd_set {
	uint64_t offset;
	/* Another one, where the record says, or G_MAXUINT64 */
	uint64_t alt_offset;
	uint64_t size;
	/* The size is not known: the directory ends at the first other data */
	gboolean open_end;
	/* The offset the record holds, which counts from the start of its archive */
	uint64_t declared_offset;
	/* The size the record holds */
	uint64_t declared_size;
	/*
	 * Where the archive of the record starts, when its directory is right
	 * before the record (G_MAXUINT64 if not): data in front of it may be
	 * another archive
	 */
	uint64_t front;
};

/*
 * The directory where the record says, or right before the record (`limit`):
 * the offsets of an archive with data in front of it (a self-extracting stub,
 * another archive) count from the start of the archive, and readers such as
 * Python's zipfile or unzip take the directory before the record whatever the
 * offset says. When both are directories and they differ (two archives one
 * after the other), readers do not agree on the files: both are listed then,
 * the one right before the record first
 */
static gboolean
rspamd_archive_zip_cd_set(const unsigned char *start, uint64_t limit,
						  uint64_t cd_offset, uint64_t cd_size,
						  struct rspamd_zip_cd_set *set)
{
	static const unsigned char cd_magic[] = {0x50, 0x4b, 0x01, 0x02};

	if (cd_size > limit) {
		return FALSE;
	}

	gboolean declared = cd_offset <= limit - cd_size &&
						(cd_size < sizeof(cd_magic) ||
						 memcmp(start + cd_offset, cd_magic, sizeof(cd_magic)) == 0);
	gboolean adjacent = cd_size >= sizeof(cd_magic) &&
						memcmp(start + limit - cd_size, cd_magic, sizeof(cd_magic)) == 0;

	set->alt_offset = G_MAXUINT64;
	set->size = cd_size;
	set->open_end = FALSE;
	set->declared_offset = cd_offset;
	set->declared_size = cd_size;
	set->front = G_MAXUINT64;

	if (declared && cd_size < sizeof(cd_magic) && limit - cd_offset >= sizeof(cd_magic) &&
		memcmp(start + cd_offset, cd_magic, sizeof(cd_magic)) == 0) {
		/*
		 * An empty directory, according to the record, where a directory
		 * is (a record appended to an archive): unzip and 7-Zip list it,
		 * up to the record
		 */
		set->offset = cd_offset;
		set->size = limit - cd_offset;
		set->open_end = TRUE;

		return TRUE;
	}

	if ((adjacent || cd_size < sizeof(cd_magic)) && limit - cd_size >= cd_offset) {
		/* An empty directory is right before its record too */
		set->front = limit - cd_size - cd_offset;
	}

	if (adjacent) {
		set->offset = limit - cd_size;

		if (declared && cd_offset != set->offset) {
			set->alt_offset = cd_offset;
		}
	}
	else if (declared) {
		set->offset = cd_offset;
	}
	else {
		return FALSE;
	}

	return TRUE;
}

/*
 * Checks an end of central directory record: the central directory it
 * describes must be within the data before it and start with its magic.
 * With a zip64 locator right before the record, readers (Python, bsdtar)
 * take the values of the zip64 record, whatever the 32-bit fields hold; when
 * these fields are not maxed out, they are the next choice (base readers use
 * them), and when they are, readers do not look any further back either.
 * Without a zip64 record, a maxed offset alone (Info-ZIP `zip -fz` to a pipe)
 * still leaves the directory right before the record, which readers take.
 * Fills up to two sets of directories, in the order to read them.
 */
static enum rspamd_zip_eocd_check
rspamd_archive_zip_check_eocd(const unsigned char *start,
							  const unsigned char *eocd,
							  struct rspamd_zip_cd_set *sets,
							  unsigned int *nsets)
{
	const uint32_t zip64_locator_magic = 0x07064b50, zip64_eocd_magic = 0x06064b50;
	/* Up to the cd size and offset fields, which are the last ones we read */
	const uint64_t zip64_eocd_len = 56, zip64_locator_len = 20;
	uint32_t cd_offset32, cd_size32;
	uint64_t limit = eocd - start, z64_pos = G_MAXUINT64;

	memcpy(&cd_size32, eocd + 12, sizeof(cd_size32));
	cd_size32 = GUINT32_FROM_LE(cd_size32);
	memcpy(&cd_offset32, eocd + 16, sizeof(cd_offset32));
	cd_offset32 = GUINT32_FROM_LE(cd_offset32);

	gboolean maxed = cd_size32 == G_MAXUINT32 || cd_offset32 == G_MAXUINT32;

	/*
	 * The zip64 record is where the locator says, or right before the
	 * locator when the offsets count from an archive with data in front of it
	 */
	if (limit >= zip64_locator_len) {
		const unsigned char *loc = eocd - zip64_locator_len;
		uint64_t loc_off = loc - start, z64_offset;
		uint32_t magic;

		memcpy(&magic, loc, sizeof(magic));

		if (GUINT32_FROM_LE(magic) == zip64_locator_magic) {
			memcpy(&z64_offset, loc + 8, sizeof(z64_offset));
			z64_offset = GUINT64_FROM_LE(z64_offset);

			if (z64_offset <= loc_off && loc_off - z64_offset >= zip64_eocd_len) {
				memcpy(&magic, start + z64_offset, sizeof(magic));

				if (GUINT32_FROM_LE(magic) == zip64_eocd_magic) {
					z64_pos = z64_offset;
				}
			}

			if (z64_pos == G_MAXUINT64 && loc_off >= zip64_eocd_len) {
				memcpy(&magic, loc - zip64_eocd_len, sizeof(magic));

				if (GUINT32_FROM_LE(magic) == zip64_eocd_magic) {
					z64_pos = loc_off - zip64_eocd_len;
				}
			}
		}
	}

	*nsets = 0;

	if (z64_pos != G_MAXUINT64) {
		uint64_t cd_offset, cd_size;

		memcpy(&cd_size, start + z64_pos + 40, sizeof(cd_size));
		cd_size = GUINT64_FROM_LE(cd_size);
		memcpy(&cd_offset, start + z64_pos + 48, sizeof(cd_offset));
		cd_offset = GUINT64_FROM_LE(cd_offset);

		if (rspamd_archive_zip_cd_set(start, z64_pos, cd_offset, cd_size, &sets[*nsets])) {
			(*nsets)++;
		}
	}

	if ((!maxed || (z64_pos == G_MAXUINT64 && cd_size32 != G_MAXUINT32)) &&
		rspamd_archive_zip_cd_set(start, limit, cd_offset32, cd_size32, &sets[*nsets])) {
		if (*nsets == 0 || sets[1].offset != sets[0].offset ||
			sets[1].size != sets[0].size) {
			(*nsets)++;
		}
	}

	if (*nsets == 0) {
		/* Without its zip64 record, readers look no further back either */
		return maxed ? RSPAMD_ZIP_EOCD_STOP : RSPAMD_ZIP_EOCD_SKIP;
	}

	return RSPAMD_ZIP_EOCD_USABLE;
}

/*
 * Where libarchive (bsdtar) shows a name: it compares the CRC of a Unicode
 * Path with that of the name it shows so far only when that name converts to
 * the locale, else it takes the next Unicode Path whatever its CRC. Names in
 * UTF-8 (Unicode Paths, names with the UTF-8 flag) are normalized as they
 * convert, and the CRC is that of the normalized name
 */
enum rspamd_zip_bsdtar_locale {
	RSPAMD_ZIP_BSDTAR_ANY = 0,  /* Names compared as they are stored */
	RSPAMD_ZIP_BSDTAR_UTF8_NFC, /* A UTF-8 locale: valid UTF-8 converts, to NFC */
	RSPAMD_ZIP_BSDTAR_UTF8_NFD, /* The same on macOS, to NFD */
	RSPAMD_ZIP_BSDTAR_ASCII,    /* The C locale: ASCII converts */
	RSPAMD_ZIP_BSDTAR_LOCALES,
};

/* The length of a name up to its first NUL, as readers that take it as a C string do */
static gsize
rspamd_zip_cstr_len(const unsigned char *s, gsize len)
{
	const unsigned char *nul = memchr(s, 0, len);

	return nul ? (gsize) (nul - s) : len;
}

static uint32_t
rspamd_zip_cstr_crc(const unsigned char *s, gsize len)
{
	return crc32(0, (const Bytef *) s, rspamd_zip_cstr_len(s, len));
}

/* Buffers to normalize names, kept over the names of an entry */
struct rspamd_zip_norm_bufs {
	UChar *u16, *norm;
	char *u8;
	int32_t u16_size, norm_size, u8_size;
};

static void
rspamd_zip_norm_bufs_free(struct rspamd_zip_norm_bufs *bufs)
{
	g_free(bufs->u16);
	g_free(bufs->norm);
	g_free(bufs->u8);
}

/*
 * Combining marks in a row past which a name is not normalized, as ICU sorts
 * them in quadratic time (30 is the limit of the stream-safe text format); a
 * character that decomposes to marks counts as one
 */
#define rspamd_zip_norm_max_marks 30

/*
 * The CRC of a name, `u16_len` units of `bufs->u16` from `len` bytes of valid
 * UTF-8 `s`, normalized to NFC or NFD; FALSE if it cannot be normalized.
 * libarchive has normalizers of its own, which compose or decompose pairs by
 * tables of Unicode 6.0 and differ from these on some names (singletons,
 * composition exclusions, order of marks, later marks)
 */
static gboolean
rspamd_zip_normalized_crc(const UNormalizer2 *norm, const char *s, int32_t len,
						  struct rspamd_zip_norm_bufs *bufs, int32_t u16_len, uint32_t *crc)
{
	UErrorCode err = U_ZERO_ERROR;
	int32_t norm_len, u8_len;

	if (unorm2_spanQuickCheckYes(norm, bufs->u16, u16_len, &err) == u16_len && U_SUCCESS(err)) {
		/* Already in that form */
		*crc = crc32(0, (const Bytef *) s, len);

		return TRUE;
	}

	err = U_ZERO_ERROR;
	norm_len = unorm2_normalize(norm, bufs->u16, u16_len, bufs->norm, bufs->norm_size, &err);

	if (err == U_BUFFER_OVERFLOW_ERROR) {
		err = U_ZERO_ERROR;
		bufs->norm_size = norm_len + 1;
		bufs->norm = g_realloc_n(bufs->norm, bufs->norm_size, sizeof(UChar));
		norm_len = unorm2_normalize(norm, bufs->u16, u16_len, bufs->norm, bufs->norm_size, &err);
	}

	if (U_FAILURE(err)) {
		return FALSE;
	}

	u_strToUTF8(bufs->u8, bufs->u8_size, &u8_len, bufs->norm, norm_len, &err);

	if (err == U_BUFFER_OVERFLOW_ERROR || err == U_STRING_NOT_TERMINATED_WARNING) {
		err = U_ZERO_ERROR;
		bufs->u8_size = u8_len + 1;
		bufs->u8 = g_realloc(bufs->u8, bufs->u8_size);
		u_strToUTF8(bufs->u8, bufs->u8_size, &u8_len, bufs->norm, norm_len, &err);
	}

	if (U_FAILURE(err)) {
		return FALSE;
	}

	*crc = crc32(0, (const Bytef *) bufs->u8, u8_len);

	return TRUE;
}

/*
 * What bsdtar shows of a name in UTF-8 in each locale: whether it converts,
 * and the CRC of what it shows (up to a NUL)
 */
struct rspamd_zip_bsdtar_name {
	uint32_t crc;
	gboolean converts;
};

static void
rspamd_zip_bsdtar_utf8_names(const unsigned char *s, gsize len,
							 struct rspamd_zip_norm_bufs *bufs,
							 struct rspamd_zip_bsdtar_name names[RSPAMD_ZIP_BSDTAR_LOCALES])
{
	static const enum rspamd_zip_bsdtar_locale normalized[] = {
		RSPAMD_ZIP_BSDTAR_UTF8_NFC,
		RSPAMD_ZIP_BSDTAR_UTF8_NFD,
	};
	UErrorCode err = U_ZERO_ERROR;
	const UNormalizer2 *norms[G_N_ELEMENTS(normalized)];
	gsize clen = rspamd_zip_cstr_len(s, len);
	uint32_t crc = crc32(0, (const Bytef *) s, clen);
	int32_t u16_len, i, marks = 0, max_marks = 0;
	unsigned int j;

	names[RSPAMD_ZIP_BSDTAR_ANY].crc = crc;
	names[RSPAMD_ZIP_BSDTAR_ANY].converts = TRUE;

	if (!rspamd_str_has_8bit(s, clen)) {
		/* ASCII is the same in all forms and converts to all locales */
		for (j = RSPAMD_ZIP_BSDTAR_ANY + 1; j < RSPAMD_ZIP_BSDTAR_LOCALES; j++) {
			names[j].crc = crc;
			names[j].converts = TRUE;
		}

		return;
	}

	/*
	 * What is not ASCII does not convert to the C locale: libarchive only
	 * composes, which never gives ASCII (NFC of ICU may)
	 */
	for (j = RSPAMD_ZIP_BSDTAR_ANY + 1; j < RSPAMD_ZIP_BSDTAR_LOCALES; j++) {
		names[j].crc = 0;
		names[j].converts = FALSE;
	}

	if (rspamd_fast_utf8_validate(s, clen) != 0) {
		return;
	}

	if (bufs->u16_size < (int32_t) clen + 1) {
		bufs->u16_size = clen + 1;
		bufs->u16 = g_realloc_n(bufs->u16, bufs->u16_size, sizeof(UChar));
	}

	u_strFromUTF8(bufs->u16, bufs->u16_size, &u16_len, (const char *) s, clen, &err);

	if (U_FAILURE(err)) {
		return;
	}

	for (i = 0; i < u16_len;) {
		UChar32 uc;

		U16_NEXT(bufs->u16, i, u16_len, uc);
		/* Marks it decomposes to, at most two, go on with the run (U+0F73 is two) */
		marks = u_getIntPropertyValue(uc, UCHAR_LEAD_CANONICAL_COMBINING_CLASS) != 0 ? marks + 1 : 0;
		max_marks = MAX(max_marks, marks);
	}

	norms[0] = unorm2_getNFCInstance(&err);
	norms[1] = unorm2_getNFDInstance(&err);

	for (j = 0; j < G_N_ELEMENTS(normalized); j++) {
		if (max_marks > rspamd_zip_norm_max_marks || U_FAILURE(err)) {
			/* Taken as it is: libarchive does not sort such marks either */
			names[normalized[j]].crc = crc;
			names[normalized[j]].converts = TRUE;
		}
		else if (rspamd_zip_normalized_crc(norms[j], (const char *) s, clen, bufs, u16_len,
										   &names[normalized[j]].crc)) {
			names[normalized[j]].converts = TRUE;
		}
	}
}

/* Names that readers show of the Unicode Paths of an entry, each in its own way */
#define rspamd_zip_unicode_readers (6 + RSPAMD_ZIP_BSDTAR_LOCALES)
/* Those names and the name, each also up to its first NUL */
#define rspamd_zip_entry_names (2 * (rspamd_zip_unicode_readers + 1))

/*
 * The names readers show in place of the name of an entry from its Info-ZIP
 * Unicode Path fields (0x7075), which hold a version, the CRC of the name they
 * replace, and a name. Readers do not take the same field (checked with 7-Zip
 * 17, Python 3.13, bsdtar 3.7 and the sources of unzip 6.0, yauzl and
 * libarchive):
 * - 7-Zip: the first field, if it has the CRC of the name;
 * - Info-ZIP unzip: the last of the fields from the first one on that have
 *   the CRC of the name (as a C string) and version 1 at most;
 * - Python: the last field with the CRC of the name, version 1 and a name;
 * - yauzl: the first such field;
 * - others may take the first or the last field with the CRC of the name;
 * - bsdtar: each field with the CRC of the name it shows so far (as a C
 *   string) replaces that name, any field when that name does not convert
 *   to the locale; a name with the UTF-8 flag converts from UTF-8, and names
 *   from UTF-8 are normalized (NFD on macOS, NFC elsewhere) before their CRC.
 *   Its decoding of CESU-8 is not done here.
 * Python, unzip and bsdtar show a name up to its first NUL, so the name and
 * each of these names are also there up to it. Each name is in `paths` once,
 * and not when it is the name. The CRC of the name is computed once, and what
 * bsdtar shows of the name and of each field at most once
 */
static unsigned int
rspamd_archive_zip_unicode_paths(const unsigned char *extra, gsize extra_len,
								 const unsigned char *name, gsize name_len, gboolean utf8_name,
								 rspamd_ftok_t paths[rspamd_zip_entry_names])
{
	enum {
		pick_7zip = 0,
		pick_unzip,
		pick_python,
		pick_yauzl,
		pick_first,
		pick_last,
		pick_bsdtar,
	};
	rspamd_ftok_t picks[rspamd_zip_unicode_readers];
	struct rspamd_zip_bsdtar_name shown[RSPAMD_ZIP_BSDTAR_LOCALES];
	struct rspamd_zip_norm_bufs bufs;
	uint32_t name_crc = crc32(0, (const Bytef *) name, name_len),
			 name_cstr_crc = rspamd_zip_cstr_crc(name, name_len);
	gboolean first = TRUE, in_run = TRUE, name_shown = FALSE;
	unsigned int npaths = 0, i, j, k;
	gsize pos = 0;

	memset(picks, 0, sizeof(picks));
	memset(&bufs, 0, sizeof(bufs));

	while (extra_len - pos >= 4) {
		const unsigned char *p = extra + pos;
		uint16_t hid, hlen;
		uint32_t crc;
		unsigned int version;
		gboolean of_name, path_shown = FALSE;
		struct rspamd_zip_bsdtar_name path_names[RSPAMD_ZIP_BSDTAR_LOCALES];
		rspamd_ftok_t path;

		memcpy(&hid, p, sizeof(hid));
		memcpy(&hlen, p + 2, sizeof(hlen));
		hid = GUINT16_FROM_LE(hid);
		hlen = GUINT16_FROM_LE(hlen);

		if (hlen > extra_len - pos - 4) {
			break;
		}

		pos += 4 + hlen;

		if (hid != 0x7075) {
			continue;
		}

		if (hlen < 5) {
			/* No CRC: no reader takes it, and it ends the fields of unzip */
			first = FALSE;
			in_run = FALSE;
			continue;
		}

		version = p[4];
		memcpy(&crc, p + 5, sizeof(crc));
		crc = GUINT32_FROM_LE(crc);
		path.begin = (const char *) p + 9;
		path.len = hlen - 5;
		of_name = crc == name_crc;

		if (first) {
			first = FALSE;

			if (of_name) {
				picks[pick_7zip] = path;
			}
		}

		if (in_run) {
			if (crc == name_cstr_crc && version <= 1) {
				picks[pick_unzip] = path;
			}
			else {
				in_run = FALSE;
			}
		}

		if (of_name && path.len > 0) {
			if (version == 1) {
				picks[pick_python] = path;

				if (picks[pick_yauzl].len == 0) {
					picks[pick_yauzl] = path;
				}
			}

			if (picks[pick_first].len == 0) {
				picks[pick_first] = path;
			}

			picks[pick_last] = path;
		}

		if (!name_shown) {
			/* What bsdtar shows of the name, once a Unicode Path needs it */
			if (utf8_name) {
				rspamd_zip_bsdtar_utf8_names(name, name_len, &bufs, shown);
			}
			else {
				/* Taken as it is, without a conversion */
				for (i = 0; i < RSPAMD_ZIP_BSDTAR_LOCALES; i++) {
					shown[i].crc = name_cstr_crc;
					shown[i].converts = TRUE;
				}
			}

			name_shown = TRUE;
		}

		for (i = 0; i < RSPAMD_ZIP_BSDTAR_LOCALES; i++) {
			if (!shown[i].converts || crc == shown[i].crc) {
				picks[pick_bsdtar + i] = path;

				if (!path_shown) {
					/* A Unicode Path is in UTF-8 */
					rspamd_zip_bsdtar_utf8_names((const unsigned char *) path.begin, path.len,
												 &bufs, path_names);
					path_shown = TRUE;
				}

				shown[i] = path_names[i];
			}
		}
	}

	rspamd_zip_norm_bufs_free(&bufs);

	/* The name, then each pick: each as it is, then up to its first NUL */
	for (i = 0; i <= G_N_ELEMENTS(picks); i++) {
		rspamd_ftok_t forms[2];

		if (i == 0) {
			forms[0].begin = (const char *) name;
			forms[0].len = name_len;
		}
		else {
			forms[0] = picks[i - 1];
		}

		forms[1].begin = forms[0].begin;
		forms[1].len = 0;

		if (forms[0].len > 0) {
			forms[1].len = rspamd_zip_cstr_len((const unsigned char *) forms[0].begin, forms[0].len);
		}

		for (k = 0; k < G_N_ELEMENTS(forms); k++) {
			if (forms[k].len == 0 ||
				(forms[k].len == name_len && memcmp(forms[k].begin, name, name_len) == 0)) {
				continue;
			}

			for (j = 0; j < npaths; j++) {
				if (rspamd_ftok_cmp(&paths[j], &forms[k]) == 0) {
					break;
				}
			}

			if (j == npaths) {
				g_assert(npaths < rspamd_zip_entry_names);
				paths[npaths++] = forms[k];
			}
		}
	}

	return npaths;
}

enum rspamd_zip_cd_read {
	RSPAMD_ZIP_CD_OK = 0,
	/* Stopped at a record that runs past the end record, which is listed */
	RSPAMD_ZIP_CD_PARTIAL,
	RSPAMD_ZIP_CD_INVALID,
	RSPAMD_ZIP_CD_LIMIT,
};

/*
 * Directories read for several end records may be the same one, or run into
 * one another: the records listed so far, one per file of the archive, so that
 * no record is listed twice
 */
struct rspamd_zip_listed {
	GArray *records; /* const unsigned char *, in the order of the files */
	/* Records of the earlier reads, sorted, while a directory is read */
	const unsigned char **prev;
	gsize nprev;
};

static int
rspamd_archive_zip_record_cmp(const void *a, const void *b)
{
	const unsigned char *ra = *(const unsigned char *const *) a,
						*rb = *(const unsigned char *const *) b;

	return ra < rb ? -1 : (ra > rb ? 1 : 0);
}

static void
rspamd_archive_zip_unlist(struct rspamd_task *task,
						  struct rspamd_archive *arch,
						  struct rspamd_zip_listed *listed,
						  unsigned int len)
{
	rspamd_archive_files_truncate(task, arch, len);
	g_array_set_size(listed->records, len);
}

/*
 * Lists the files of the central directory [cd, cd_end); with `open_end`, its
 * size is not known and it ends at the first data that is not a record
 */
static enum rspamd_zip_cd_read
rspamd_archive_zip_read_records(struct rspamd_task *task,
								struct rspamd_archive *arch,
								struct rspamd_zip_listed *listed,
								const unsigned char *cd,
								const unsigned char *cd_end,
								const unsigned char *eocd,
								gboolean open_end)
{
	const uint32_t cd_basic_len = 46;
	const unsigned char cd_magic[] = {0x50, 0x4b, 0x01, 0x02};
	uint32_t comp_size, uncomp_size;
	uint16_t extra_len, fname_len, comment_len;
	struct rspamd_archive_file *f;
	const unsigned char *p;
	unsigned int nrecords = 0;

	while (cd < cd_end) {
		uint16_t flags;

		/*
		 * Listed by an earlier read, which may have stopped before the end of
		 * this directory: skipped, and the next records are read
		 */
		gboolean listed_before = listed->nprev > 0 &&
								 bsearch(&cd, listed->prev, listed->nprev, sizeof(*listed->prev),
										 rspamd_archive_zip_record_cmp) != NULL;

		/* Read central directory record */
		if (eocd - cd < cd_basic_len ||
			memcmp(cd, cd_magic, sizeof(cd_magic)) != 0) {
			if (open_end && nrecords > 0) {
				/* Its size is not known: it ends with the last record that reads */
				return RSPAMD_ZIP_CD_OK;
			}

			msg_info_task("zip archive is invalid (bad cd record)");

			return RSPAMD_ZIP_CD_INVALID;
		}

		memcpy(&flags, cd + 8, sizeof(uint16_t));
		flags = GUINT16_FROM_LE(flags);
		memcpy(&comp_size, cd + 20, sizeof(uint32_t));
		comp_size = GUINT32_FROM_LE(comp_size);
		memcpy(&uncomp_size, cd + 24, sizeof(uint32_t));
		uncomp_size = GUINT32_FROM_LE(uncomp_size);
		memcpy(&fname_len, cd + 28, sizeof(fname_len));
		fname_len = GUINT16_FROM_LE(fname_len);
		memcpy(&extra_len, cd + 30, sizeof(extra_len));
		extra_len = GUINT16_FROM_LE(extra_len);
		memcpy(&comment_len, cd + 32, sizeof(comment_len));
		comment_len = GUINT16_FROM_LE(comment_len);

		if (cd + cd_basic_len + fname_len > eocd) {
			if (open_end && nrecords > 0) {
				return RSPAMD_ZIP_CD_OK;
			}

			msg_info_task("zip archive is invalid (too large cd record)");

			return RSPAMD_ZIP_CD_INVALID;
		}

		/*
		 * The extra field or the comment may run past the end record: readers
		 * (Python, unzip, 7-Zip) still list the file, and no record after it
		 * can be found
		 */
		gboolean overrun = cd + cd_basic_len + fname_len + extra_len + comment_len > eocd;

		if (!listed_before) {
			f = g_malloc0(sizeof(*f));
			rspamd_archive_file_try_utf(task, arch, f, cd + cd_basic_len, fname_len);

			f->compressed_size = comp_size;
			f->uncompressed_size = uncomp_size;

			if (flags & 0x41u) {
				f->flags |= RSPAMD_ARCHIVE_FILE_ENCRYPTED;
			}

			if (f->fname) {
				if (f->flags & RSPAMD_ARCHIVE_FILE_OBFUSCATED) {
					arch->flags |= RSPAMD_ARCHIVE_HAS_OBFUSCATED_FILES;
				}

				if (!rspamd_archive_file_add(task, arch, f)) {
					return RSPAMD_ZIP_CD_LIMIT;
				}
				g_array_append_val(listed->records, cd);
				msg_debug_archive("found file in zip archive: %v", f->fname);
			}
			else {
				g_free(f);

				return RSPAMD_ZIP_CD_INVALID;
			}

			/* Process extra fields */
			const unsigned char *extra = cd + fname_len + cd_basic_len,
								*extra_end = MIN(extra + extra_len, eocd);
			p = extra;

			while (p + sizeof(uint16_t) * 2 < extra_end) {
				uint16_t hid, hlen;

				memcpy(&hid, p, sizeof(uint16_t));
				hid = GUINT16_FROM_LE(hid);
				memcpy(&hlen, p + sizeof(uint16_t), sizeof(uint16_t));
				hlen = GUINT16_FROM_LE(hlen);

				if (hid == 0x0017) {
					f->flags |= RSPAMD_ARCHIVE_FILE_ENCRYPTED;
				}

				if (hlen + sizeof(uint16_t) * 2 > (gsize) (extra_end - p)) {
					/* Truncated or malformed extra field */
					break;
				}

				p += hlen + sizeof(uint16_t) * 2;
			}

			rspamd_ftok_t upaths[rspamd_zip_entry_names];
			unsigned int nupaths = rspamd_archive_zip_unicode_paths(extra, extra_end - extra,
																	cd + cd_basic_len, fname_len,
																	(flags & 0x800u) != 0, upaths);

			for (unsigned int k = 0; k < nupaths; k++) {
				/* The name these readers show, listed as well */
				struct rspamd_archive_file *uf = g_malloc0(sizeof(*uf));

				rspamd_archive_file_try_utf(task, arch, uf, upaths[k].begin, upaths[k].len);

				if (uf->fname == NULL || g_string_equal(uf->fname, f->fname)) {
					rspamd_archive_file_free(uf);
				}
				else {
					uf->compressed_size = f->compressed_size;
					uf->uncompressed_size = f->uncompressed_size;
					uf->flags |= (f->flags & RSPAMD_ARCHIVE_FILE_ENCRYPTED) | RSPAMD_ARCHIVE_FILE_ALIAS |
								 RSPAMD_ARCHIVE_FILE_SAME_ENTRY;

					if (uf->flags & RSPAMD_ARCHIVE_FILE_OBFUSCATED) {
						arch->flags |= RSPAMD_ARCHIVE_HAS_OBFUSCATED_FILES;
					}

					if (!rspamd_archive_file_add(task, arch, uf)) {
						return RSPAMD_ZIP_CD_LIMIT;
					}

					/* Its record, as for any file listed */
					g_array_append_val(listed->records, cd);
				}
			}
		}

		nrecords++;

		if (overrun) {
			/*
			 * Readers that keep it go no further, others refuse the
			 * directory: the next choices are still tried
			 */
			return RSPAMD_ZIP_CD_PARTIAL;
		}

		cd += fname_len + comment_len + extra_len + cd_basic_len;

		if (open_end && cd < cd_end && (cd_end - cd < sizeof(cd_magic) || memcmp(cd, cd_magic, sizeof(cd_magic)) != 0)) {
			/* Its size is not known: the directory ends at the first other data */
			break;
		}
	}

	return RSPAMD_ZIP_CD_OK;
}

static enum rspamd_zip_cd_read
rspamd_archive_zip_read_cd(struct rspamd_task *task,
						   struct rspamd_archive *arch,
						   struct rspamd_zip_listed *listed,
						   const unsigned char *cd,
						   const unsigned char *cd_end,
						   const unsigned char *eocd,
						   gboolean open_end)
{
	enum rspamd_zip_cd_read read;

	listed->nprev = listed->records->len;

	if (listed->nprev > 0) {
		listed->prev = g_malloc(listed->nprev * sizeof(*listed->prev));
		memcpy(listed->prev, listed->records->data, listed->nprev * sizeof(*listed->prev));
		qsort(listed->prev, listed->nprev, sizeof(*listed->prev),
			  rspamd_archive_zip_record_cmp);
	}

	read = rspamd_archive_zip_read_records(task, arch, listed, cd, cd_end, eocd, open_end);

	g_free(listed->prev);
	listed->prev = NULL;
	listed->nprev = 0;

	return read;
}

/*
 * Lists the files of the sets of directories of an end record that read: the
 * zip64 values and the 32-bit ones, when they differ, are what different
 * readers take (Python and bsdtar the former, 7-Zip the latter). A directory
 * that does not read leaves no files; one that stops at a record running past
 * the end record keeps its files. Sets the set that read with the most data
 * in front of its archive, which rspamd_archive_zip_read_first looks into
 */
static enum rspamd_zip_cd_read
rspamd_archive_zip_read_sets(struct rspamd_task *task,
							 struct rspamd_archive *arch,
							 struct rspamd_zip_listed *listed,
							 const unsigned char *start,
							 const unsigned char *eocd,
							 const struct rspamd_zip_cd_set *sets,
							 unsigned int nsets,
							 const struct rspamd_zip_cd_set **pread_set)
{
	enum rspamd_zip_cd_read read, res = RSPAMD_ZIP_CD_INVALID;
	const struct rspamd_zip_cd_set *first_read = NULL;

	for (unsigned int i = 0; i < nsets; i++) {
		const struct rspamd_zip_cd_set *set = &sets[i];
		unsigned int mark = arch->files->len;

		read = rspamd_archive_zip_read_cd(task, arch, listed, start + set->offset,
										  start + set->offset + set->size, eocd,
										  set->open_end);

		if (read == RSPAMD_ZIP_CD_INVALID) {
			rspamd_archive_zip_unlist(task, arch, listed, mark);

			if (set->open_end && set->declared_size == 0) {
				/* Nothing there reads: the directory is empty, as the record says */
				read = RSPAMD_ZIP_CD_OK;
			}
			else if (set->alt_offset != G_MAXUINT64) {
				/* Only the directory where the record says can be read */
				read = rspamd_archive_zip_read_cd(task, arch, listed, start + set->alt_offset,
												  start + set->alt_offset + set->size,
												  eocd, FALSE);

				if (read == RSPAMD_ZIP_CD_INVALID) {
					rspamd_archive_zip_unlist(task, arch, listed, mark);
				}
			}
		}
		else if (read != RSPAMD_ZIP_CD_LIMIT && set->alt_offset != G_MAXUINT64) {
			/*
			 * The other directory, as far as it reads, which some readers
			 * list, also when the first one stops at a record running past
			 * the end record. Its records that the first one has listed
			 * are skipped
			 */
			rspamd_archive_zip_read_cd(task, arch, listed, start + set->alt_offset,
									   start + set->alt_offset + set->size,
									   eocd, FALSE);
		}

		if (read == RSPAMD_ZIP_CD_INVALID) {
			continue;
		}

		if (first_read == NULL ||
			(set->front != G_MAXUINT64 &&
			 (first_read->front == G_MAXUINT64 || set->front > first_read->front))) {
			first_read = set;
		}

		if (read == RSPAMD_ZIP_CD_LIMIT) {
			res = read;
			break;
		}

		if (read == RSPAMD_ZIP_CD_OK || res == RSPAMD_ZIP_CD_INVALID) {
			res = read;
		}
	}

	if (first_read != NULL) {
		*pread_set = first_read;
	}

	return res;
}

/* Whether a local header or a directory record is at `pos` */
static gboolean
rspamd_archive_zip_entry_follows(const unsigned char *start, uint64_t limit, uint64_t pos)
{
	static const unsigned char lh_magic[] = {0x50, 0x4b, 0x03, 0x04},
							   cd_magic[] = {0x50, 0x4b, 0x01, 0x02};

	return pos <= limit && limit - pos >= sizeof(lh_magic) &&
		   (memcmp(start + pos, lh_magic, sizeof(lh_magic)) == 0 ||
			memcmp(start + pos, cd_magic, sizeof(cd_magic)) == 0);
}

/*
 * The local headers a walk reached: one per name and extra field, which
 * copies of a header do not hide another one behind
 */
struct rspamd_zip_locals {
	GArray *lhs;        /* uint64_t offsets */
	GHashTable *seen;   /* rspamd_ftok_t * over the name and extra field */
	gboolean truncated; /* some were dropped at the files limit */
};

static unsigned int
rspamd_archive_ftok_hash(gconstpointer key)
{
	return rspamd_ftok_hash((const rspamd_ftok_t *) key);
}

static gboolean
rspamd_archive_ftok_equal(gconstpointer a, gconstpointer b)
{
	return rspamd_ftok_cmp((const rspamd_ftok_t *) a, (const rspamd_ftok_t *) b) == 0;
}

static rspamd_ftok_t *
rspamd_archive_ftok_dup(const rspamd_ftok_t *tok)
{
	rspamd_ftok_t *res = g_new(rspamd_ftok_t, 1);

	*res = *tok;

	return res;
}

static void
rspamd_archive_zip_locals_init(struct rspamd_zip_locals *locals)
{
	locals->lhs = g_array_new(FALSE, FALSE, sizeof(uint64_t));
	locals->seen = g_hash_table_new_full(rspamd_archive_ftok_hash, rspamd_archive_ftok_equal,
										 g_free, NULL);
	locals->truncated = FALSE;
}

static void
rspamd_archive_zip_locals_free(struct rspamd_zip_locals *locals)
{
	g_array_free(locals->lhs, TRUE);
	g_hash_table_unref(locals->seen);
}

/*
 * A data descriptor at `at` for the data from `data`: the size it holds is
 * their distance and an entry follows it. With its signature or without
 * (`signed_only` FALSE), 32 or 64-bit. Returns its end, or G_MAXUINT64
 */
static uint64_t
rspamd_archive_zip_descriptor_at(const unsigned char *start, uint64_t limit,
								 uint64_t data, uint64_t at, gboolean signed_only)
{
	static const unsigned char dd_magic[] = {0x50, 0x4b, 0x07, 0x08};
	gboolean has_magic = at <= limit && limit - at >= sizeof(dd_magic) &&
						 memcmp(start + at, dd_magic, sizeof(dd_magic)) == 0;

	for (unsigned int with_magic = 0; with_magic < 2; with_magic++) {
		/* The sizes follow the CRC, which follows the signature */
		uint64_t size_off = with_magic ? 8 : 4;

		if ((with_magic && !has_magic) || (!with_magic && signed_only)) {
			continue;
		}

		for (unsigned int wide = 0; wide < 2; wide++) {
			uint64_t len = size_off + (wide ? 16 : 8), dsize;

			if (at > limit || limit - at < len) {
				continue;
			}

			if (wide) {
				memcpy(&dsize, start + at + size_off, sizeof(dsize));
				dsize = GUINT64_FROM_LE(dsize);
			}
			else {
				uint32_t dsize32;

				memcpy(&dsize32, start + at + size_off, sizeof(dsize32));
				dsize = GUINT32_FROM_LE(dsize32);
			}

			if (dsize == at - data && rspamd_archive_zip_entry_follows(start, limit, at + len)) {
				return at + len;
			}
		}
	}

	return G_MAXUINT64;
}

/*
 * Walks the archive at the start of the data as 7-Zip and streaming readers
 * do: each local header, its data by the size it holds, its data descriptor,
 * up to the central directory, whose records are walked by their lengths too.
 * Data that looks like a directory and its end record, in a file or in a
 * record, is passed this way. The local headers walked are kept in `locals`.
 * Returns where the end record of that archive is: right after its
 * directory, or, when the walk cannot go on, at the local header it stopped
 * at
 */
static uint64_t
rspamd_archive_zip_walk_first(const unsigned char *start, uint64_t limit,
							  struct rspamd_zip_locals *locals)
{
	static const unsigned char lh_magic[] = {0x50, 0x4b, 0x03, 0x04},
							   cd_magic[] = {0x50, 0x4b, 0x01, 0x02},
							   dd_magic[] = {0x50, 0x4b, 0x07, 0x08},
							   eocd_magic[] = {0x50, 0x4b, 0x05, 0x06},
							   z64_eocd_magic[] = {0x50, 0x4b, 0x06, 0x06},
							   z64_loc_magic[] = {0x50, 0x4b, 0x06, 0x07};
	const uint64_t cd_basic_len = 46, lh_basic_len = 30;
	uint64_t pos = 0, entry = 0;
	/* A search for a descriptor read up to the limit: not done again, which would cost a square */
	gboolean search_failed = FALSE;

	while (limit - pos >= lh_basic_len && memcmp(start + pos, lh_magic, sizeof(lh_magic)) == 0) {
		uint16_t flags, fname_len, extra_len;
		uint32_t csize32;
		uint64_t data, csize, next = G_MAXUINT64;

		entry = pos;
		memcpy(&flags, start + pos + 6, sizeof(flags));
		flags = GUINT16_FROM_LE(flags);
		memcpy(&csize32, start + pos + 18, sizeof(csize32));
		csize = GUINT32_FROM_LE(csize32);
		memcpy(&fname_len, start + pos + 26, sizeof(fname_len));
		memcpy(&extra_len, start + pos + 28, sizeof(extra_len));
		data = pos + lh_basic_len + GUINT16_FROM_LE(fname_len) + GUINT16_FROM_LE(extra_len);

		if (data > limit) {
			return entry;
		}

		if (data > pos + lh_basic_len) {
			rspamd_ftok_t key = {.begin = (const char *) start + pos + lh_basic_len,
								 .len = data - pos - lh_basic_len};

			if (!g_hash_table_contains(locals->seen, &key)) {
				if (locals->lhs->len < max_archive_files) {
					g_hash_table_add(locals->seen, rspamd_archive_ftok_dup(&key));
					g_array_append_val(locals->lhs, entry);
				}
				else {
					locals->truncated = TRUE;
				}
			}
		}

		if (csize == G_MAXUINT32) {
			/* The zip64 extra field: the uncompressed size, then the compressed one */
			uint64_t extra = data - GUINT16_FROM_LE(extra_len);

			csize = G_MAXUINT64;

			while (data - extra >= 4) {
				uint16_t id, len;

				memcpy(&id, start + extra, sizeof(id));
				memcpy(&len, start + extra + 2, sizeof(len));
				len = GUINT16_FROM_LE(len);

				if (data - extra - 4 < len) {
					break;
				}

				if (GUINT16_FROM_LE(id) == 0x0001 && len >= 16) {
					memcpy(&csize, start + extra + 4 + 8, sizeof(csize));
					csize = GUINT64_FROM_LE(csize);
					break;
				}

				extra += 4 + len;
			}

			if (csize == G_MAXUINT64) {
				return entry;
			}
		}

		if (flags & 0x8) {
			/*
			 * The sizes are in the descriptor after the data. 7-Zip takes the
			 * first one whose size is its distance from the data, whatever
			 * the header says, so a size in the header that leads inside the
			 * data does not lead the walk; one at that size, unsigned too, is
			 * the next choice
			 */
			if (!search_failed) {
				const unsigned char *q = start + data, *end = start + limit;

				while (end - q >= 16 && (q = memchr(q, dd_magic[0], end - q - 15)) != NULL) {
					if (memcmp(q, dd_magic, sizeof(dd_magic)) == 0 &&
						(next = rspamd_archive_zip_descriptor_at(start, limit, data, q - start,
																 TRUE)) != G_MAXUINT64) {
						break;
					}

					q++;
				}

				search_failed = next == G_MAXUINT64;
			}

			if (next == G_MAXUINT64 && csize != 0 && csize <= limit - data) {
				next = rspamd_archive_zip_descriptor_at(start, limit, data, data + csize, FALSE);
			}
		}
		else if (csize <= limit - data) {
			next = data + csize;
		}

		if (next == G_MAXUINT64) {
			return entry;
		}

		pos = next;
	}

	if (pos == 0 || limit - pos < sizeof(cd_magic) ||
		memcmp(start + pos, cd_magic, sizeof(cd_magic)) != 0) {
		return entry;
	}

	/* The directory */
	uint64_t cd_start = pos;

	while (limit - pos >= cd_basic_len && memcmp(start + pos, cd_magic, sizeof(cd_magic)) == 0) {
		uint16_t fname_len, extra_len, comment_len;
		uint64_t len;

		memcpy(&fname_len, start + pos + 28, sizeof(fname_len));
		memcpy(&extra_len, start + pos + 30, sizeof(extra_len));
		memcpy(&comment_len, start + pos + 32, sizeof(comment_len));
		len = cd_basic_len + GUINT16_FROM_LE(fname_len) + GUINT16_FROM_LE(extra_len) +
			  GUINT16_FROM_LE(comment_len);

		if (len > limit - pos) {
			break;
		}

		pos += len;
	}

	/*
	 * Records whose lengths run past others, or past the end record, are
	 * not walked through: the end record is then looked for from the start
	 * of the directory
	 */
	if (limit - pos >= 12 && memcmp(start + pos, z64_eocd_magic, sizeof(z64_eocd_magic)) == 0) {
		/* The zip64 end record and its locator, by their sizes: data in them is passed too */
		uint64_t z64_size, after;

		memcpy(&z64_size, start + pos + 4, sizeof(z64_size));
		z64_size = GUINT64_FROM_LE(z64_size);

		if (z64_size <= limit - pos - 12) {
			after = pos + 12 + z64_size;

			if (limit - after >= 20 && memcmp(start + after, z64_loc_magic, sizeof(z64_loc_magic)) == 0) {
				after += 20;
			}

			if (limit - after >= sizeof(eocd_magic) &&
				memcmp(start + after, eocd_magic, sizeof(eocd_magic)) == 0) {
				return after;
			}
		}

		return pos;
	}

	if (limit - pos < sizeof(eocd_magic) ||
		memcmp(start + pos, eocd_magic, sizeof(eocd_magic)) != 0) {
		return cd_start;
	}

	return pos;
}

/*
 * The files of the local headers walked that no directory listed: 7-Zip
 * lists these entries too, and so do readers that go by local headers
 * (bsdtar, macOS), so that a directory that names other files, or data that
 * looks like a directory, does not hide them
 */
static void
rspamd_archive_zip_list_local(struct rspamd_task *task,
							  struct rspamd_archive *arch,
							  struct rspamd_zip_listed *listed,
							  const unsigned char *start,
							  struct rspamd_zip_locals *locals)
{
	const uint64_t lh_basic_len = 30;
	GHashTable *names, *raw_names;

	if (locals->truncated) {
		arch->flags |= RSPAMD_ARCHIVE_FILES_TRUNCATED;
	}

	if (locals->lhs->len == 0) {
		return;
	}

	names = g_hash_table_new((GHashFunc) g_string_hash, (GEqualFunc) g_string_equal);
	/* Names as they are, each converted once: a name of a record is not again */
	raw_names = g_hash_table_new_full(rspamd_archive_ftok_hash, rspamd_archive_ftok_equal,
									  g_free, NULL);

	for (unsigned int i = 0; i < arch->files->len; i++) {
		struct rspamd_archive_file *f = g_ptr_array_index(arch->files, i);

		if (f->fname) {
			g_hash_table_add(names, f->fname);
		}
	}

	for (unsigned int i = 0; i < listed->records->len; i++) {
		const unsigned char *cd = g_array_index(listed->records, const unsigned char *, i);
		uint16_t fname_len;
		rspamd_ftok_t key;

		memcpy(&fname_len, cd + 28, sizeof(fname_len));
		key.begin = (const char *) cd + 46;
		key.len = GUINT16_FROM_LE(fname_len);
		g_hash_table_add(raw_names, rspamd_archive_ftok_dup(&key));
	}

	for (unsigned int i = 0; i < locals->lhs->len; i++) {
		const unsigned char *lh = start + g_array_index(locals->lhs, uint64_t, i);
		uint16_t flags, fname_len, extra_len;
		uint32_t csize, usize;
		rspamd_ftok_t lh_names[1 + rspamd_zip_entry_names];
		unsigned int nlh_names;
		gboolean stop = FALSE, listed_one = FALSE;

		memcpy(&fname_len, lh + 26, sizeof(fname_len));
		fname_len = GUINT16_FROM_LE(fname_len);
		memcpy(&extra_len, lh + 28, sizeof(extra_len));
		extra_len = GUINT16_FROM_LE(extra_len);
		memcpy(&flags, lh + 6, sizeof(flags));
		memcpy(&csize, lh + 18, sizeof(csize));
		memcpy(&usize, lh + 22, sizeof(usize));

		/* Its name, then the other names readers show of it */
		lh_names[0].begin = (const char *) lh + lh_basic_len;
		lh_names[0].len = fname_len;
		nlh_names = 1 + rspamd_archive_zip_unicode_paths(lh + lh_basic_len + fname_len, extra_len,
														 lh + lh_basic_len, fname_len,
														 (GUINT16_FROM_LE(flags) & 0x800u) != 0, lh_names + 1);

		for (unsigned int k = 0; k < nlh_names; k++) {
			struct rspamd_archive_file *f;
			const rspamd_ftok_t *key = &lh_names[k];

			if (key->len == 0 || g_hash_table_contains(raw_names, key)) {
				continue;
			}

			g_hash_table_add(raw_names, rspamd_archive_ftok_dup(key));
			f = g_malloc0(sizeof(*f));
			rspamd_archive_file_try_utf(task, arch, f, key->begin, key->len);

			if (f->fname == NULL || g_hash_table_contains(names, f->fname)) {
				rspamd_archive_file_free(f);
				continue;
			}

			f->compressed_size = GUINT32_FROM_LE(csize);
			f->uncompressed_size = GUINT32_FROM_LE(usize);
			/*
			 * Mostly a file of the directory under another name: counts of
			 * files go by the directory
			 */
			f->flags |= RSPAMD_ARCHIVE_FILE_ALIAS;

			if (listed_one) {
				/* Another name of this local header, listed after it */
				f->flags |= RSPAMD_ARCHIVE_FILE_SAME_ENTRY;
			}

			if (GUINT16_FROM_LE(flags) & 0x41u) {
				f->flags |= RSPAMD_ARCHIVE_FILE_ENCRYPTED;
			}

			if (f->flags & RSPAMD_ARCHIVE_FILE_OBFUSCATED) {
				arch->flags |= RSPAMD_ARCHIVE_HAS_OBFUSCATED_FILES;
			}

			if (!rspamd_archive_file_add(task, arch, f)) {
				stop = TRUE;
				break;
			}

			listed_one = TRUE;
			g_hash_table_add(names, f->fname);
			msg_debug_archive("found file in a local header of zip archive: %v", f->fname);
		}

		if (stop) {
			break;
		}
	}

	g_hash_table_unref(names);
	g_hash_table_unref(raw_names);
}

/*
 * The local headers of the archive that starts at `base`, up to its
 * directory at `cd_offset`: the files that no directory listed
 */
static void
rspamd_archive_zip_list_main(struct rspamd_task *task,
							 struct rspamd_archive *arch,
							 struct rspamd_zip_listed *listed,
							 const unsigned char *start,
							 uint64_t base,
							 uint64_t cd_offset)
{
	static const unsigned char lh_magic[] = {0x50, 0x4b, 0x03, 0x04};
	struct rspamd_zip_locals locals;

	if (base >= cd_offset || cd_offset - base < sizeof(lh_magic) ||
		memcmp(start + base, lh_magic, sizeof(lh_magic)) != 0) {
		return;
	}

	rspamd_archive_zip_locals_init(&locals);
	rspamd_archive_zip_walk_first(start + base, cd_offset - base, &locals);
	rspamd_archive_zip_list_local(task, arch, listed, start + base, &locals);
	rspamd_archive_zip_locals_free(&locals);
}

/*
 * End records in [p, end) of an archive at the start of the data, whose
 * directory is right before them: the first one that lists files does.
 * Returns whether one did
 */
static gboolean
rspamd_archive_zip_scan_first(struct rspamd_task *task,
							  struct rspamd_archive *arch,
							  struct rspamd_zip_listed *listed,
							  const unsigned char *start,
							  const unsigned char *p,
							  const unsigned char *end)
{
	static const unsigned char cd_magic[] = {0x50, 0x4b, 0x01, 0x02},
							   eocd_magic[] = {0x50, 0x4b, 0x05, 0x06};
	const uint64_t cd_basic_len = 46;
	/* Records tried, each a directory read: not free */
	const unsigned int max_candidates = 8;
	unsigned int candidates = 0;

	while (end - p >= 22 && candidates < max_candidates) {
		p = memchr(p, eocd_magic[0], end - p - 21);

		if (p == NULL) {
			break;
		}

		if (memcmp(p, eocd_magic, sizeof(eocd_magic)) == 0) {
			struct rspamd_zip_cd_set sets[2];
			unsigned int nsets = 0, mark = arch->files->len;
			gboolean read_any = FALSE;

			if (rspamd_archive_zip_check_eocd(start, p, sets, &nsets) == RSPAMD_ZIP_EOCD_USABLE) {
				/* An archive at the start, its directory right before its record */
				for (unsigned int i = 0; i < nsets; i++) {
					const unsigned char *cd = start + sets[i].offset;
					uint16_t fname_len;

					if (sets[i].open_end || sets[i].declared_size < sizeof(cd_magic) ||
						sets[i].front != 0) {
						continue;
					}

					/* Its first record must read, which the directory read checks again */
					if ((uint64_t) (p - cd) < cd_basic_len || memcmp(cd, cd_magic, sizeof(cd_magic)) != 0) {
						continue;
					}

					memcpy(&fname_len, cd + 28, sizeof(fname_len));

					if ((uint64_t) (p - cd) < cd_basic_len + GUINT16_FROM_LE(fname_len)) {
						continue;
					}

					candidates++;

					/*
					 * Both directories, as for the last archive; their records
					 * are kept as far as they read
					 */
					if (rspamd_archive_zip_read_cd(task, arch, listed, cd, cd + sets[i].size,
												   p, FALSE) != RSPAMD_ZIP_CD_INVALID) {
						read_any = TRUE;
					}
				}
			}

			if (read_any || arch->files->len > mark) {
				return TRUE;
			}
		}

		p++;
	}

	return FALSE;
}

/*
 * An archive with data in front of it may follow another archive (`cat a.zip
 * b.zip`, the last one possibly empty): readers that take the record at the
 * end list the last one, but 7-Zip and WinRAR read from the start and list
 * the first one. That is the record after its entries, else the first one,
 * zip64 or not, whose offsets count from the start of the data and describe
 * the directory right before it; its files are listed too, and so are the
 * local headers walked. Sets `*last_start` to where the last archive starts
 * when its offsets count from the start of the data
 */
static void
rspamd_archive_zip_read_first(struct rspamd_task *task,
							  struct rspamd_archive *arch,
							  struct rspamd_zip_listed *listed,
							  const unsigned char *start,
							  const unsigned char *last_eocd,
							  const struct rspamd_zip_cd_set *last_set,
							  uint64_t *last_start)
{
	static const unsigned char lh_magic[] = {0x50, 0x4b, 0x03, 0x04},
							   cd_magic[] = {0x50, 0x4b, 0x01, 0x02};
	const uint64_t cd_basic_len = 46, lh_basic_len = 30;
	uint64_t front = last_set->front, limit = last_eocd - start, walked;
	struct rspamd_zip_locals locals;

	if (front == G_MAXUINT64 || limit < sizeof(lh_magic) ||
		memcmp(start, lh_magic, sizeof(lh_magic)) != 0) {
		return;
	}

	if (front == 0) {
		/*
		 * Offsets that count from the start of the data (`zip -A` after
		 * `cat`): the last archive starts where its entries do (the local
		 * headers its records point to, with their names), or at an empty
		 * directory
		 */
		if (last_set->declared_size < sizeof(cd_magic)) {
			front = last_set->declared_offset;
		}
		else {
			const unsigned char *cd = start + last_set->offset,
								*cd_end = cd + last_set->size;

			front = G_MAXUINT64;

			while (cd < cd_end && (uint64_t) (cd_end - cd) >= cd_basic_len &&
				   memcmp(cd, cd_magic, sizeof(cd_magic)) == 0) {
				uint32_t lh_offset;
				uint16_t fname_len, extra_len, comment_len, lh_fname_len;

				memcpy(&lh_offset, cd + 42, sizeof(lh_offset));
				lh_offset = GUINT32_FROM_LE(lh_offset);
				memcpy(&fname_len, cd + 28, sizeof(fname_len));
				fname_len = GUINT16_FROM_LE(fname_len);
				memcpy(&extra_len, cd + 30, sizeof(extra_len));
				memcpy(&comment_len, cd + 32, sizeof(comment_len));

				if ((uint64_t) (cd_end - cd) >= cd_basic_len + fname_len &&
					(uint64_t) lh_offset + lh_basic_len + fname_len <= limit &&
					memcmp(start + lh_offset, lh_magic, sizeof(lh_magic)) == 0) {
					memcpy(&lh_fname_len, start + lh_offset + 26, sizeof(lh_fname_len));

					if (GUINT16_FROM_LE(lh_fname_len) == fname_len &&
						memcmp(start + lh_offset + lh_basic_len, cd + cd_basic_len, fname_len) == 0) {
						front = MIN(front, lh_offset);
					}
				}

				cd += cd_basic_len + fname_len + GUINT16_FROM_LE(extra_len) +
					  GUINT16_FROM_LE(comment_len);
			}
		}

		if (front != G_MAXUINT64) {
			*last_start = front;
		}

		if (front == G_MAXUINT64 || front == 0) {
			return;
		}
	}

	if (front > limit) {
		return;
	}

	/*
	 * The first archive ends where the last one starts, and its end record
	 * is after its entries. When nothing is found there, the records in
	 * front of that place are tried as well
	 */
	rspamd_archive_zip_locals_init(&locals);
	walked = rspamd_archive_zip_walk_first(start, front, &locals);

	if (!rspamd_archive_zip_scan_first(task, arch, listed, start, start + walked, start + front) &&
		walked > 0) {
		rspamd_archive_zip_scan_first(task, arch, listed, start, start,
									  start + MIN(front, walked + 21));
	}

	rspamd_archive_zip_list_local(task, arch, listed, start, &locals);
	rspamd_archive_zip_locals_free(&locals);
}

static void
rspamd_archive_process_zip(struct rspamd_task *task,
						   struct rspamd_mime_part *part)
{
	const unsigned char *p, *start;
	const uint32_t eocd_magic = 0x06054b50;
	/* The record is followed by a comment of up to 64 KB */
	const unsigned int max_processed = G_MAXUINT16;
	struct rspamd_zip_cd_set sets[2];
	unsigned int nsets = 0;
	uint32_t processed = 0;
	/* Directories are read for a few records only: each read is not free */
	unsigned int records_read = 0;
	const unsigned int max_records_read = 4;
	struct rspamd_archive *arch = NULL;
	enum rspamd_zip_cd_read read = RSPAMD_ZIP_CD_INVALID;
	const struct rspamd_zip_cd_set *read_set = NULL;
	const unsigned char *read_eocd = NULL;
	/* The sets of the record that was read, as `sets` changes with each record */
	struct rspamd_zip_cd_set read_set_copy;
	struct rspamd_zip_listed listed = {NULL, NULL, 0};

	/*
	 * Need at least 22 bytes for a minimal EOCD record; otherwise the
	 * scan below would compute a pointer below parsed_data.begin (UB).
	 */
	if (part->parsed_data.len < 22) {
		return;
	}

	/* Zip files have interesting data at the end of archive */
	p = part->parsed_data.begin + part->parsed_data.len - 1;
	start = part->parsed_data.begin;
	listed.records = g_array_new(FALSE, FALSE, sizeof(const unsigned char *));

	/*
	 * Search for EOCD: it is 22 bytes followed by a comment of up to 64 KB,
	 * as far back as zip readers look. They use the last record; the comment
	 * may hold the magic as well, so skip records that describe no central
	 * directory, or none that reads. `p` points to the last character.
	 */
	p -= 21;

	while (p >= start && processed <= max_processed) {
		uint32_t t;

		memcpy(&t, p, sizeof(t));

		if (GUINT32_FROM_LE(t) == eocd_magic) {
			enum rspamd_zip_eocd_check check = rspamd_archive_zip_check_eocd(start, p,
																			 sets, &nsets);

			if (check == RSPAMD_ZIP_EOCD_USABLE) {
				if (arch == NULL) {
					arch = rspamd_mempool_alloc0(task->task_pool, sizeof(*arch));
					arch->files = g_ptr_array_new();
					arch->type = RSPAMD_ARCHIVE_ZIP;
					if (part->cd) {
						arch->archive_name = &part->cd->filename;
					}
					rspamd_mempool_add_destructor(task->task_pool, rspamd_archive_dtor,
												  arch);
					if (!rspamd_archive_file_limit_check(task, arch)) {
						goto set;
					}
				}

				enum rspamd_zip_cd_read record_read = rspamd_archive_zip_read_sets(task, arch, &listed,
																				   start, p, sets, nsets, &read_set);

				if (record_read != RSPAMD_ZIP_CD_INVALID) {
					read_eocd = p;
					read = record_read;
					read_set_copy = *read_set;
					read_set = &read_set_copy;
				}

				/*
				 * A directory that stopped at a record running past the end
				 * record keeps its files, and earlier records are looked at
				 */
				if ((record_read != RSPAMD_ZIP_CD_INVALID && record_read != RSPAMD_ZIP_CD_PARTIAL) ||
					++records_read >= max_records_read) {
					break;
				}
			}
			else if (check == RSPAMD_ZIP_EOCD_STOP) {
				break;
			}
		}

		p--;
		processed++;
	}

	if (read == RSPAMD_ZIP_CD_INVALID) {
		/* Not a zip file */
		msg_info_task("zip archive is invalid (no usable EOCD)");
		g_array_free(listed.records, TRUE);

		return;
	}

	if (read != RSPAMD_ZIP_CD_LIMIT && read_set != NULL) {
		/* Where the archive starts: offsets count from the start of the data when not known */
		uint64_t last_start = read_set->front == G_MAXUINT64 ? 0 : read_set->front;

		/* Data in front of the archive, which may be another archive */
		rspamd_archive_zip_read_first(task, arch, &listed, start, read_eocd, read_set, &last_start);
		rspamd_archive_zip_list_main(task, arch, &listed, start, last_start, read_set->offset);
	}

set:
	g_array_free(listed.records, TRUE);
	part->part_type = RSPAMD_MIME_PART_ARCHIVE;
	part->specific.arch = arch;

	arch->size = part->parsed_data.len;
}

static inline int
rspamd_archive_rar_read_vint(const unsigned char *start, gsize remain, uint64_t *res)
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
	uint64_t t = 0;
	unsigned int shift = 0;
	const unsigned char *p = start;

	while (remain > 0 && shift <= 57) {
		if (*p & 0x80) {
			t |= ((uint64_t) (*p & 0x7f)) << shift;
		}
		else {
			t |= ((uint64_t) (*p & 0x7f)) << shift;
			p++;
			break;
		}

		shift += 7;
		p++;
		remain--;
	}

	if (remain == 0 || shift > 64) {
		return -1;
	}

	*res = GUINT64_FROM_LE(t);

	return p - start;
}

/*
 * Readers of rar 4 archives: each goes from a header to the next in its own
 * way. libarchive is followed a second time where it can go two ways
 */
enum rspamd_rar4_walker {
	RSPAMD_RAR4_WALK_UNRAR = 0,
	RSPAMD_RAR4_WALK_7ZIP,
	RSPAMD_RAR4_WALK_LIBARCHIVE,
	RSPAMD_RAR4_WALK_LIBARCHIVE_FORK,
	RSPAMD_RAR4_WALKERS,
};

/* Where a reader is, and what it keeps from a header to the next */
struct rspamd_rar4_walk {
	const unsigned char *at; /* NULL once it stops */
	gboolean opening;        /* unrar looks for the main header */
	gboolean volume;         /* libarchive: the last main header is of a volume */
	unsigned int split_ends; /* libarchive: end blocks it crosses for the rest of a split file */
};

/*
 * A header as unrar reads it: a field that runs past its end reads as zero,
 * and the next field is read from where that one began
 */
struct rspamd_rar_raw {
	const unsigned char *p;
	gsize len;
	gsize pos;
};

static inline unsigned int
rspamd_rar_raw_get1(struct rspamd_rar_raw *raw)
{
	return raw->pos < raw->len ? raw->p[raw->pos++] : 0;
}

static inline unsigned int
rspamd_rar_raw_get2(struct rspamd_rar_raw *raw)
{
	unsigned int v = 0;

	if (raw->pos + 1 < raw->len) {
		v = raw->p[raw->pos] | (raw->p[raw->pos + 1] << 8);
		raw->pos += 2;
	}

	return v;
}

static inline uint32_t
rspamd_rar_raw_get4(struct rspamd_rar_raw *raw)
{
	uint32_t v = 0;

	if (raw->pos + 3 < raw->len) {
		v = (uint32_t) raw->p[raw->pos] | ((uint32_t) raw->p[raw->pos + 1] << 8) |
			((uint32_t) raw->p[raw->pos + 2] << 16) | ((uint32_t) raw->p[raw->pos + 3] << 24);
		raw->pos += 4;
	}

	return v;
}

/* Fields of a file or service header */
struct rspamd_rar4_file_head {
	uint64_t pack_size;
	uint64_t unp_size;
	gsize name_off;
	unsigned int name_size;
};

static void
rspamd_rar4_read_file_head(struct rspamd_rar_raw *raw, unsigned int flags,
						   struct rspamd_rar4_file_head *fh)
{
	uint32_t low_pack, low_unp, high_pack = 0, high_unp = 0;

	low_pack = rspamd_rar_raw_get4(raw);
	low_unp = rspamd_rar_raw_get4(raw);
	/* Host OS, CRC, time, version and method */
	(void) rspamd_rar_raw_get1(raw);
	(void) rspamd_rar_raw_get4(raw);
	(void) rspamd_rar_raw_get4(raw);
	(void) rspamd_rar_raw_get1(raw);
	(void) rspamd_rar_raw_get1(raw);
	fh->name_size = rspamd_rar_raw_get2(raw);
	/* Attributes */
	(void) rspamd_rar_raw_get4(raw);

	if (flags & 0x100) {
		/* High 32 bits of the sizes */
		high_pack = rspamd_rar_raw_get4(raw);
		high_unp = rspamd_rar_raw_get4(raw);
	}

	fh->pack_size = ((uint64_t) high_pack << 32) | low_pack;
	fh->unp_size = ((uint64_t) high_unp << 32) | low_unp;
	fh->name_off = raw->pos;
}

/* A file header that 7-Zip and libarchive take: whole, with all its fields and its name */
static inline gboolean
rspamd_rar4_file_head_whole(const struct rspamd_rar4_file_head *fh, unsigned int flags,
							uint64_t head_size, uint64_t avail, gboolean name_in_head)
{
	uint64_t fixed = 7 + 25 + ((flags & 0x100) ? 8 : 0);

	return head_size <= avail && head_size >= fixed &&
		   (!name_in_head || fh->name_size <= head_size - fixed);
}

/* The next header after a header and its data, NULL past the end */
static inline const unsigned char *
rspamd_rar_skip(const unsigned char *p, const unsigned char *end,
				uint64_t head_size, uint64_t data)
{
	uint64_t avail = end - p;

	if (head_size > avail || data > avail - head_size) {
		return NULL;
	}

	return p + head_size + data;
}

static gboolean
rspamd_archive_rar4_add_file(struct rspamd_task *task, struct rspamd_archive *arch,
							 const unsigned char *p, gsize avail, unsigned int flags,
							 const struct rspamd_rar4_file_head *fh)
{
	struct rspamd_archive_file *f;
	unsigned int fname_len = fh->name_size;
	/* Names of the Unicode version, and the length of the name before it */
	GString *unicode_names[RSPAMD_RAR4_UNICODE_READERS];
	unsigned int nunicode_names = 0;
	gsize ascii_len = avail;
	gboolean listed = TRUE, capped = FALSE;

	f = g_malloc0(sizeof(*f));

	if (flags & 0x200) {
		/* We have unicode + normal version */
		const unsigned char *tmp;

		tmp = memchr(p, '\0', avail);

		if (tmp != NULL || avail < fname_len) {
			ascii_len = tmp ? (gsize) (tmp - p) : avail;
			nunicode_names = rspamd_archive_rar4_unicode_names(p, avail, fname_len, ascii_len,
															   unicode_names, &capped);
		}

		if (nunicode_names > 0) {
			/* Readers show it instead of the name before the NUL */
			rspamd_archive_file_try_utf(task, arch, f, unicode_names[0]->str,
										unicode_names[0]->len);

			if (capped) {
				/* No file system takes such a name: only its ends are listed */
				f->flags |= RSPAMD_ARCHIVE_FILE_OBFUSCATED;
			}
			msg_debug_archive("found unicode filename in rarv4 archive: %v",
							  f->fname);
		}
		else if (ascii_len < avail || avail < fname_len) {
			/* Just use ASCII version */
			rspamd_archive_file_try_utf(task, arch, f, p, ascii_len);
			msg_debug_archive("found ascii filename in rarv4 archive: %v",
							  f->fname);
		}
		else {
			/* We have UTF8 filename, use it as is */
			rspamd_archive_file_try_utf(task, arch, f, p, avail);
			msg_debug_archive("found utf filename in rarv4 archive: %v",
							  f->fname);
		}
	}
	else {
		rspamd_archive_file_try_utf(task, arch, f, p, avail);
		msg_debug_archive("found ascii (old) filename in rarv4 archive: %v",
						  f->fname);
	}

	f->compressed_size = fh->pack_size;
	f->uncompressed_size = fh->unp_size;

	if (flags & 0x4) {
		f->flags |= RSPAMD_ARCHIVE_FILE_ENCRYPTED;
	}

	if (f->fname) {
		if (f->flags & RSPAMD_ARCHIVE_FILE_OBFUSCATED) {
			arch->flags |= RSPAMD_ARCHIVE_HAS_OBFUSCATED_FILES;
		}

		listed = rspamd_archive_file_add(task, arch, f);

		if (listed && nunicode_names > 0) {
			/* Where other readers stop, and the name older ones show */
			for (unsigned int k = 1; k < nunicode_names && listed; k++) {
				listed = rspamd_archive_file_add_name(task, arch, f, unicode_names[k]->str,
													  unicode_names[k]->len);
			}

			if (listed) {
				listed = rspamd_archive_file_add_name(task, arch, f, (const char *) p, ascii_len);
			}
		}
		else if (listed && !(flags & 0x200)) {
			/* A name with a NUL is shown up to it */
			listed = rspamd_archive_file_add_cstr_name(task, arch, f, p, avail);
		}

		if (listed && nunicode_names == 0) {
			/* unrar on macOS decodes the name as UTF-8 */
			listed = rspamd_archive_file_add_unrar_utf_name(task, arch, f, p, ascii_len);
		}
	}
	else {
		g_free(f);
	}

	for (unsigned int k = 0; k < nunicode_names; k++) {
		g_string_free(unicode_names[k], TRUE);
	}

	return listed;
}

/*
 * libarchive at a header. After a file split into the next volume, it reads
 * the rest of it: the next file header, which it does not list, past up to
 * two end blocks. When it cannot convert the name of that file, it reads the
 * headers in its data instead: *fork is set to where it goes then
 */
static void
rspamd_rar4_libarchive_step(struct rspamd_archive *arch, struct rspamd_rar4_walk *w,
							const unsigned char *p, const unsigned char *end,
							unsigned int type, unsigned int flags, uint64_t head_size,
							uint64_t add_size, const struct rspamd_rar4_file_head *fh,
							gboolean *lists, gboolean *ended, const unsigned char **fork)
{
	static const unsigned char rar4_marker[] = {0x52, 0x61, 0x72, 0x21, 0x1A, 0x07, 0x00};
	uint64_t avail = end - p;

	switch (type) {
	case 0x72:
		/* A marker of another archive */
		if (memcmp(p, rar4_marker, sizeof(rar4_marker)) == 0) {
			w->at = p + sizeof(rar4_marker);
		}
		break;
	case 0x73:
		if (head_size >= 13) {
			if (flags & 0x80) {
				arch->flags |= RSPAMD_ARCHIVE_ENCRYPTED;
				*ended = TRUE;
			}
			else {
				w->volume = (flags & 0x1) != 0;
				w->at = rspamd_rar_skip(p, end, head_size, 0);
			}
		}
		break;
	case 0x74:
	case 0x7a:
		/* A service header is read with its data, which can hold its name */
		if (rspamd_rar4_file_head_whole(fh, flags, head_size, avail, type == 0x74) &&
			fh->pack_size < (UINT64_C(1) << 63) && fh->unp_size < (UINT64_C(1) << 63)) {
			w->at = rspamd_rar_skip(p, end, head_size, fh->pack_size);

			if (type == 0x74) {
				if (w->split_ends > 0) {
					/*
					 * The rest of a split file: a name it cannot convert to the
					 * locale, which can be any name of other than ASCII, stops
					 * the skip of its data
					 */
					gboolean ascii = !(flags & 0x200);

					for (unsigned int i = 0; i < fh->name_size && ascii; i++) {
						ascii = p[fh->name_off + i] < 0x80;
					}

					if (!ascii) {
						*fork = p + head_size;
					}
				}
				else {
					*lists = TRUE;
				}

				w->split_ends = (w->volume && (flags & 0x2)) ? 2 : 0;
			}
		}
		break;
	case 0x7b:
		if (w->split_ends == 0) {
			*ended = TRUE;
			break;
		}

		/* Looking for the rest of a split file */
		w->split_ends--;
		/* FALLTHROUGH */
	case 0x75:
	case 0x76:
	case 0x77:
	case 0x78:
	case 0x79:
		if (!(flags & 0x8000)) {
			w->at = rspamd_rar_skip(p, end, head_size, 0);
		}
		else if (head_size >= 11 && head_size <= avail) {
			w->at = rspamd_rar_skip(p, end, head_size, add_size);
		}
		break;
	default:
		break;
	}
}

/*
 * The header at p for the readers there (a mask of walkers): where each of
 * them goes next (NULL once it stops) and the file listed. FALSE once no
 * more files fit. While unrar looks for the main header, it skips the end
 * block, and goes on 7 bytes after the start of a broken header, from where
 * it lists files
 */
static gboolean
rspamd_archive_rar4_header(struct rspamd_task *task, struct rspamd_archive *arch,
						   const unsigned char *start, const unsigned char *end,
						   const unsigned char *p, unsigned int readers,
						   struct rspamd_rar4_walk *w, gboolean *ended)
{
	struct rspamd_rar_raw raw;
	struct rspamd_rar4_file_head fh;
	struct rspamd_rar4_walk *u = &w[RSPAMD_RAR4_WALK_UNRAR], *z = &w[RSPAMD_RAR4_WALK_7ZIP];
	uint64_t avail = end - p, head_size, add_size;
	unsigned int type, flags, lists = 0, r;
	gsize name_len;

	for (r = 0; r < RSPAMD_RAR4_WALKERS; r++) {
		if (readers & (1u << r)) {
			w[r].at = NULL;
		}
	}

	if (avail == 0) {
		*ended = TRUE;

		return TRUE;
	}

	if (avail < 7) {
		msg_debug_archive("rar archive is invalid (truncated block header)");

		return TRUE;
	}

	type = p[2];
	flags = p[3] | (p[4] << 8);
	head_size = p[5] | (p[6] << 8);

	if (head_size < 7) {
		/* Shorter than the fields above: readers stop there */
		msg_debug_archive("rar archive is invalid (block of %L bytes)", head_size);

		if ((readers & (1u << RSPAMD_RAR4_WALK_UNRAR)) && u->opening) {
			u->opening = FALSE;
			u->at = p + 7;
		}

		return TRUE;
	}

	raw.p = p;
	raw.len = MIN(head_size, avail);
	raw.pos = 7;
	memset(&fh, 0, sizeof(fh));

	if (type == 0x74 || type == 0x7a || type == 0x02 || type == 0x03) {
		rspamd_rar4_read_file_head(&raw, flags, &fh);
	}

	/* The size of the data after a block, read from its header */
	add_size = raw.len >= 11 ? (uint64_t) p[7] | ((uint64_t) p[8] << 8) |
								   ((uint64_t) p[9] << 16) | ((uint64_t) p[10] << 24)
							 : 0;

	if (readers & (1u << RSPAMD_RAR4_WALK_UNRAR)) {
		/* unrar takes the types of rar 5 headers as the rar 4 ones */
		switch (type) {
		case 0x73:
		case 0x01:
			u->opening = FALSE;

			if (flags & 0x80) {
				/* Headers are encrypted */
				arch->flags |= RSPAMD_ARCHIVE_ENCRYPTED;
				*ended = TRUE;
			}
			else {
				u->at = rspamd_rar_skip(p, end, head_size, 0);
			}
			break;
		case 0x74:
		case 0x02:
			lists |= 1u << RSPAMD_RAR4_WALK_UNRAR;
			/* FALLTHROUGH */
		case 0x7a:
		case 0x03:
			if (u->opening && fh.pack_size > (uint64_t) G_MAXINT64 - (p - start) - head_size) {
				/* Past the largest offset: a broken header, after which unrar lists files */
				u->opening = FALSE;
				u->at = rspamd_rar_skip(p, end, head_size, 0);
			}
			else {
				/* Data of the size in the header, whatever the flags */
				u->at = rspamd_rar_skip(p, end, head_size, fh.pack_size);
			}
			break;
		case 0x7b:
		case 0x05:
			if (u->opening) {
				u->at = rspamd_rar_skip(p, end, head_size, 0);
			}
			else {
				*ended = TRUE;
			}
			break;
		case 0x75:
			/* A comment has no data */
			u->at = rspamd_rar_skip(p, end, head_size, 0);
			break;
		case 0x77:
		case 0x78:
			u->at = rspamd_rar_skip(p, end, head_size, add_size);
			break;
		default:
			u->at = rspamd_rar_skip(p, end, head_size, (flags & 0x8000) ? add_size : 0);
			break;
		}
	}

	if (readers & (1u << RSPAMD_RAR4_WALK_7ZIP)) {
		if (p == start) {
			/* 7-Zip takes an archive that starts with a main header */
			if (type == 0x73 && head_size >= 13) {
				if (flags & 0x80) {
					arch->flags |= RSPAMD_ARCHIVE_ENCRYPTED;
					*ended = TRUE;
				}
				else {
					z->at = rspamd_rar_skip(p, end, head_size, 0);
				}
			}
		}
		else if (type == 0x74) {
			/* p7zip 17 takes any packed size, later versions one under 2^63 */
			if (rspamd_rar4_file_head_whole(&fh, flags, head_size, avail, TRUE)) {
				lists |= 1u << RSPAMD_RAR4_WALK_7ZIP;
				z->at = rspamd_rar_skip(p, end, head_size, fh.pack_size);
			}
		}
		else if (type == 0x7b) {
			*ended = TRUE;
		}
		else if (type >= 0x75 && type <= 0x7a) {
			/* Data of the size after the base fields, read even past a short header */
			if (!(flags & 0x8000)) {
				z->at = rspamd_rar_skip(p, end, head_size, 0);
			}
			else if (avail >= 11) {
				z->at = rspamd_rar_skip(p, end, head_size,
										(uint64_t) p[7] | ((uint64_t) p[8] << 8) |
											((uint64_t) p[9] << 16) | ((uint64_t) p[10] << 24));
			}
		}
	}

	for (r = RSPAMD_RAR4_WALK_LIBARCHIVE; r <= RSPAMD_RAR4_WALK_LIBARCHIVE_FORK; r++) {
		struct rspamd_rar4_walk *fw = &w[RSPAMD_RAR4_WALK_LIBARCHIVE_FORK];
		const unsigned char *fork = NULL;
		gboolean la_lists = FALSE;

		if (!(readers & (1u << r))) {
			continue;
		}

		rspamd_rar4_libarchive_step(arch, &w[r], p, end, type, flags, head_size, add_size, &fh,
									&la_lists, ended, &fork);

		if (la_lists) {
			lists |= 1u << r;
		}

		if (fork != NULL) {
			if (fw->at == NULL && !(readers & (1u << RSPAMD_RAR4_WALK_LIBARCHIVE_FORK))) {
				/* It lists the files from there */
				fw->at = fork;
				fw->volume = w[r].volume;
				fw->split_ends = 0;
			}
			else {
				msg_debug_archive("rar archive has more ways for libarchive than followed");
			}
		}
	}

	if (lists == 0) {
		return TRUE;
	}

	/*
	 * The name is read from the header only: unrar reads zeros after its
	 * end (7-Zip and libarchive refuse such a name), and a name past it
	 * would take bytes of the data or of the next headers
	 */
	name_len = raw.len > fh.name_off ? MIN(raw.len - fh.name_off, fh.name_size) : 0;

	if (name_len == 0) {
		/* unrar skips a file of no name and goes on */
		msg_debug_archive("rar archive has a file of no name");

		return TRUE;
	}

	return rspamd_archive_rar4_add_file(task, arch, p + fh.name_off, name_len, flags, &fh);
}

static void
rspamd_archive_process_rar_v4(struct rspamd_task *task, const unsigned char *start,
							  const unsigned char *end, struct rspamd_mime_part *part)
{
	/*
	 * Each reader, NULL once it stops. Readers agree on the archives rar
	 * writes, and part ways on blocks that only some of them skip with their
	 * data: each is followed, so the files that any of them lists are listed
	 */
	struct rspamd_rar4_walk w[RSPAMD_RAR4_WALKERS];
	struct rspamd_archive *arch;
	gboolean ended = FALSE;
	unsigned int r;

	arch = rspamd_mempool_alloc0(task->task_pool, sizeof(*arch));
	arch->files = g_ptr_array_new();
	arch->type = RSPAMD_ARCHIVE_RAR;
	if (part->cd) {
		arch->archive_name = &part->cd->filename;
	}
	rspamd_mempool_add_destructor(task->task_pool, rspamd_archive_dtor,
								  arch);
	if (!rspamd_archive_file_limit_check(task, arch)) {
		goto end;
	}

	memset(w, 0, sizeof(w));

	for (r = 0; r < RSPAMD_RAR4_WALK_LIBARCHIVE_FORK; r++) {
		w[r].at = start;
	}

	w[RSPAMD_RAR4_WALK_UNRAR].opening = TRUE;

	for (;;) {
		const unsigned char *p = NULL;
		unsigned int readers = 0;

		/* Readers only go forward, so the first header one is at comes first */
		for (r = 0; r < RSPAMD_RAR4_WALKERS; r++) {
			if (w[r].at != NULL && (p == NULL || w[r].at < p)) {
				p = w[r].at;
			}
		}

		if (p == NULL) {
			break;
		}

		for (r = 0; r < RSPAMD_RAR4_WALKERS; r++) {
			if (w[r].at == p) {
				readers |= 1u << r;
			}
		}

		if (!rspamd_archive_rar4_header(task, arch, start, end, p, readers, w, &ended)) {
			goto end;
		}
	}

	if (!ended && arch->files->len == 0) {
		/* Readers list the files before a broken or cut header, if any */
		return;
	}

end:
	part->part_type = RSPAMD_MIME_PART_ARCHIVE;
	part->specific.arch = arch;
	arch->size = part->parsed_data.len;
}

/* A number of the rar 5 format as unrar reads it in a header: zero past its end */
static uint64_t
rspamd_rar_raw_getv(struct rspamd_rar_raw *raw)
{
	uint64_t v = 0;

	for (unsigned int shift = 0; raw->pos < raw->len && shift < 64; shift += 7) {
		unsigned int c = raw->p[raw->pos++];

		v += (uint64_t) (c & 0x7f) << shift;

		if ((c & 0x80) == 0) {
			return v;
		}
	}

	return 0;
}

/* Whether extra records of a rar 5 file header hold an encryption record */
static gboolean
rspamd_rar5_extra_encrypted(const unsigned char *p, gsize len)
{
	struct rspamd_rar_raw raw = {p, len, 0};

	while (raw.len - raw.pos >= 2) {
		uint64_t field_size, field_end;

		field_size = rspamd_rar_raw_getv(&raw);

		if (field_size == 0 || field_size > raw.len - raw.pos) {
			break;
		}

		field_end = raw.pos + field_size;

		if (rspamd_rar_raw_getv(&raw) == 0x01) {
			return TRUE;
		}

		if (raw.pos > field_end) {
			break;
		}

		raw.pos = field_end;
	}

	return FALSE;
}

/*
 * Readers of rar 5 archives: unrar, which 7-Zip follows where it does not
 * stop first, and libarchive, which goes its own way
 */
enum rspamd_rar5_walker {
	RSPAMD_RAR5_WALK_UNRAR = 0,
	RSPAMD_RAR5_WALK_LIBARCHIVE,
	RSPAMD_RAR5_WALKERS,
};

/* Where a reader is, and what it keeps from a header to the next */
struct rspamd_rar5_walk {
	const unsigned char *at; /* NULL once it stops */
	gboolean opening;        /* unrar looks for the main header */
	gboolean volume;         /* libarchive: flags of the last main header */
	gboolean solid;
	gboolean window; /* libarchive has decoded the data of a solid file */
	uint64_t vol_no;
	uint64_t expected_vol_no;
};

/*
 * libarchive reads a header field after field from the stream, and never
 * goes to its declared end: the next header starts where its reads end
 */
struct rspamd_rar5_la {
	const unsigned char *p;
	const unsigned char *end;
};

/*
 * A number as libarchive reads it: 8 bytes from its start must be there, at
 * most 8 bytes are read, and a 9th one is taken, whatever it is, after 8
 * that go on
 */
static gboolean
rspamd_rar5_la_peek(const struct rspamd_rar5_la *c, uint64_t *v, unsigned int *len)
{
	uint64_t r = 0;
	unsigned int i;

	if (c->end - c->p < 8) {
		return FALSE;
	}

	for (i = 0; i < 8; i++) {
		r += (uint64_t) (c->p[i] & 0x7f) << (7 * i);

		if (!(c->p[i] & 0x80)) {
			*v = r;
			*len = i + 1;

			return TRUE;
		}
	}

	*v = r;
	*len = 9;

	return TRUE;
}

static gboolean
rspamd_rar5_la_skip(struct rspamd_rar5_la *c, uint64_t n)
{
	if (n > (uint64_t) (c->end - c->p)) {
		c->p = c->end;

		return FALSE;
	}

	c->p += n;

	return TRUE;
}

static gboolean
rspamd_rar5_la_var(struct rspamd_rar5_la *c, uint64_t *v)
{
	unsigned int len;

	return rspamd_rar5_la_peek(c, v, &len) && rspamd_rar5_la_skip(c, len);
}

/* A number that counts against the extra area, by the bytes it takes */
static gboolean
rspamd_rar5_la_extra_var(struct rspamd_rar5_la *c, int64_t *eds, uint64_t *v)
{
	unsigned int len;

	if (!rspamd_rar5_la_peek(c, v, &len)) {
		return FALSE;
	}

	*eds -= len;

	return rspamd_rar5_la_skip(c, len);
}

/*
 * The extra area of a file header, as libarchive 3.7 reads it: record sizes
 * are not used, each record takes what its parser reads, the result of the
 * last record counts, and an unknown record takes what is left of the area
 */
static gboolean
rspamd_rar5_la_extra(struct rspamd_rar5_la *c, int64_t eds)
{
	gboolean ok = FALSE;
	uint64_t v, id, n;
	unsigned int bit;

	while (eds > 0) {
		/* The size of the record, then its type */
		if (!rspamd_rar5_la_extra_var(c, &eds, &v) || !rspamd_rar5_la_extra_var(c, &eds, &id)) {
			return FALSE;
		}

		switch (id) {
		case 2:
			/* Hash: its type, and 32 bytes of BLAKE2sp */
			ok = FALSE;

			if (rspamd_rar5_la_extra_var(c, &eds, &v) && v == 0 && c->end - c->p >= 32) {
				c->p += 32;
				eds -= 32;
				ok = TRUE;
			}
			break;
		case 3:
			/* Times: four bytes each when unix, else eight, skipped when missing */
			ok = rspamd_rar5_la_extra_var(c, &eds, &v);

			if (ok) {
				unsigned int sz = (v & 0x1) ? 4 : 8;

				for (bit = 0x2; bit <= 0x8; bit <<= 1) {
					if ((v & bit) && c->end - c->p >= sz) {
						c->p += sz;
						eds -= sz;
					}
				}

				if (v & 0x10) {
					/* A field that is not there does not move it */
					ok = c->end - c->p >= 4;

					if (ok) {
						c->p += 4;
						eds -= 4;
					}
				}
			}
			break;
		case 5:
			/* Link: its type, flags and target, which counts as a byte and its length */
			ok = rspamd_rar5_la_extra_var(c, &eds, &v) && rspamd_rar5_la_extra_var(c, &eds, &v) &&
				 rspamd_rar5_la_var(c, &n);

			if (ok) {
				eds -= n + 1;
				ok = n <= (uint64_t) (c->end - c->p) && n > 0 && n < 2048;

				if (ok) {
					c->p += n;
				}
			}
			break;
		case 6:
			/* Owner: names that count as a byte and their length, then ids */
			ok = rspamd_rar5_la_extra_var(c, &eds, &v);

			for (bit = 0x1; ok && bit <= 0x2; bit <<= 1) {
				if (v & bit) {
					ok = rspamd_rar5_la_var(c, &n);

					if (ok) {
						eds -= n + 1;
						ok = n <= (uint64_t) (c->end - c->p);

						if (ok) {
							c->p += n;
						}
					}
				}
			}

			for (bit = 0x4; ok && bit <= 0x8; bit <<= 1) {
				if (v & bit) {
					ok = rspamd_rar5_la_extra_var(c, &eds, &n);
				}
			}
			break;
		case 4:
			/* Version: flags and the number */
			ok = rspamd_rar5_la_extra_var(c, &eds, &v) && rspamd_rar5_la_extra_var(c, &eds, &v);
			break;
		default:
			/* Encryption, service data and unknown records: the rest of the area */
			return eds >= 0 && rspamd_rar5_la_skip(c, eds);
		}
	}

	return ok;
}

/* The fields of a file or service header that libarchive reads, FALSE where it stops */
struct rspamd_rar5_la_file {
	uint64_t data_size;
	uint64_t unp_size;
	const unsigned char *name;
	gsize name_len;
	gboolean dir;
	unsigned int method;
};

static gboolean
rspamd_rar5_la_file_head(struct rspamd_rar5_la *c, const struct rspamd_rar5_walk *w,
						 uint64_t hflags, struct rspamd_rar5_la_file *fh)
{
	uint64_t eds = 0, ff, ci, host, ns, v;

	if ((hflags & 0x1) && !rspamd_rar5_la_var(c, &eds)) {
		return FALSE;
	}

	if (!(hflags & 0x2) || !rspamd_rar5_la_var(c, &fh->data_size)) {
		/* No data found in file/service block */
		return FALSE;
	}

	if (!rspamd_rar5_la_var(c, &ff) || !rspamd_rar5_la_var(c, &fh->unp_size) || (ff & 0x8)) {
		/* Files with unknown unpacked size are not supported */
		return FALSE;
	}

	fh->dir = (ff & 0x1) != 0;

	/* Attributes, then the mtime and the CRC */
	if (!rspamd_rar5_la_var(c, &v) ||
		((ff & 0x2) && !rspamd_rar5_la_skip(c, 4)) ||
		((ff & 0x4) && !rspamd_rar5_la_skip(c, 4)) ||
		!rspamd_rar5_la_var(c, &ci)) {
		return FALSE;
	}

	fh->method = (ci >> 7) & 7;

	if (((ci & 0x40) && !w->window) || (!fh->dir && ((ci >> 10) & 0xf) > 9)) {
		/* A solid file before any decoded one, or a window over 64 MiB */
		return FALSE;
	}

	if (!rspamd_rar5_la_var(c, &host) || host > 1 || !rspamd_rar5_la_var(c, &ns) ||
		ns > (uint64_t) (c->end - c->p) || ns == 0 || ns > 2047) {
		return FALSE;
	}

	fh->name = c->p;
	fh->name_len = ns;
	c->p += ns;

	/* The extra area size is signed, but numbers read are under 2^56 */
	return eds == 0 || rspamd_rar5_la_extra(c, (int64_t) eds);
}

/*
 * The data of an entry, as libarchive skips it: in a solid archive, the data
 * of a directory or of an unknown method stops it, and compressed data is
 * decoded (which is taken as a skip here)
 */
static const unsigned char *
rspamd_rar5_la_data(struct rspamd_rar5_la *c, struct rspamd_rar5_walk *w,
					const struct rspamd_rar5_la_file *fh, gboolean service)
{
	if (w->solid && fh->data_size > 0) {
		if (fh->dir || (!service && fh->method > 5)) {
			return NULL;
		}

		if (!service && fh->method > 0) {
			w->window = TRUE;
		}
	}

	return rspamd_rar5_la_skip(c, fh->data_size) ? c->p : NULL;
}

/*
 * libarchive 3.7 at the header at p: where it goes next (NULL once it
 * stops), and the name of the file it lists there, or NULL
 */
static void
rspamd_rar5_la_step(struct rspamd_archive *arch, struct rspamd_rar5_walk *w,
					const unsigned char *p, const unsigned char *end,
					struct rspamd_rar5_la_file *listed, gboolean *ended)
{
	static const unsigned char rar5_marker[] = {0x52, 0x61, 0x72, 0x21, 0x1A, 0x07, 0x01, 0x00};
	struct rspamd_rar5_la c = {p, end};
	struct rspamd_rar5_la_file fh;
	uint64_t raw, hs, type, hflags, v, es;
	unsigned int len;

	w->at = NULL;
	listed->name = NULL;

	if (end - p < 4) {
		return;
	}

	c.p += 4;

	if (!rspamd_rar5_la_peek(&c, &raw, &len)) {
		return;
	}

	hs = raw + len;

	/*
	 * Size limits and the whole header. Its CRC is not checked: libarchive
	 * stops at a bad one, but a CRC over each header, which can be 2 MiB
	 * long and start a few bytes after the one before, takes quadratic time,
	 * and following it past a broken header only lists more
	 */
	if (hs > 2 * 1024 * 1024 || raw == 0 || hs < 3 || hs > (uint64_t) (end - c.p)) {
		return;
	}

	c.p += len;

	if (!rspamd_rar5_la_var(&c, &type) || !rspamd_rar5_la_var(&c, &hflags)) {
		return;
	}

	memset(&fh, 0, sizeof(fh));

	switch (type) {
	case 1:
		/* Main: fields from the stream, without its data, padding or other records */
		es = 0;

		if (((hflags & 0x1) && !rspamd_rar5_la_var(&c, &es)) || !rspamd_rar5_la_var(&c, &v)) {
			return;
		}

		w->volume = (v & 0x1) != 0;
		w->solid = (v & 0x4) != 0;
		w->vol_no = 0;

		if ((v & 0x2) && (!rspamd_rar5_la_var(&c, &w->vol_no) || w->vol_no > G_MAXUINT32)) {
			return;
		}

		if (w->expected_vol_no > 0 && w->vol_no != w->expected_vol_no) {
			return;
		}

		if (es > 0) {
			uint64_t fs, id;

			/* Only a locator record is taken */
			if (!rspamd_rar5_la_var(&c, &fs) || !rspamd_rar5_la_var(&c, &id) || fs == 0 || id != 1 ||
				!rspamd_rar5_la_var(&c, &v) ||
				((v & 0x1) && !rspamd_rar5_la_var(&c, &fs)) ||
				((v & 0x2) && !rspamd_rar5_la_var(&c, &fs))) {
				return;
			}
		}

		w->at = c.p;
		break;
	case 2:
	case 3:
		if (!rspamd_rar5_la_file_head(&c, w, hflags, &fh)) {
			return;
		}

		if ((type == 2 && !(hflags & 0x8)) || (w->solid && fh.dir && fh.data_size > 0)) {
			/*
			 * A file that is not the rest of a split one is listed, and so is
			 * any entry that stops a solid archive with the data of a directory
			 */
			*listed = fh;
		}

		/* The data of the rest of a split service is skipped as that of a file */
		w->at = rspamd_rar5_la_data(&c, w, &fh, type == 3 && !(hflags & 0x8));
		break;
	case 4:
		arch->flags |= RSPAMD_ARCHIVE_ENCRYPTED;
		break;
	case 5:
		if (!w->volume) {
			*ended = TRUE;
		}
		else {
			const unsigned char *s = c.p;
			gboolean found = FALSE;

			/*
			 * The next volume: the signature at the first 504 offsets of
			 * each 512 bytes, else what is left after the last 512 bytes
			 */
			while (end - s >= 512 && !found) {
				goffset off = rspamd_substring_search((const char *) s, 511,
													  (const char *) rar5_marker, sizeof(rar5_marker));

				if (off >= 0) {
					s += off + sizeof(rar5_marker);
					found = TRUE;
				}
				else {
					s += 512;
				}
			}

			if (w->expected_vol_no != G_MAXUINT32) {
				w->expected_vol_no = (w->vol_no + 1) & G_MAXUINT32;
				w->at = s;
			}
		}
		break;
	case 0:
		break;
	default:
		if (hflags & 0x4) {
			/* Skipped if unknown: the rest of the header is read as headers */
			w->at = c.p;
		}
		break;
	}
}

/*
 * A file of a rar 5 archive. unrar_names adds the names unrar shows for its
 * bytes. FALSE once no more files fit
 */
static gboolean
rspamd_archive_rar5_add_file(struct rspamd_task *task, struct rspamd_archive *arch,
							 const unsigned char *name, gsize len, uint64_t uncomp_sz,
							 uint64_t comp_sz, gboolean encrypted, gboolean unrar_names)
{
	struct rspamd_archive_file *f = g_malloc0(sizeof(*f));

	f->uncompressed_size = uncomp_sz;
	f->compressed_size = comp_sz;
	rspamd_archive_file_try_utf(task, arch, f, name, len);

	if (f->fname == NULL) {
		g_free(f);

		return TRUE;
	}

	msg_debug_archive("added rarv5 file: %v", f->fname);

	if (encrypted) {
		f->flags |= RSPAMD_ARCHIVE_FILE_ENCRYPTED;
		arch->flags |= RSPAMD_ARCHIVE_ENCRYPTED;
	}

	if (!rspamd_archive_file_add(task, arch, f)) {
		return FALSE;
	}

	if (f->flags & RSPAMD_ARCHIVE_FILE_OBFUSCATED) {
		arch->flags |= RSPAMD_ARCHIVE_HAS_OBFUSCATED_FILES;
	}

	/* A name with a NUL is shown up to it, and as unrar decodes it */
	return !unrar_names ||
		   (rspamd_archive_file_add_cstr_name(task, arch, f, name, len) &&
			rspamd_archive_file_add_unrar_utf_name(task, arch, f, name, len));
}

/*
 * unrar at the header at p: headers are whole, and fields past their end
 * read as zero. While it looks for the main header, it skips the end block
 * and goes on after a broken header, from where it lists files. Sets where
 * it goes next (NULL once it stops) and the name listed. FALSE once no more
 * files fit
 */
static gboolean
rspamd_archive_rar5_unrar_step(struct rspamd_task *task, struct rspamd_archive *arch,
							   const unsigned char *arc_start, const unsigned char *end,
							   const unsigned char *p, struct rspamd_rar5_walk *w,
							   gboolean *ended, const unsigned char **listed, gsize *listed_len)
{
	struct rspamd_rar_raw raw;
	uint64_t block_size, head_size = 0, type, flags, extra_sz = 0, data_sz = 0;
	const unsigned char *next;
	int size_len;

	w->at = NULL;
	*listed = NULL;

	if (end - p < 7) {
		msg_debug_archive("rar archive is invalid (truncated block header)");

		return TRUE;
	}

	/* A CRC, then the size of the rest */
	size_len = rspamd_archive_rar_read_vint(p + 4, end - p - 4, &block_size);

	if (size_len > 0 && block_size > (uint64_t) (end - p) - 4 - size_len) {
		/* Readers stop at a cut header */
		msg_debug_archive("rar archive is invalid (truncated block)");

		return TRUE;
	}

	if (size_len > 0) {
		head_size = 4 + size_len + block_size;
	}

	if (head_size < 7) {
		/* No size, or too short for a type and flags */
		msg_debug_archive("rar archive is invalid (block of %L bytes)", head_size);

		if (w->opening) {
			/* unrar goes on after the 7 bytes it has read */
			w->opening = FALSE;
			w->at = p + 7;
		}

		return TRUE;
	}

	raw.p = p;
	raw.len = head_size;
	raw.pos = 4 + size_len;
	/* unrar keeps 32 bits of these */
	type = (uint32_t) rspamd_rar_raw_getv(&raw);
	flags = (uint32_t) rspamd_rar_raw_getv(&raw);

	if (type == 4) {
		/* We can't read any further information as headers are encrypted */
		arch->flags |= RSPAMD_ARCHIVE_ENCRYPTED;
		*ended = TRUE;

		return TRUE;
	}

	if (flags & 0x1) {
		/* Have extra zone */
		extra_sz = rspamd_rar_raw_getv(&raw);

		if (extra_sz >= head_size) {
			msg_debug_archive("rar archive is invalid (bad extra size)");

			if (w->opening) {
				/* unrar goes on after this header */
				w->opening = FALSE;
				w->at = p + head_size;
			}

			return TRUE;
		}
	}

	if (flags & 0x2) {
		/* Data zone is presented */
		data_sz = rspamd_rar_raw_getv(&raw);
	}

	if (w->opening && data_sz > (uint64_t) G_MAXINT64 - (p - arc_start) - head_size) {
		/* Data past the largest offset: unrar goes on after this header */
		w->opening = FALSE;
		w->at = p + head_size;

		return TRUE;
	}

	next = rspamd_rar_skip(p, end, head_size, data_sz);

	if (type == 5 && !w->opening) {
		/* The end of the archive */
		*ended = TRUE;

		return TRUE;
	}

	if (type == 1) {
		w->opening = FALSE;
	}
	else if (type == 2) {
		uint64_t file_flags, uncomp_sz, fname_len;
		gsize name_off, avail;

		file_flags = rspamd_rar_raw_getv(&raw);
		uncomp_sz = rspamd_rar_raw_getv(&raw);
		/* Attributes */
		(void) rspamd_rar_raw_getv(&raw);

		if (file_flags & 0x2) {
			/* Unix mtime */
			(void) rspamd_rar_raw_get4(&raw);
		}
		if (file_flags & 0x4) {
			/* Crc32 */
			(void) rspamd_rar_raw_get4(&raw);
		}

		/* Compression and host OS */
		(void) rspamd_rar_raw_getv(&raw);
		(void) rspamd_rar_raw_getv(&raw);
		fname_len = rspamd_rar_raw_getv(&raw);
		name_off = raw.pos;
		/* The name is read from the header only: unrar reads zeros after its end */
		avail = MIN(raw.len - name_off, fname_len);

		if (file_flags & 0x1) {
			/* Ignore directories for sanity purposes */
			msg_debug_archive("skip directory record in a rar archive");
		}
		else if (avail == 0) {
			/* unrar skips a file of no name and goes on */
			msg_debug_archive("rar archive has a file of no name");
		}
		else {
			gsize after_name = name_off + avail;
			/*
			 * The extra records: unrar reads them at the end of the header,
			 * past the name, 7-Zip right after the name
			 */
			gboolean encrypted = extra_sz > 0 &&
								 ((head_size - extra_sz >= after_name &&
								   rspamd_rar5_extra_encrypted(p + head_size - extra_sz, extra_sz)) ||
								  rspamd_rar5_extra_encrypted(p + after_name,
															  MIN(extra_sz, (uint64_t) (end - p) - after_name)));

			if (!rspamd_archive_rar5_add_file(task, arch, p + name_off, avail, uncomp_sz, data_sz,
											  encrypted, TRUE)) {
				return FALSE;
			}

			*listed = p + name_off;
			*listed_len = avail;
		}
	}

	if (next == NULL) {
		/* Readers stop where the data runs past the end */
		msg_debug_archive("rar archive is invalid (truncated data)");
	}

	w->at = next;

	return TRUE;
}

static void
rspamd_archive_process_rar(struct rspamd_task *task,
						   struct rspamd_mime_part *part)
{
	const unsigned char *p, *end;
	const unsigned char rar_v5_magic[] = {0x52, 0x61, 0x72, 0x21, 0x1A, 0x07, 0x01, 0x00},
						rar_v4_magic[] = {0x52, 0x61, 0x72, 0x21, 0x1A, 0x07, 0x00};
	struct rspamd_rar5_walk w[RSPAMD_RAR5_WALKERS];
	struct rspamd_archive *arch;
	gboolean ended = FALSE;
	unsigned int r;

	p = part->parsed_data.begin;
	end = p + part->parsed_data.len;

	if ((gsize) (end - p) <= sizeof(rar_v5_magic)) {
		msg_debug_archive("rar archive is invalid (too small)");

		return;
	}

	if (memcmp(p, rar_v5_magic, sizeof(rar_v5_magic)) == 0) {
		p += sizeof(rar_v5_magic);
	}
	else if (memcmp(p, rar_v4_magic, sizeof(rar_v4_magic)) == 0) {
		p += sizeof(rar_v4_magic);

		rspamd_archive_process_rar_v4(task, p, end, part);
		return;
	}
	else {
		msg_debug_archive("rar archive is invalid (no rar magic)");

		return;
	}

	/* Rar v5 format */
	arch = rspamd_mempool_alloc0(task->task_pool, sizeof(*arch));
	arch->files = g_ptr_array_new();
	arch->type = RSPAMD_ARCHIVE_RAR;
	if (part->cd) {
		arch->archive_name = &part->cd->filename;
	}
	rspamd_mempool_add_destructor(task->task_pool, rspamd_archive_dtor,
								  arch);
	if (!rspamd_archive_file_limit_check(task, arch)) {
		goto end;
	}

	/*
	 * Each reader, NULL once it stops. They agree on the archives rar
	 * writes; libarchive reads headers from the stream without going to
	 * their declared end, so bytes that unrar skips can hold other headers
	 * for it, and the files that either lists are listed
	 */
	memset(w, 0, sizeof(w));
	w[RSPAMD_RAR5_WALK_UNRAR].at = p;
	w[RSPAMD_RAR5_WALK_UNRAR].opening = TRUE;
	w[RSPAMD_RAR5_WALK_LIBARCHIVE].at = p;

	for (;;) {
		const unsigned char *cur = NULL, *listed = NULL;
		gsize listed_len = 0;
		unsigned int readers = 0;

		/* Readers only go forward, so the first header one is at comes first */
		for (r = 0; r < RSPAMD_RAR5_WALKERS; r++) {
			if (w[r].at != NULL && (cur == NULL || w[r].at < cur)) {
				cur = w[r].at;
			}
		}

		if (cur == NULL) {
			break;
		}

		for (r = 0; r < RSPAMD_RAR5_WALKERS; r++) {
			if (w[r].at == cur) {
				readers |= 1u << r;
			}
		}

		if ((readers & (1u << RSPAMD_RAR5_WALK_UNRAR)) &&
			!rspamd_archive_rar5_unrar_step(task, arch, part->parsed_data.begin, end, cur,
											&w[RSPAMD_RAR5_WALK_UNRAR], &ended, &listed, &listed_len)) {
			goto end;
		}

		if (readers & (1u << RSPAMD_RAR5_WALK_LIBARCHIVE)) {
			struct rspamd_rar5_la_file lf;

			rspamd_rar5_la_step(arch, &w[RSPAMD_RAR5_WALK_LIBARCHIVE], cur, end, &lf, &ended);

			if (lf.name != NULL) {
				/* libarchive shows a name up to its first NUL */
				const unsigned char *nul = memchr(lf.name, 0, lf.name_len);
				gsize len = nul ? (gsize) (nul - lf.name) : lf.name_len;

				if (listed != NULL) {
					const unsigned char *unul = memchr(listed, 0, listed_len);

					if (unul) {
						listed_len = unul - listed;
					}
				}

				if (len > 0 && !(listed && listed_len == len && memcmp(listed, lf.name, len) == 0) &&
					!rspamd_archive_rar5_add_file(task, arch, lf.name, len, lf.unp_size, lf.data_size,
												  FALSE, FALSE)) {
					goto end;
				}
			}
		}
	}

	if (!ended && arch->files->len == 0) {
		/* Readers list the files before a broken or cut header, if any */
		return;
	}

end:
	part->part_type = RSPAMD_MIME_PART_ARCHIVE;
	part->specific.arch = arch;
	arch->size = part->parsed_data.len;
}

static inline int
rspamd_archive_7zip_read_vint(const unsigned char *start, gsize remain, uint64_t *res)
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
	unsigned char t;

	if (remain == 0) {
		return -1;
	}

	t = *start;

	if (!isset(&t, 7)) {
		/* Trivial case */
		*res = t;
		return 1;
	}
	else if (t == 0xFF) {
		if (remain >= sizeof(uint64_t) + 1) {
			memcpy(res, start + 1, sizeof(uint64_t));
			*res = GUINT64_FROM_LE(*res);

			return sizeof(uint64_t) + 1;
		}
	}
	else {
		int cur_bit = 6, intlen = 1;
		const unsigned char bmask = 0xFF;
		uint64_t tgt = 0;

		while (cur_bit > 0) {
			if (!isset(&t, cur_bit)) {
				if (remain >= intlen + 1) {
					memcpy(&tgt, start + 1, intlen);
					tgt = GUINT64_FROM_LE(tgt);
					/*
					 * tgt was zero-initialised, so it now holds the
					 * intlen-byte little-endian value directly.
					 */
					/* Add masked value */
					tgt += (uint64_t) (t & (bmask >> (NBBY - cur_bit)))
						   << (NBBY * intlen);
					*res = tgt;

					return intlen + 1;
				}
			}
			cur_bit--;
			intlen++;
		}
	}

	return -1;
}

#define SZ_READ_VINT_SKIP()                                        \
	do {                                                           \
		r = rspamd_archive_7zip_read_vint(p, end - p, &vint);      \
		if (r == -1) {                                             \
			msg_debug_archive("7z archive is invalid (bad vint)"); \
			return;                                                \
		}                                                          \
		p += r;                                                    \
	} while (0)
#define SZ_READ_VINT(var)                                                        \
	do {                                                                         \
		int r;                                                                   \
		r = rspamd_archive_7zip_read_vint(p, end - p, &(var));                   \
		if (r == -1) {                                                           \
			msg_debug_archive("7z archive is invalid (bad vint): %s", G_STRLOC); \
			return NULL;                                                         \
		}                                                                        \
		p += r;                                                                  \
	} while (0)

#define SZ_READ_UINT64(n)                                                            \
	do {                                                                             \
		if (end - p < (goffset) sizeof(uint64_t)) {                                  \
			msg_debug_archive("7zip archive is invalid (bad uint64): %s", G_STRLOC); \
			return;                                                                  \
		}                                                                            \
		memcpy(&(n), p, sizeof(uint64_t));                                           \
		n = GUINT64_FROM_LE(n);                                                      \
		p += sizeof(uint64_t);                                                       \
	} while (0)
#define SZ_SKIP_BYTES(n)                                                                                                                           \
	do {                                                                                                                                           \
		if (end - p >= (n)) {                                                                                                                      \
			p += (n);                                                                                                                              \
		}                                                                                                                                          \
		else {                                                                                                                                     \
			msg_debug_archive("7zip archive is invalid (truncated); wanted to read %d bytes, %d avail: %s", (int) (n), (int) (end - p), G_STRLOC); \
			return NULL;                                                                                                                           \
		}                                                                                                                                          \
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


#define _7Z_CRYPTO_MAIN_ZIP 0x06F10101        /* Main Zip crypto algo */
#define _7Z_CRYPTO_RAR_29 0x06F10303          /* Rar29 AES-128 + (modified SHA-1) */
#define _7Z_CRYPTO_AES_256_SHA_256 0x06F10701 /* AES-256 + SHA-256 */

#define IS_SZ_ENCRYPTED(codec_id) (((codec_id) == _7Z_CRYPTO_MAIN_ZIP) || \
								   ((codec_id) == _7Z_CRYPTO_RAR_29) ||   \
								   ((codec_id) == _7Z_CRYPTO_AES_256_SHA_256))

static const unsigned char *
rspamd_7zip_read_bits(struct rspamd_task *task,
					  const unsigned char *p, const unsigned char *end,
					  struct rspamd_archive *arch, unsigned int nbits,
					  unsigned int *pbits_set)
{
	unsigned mask = 0, avail = 0, i;
	gboolean bit_set = 0;

	for (i = 0; i < nbits; i++) {
		if (mask == 0) {
			if (p >= end) {
				return NULL;
			}

			avail = *p;
			SZ_SKIP_BYTES(1);
			mask = 0x80;
		}

		bit_set = (avail & mask) ? 1 : 0;

		if (bit_set && pbits_set) {
			(*pbits_set)++;
		}

		mask >>= 1;
	}

	return p;
}

static const unsigned char *
rspamd_7zip_read_digest(struct rspamd_task *task,
						const unsigned char *p, const unsigned char *end,
						struct rspamd_archive *arch,
						uint64_t num_streams,
						unsigned int *pdigest_read)
{
	if (p >= end) {
		return NULL;
	}

	unsigned char all_defined = *p;
	uint64_t i;
	unsigned int num_defined = 0;
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

		p = rspamd_7zip_read_bits(task, p, end, arch, num_streams, &num_defined);

		if (p == NULL) {
			return NULL;
		}
	}

	for (i = 0; i < num_defined; i++) {
		SZ_SKIP_BYTES(sizeof(uint32_t));
	}

	if (pdigest_read) {
		*pdigest_read = num_defined;
	}

	return p;
}

static const unsigned char *
rspamd_7zip_read_pack_info(struct rspamd_task *task,
						   const unsigned char *p, const unsigned char *end,
						   struct rspamd_archive *arch)
{
	uint64_t pack_pos = 0, pack_streams = 0, i, cur_sz;
	unsigned int num_digests = 0;
	unsigned char t;
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
		msg_debug_archive("7zip: read pack info %xd", t);

		switch (t) {
		case kSize:
			/* We need to skip pack_streams VINTS */
			for (i = 0; i < pack_streams; i++) {
				SZ_READ_VINT(cur_sz);
			}
			break;
		case kCRC:
			/* CRCs are more complicated */
			p = rspamd_7zip_read_digest(task, p, end, arch, pack_streams,
										&num_digests);
			break;
		case kEnd:
			goto end;
			break;
		default:
			p = NULL;
			msg_debug_archive("bad 7zip type: %xd; %s", t, G_STRLOC);
			goto end;
			break;
		}
	}

end:

	return p;
}

static const unsigned char *
rspamd_7zip_read_folder(struct rspamd_task *task,
						const unsigned char *p, const unsigned char *end,
						struct rspamd_archive *arch, unsigned int *pnstreams, unsigned int *ndigests)
{
	uint64_t ncoders = 0, i, j, noutstreams = 0, ninstreams = 0;

	SZ_READ_VINT(ncoders);

	for (i = 0; i < ncoders && p != NULL && p < end; i++) {
		uint64_t sz, tmp;
		unsigned char t;
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
		SZ_SKIP_BYTES(1);
		sz = t & 0xF;
		/* Codec ID - validate bounds before reading */
		if (end - p < (goffset) sz) {
			msg_debug_archive("7zip archive is invalid (codec id truncated)");
			return NULL;
		}
		tmp = 0;
		for (j = 0; j < sz; j++) {
			tmp <<= 8;
			tmp += p[j];
		}

		msg_debug_archive("7zip: read codec id: %L", tmp);

		if (IS_SZ_ENCRYPTED(tmp)) {
			msg_debug_archive("7zip: encrypted codec: %L", tmp);
			arch->flags |= RSPAMD_ARCHIVE_ENCRYPTED;
		}

		SZ_SKIP_BYTES(sz);

		if (t & (1u << 4)) {
			/* Complex */
			SZ_READ_VINT(tmp); /* InStreams */
			ninstreams += tmp;
			SZ_READ_VINT(tmp); /* OutStreams */
			noutstreams += tmp;
		}
		else {
			/* XXX: is it correct ? */
			noutstreams++;
			ninstreams++;
		}
		if (t & (1u << 5)) {
			/* Attributes ... */
			SZ_READ_VINT(tmp); /* Size of attrs */
			SZ_SKIP_BYTES(tmp);
		}
	}

	if (noutstreams > 1) {
		/* BindPairs, WTF, huh */
		for (i = 0; i < noutstreams - 1; i++) {
			uint64_t tmp;

			SZ_READ_VINT(tmp);
			SZ_READ_VINT(tmp);
		}
	}

	int64_t npacked = (int64_t) ninstreams - (int64_t) noutstreams + 1;
	msg_debug_archive("7zip: instreams=%L, outstreams=%L, packed=%L",
					  ninstreams, noutstreams, npacked);

	if (npacked > 1) {
		/* Gah... */
		for (i = 0; i < npacked; i++) {
			uint64_t tmp;

			SZ_READ_VINT(tmp);
		}
	}

	*pnstreams = noutstreams;
	(*ndigests) += npacked;

	return p;
}

static const unsigned char *
rspamd_7zip_read_coders_info(struct rspamd_task *task,
							 const unsigned char *p, const unsigned char *end,
							 struct rspamd_archive *arch,
							 unsigned int *pnum_folders, unsigned int *pnum_nodigest)
{
	uint64_t num_folders = 0, i, tmp;
	unsigned char t;
	unsigned int *folder_nstreams = NULL, num_digests = 0, digests_read = 0;

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
		msg_debug_archive("7zip: read coders info %xd", t);

		switch (t) {
		case kFolder:
			SZ_READ_VINT(num_folders);
			msg_debug_archive("7zip: nfolders=%L", num_folders);

			if (num_folders > 8192) {
				/* Gah */
				msg_debug_archive("7zip: too many folders: %L", num_folders);
				return NULL;
			}

			if (p >= end) {
				msg_debug_archive("7zip archive is invalid (truncated); %s", G_STRLOC);
				return NULL;
			}

			if (*p != 0) {
				/*
				 * External folders are described in a separate stream that
				 * is not parsed here, so all subsequent folder metadata
				 * would be inconsistent
				 */
				msg_debug_archive("7zip: external folders are not supported");
				return NULL;
			}

			SZ_SKIP_BYTES(1);

			if (num_folders > 0) {
				folder_nstreams = rspamd_mempool_alloc0(task->task_pool,
														sizeof(*folder_nstreams) * num_folders);

				for (i = 0; i < num_folders && p != NULL && p < end; i++) {
					p = rspamd_7zip_read_folder(task, p, end, arch,
												&folder_nstreams[i], &num_digests);
				}
			}
			break;
		case kCodersUnPackSize:
			if (num_folders > 0 && folder_nstreams == NULL) {
				msg_debug_archive("7zip: unpacked sizes without a folders "
								  "definition; %s",
								  G_STRLOC);
				return NULL;
			}

			for (i = 0; i < num_folders; i++) {
				for (unsigned int j = 0; j < folder_nstreams[i]; j++) {
					SZ_READ_VINT(tmp); /* Unpacked size */
					msg_debug_archive("7zip: unpacked size "
									  "(folder=%d, stream=%d) = %L",
									  (int) i, j, tmp);
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
			p = rspamd_7zip_read_digest(task, p, end, arch, num_digests,
										&digests_read);
			break;
		case kEnd:
			goto end;
			break;
		default:
			p = NULL;
			msg_debug_archive("bad 7zip type: %xd; %s", t, G_STRLOC);
			goto end;
			break;
		}
	}

end:

	if (pnum_nodigest) {
		*pnum_nodigest = num_digests - digests_read;
	}
	if (pnum_folders) {
		/* Bounded by the check in the kFolder branch */
		*pnum_folders = (unsigned int) num_folders;
	}

	return p;
}

static const unsigned char *
rspamd_7zip_read_substreams_info(struct rspamd_task *task,
								 const unsigned char *p, const unsigned char *end,
								 struct rspamd_archive *arch,
								 unsigned int num_folders, unsigned int num_nodigest)
{
	unsigned char t;
	unsigned int i;
	uint64_t *folder_nstreams;

	if (num_folders > 8192) {
		/* Gah */
		return NULL;
	}

	folder_nstreams = rspamd_mempool_alloc(task->task_pool,
										   sizeof(uint64_t) * num_folders);

	/* Without kNumUnPackStream, every folder holds a single stream */
	for (i = 0; i < num_folders; i++) {
		folder_nstreams[i] = 1;
	}

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

		msg_debug_archive("7zip: read substream info %xd", t);

		switch (t) {
		case kNumUnPackStream:
			for (i = 0; i < num_folders; i++) {
				uint64_t tmp;

				SZ_READ_VINT(tmp);
				folder_nstreams[i] = tmp;
			}
			break;
		case kCRC: {
			/*
			 * Digests are listed per stream, except for single stream
			 * folders whose CRC is already known from the folder itself.
			 * Only the number of folders without a CRC is known here, which
			 * is exact when either all or none of them have one
			 */
			uint64_t num_streams = 0, num_single = 0;

			for (i = 0; i < num_folders; i++) {
				if (folder_nstreams[i] == 1) {
					num_single++;
				}
				else {
					num_streams += folder_nstreams[i];
				}
			}

			num_streams += MIN(num_single, num_nodigest);
			p = rspamd_7zip_read_digest(task, p, end, arch, num_streams,
										NULL);
			break;
		}
		case kSize:
			/*
			 * Sizes of all streams in a folder but the last one, which
			 * is implied by the folder unpacked size
			 */
			for (i = 0; i < num_folders; i++) {
				for (uint64_t j = 1; j < folder_nstreams[i]; j++) {
					uint64_t tmp;

					SZ_READ_VINT(tmp); /* Who cares indeed */
				}
			}
			break;
		case kEnd:
			goto end;
			break;
		default:
			p = NULL;
			msg_debug_archive("bad 7zip type: %xd; %s", t, G_STRLOC);
			goto end;
			break;
		}
	}

end:
	return p;
}

static const unsigned char *
rspamd_7zip_read_main_streams_info(struct rspamd_task *task,
								   const unsigned char *p, const unsigned char *end,
								   struct rspamd_archive *arch)
{
	unsigned char t;
	unsigned int num_folders = 0, unknown_digests = 0;
	/*
	 * Each of the sections below allocates per folder, and a repeated one
	 * would allocate again for the same folders: allow each only once
	 */
	unsigned int seen_sections = 0;

	while (p != NULL && p < end) {
		t = *p;
		SZ_SKIP_BYTES(1);
		msg_debug_archive("7zip: read main streams info %xd", t);

		if (t == kPackInfo || t == kUnPackInfo || t == kSubStreamsInfo) {
			if (seen_sections & (1u << t)) {
				msg_debug_archive("7zip: duplicate streams info section %xd; %s",
								  t, G_STRLOC);
				p = NULL;
				goto end;
			}

			seen_sections |= 1u << t;
		}

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
			p = rspamd_7zip_read_pack_info(task, p, end, arch);
			break;
		case kUnPackInfo:
			p = rspamd_7zip_read_coders_info(task, p, end, arch, &num_folders,
											 &unknown_digests);
			break;
		case kSubStreamsInfo:
			p = rspamd_7zip_read_substreams_info(task, p, end, arch, num_folders,
												 unknown_digests);
			break;
			break;
		case kEnd:
			goto end;
			break;
		default:
			p = NULL;
			msg_debug_archive("bad 7zip type: %xd; %s", t, G_STRLOC);
			goto end;
			break;
		}
	}

end:
	return p;
}

static const unsigned char *
rspamd_7zip_read_archive_props(struct rspamd_task *task,
							   const unsigned char *p, const unsigned char *end,
							   struct rspamd_archive *arch)
{
	unsigned char proptype;
	uint64_t proplen;

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

	if (p != NULL && p < end) {
		proptype = *p;
		SZ_SKIP_BYTES(1);

		while (proptype != 0) {
			SZ_READ_VINT(proplen);

			/*
			 * proplen is a 64-bit varint; compare sizes to avoid
			 * a pointer-arithmetic wrap (p + proplen < end).
			 */
			if (proplen < (uint64_t) (end - p)) {
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

/*
 * 7z stores names as UTF-16LE at any offset of the header, so code units are
 * assembled from bytes: a uint16_t load there is misaligned and host-endian
 */
static inline UChar32
rspamd_7zip_utf16le_unit(const unsigned char *p, gsize idx)
{
	return (UChar32) p[idx * 2] | ((UChar32) p[idx * 2 + 1] << 8);
}

/*
 * Converts a UTF-16LE name; an unpaired surrogate becomes U+FFFD and sets
 * `obfuscated` rather than losing the whole name (and its extension)
 */
static GString *
rspamd_7zip_ucs2_to_utf8(struct rspamd_task *task, const unsigned char *p,
						 const unsigned char *end, gboolean *obfuscated)
{
	GString *res;
	goffset dest_pos = 0;
	gsize src_pos = 0;
	const gsize len = (end - p) / sizeof(uint16_t);
	UChar32 wc, trail;
	UBool is_error = 0;

	res = g_string_sized_new((end - p) * 3 / 2 + sizeof(wc) + 1);

	while (src_pos < len) {
		/* U16_NEXT on units read in little-endian order */
		wc = rspamd_7zip_utf16le_unit(p, src_pos++);

		if (U16_IS_LEAD(wc) && src_pos < len) {
			trail = rspamd_7zip_utf16le_unit(p, src_pos);

			if (U16_IS_TRAIL(trail)) {
				src_pos++;
				wc = U16_GET_SUPPLEMENTARY(wc, trail);
			}
		}

		if (U_IS_SURROGATE(wc)) {
			wc = 0xFFFD;
			*obfuscated = TRUE;
		}

		if (wc > 0) {
			U8_APPEND(res->str, dest_pos,
					  res->allocated_len - 1,
					  wc, is_error);
		}

		if (is_error) {
			g_string_free(res, TRUE);

			return NULL;
		}
	}

	g_assert(dest_pos < res->allocated_len);

	res->len = dest_pos;
	res->str[dest_pos] = '\0';

	return res;
}

static const unsigned char *
rspamd_7zip_read_files_info(struct rspamd_task *task,
							const unsigned char *p, const unsigned char *end,
							struct rspamd_archive *arch)
{
	uint64_t nfiles = 0, sz, i;
	unsigned char t, b;
	struct rspamd_archive_file *fentry;

	SZ_READ_VINT(nfiles);

	for (; p != NULL && p < end;) {
		t = *p;
		SZ_SKIP_BYTES(1);

		msg_debug_archive("7zip: read file data type %xd", t);

		if (t == kEnd) {
			goto end;
		}

		/* This is SO SPECIAL, gah */
		SZ_READ_VINT(sz);

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
				SZ_SKIP_BYTES(sz);
			}
			break;
		case kName: {
			/* The most useful part in this whole bloody format */
			const unsigned char *names_end;

			/* The external flag and the names must fit the property */
			if (sz == 0 || sz > (uint64_t) (end - p)) {
				msg_debug_archive("bad 7zip names size; %s", G_STRLOC);
				p = NULL;
				goto end;
			}

			names_end = p + sz;
			b = *p; /* External flag */
			p++;

			if (!b) {
				/*
				 * External names (b != 0) are stored in a separate stream
				 * and are not parsed here
				 */
				for (i = 0; i < nfiles; i++) {
					/* Zero terminated wchar_t: happy converting... */
					/* First, find terminator */
					const unsigned char *fend = NULL, *tp = p;
					GString *res;

					while (tp + 1 < names_end) {
						if (*tp == 0 && *(tp + 1) == 0) {
							fend = tp;
							break;
						}

						tp += 2;
					}

					if (fend == NULL || fend - p == 0) {
						/* Crap instead of fname */
						msg_debug_archive("bad 7zip name; %s", G_STRLOC);
						goto end;
					}

					gboolean obfuscated = FALSE;

					res = rspamd_7zip_ucs2_to_utf8(task, p, fend, &obfuscated);

					if (res != NULL) {
						fentry = g_malloc0(sizeof(*fentry));
						fentry->fname = res;

						if (obfuscated) {
							fentry->flags |= RSPAMD_ARCHIVE_FILE_OBFUSCATED;
							arch->flags |= RSPAMD_ARCHIVE_HAS_OBFUSCATED_FILES;
						}

						if (!rspamd_archive_file_add(task, arch, fentry)) {
							p = NULL;
							goto end;
						}
						msg_debug_archive("7zip: found file %v", res);
					}
					else {
						msg_debug_archive("bad 7zip name; %s", G_STRLOC);
					}
					/* Skip zero terminating character */
					p = fend + 2;
				}
			}

			p = names_end;
			break;
		}
		case kDummy:
		case kWinAttributes:
			if (sz > 0) {
				SZ_SKIP_BYTES(sz);
			}
			break;
		default:
			p = NULL;
			msg_debug_archive("bad 7zip type: %xd; %s", t, G_STRLOC);
			goto end;
			break;
		}
	}

end:
	return p;
}

#ifdef HAVE_USELOCALE
/*
 * libarchive converts 7z names (UTF-16LE) to the charset of the current
 * locale, and rspamd runs in the C locale unless LANG is set: there every
 * non-ASCII name fails to convert. The names are converted in a UTF-8 locale
 * instead, created once; (locale_t) 0 if the system has none
 */
static locale_t
rspamd_archive_utf8_locale(void)
{
	static locale_t utf8_locale = (locale_t) 0;
	static gboolean initialized = FALSE;

	if (!initialized) {
		static const char *names[] = {"C.UTF-8", "en_US.UTF-8", "UTF-8"};

		initialized = TRUE;

		for (unsigned int i = 0; i < G_N_ELEMENTS(names) && utf8_locale == (locale_t) 0; i++) {
			utf8_locale = newlocale(LC_CTYPE_MASK, names[i], (locale_t) 0);
		}
	}

	return utf8_locale;
}
#endif

static const unsigned char *
rspamd_7zip_read_next_section(struct rspamd_task *task,
							  const unsigned char *p, const unsigned char *end,
							  struct rspamd_archive *arch,
							  struct rspamd_mime_part *part)
{
	if (p >= end) {
		return NULL;
	}

	unsigned char t = *p;

	SZ_SKIP_BYTES(1);

	msg_debug_archive("7zip: read section %xd", t);

	switch (t) {
	case kHeader:
		/* We just skip byte and go further */
		break;
	case kEncodedHeader:
		/*
		 * In fact, headers are just packed, but we assume it as
		 * encrypted to distinguish from the normal archives
		 */
		{
			msg_debug_archive("7zip: encoded header, needs to be uncompressed");
			struct archive *a = archive_read_new();
			archive_read_support_format_7zip(a);
			int r = archive_read_open_memory(a, part->parsed_data.begin, part->parsed_data.len);
			if (r != ARCHIVE_OK) {
				msg_debug_archive("7zip: cannot open memory archive: %s", archive_error_string(a));
				archive_read_free(a);
				return NULL;
			}

			/* Clean the existing files if any */
			rspamd_archive_files_reset(task, arch);

			struct archive_entry *ae;
			/* Whether a name that fails to convert is not valid UTF-16 */
			gboolean names_utf8 = FALSE;
#ifdef HAVE_USELOCALE
			locale_t utf8_locale = rspamd_archive_utf8_locale(), old_locale = (locale_t) 0;

			if (utf8_locale != (locale_t) 0) {
				old_locale = uselocale(utf8_locale);
				names_utf8 = TRUE;
			}
#endif

			/*
			 * A name that does not convert gives ARCHIVE_WARN: the entry is
			 * still read, and the entries after it too
			 */
			while ((r = archive_read_next_header(a, &ae)) == ARCHIVE_OK || r == ARCHIVE_WARN) {
				const char *name = archive_entry_pathname_utf8(ae);
				struct rspamd_archive_file *f = NULL;

				if (name) {
					msg_debug_archive("7zip: found file %s", name);
					f = g_malloc0(sizeof(*f));
					f->fname = g_string_new(name);
				}
				else if (r == ARCHIVE_WARN) {
					/*
					 * libarchive gives nothing of a name it cannot convert: the
					 * file is kept with U+FFFD for a name, and flagged as a bad
					 * name in a plain header is
					 */
					msg_debug_archive("7zip: found file with a name that cannot be converted");
					f = g_malloc0(sizeof(*f));
					f->fname = g_string_new("\xEF\xBF\xBD");

					if (names_utf8) {
						f->flags |= RSPAMD_ARCHIVE_FILE_OBFUSCATED;
						arch->flags |= RSPAMD_ARCHIVE_HAS_OBFUSCATED_FILES;
					}
				}

				if (f != NULL && !rspamd_archive_file_add(task, arch, f)) {
					break;
				}

				archive_read_data_skip(a);
			}

#ifdef HAVE_USELOCALE
			if (utf8_locale != (locale_t) 0) {
				uselocale(old_locale);
			}
#endif

			if (archive_read_has_encrypted_entries(a) > 0) {
				msg_debug_archive("7zip: found encrypted stuff");
				arch->flags |= RSPAMD_ARCHIVE_ENCRYPTED;
			}

			archive_read_free(a);
			p = NULL; /* Stop internal processor, as we rely on libarchive here */
			break;
		}
	case kArchiveProperties:
		p = rspamd_7zip_read_archive_props(task, p, end, arch);
		break;
	case kMainStreamsInfo:
		p = rspamd_7zip_read_main_streams_info(task, p, end, arch);
		break;
	case kAdditionalStreamsInfo:
		p = rspamd_7zip_read_main_streams_info(task, p, end, arch);
		break;
	case kFilesInfo:
		p = rspamd_7zip_read_files_info(task, p, end, arch);
		break;
	case kEnd:
		p = NULL;
		msg_debug_archive("7zip: read final section");
		break;
	default:
		p = NULL;
		msg_debug_archive("bad 7zip type: %xd; %s", t, G_STRLOC);
		break;
	}

	return p;
}

static void
rspamd_archive_process_7zip(struct rspamd_task *task,
							struct rspamd_mime_part *part)
{
	struct rspamd_archive *arch;
	const unsigned char *start, *p, *end;
	const unsigned char sz_magic[] = {'7', 'z', 0xBC, 0xAF, 0x27, 0x1C};
	uint64_t section_offset = 0, section_length = 0;

	start = part->parsed_data.begin;
	p = start;
	end = p + part->parsed_data.len;

	if (end - p <= sizeof(uint64_t) + sizeof(uint32_t) ||
		memcmp(p, sz_magic, sizeof(sz_magic)) != 0) {
		msg_debug_archive("7z archive is invalid (no 7z magic)");

		return;
	}

	arch = rspamd_mempool_alloc0(task->task_pool, sizeof(*arch));
	arch->files = g_ptr_array_new();
	arch->type = RSPAMD_ARCHIVE_7ZIP;
	rspamd_mempool_add_destructor(task->task_pool, rspamd_archive_dtor,
								  arch);
	if (!rspamd_archive_file_limit_check(task, arch)) {
		goto end;
	}

	/* Magic (6 bytes) + version (2 bytes) + crc32 (4 bytes) */
	p += sizeof(uint64_t) + sizeof(uint32_t);

	SZ_READ_UINT64(section_offset);
	SZ_READ_UINT64(section_length);

	if (end - p > sizeof(uint32_t)) {
		p += sizeof(uint32_t);
	}
	else {
		msg_debug_archive("7z archive is invalid (truncated crc)");

		return;
	}

	if (end - p > section_offset) {
		p += section_offset;
	}
	else {
		msg_debug_archive("7z archive is invalid (incorrect section offset)");

		return;
	}

	while ((p = rspamd_7zip_read_next_section(task, p, end, arch, part)) != NULL);

end:
	part->part_type = RSPAMD_MIME_PART_ARCHIVE;
	part->specific.arch = arch;
	if (part->cd != NULL) {
		arch->archive_name = &part->cd->filename;
	}
	arch->size = part->parsed_data.len;
}

static void
rspamd_archive_process_gzip(struct rspamd_task *task,
							struct rspamd_mime_part *part)
{
	struct rspamd_archive *arch;
	const unsigned char *start, *p, *end;
	const unsigned char gz_magic[] = {0x1F, 0x8B};
	unsigned char flags;

	start = part->parsed_data.begin;
	p = start;
	end = p + part->parsed_data.len;

	if (end - p <= 10 || memcmp(p, gz_magic, sizeof(gz_magic)) != 0) {
		msg_debug_archive("gzip archive is invalid (no gzip magic)");

		return;
	}

	arch = rspamd_mempool_alloc0(task->task_pool, sizeof(*arch));
	arch->files = g_ptr_array_sized_new(1);
	arch->type = RSPAMD_ARCHIVE_GZIP;
	if (part->cd) {
		arch->archive_name = &part->cd->filename;
	}
	rspamd_mempool_add_destructor(task->task_pool, rspamd_archive_dtor,
								  arch);
	if (!rspamd_archive_file_limit_check(task, arch)) {
		goto set;
	}

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
			uint16_t optlen = 0;

			if (end - p < (glong) sizeof(uint16_t)) {
				msg_debug_archive("gzip archive is invalid (bad int16)");
				return;
			}

			optlen = p[0] + (p[1] << 8);
			p += sizeof(uint16_t);

			if (end <= p + optlen) {
				msg_debug_archive("gzip archive is invalid, bad extra length: %d",
								  (int) optlen);

				return;
			}

			p += optlen;
		}

		/* Read file name */
		const unsigned char *fname_start = p;

		while (p < end) {
			if (*p == '\0') {
				if (p > fname_start) {
					struct rspamd_archive_file *f;

					f = g_malloc0(sizeof(*f));

					rspamd_archive_file_try_utf(task, arch, f,
												fname_start, p - fname_start);

					if (f->fname) {
						if (!rspamd_archive_file_add(task, arch, f)) {
							goto set;
						}

						if (f->flags & RSPAMD_ARCHIVE_FILE_OBFUSCATED) {
							arch->flags |= RSPAMD_ARCHIVE_HAS_OBFUSCATED_FILES;
						}
					}
					else {
						/* Invalid filename, skip */
						g_free(f);
					}

					goto set;
				}
			}

			p++;
		}

		/* Wrong filename, not zero terminated */
		msg_debug_archive("gzip archive is invalid, bad filename at pos %d",
						  (int) (p - start));

		return;
	}

	/* Fallback, we need to extract file name from archive name if possible */
	if (part->cd && part->cd->filename.len > 0) {
		const char *dot_pos, *slash_pos;

		dot_pos = rspamd_memrchr(part->cd->filename.begin, '.',
								 part->cd->filename.len);

		if (dot_pos) {
			struct rspamd_archive_file *f;

			slash_pos = rspamd_memrchr(part->cd->filename.begin, '/',
									   part->cd->filename.len);

			if (slash_pos && slash_pos < dot_pos) {
				f = g_malloc0(sizeof(*f));
				f->fname = g_string_sized_new(dot_pos - slash_pos);
				g_string_append_len(f->fname, slash_pos + 1,
									dot_pos - slash_pos - 1);

				msg_debug_archive("fallback to gzip filename based on cd: %v",
								  f->fname);

				if (!rspamd_archive_file_add(task, arch, f)) {
					goto set;
				}

				goto set;
			}
			else {
				const char *fname_start = part->cd->filename.begin;

				f = g_malloc0(sizeof(*f));

				if (memchr(fname_start, '.', part->cd->filename.len) != dot_pos) {
					/* Double dots, something like foo.exe.gz */
					f->fname = g_string_sized_new(dot_pos - fname_start);
					g_string_append_len(f->fname, fname_start,
										dot_pos - fname_start);
				}
				else {
					/* Single dot, something like foo.gzz */
					f->fname = g_string_sized_new(part->cd->filename.len);
					g_string_append_len(f->fname, fname_start,
										part->cd->filename.len);
				}

				msg_debug_archive("fallback to gzip filename based on cd: %v",
								  f->fname);

				if (!rspamd_archive_file_add(task, arch, f)) {
					goto set;
				}

				goto set;
			}
		}
	}

	return;

set:
	/* Set archive data */
	part->part_type = RSPAMD_MIME_PART_ARCHIVE;
	part->specific.arch = arch;
	arch->size = part->parsed_data.len;
}

static gboolean
rspamd_archive_cheat_detect(struct rspamd_mime_part *part, const char *str,
							const unsigned char *magic_start, gsize magic_len)
{
	struct rspamd_content_type *ct;
	const char *p;
	rspamd_ftok_t srch, *fname;

	ct = part->ct;
	RSPAMD_FTOK_ASSIGN(&srch, "application");

	if (ct && ct->type.len && ct->subtype.len > 0 && rspamd_ftok_cmp(&ct->type, &srch) == 0) {
		if (rspamd_substring_search_caseless(ct->subtype.begin, ct->subtype.len,
											 str, strlen(str)) != -1) {
			/* We still need to check magic, see #1848 */
			if (magic_start != NULL) {
				if (part->parsed_data.len > magic_len &&
					memcmp(part->parsed_data.begin,
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

		if (fname && fname->len > strlen(str)) {
			p = fname->begin + fname->len - strlen(str);

			if (rspamd_lc_cmp(p, str, strlen(str)) == 0) {
				if (*(p - 1) == '.') {
					if (magic_start != NULL) {
						if (part->parsed_data.len > magic_len &&
							memcmp(part->parsed_data.begin,
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
				memcmp(part->parsed_data.begin, magic_start, magic_len) == 0) {
				return TRUE;
			}
		}
	}
	else {
		if (magic_start != NULL) {
			if (part->parsed_data.len > magic_len &&
				memcmp(part->parsed_data.begin, magic_start, magic_len) == 0) {
				return TRUE;
			}
		}
	}

	return FALSE;
}

void rspamd_archives_process(struct rspamd_task *task)
{
	unsigned int i;
	struct rspamd_mime_part *part;

	PTR_ARRAY_FOREACH(MESSAGE_FIELD(task, parts), i, part)
	{
		if (part->parsed_data.len > 0 && part->part_type != RSPAMD_MIME_PART_ARCHIVE) {
			const char *ext = part->detected_ext;
			if (ext) {
				if (g_ascii_strcasecmp(ext, "zip") == 0) {
					rspamd_archive_process_zip(task, part);
				}
				else if (g_ascii_strcasecmp(ext, "rar") == 0) {
					rspamd_archive_process_rar(task, part);
				}
				else if (g_ascii_strcasecmp(ext, "7z") == 0) {
					rspamd_archive_process_7zip(task, part);
				}
				else if (g_ascii_strcasecmp(ext, "gz") == 0) {
					rspamd_archive_process_gzip(task, part);
				}
			}

			if (part->ct && (part->ct->flags & RSPAMD_CONTENT_TYPE_TEXT) &&
				part->part_type == RSPAMD_MIME_PART_ARCHIVE &&
				part->specific.arch) {
				struct rspamd_archive *arch = part->specific.arch;

				msg_info_task("found %s archive with incorrect content-type: %T/%T",
							  rspamd_archive_type_str(arch->type),
							  &part->ct->type, &part->ct->subtype);

				if (!(part->ct->flags & RSPAMD_CONTENT_TYPE_MISSING)) {
					part->ct->flags |= RSPAMD_CONTENT_TYPE_BROKEN;
				}
			}
		}
	}
}


const char *
rspamd_archive_type_str(enum rspamd_archive_type type)
{
	const char *ret = "unknown";

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
