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
	struct rspamd_archive_file *cf;

	if (nul == NULL || nul == name || f->fname == NULL) {
		return TRUE;
	}

	cf = g_malloc0(sizeof(*cf));
	rspamd_archive_file_try_utf(task, arch, cf, (const char *) name, nul - name);

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

#define RAR_SKIP_BYTES(n)                                                 \
	do {                                                                  \
		if ((n) <= 0) {                                                   \
			msg_debug_archive("rar archive is invalid (bad skip value)"); \
			return;                                                       \
		}                                                                 \
		if ((gsize) (end - p) < (n)) {                                    \
			msg_debug_archive("rar archive is invalid (truncated)");      \
			return;                                                       \
		}                                                                 \
		p += (n);                                                         \
	} while (0)

#define RAR_READ_VINT()                                                    \
	do {                                                                   \
		r = rspamd_archive_rar_read_vint(p, end - p, &vint);               \
		if (r == -1) {                                                     \
			msg_debug_archive("rar archive is invalid (bad vint)");        \
			return;                                                        \
		}                                                                  \
		else if (r == 0) {                                                 \
			msg_debug_archive("rar archive is invalid (BAD vint offset)"); \
			return;                                                        \
		}                                                                  \
	} while (0)

#define RAR_READ_VINT_SKIP()                                        \
	do {                                                            \
		r = rspamd_archive_rar_read_vint(p, end - p, &vint);        \
		if (r == -1) {                                              \
			msg_debug_archive("rar archive is invalid (bad vint)"); \
			return;                                                 \
		}                                                           \
		p += r;                                                     \
	} while (0)

#define RAR_READ_UINT16(n)                                           \
	do {                                                             \
		if (end - p < (glong) sizeof(uint16_t)) {                    \
			msg_debug_archive("rar archive is invalid (bad int16)"); \
			return;                                                  \
		}                                                            \
		n = p[0] + (p[1] << 8);                                      \
		p += sizeof(uint16_t);                                       \
	} while (0)

#define RAR_READ_UINT32(n)                                                                                                \
	do {                                                                                                                  \
		if (end - p < (glong) sizeof(uint32_t)) {                                                                         \
			msg_debug_archive("rar archive is invalid (bad int32)");                                                      \
			return;                                                                                                       \
		}                                                                                                                 \
		n = (unsigned int) p[0] + ((unsigned int) p[1] << 8) + ((unsigned int) p[2] << 16) + ((unsigned int) p[3] << 24); \
		p += sizeof(uint32_t);                                                                                            \
	} while (0)

static void
rspamd_archive_process_rar_v4(struct rspamd_task *task, const unsigned char *start,
							  const unsigned char *end, struct rspamd_mime_part *part)
{
	const unsigned char *p = start, *start_section;
	uint8_t type;
	unsigned int flags;
	uint64_t sz, comp_sz = 0, uncomp_sz = 0;
	struct rspamd_archive *arch;
	struct rspamd_archive_file *f;

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

	while (p < end) {
		/* Crc16 */
		start_section = p;
		RAR_SKIP_BYTES(sizeof(uint16_t));

		if (p >= end) {
			msg_debug_archive("rar archive is invalid (truncated block header)");
			return;
		}

		type = *p;
		p++;
		RAR_READ_UINT16(flags);

		if (type == 0x73) {
			/* Main header, check for encryption */
			if (flags & 0x80) {
				arch->flags |= RSPAMD_ARCHIVE_ENCRYPTED;
				goto end;
			}
		}

		RAR_READ_UINT16(sz);

		if (flags & 0x8000) {
			/* We also need to read ADD_SIZE element */
			uint32_t tmp;

			RAR_READ_UINT32(tmp);
			sz += tmp;
			/* This is also used as PACK_SIZE */
			comp_sz = tmp;
		}

		if (sz == 0) {
			/* Zero sized block - error */
			msg_debug_archive("rar archive is invalid (zero size block)");

			return;
		}

		if (type == 0x74) {
			unsigned int fname_len;

			/* File header */
			/* Uncompressed size */
			RAR_READ_UINT32(uncomp_sz);
			/* Skip to NAME_SIZE element */
			RAR_SKIP_BYTES(11);
			RAR_READ_UINT16(fname_len);

			if (fname_len == 0 || fname_len > (gsize) (end - p)) {
				msg_debug_archive("rar archive is invalid (bad filename size: %d)",
								  fname_len);

				return;
			}

			/* Attrs */
			RAR_SKIP_BYTES(4);

			if (flags & 0x100) {
				/* We also need to read HIGH_PACK_SIZE */
				uint32_t tmp;

				RAR_READ_UINT32(tmp);
				sz += tmp;
				comp_sz += tmp;
				/* HIGH_UNP_SIZE  */
				RAR_READ_UINT32(tmp);
				uncomp_sz += tmp;
			}

			/*
			 * p advanced past the attrs and optional HIGH_*_SIZE fields
			 * after fname_len was validated above, so re-check it against
			 * the remaining buffer before reading the filename.
			 */
			if (fname_len > (gsize) (end - p)) {
				msg_debug_archive("rar archive is invalid (truncated filename)");

				return;
			}

			f = g_malloc0(sizeof(*f));

			if (flags & 0x200) {
				/* We have unicode + normal version */
				unsigned char *tmp;

				tmp = memchr(p, '\0', fname_len);

				if (tmp != NULL) {
					/* Just use ASCII version */
					rspamd_archive_file_try_utf(task, arch, f, p, tmp - p);
					msg_debug_archive("found ascii filename in rarv4 archive: %v",
									  f->fname);
				}
				else {
					/* We have UTF8 filename, use it as is */
					rspamd_archive_file_try_utf(task, arch, f, p, fname_len);
					msg_debug_archive("found utf filename in rarv4 archive: %v",
									  f->fname);
				}
			}
			else {
				rspamd_archive_file_try_utf(task, arch, f, p, fname_len);
				msg_debug_archive("found ascii (old) filename in rarv4 archive: %v",
								  f->fname);
			}

			f->compressed_size = comp_sz;
			f->uncompressed_size = uncomp_sz;

			if (flags & 0x4) {
				f->flags |= RSPAMD_ARCHIVE_FILE_ENCRYPTED;
			}

			if (f->fname) {
				if (f->flags & RSPAMD_ARCHIVE_FILE_OBFUSCATED) {
					arch->flags |= RSPAMD_ARCHIVE_HAS_OBFUSCATED_FILES;
				}
				if (!rspamd_archive_file_add(task, arch, f)) {
					goto end;
				}

				/* A name with a NUL is shown up to it (a Unicode name follows its NUL) */
				if (!(flags & 0x200) &&
					!rspamd_archive_file_add_cstr_name(task, arch, f, p, fname_len)) {
					goto end;
				}
			}
			else {
				g_free(f);
			}
		}

		p = start_section;
		RAR_SKIP_BYTES(sz);
	}

end:
	part->part_type = RSPAMD_MIME_PART_ARCHIVE;
	part->specific.arch = arch;
	arch->size = part->parsed_data.len;
}

static void
rspamd_archive_process_rar(struct rspamd_task *task,
						   struct rspamd_mime_part *part)
{
	const unsigned char *p, *end, *section_start;
	const unsigned char rar_v5_magic[] = {0x52, 0x61, 0x72, 0x21, 0x1A, 0x07, 0x01, 0x00},
						rar_v4_magic[] = {0x52, 0x61, 0x72, 0x21, 0x1A, 0x07, 0x00};
	const unsigned int rar_encrypted_header = 4, rar_main_header = 1,
					   rar_file_header = 2;
	uint64_t vint, sz, comp_sz = 0, uncomp_sz = 0, flags = 0, type = 0,
					   extra_sz = 0;
	struct rspamd_archive *arch;
	struct rspamd_archive_file *f;
	int r;

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

	/* Now we can have either encryption header or archive header */
	/* Crc 32 */
	RAR_SKIP_BYTES(sizeof(uint32_t));
	/* Size */
	RAR_READ_VINT_SKIP();
	sz = vint;
	/* Type */
	section_start = p;
	RAR_READ_VINT_SKIP();
	type = vint;
	/* Header flags */
	RAR_READ_VINT_SKIP();
	flags = vint;

	if (flags & 0x1) {
		/* Have extra zone */
		RAR_READ_VINT_SKIP();
	}
	if (flags & 0x2) {
		/* Data zone is presented */
		RAR_READ_VINT_SKIP();
		sz += vint;
	}

	if (type == rar_encrypted_header) {
		/* We can't read any further information as archive is encrypted */
		arch->flags |= RSPAMD_ARCHIVE_ENCRYPTED;
		goto end;
	}
	else if (type != rar_main_header) {
		msg_debug_archive("rar archive is invalid (bad main header)");

		return;
	}

	/* Nothing useful in main header */
	p = section_start;
	RAR_SKIP_BYTES(sz);

	while (p < end) {
		gboolean has_extra = FALSE;
		/* Read the next header */
		/* Crc 32 */
		RAR_SKIP_BYTES(sizeof(uint32_t));
		/* Size */
		RAR_READ_VINT_SKIP();

		sz = vint;
		if (sz == 0) {
			/* Zero sized block - error */
			msg_debug_archive("rar archive is invalid (zero size block)");

			return;
		}

		section_start = p;
		/* Type */
		RAR_READ_VINT_SKIP();
		type = vint;
		/* Header flags */
		RAR_READ_VINT_SKIP();
		flags = vint;

		if (flags & 0x1) {
			/* Have extra zone */
			RAR_READ_VINT_SKIP();
			extra_sz = vint;
			has_extra = TRUE;
		}

		if (flags & 0x2) {
			/* Data zone is presented */
			RAR_READ_VINT_SKIP();
			sz += vint;
			comp_sz = vint;
		}

		if (type != rar_file_header) {
			p = section_start;
			RAR_SKIP_BYTES(sz);
		}
		else {
			/* We have a file header, go forward */
			uint64_t fname_len;
			bool is_directory = false;

			/* File header specific flags */
			RAR_READ_VINT_SKIP();
			flags = vint;

			/* Unpacked size */
			RAR_READ_VINT_SKIP();
			uncomp_sz = vint;
			/* Attributes */
			RAR_READ_VINT_SKIP();

			if (flags & 0x2) {
				/* Unix mtime */
				RAR_SKIP_BYTES(sizeof(uint32_t));
			}
			if (flags & 0x4) {
				/* Crc32 */
				RAR_SKIP_BYTES(sizeof(uint32_t));
			}
			if (flags & 0x1) {
				/* Ignore directories for sanity purposes */
				is_directory = true;
				msg_debug_archive("skip directory record in a rar archive");
			}

			if (!is_directory) {
				/* Compression */
				RAR_READ_VINT_SKIP();
				/* Host OS */
				RAR_READ_VINT_SKIP();
				/* Filename length (finally!) */
				RAR_READ_VINT_SKIP();
				fname_len = vint;

				if (fname_len == 0 || fname_len > (gsize) (end - p)) {
					msg_debug_archive("rar archive is invalid (bad filename size)");

					return;
				}

				f = g_malloc0(sizeof(*f));
				f->uncompressed_size = uncomp_sz;
				f->compressed_size = comp_sz;
				rspamd_archive_file_try_utf(task, arch, f, p, fname_len);

				if (f->fname) {
					msg_debug_archive("added rarv5 file: %v", f->fname);
					if (!rspamd_archive_file_add(task, arch, f)) {
						f = NULL;
						goto end;
					}
					if (f->flags & RSPAMD_ARCHIVE_FILE_OBFUSCATED) {
						arch->flags |= RSPAMD_ARCHIVE_HAS_OBFUSCATED_FILES;
					}
				}
				else {
					g_free(f);
					f = NULL;
				}

				/*
				 * Bound the extra-field block using sizes rather than
				 * pointer arithmetic: extra_sz is a 64-bit varint and
				 * "p + fname_len + extra_sz" could otherwise wrap.
				 */
				if (f && has_extra && extra_sz > 0 &&
					fname_len <= (uint64_t) (end - p) &&
					extra_sz <= (uint64_t) (end - p) - fname_len) {
					/* Try to find encryption record in extra field */
					const unsigned char *ex = p + fname_len;
					const unsigned char *extra_end = ex + extra_sz;

					while (ex < extra_end) {
						const unsigned char *t;
						int64_t cur_sz = 0, sec_type = 0;
						int vint_len;

						vint_len = rspamd_archive_rar_read_vint(ex, extra_end - ex, &cur_sz);
						if (vint_len == -1) {
							msg_debug_archive("rar archive is invalid (bad vint)");
							return;
						}

						if (cur_sz <= 0 || ex + vint_len + cur_sz > extra_end) {
							msg_debug_archive("rar archive is invalid (bad extra record size)");
							break;
						}

						t = ex + vint_len;

						r = rspamd_archive_rar_read_vint(t, cur_sz, &sec_type);
						if (r == -1) {
							msg_debug_archive("rar archive is invalid (bad vint)");
							return;
						}

						if (sec_type == 0x01) {
							f->flags |= RSPAMD_ARCHIVE_FILE_ENCRYPTED;
							arch->flags |= RSPAMD_ARCHIVE_ENCRYPTED;
							break;
						}

						ex += vint_len + cur_sz;
					}
				}

				/* A name with a NUL is shown up to it */
				if (f && !rspamd_archive_file_add_cstr_name(task, arch, f, p, fname_len)) {
					goto end;
				}
			}

			/* Restore p to the beginning of the header */
			p = section_start;
			RAR_SKIP_BYTES(sz);
		}
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

			RAR_READ_UINT16(optlen);

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
