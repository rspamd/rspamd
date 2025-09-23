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
#include <unicode/uchar.h>
#include <unicode/utf8.h>
#include <unicode/utf16.h>
#include <unicode/ucnv.h>

#include <archive.h>
#include <archive_entry.h>
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
rspamd_archive_dtor(gpointer p)
{
	struct rspamd_archive *arch = p;
	struct rspamd_archive_file *f;
	unsigned int i;

	for (i = 0; i < arch->files->len; i++) {
		f = g_ptr_array_index(arch->files, i);

		if (f->fname) {
			g_string_free(f->fname, TRUE);
		}

		g_free(f);
	}

	g_ptr_array_free(arch->files, TRUE);
}

static inline guint16
rspamd_zip_time_dos(time_t t)
{
	struct tm lt;

	if (t == 0) {
		t = time(NULL);
	}

	(void) localtime_r(&t, &lt);

	guint16 dos_time = ((guint16) (lt.tm_hour & 0x1f) << 11) |
					   ((guint16) (lt.tm_min & 0x3f) << 5) |
					   ((guint16) ((lt.tm_sec / 2) & 0x1f));

	return dos_time;
}

static inline guint16
rspamd_zip_date_dos(time_t t)
{
	struct tm lt;

	if (t == 0) {
		t = time(NULL);
	}

	(void) localtime_r(&t, &lt);

	int year = lt.tm_year + 1900;
	if (year < 1980) {
		year = 1980; /* DOS date epoch */
	}

	guint16 dos_date = ((guint16) ((year - 1980) & 0x7f) << 9) |
					   ((guint16) ((lt.tm_mon + 1) & 0x0f) << 5) |
					   ((guint16) (lt.tm_mday & 0x1f));

	return dos_date;
}

static inline void
rspamd_ba_append_u16le(GByteArray *ba, guint16 v)
{
	union {
		guint16 u16;
		unsigned char b[2];
	} u;

	u.u16 = GUINT16_TO_LE(v);
	g_byte_array_append(ba, u.b, sizeof(u.b));
}

static inline void
rspamd_ba_append_u32le(GByteArray *ba, guint32 v)
{
	union {
		guint32 u32;
		unsigned char b[4];
	} u;

	u.u32 = GUINT32_TO_LE(v);
	g_byte_array_append(ba, u.b, sizeof(u.b));
}

static gboolean
rspamd_zip_deflate_alloc(const unsigned char *in,
						 gsize inlen,
						 unsigned char **outbuf,
						 gsize *outlen)
{
	int rc;
	z_stream strm;

	memset(&strm, 0, sizeof(strm));
	/* raw DEFLATE stream for ZIP */
	rc = deflateInit2(&strm, Z_DEFAULT_COMPRESSION, Z_DEFLATED,
					  -MAX_WBITS, MAX_MEM_LEVEL - 1, Z_DEFAULT_STRATEGY);

	if (rc != Z_OK) {
		return FALSE;
	}

	/* Compute upper bound and allocate */
	uLong bound = deflateBound(&strm, (uLong) inlen);
	unsigned char *obuf = g_malloc(bound);

	strm.next_in = (unsigned char *) in;
	strm.avail_in = inlen;
	strm.next_out = obuf;
	strm.avail_out = bound;

	rc = deflate(&strm, Z_FINISH);

	if (rc != Z_STREAM_END && rc != Z_OK && rc != Z_BUF_ERROR) {
		deflateEnd(&strm);
		g_free(obuf);
		return FALSE;
	}

	*outlen = bound - strm.avail_out;
	*outbuf = obuf;
	deflateEnd(&strm);

	return TRUE;
}

static gboolean
rspamd_zip_validate_name(const char *name)
{
	if (name == NULL || *name == '\0') {
		return FALSE;
	}
	/* Disallow absolute paths and parent traversals */
	if (name[0] == '/' || name[0] == '\\') {
		return FALSE;
	}
	if (strstr(name, "..") != NULL) {
		return FALSE;
	}
	if (strchr(name, ':') != NULL) {
		return FALSE;
	}

	return TRUE;
}

static void
rspamd_zip_write_local_header(GByteArray *zip,
							  const char *name,
							  guint16 ver_needed,
							  guint16 gp_flags,
							  guint16 method,
							  time_t mtime,
							  guint32 crc,
							  guint32 csize,
							  guint32 usize,
							  guint16 extra_len)
{
	/* Local file header */
	/* signature */
	rspamd_ba_append_u32le(zip, 0x04034b50);
	/* version needed to extract */
	rspamd_ba_append_u16le(zip, ver_needed);
	/* general purpose bit flag */
	rspamd_ba_append_u16le(zip, gp_flags);
	/* compression method */
	rspamd_ba_append_u16le(zip, method);
	/* last mod file time/date */
	rspamd_ba_append_u16le(zip, rspamd_zip_time_dos(mtime));
	rspamd_ba_append_u16le(zip, rspamd_zip_date_dos(mtime));
	/* CRC-32 */
	rspamd_ba_append_u32le(zip, crc);
	/* compressed size */
	rspamd_ba_append_u32le(zip, csize);
	/* uncompressed size */
	rspamd_ba_append_u32le(zip, usize);
	/* file name length */
	rspamd_ba_append_u16le(zip, (guint16) strlen(name));
	/* extra field length */
	rspamd_ba_append_u16le(zip, extra_len);
	/* file name */
	g_byte_array_append(zip, (const guint8 *) name, strlen(name));
}

static void
rspamd_zip_write_central_header(GByteArray *cd,
								const char *name,
								guint16 ver_needed,
								guint16 gp_flags,
								guint16 method,
								time_t mtime,
								guint32 crc,
								guint32 csize,
								guint32 usize,
								guint32 lfh_offset,
								guint32 mode,
								guint16 extra_len)
{
	/* Central directory file header */
	rspamd_ba_append_u32le(cd, 0x02014b50);
	/* version made by: 3 (UNIX) << 8 | 20 */
	rspamd_ba_append_u16le(cd, (guint16) ((3 << 8) | 20));
	/* version needed to extract */
	rspamd_ba_append_u16le(cd, ver_needed);
	/* general purpose bit flag */
	rspamd_ba_append_u16le(cd, gp_flags);
	/* compression method */
	rspamd_ba_append_u16le(cd, method);
	/* time/date */
	rspamd_ba_append_u16le(cd, rspamd_zip_time_dos(mtime));
	rspamd_ba_append_u16le(cd, rspamd_zip_date_dos(mtime));
	/* CRC and sizes */
	rspamd_ba_append_u32le(cd, crc);
	rspamd_ba_append_u32le(cd, csize);
	rspamd_ba_append_u32le(cd, usize);
	/* name len, extra len, comment len */
	rspamd_ba_append_u16le(cd, (guint16) strlen(name));
	rspamd_ba_append_u16le(cd, extra_len);
	rspamd_ba_append_u16le(cd, 0);
	/* disk number start, internal attrs */
	rspamd_ba_append_u16le(cd, 0);
	rspamd_ba_append_u16le(cd, 0);
	/* external attrs: UNIX perms in upper 16 bits */
	guint32 xattr = (mode ? mode : 0644);
	xattr = (xattr & 0xFFFF) << 16;
	rspamd_ba_append_u32le(cd, xattr);
	/* relative offset of local header */
	rspamd_ba_append_u32le(cd, lfh_offset);
	/* file name */
	g_byte_array_append(cd, (const guint8 *) name, strlen(name));
}

/* --- ZipCrypto (PKWARE traditional) helpers --- */
static const guint32 rspamd_zip_crc32_tab[256] = {
	0x00000000U, 0x77073096U, 0xEE0E612CU, 0x990951BAU, 0x076DC419U, 0x706AF48FU, 0xE963A535U, 0x9E6495A3U,
	0x0EDB8832U, 0x79DCB8A4U, 0xE0D5E91EU, 0x97D2D988U, 0x09B64C2BU, 0x7EB17CBDU, 0xE7B82D07U, 0x90BF1D91U,
	0x1DB71064U, 0x6AB020F2U, 0xF3B97148U, 0x84BE41DEU, 0x1ADAD47DU, 0x6DDDE4EBU, 0xF4D4B551U, 0x83D385C7U,
	0x136C9856U, 0x646BA8C0U, 0xFD62F97AU, 0x8A65C9ECU, 0x14015C4FU, 0x63066CD9U, 0xFA0F3D63U, 0x8D080DF5U,
	0x3B6E20C8U, 0x4C69105EU, 0xD56041E4U, 0xA2677172U, 0x3C03E4D1U, 0x4B04D447U, 0xD20D85FDU, 0xA50AB56BU,
	0x35B5A8FAU, 0x42B2986CU, 0xDBBBC9D6U, 0xACBCF940U, 0x32D86CE3U, 0x45DF5C75U, 0xDCD60DCFU, 0xABD13D59U,
	0x26D930ACU, 0x51DE003AU, 0xC8D75180U, 0xBFD06116U, 0x21B4F4B5U, 0x56B3C423U, 0xCFBA9599U, 0xB8BDA50FU,
	0x2802B89EU, 0x5F058808U, 0xC60CD9B2U, 0xB10BE924U, 0x2F6F7C87U, 0x58684C11U, 0xC1611DABU, 0xB6662D3DU,
	0x76DC4190U, 0x01DB7106U, 0x98D220BCU, 0xEFD5102AU, 0x71B18589U, 0x06B6B51FU, 0x9FBFE4A5U, 0xE8B8D433U,
	0x7807C9A2U, 0x0F00F934U, 0x9609A88EU, 0xE10E9818U, 0x7F6A0DBBU, 0x086D3D2DU, 0x91646C97U, 0xE6635C01U,
	0x6B6B51F4U, 0x1C6C6162U, 0x856530D8U, 0xF262004EU, 0x6C0695EDU, 0x1B01A57BU, 0x8208F4C1U, 0xF50FC457U,
	0x65B0D9C6U, 0x12B7E950U, 0x8BBEB8EAU, 0xFCB9887CU, 0x62DD1DDFU, 0x15DA2D49U, 0x8CD37CF3U, 0xFBD44C65U,
	0x4DB26158U, 0x3AB551CEU, 0xA3BC0074U, 0xD4BB30E2U, 0x4ADFA541U, 0x3DD895D7U, 0xA4D1C46DU, 0xD3D6F4FBU,
	0x4369E96AU, 0x346ED9FCU, 0xAD678846U, 0xDA60B8D0U, 0x44042D73U, 0x33031DE5U, 0xAA0A4C5FU, 0xDD0D7CC9U,
	0x5005713CU, 0x270241AAU, 0xBE0B1010U, 0xC90C2086U, 0x5768B525U, 0x206F85B3U, 0xB966D409U, 0xCE61E49FU,
	0x5EDEF90EU, 0x29D9C998U, 0xB0D09822U, 0xC7D7A8B4U, 0x59B33D17U, 0x2EB40D81U, 0xB7BD5C3BU, 0xC0BA6CADU,
	0xEDB88320U, 0x9ABFB3B6U, 0x03B6E20CU, 0x74B1D29AU, 0xEAD54739U, 0x9DD277AFU, 0x04DB2615U, 0x73DC1683U,
	0xE3630B12U, 0x94643B84U, 0x0D6D6A3EU, 0x7A6A5AA8U, 0xE40ECF0BU, 0x9309FF9DU, 0x0A00AE27U, 0x7D079EB1U,
	0xF00F9344U, 0x8708A3D2U, 0x1E01F268U, 0x6906C2FEU, 0xF762575DU, 0x806567CBU, 0x196C3671U, 0x6E6B06E7U,
	0xFED41B76U, 0x89D32BE0U, 0x10DA7A5AU, 0x67DD4ACCU, 0xF9B9DF6FU, 0x8EBEEFF9U, 0x17B7BE43U, 0x60B08ED5U,
	0xD6D6A3E8U, 0xA1D1937EU, 0x38D8C2C4U, 0x4FDFF252U, 0xD1BB67F1U, 0xA6BC5767U, 0x3FB506DDU, 0x48B2364BU,
	0xD80D2BDAU, 0xAF0A1B4CU, 0x36034AF6U, 0x41047A60U, 0xDF60EFC3U, 0xA867DF55U, 0x316E8EEFU, 0x4669BE79U,
	0xCB61B38CU, 0xBC66831AU, 0x256FD2A0U, 0x5268E236U, 0xCC0C7795U, 0xBB0B4703U, 0x220216B9U, 0x5505262FU,
	0xC5BA3BBEU, 0xB2BD0B28U, 0x2BB45A92U, 0x5CB36A04U, 0xC2D7FFA7U, 0xB5D0CF31U, 0x2CD99E8BU, 0x5BDEAE1DU,
	0x9B64C2B0U, 0xEC63F226U, 0x756AA39CU, 0x026D930AU, 0x9C0906A9U, 0xEB0E363FU, 0x72076785U, 0x05005713U,
	0x95BF4A82U, 0xE2B87A14U, 0x7BB12BAEU, 0x0CB61B38U, 0x92D28E9BU, 0xE5D5BE0DU, 0x7CDCEFB7U, 0x0BDBDF21U,
	0x86D3D2D4U, 0xF1D4E242U, 0x68DDB3F8U, 0x1FDA836EU, 0x81BE16CDU, 0xF6B9265BU, 0x6FB077E1U, 0x18B74777U,
	0x88085AE6U, 0xFF0F6A70U, 0x66063BCAU, 0x11010B5CU, 0x8F659EFFU, 0xF862AE69U, 0x616BFFD3U, 0x166CCF45U,
	0xA00AE278U, 0xD70DD2EEU, 0x4E048354U, 0x3903B3C2U, 0xA7672661U, 0xD06016F7U, 0x4969474DU, 0x3E6E77DBU,
	0xAED16A4AU, 0xD9D65ADCU, 0x40DF0B66U, 0x37D83BF0U, 0xA9BCAE53U, 0xDEBB9EC5U, 0x47B2CF7FU, 0x30B5FFE9U,
	0xBDBDF21CU, 0xCABAC28AU, 0x53B39330U, 0x24B4A3A6U, 0xBAD03605U, 0xCDD70693U, 0x54DE5729U, 0x23D967BFU,
	0xB3667A2EU, 0xC4614AB8U, 0x5D681B02U, 0x2A6F2B94U, 0xB40BBE37U, 0xC30C8EA1U, 0x5A05DF1BU, 0x2D02EF8DU};

static inline guint32
rspamd_zip_crc32_update(guint32 crc, guint8 c)
{
	return rspamd_zip_crc32_tab[(crc ^ c) & 0xff] ^ (crc >> 8);
}
static inline void
rspamd_zipcrypto_init_keys(guint32 keys[3])
{
	keys[0] = 0x12345678UL;
	keys[1] = 0x23456789UL;
	keys[2] = 0x34567890UL;
}

static inline void
rspamd_zipcrypto_update_keys(guint32 keys[3], guint8 c)
{
	keys[0] = rspamd_zip_crc32_update(keys[0], c);
	keys[1] = (keys[1] + (keys[0] & 0xff));
	keys[1] = keys[1] * 134775813UL + 1;
	guint8 t = (keys[1] >> 24) & 0xff;
	keys[2] = rspamd_zip_crc32_update(keys[2], t);
}

static inline guint8
rspamd_zipcrypto_crypt_byte(const guint32 keys[3])
{
	guint16 t = (guint16) ((keys[2] & 0xffff) | 2);
	return (guint8) (((t * (t ^ 1)) >> 8) & 0xff);
}

static inline void
rspamd_zipcrypto_init_with_password(guint32 keys[3], const char *password)
{
	rspamd_zipcrypto_init_keys(keys);
	if (password != NULL) {
		const unsigned char *p = (const unsigned char *) password;
		while (*p) {
			rspamd_zipcrypto_update_keys(keys, *p++);
		}
	}
}

GByteArray *
rspamd_archives_zip_write(const struct rspamd_zip_file_spec *files,
						  gsize nfiles,
						  const char *password,
						  GError **err)
{
	GByteArray *zip = NULL, *cd = NULL;
	GQuark q = rspamd_archives_err_quark();

	if (files == NULL || nfiles == 0) {
		g_set_error(err, q, EINVAL, "no files to archive");
		return NULL;
	}

	zip = g_byte_array_new();
	cd = g_byte_array_new();

	for (gsize i = 0; i < nfiles; i++) {
		const struct rspamd_zip_file_spec *f = &files[i];
		if (!rspamd_zip_validate_name(f->name)) {
			g_set_error(err, q, EINVAL, "invalid zip entry name: %s", f->name ? f->name : "(null)");
			g_byte_array_free(cd, TRUE);
			g_byte_array_free(zip, TRUE);
			return NULL;
		}

		guint32 crc = crc32(0L, Z_NULL, 0);
		crc = crc32(crc, f->data, f->len);
		guint16 method = 8;            /* deflate */
		guint16 gp_flags = (1u << 11); /* UTF-8 */
		guint16 ver_needed = 20;       /* default */
		const gboolean use_zipcrypto = (password != NULL && *password != '\0');

		/* actual method will be decided after deflate; default is deflate */

		guint16 extra_len = 0;
		guint32 csize_for_header = 0;
		gboolean use_descriptor = FALSE;
		if (use_zipcrypto) {
			/* Traditional PKWARE ZipCrypto */
			gp_flags |= 1u;        /* encrypted */
			gp_flags |= (1u << 3); /* data descriptor present */
			use_descriptor = TRUE;
			/* method remains 8 or 0 depending on compression effectiveness */
			/* no extra field */
		}

		guint32 lfh_off = zip->len;
		rspamd_zip_write_local_header(zip, f->name, ver_needed, gp_flags, method, f->mtime,
									  use_descriptor ? 0 : crc,
									  use_descriptor ? 0 : csize_for_header,
									  use_descriptor ? 0 : (guint32) f->len,
									  extra_len);
		msg_debug_archive_taskless("lfh: off=%d ver_needed=%d gp_flags=%d method=%d name_len=%d extra_len=%d",
								   (int) lfh_off, (int) ver_needed, (int) gp_flags, (int) method,
								   (int) strlen(f->name), (int) extra_len);
		if (use_zipcrypto) {
			/* Prepare ZipCrypto keys */
			guint32 keys[3];
			rspamd_zipcrypto_init_with_password(keys, password);

			/* Build 12-byte encryption header */
			guint8 hdr[12];
			ottery_rand_bytes(hdr, sizeof(hdr));
			/* set verification bytes */
			if (use_descriptor) {
				/* when bit 3 is set, use MS-DOS time field */
				guint16 dos_t = rspamd_zip_time_dos(f->mtime);
				hdr[10] = (guint8) (dos_t & 0xff);
				hdr[11] = (guint8) ((dos_t >> 8) & 0xff);
			}
			else {
				/* high 2 bytes of CRC32 of plaintext */
				hdr[10] = (guint8) ((crc >> 16) & 0xff);
				hdr[11] = (guint8) ((crc >> 24) & 0xff);
			}
			/* Encrypt header in place */
			for (guint i = 0; i < sizeof(hdr); i++) {
				guint8 k = rspamd_zipcrypto_crypt_byte(keys);
				guint8 c = hdr[i] ^ k;
				hdr[i] = c;
				/* update keys with header plaintext byte */
				rspamd_zipcrypto_update_keys(keys, (guint8) (c ^ k));
			}
			g_byte_array_append(zip, hdr, sizeof(hdr));

			/* Now compress directly into zip buffer (in place) or store */
			gsize produced = 0;
			gboolean used_deflate = TRUE;
			guint32 data_off = zip->len; /* start of (plaintext) data before encryption */

			/* Try to reserve space by deflateBound and compress into zip */
			z_stream zst;
			memset(&zst, 0, sizeof(zst));
			if (deflateInit2(&zst, Z_DEFAULT_COMPRESSION, Z_DEFLATED, -MAX_WBITS, MAX_MEM_LEVEL - 1, Z_DEFAULT_STRATEGY) == Z_OK) {
				uLong bound = deflateBound(&zst, (uLong) f->len);
				deflateEnd(&zst);

				/* Reserve space */
				g_byte_array_set_size(zip, data_off + bound);

				memset(&zst, 0, sizeof(zst));
				if (deflateInit2(&zst, Z_DEFAULT_COMPRESSION, Z_DEFLATED, -MAX_WBITS, MAX_MEM_LEVEL - 1, Z_DEFAULT_STRATEGY) != Z_OK) {
					/* fallback to store */
					used_deflate = FALSE;
				}
				else {
					zst.next_in = (unsigned char *) f->data;
					zst.avail_in = f->len;
					zst.next_out = zip->data + data_off;
					zst.avail_out = bound;
					int rc = deflate(&zst, Z_FINISH);
					if (rc != Z_STREAM_END && rc != Z_OK && rc != Z_BUF_ERROR) {
						used_deflate = FALSE;
						deflateEnd(&zst);
					}
					else {
						produced = bound - zst.avail_out;
						deflateEnd(&zst);
						if (produced >= f->len) {
							used_deflate = FALSE;
						}
					}
				}
			}
			else {
				used_deflate = FALSE;
			}

			if (!used_deflate) {
				/* Store: reset to data_off and copy original data */
				g_byte_array_set_size(zip, data_off);
				g_byte_array_set_size(zip, data_off + f->len);
				memcpy(zip->data + data_off, f->data, f->len);
				produced = f->len;
				/* patch method in local header (offset +8) */
				guint16 *pm = (guint16 *) (zip->data + lfh_off + 8);
				method = 0;
				*pm = GUINT16_TO_LE(method);
			}

			/* Encrypt in place over zip->data[data_off .. data_off+produced) */
			for (gsize i = 0; i < produced; i++) {
				guint8 k = rspamd_zipcrypto_crypt_byte(keys);
				guint8 pt = zip->data[data_off + i];
				zip->data[data_off + i] = pt ^ k;
				rspamd_zipcrypto_update_keys(keys, pt);
			}
			/* Shrink to actual size (if deflated) */
			g_byte_array_set_size(zip, data_off + produced);

			/* compressed size includes 12-byte header + encrypted data */
			csize_for_header = (guint32) (12 + produced);
			if (!use_descriptor) {
				/* patch CRC (offset +14) and compressed size (offset +18) */
				guint32 *p32 = (guint32 *) (zip->data + lfh_off + 14);
				*p32 = GUINT32_TO_LE(crc);
				p32 = (guint32 *) (zip->data + lfh_off + 18);
				*p32 = GUINT32_TO_LE(csize_for_header);
				/* uncompressed size already set in LFH */
			}
			else {
				/* append data descriptor with signature */
				rspamd_ba_append_u32le(zip, 0x08074b50);
				rspamd_ba_append_u32le(zip, crc);
				rspamd_ba_append_u32le(zip, csize_for_header);
				rspamd_ba_append_u32le(zip, (guint32) f->len);
			}

			msg_debug_archive_taskless("zip-zipcrypto: added entry '%s' (usize=%L, csize=%L, method=%s)",
									   f->name, (int64_t) f->len, (int64_t) csize_for_header,
									   used_deflate ? "deflate+zipcrypto" : "store+zipcrypto");
		}
		else {
			/* Not encrypted: deflate directly into zip, fallback to store */
			z_stream zst;
			memset(&zst, 0, sizeof(zst));
			if (deflateInit2(&zst, Z_DEFAULT_COMPRESSION, Z_DEFLATED, -MAX_WBITS, MAX_MEM_LEVEL - 1, Z_DEFAULT_STRATEGY) != Z_OK) {
				g_set_error(err, q, EIO, "deflateInit2 failed");
				return NULL;
			}
			uLong bound = deflateBound(&zst, (uLong) f->len);
			deflateEnd(&zst);
			gsize off = zip->len;
			g_byte_array_set_size(zip, zip->len + bound);
			unsigned char *outp = zip->data + off;
			memset(&zst, 0, sizeof(zst));
			if (deflateInit2(&zst, Z_DEFAULT_COMPRESSION, Z_DEFLATED, -MAX_WBITS, MAX_MEM_LEVEL - 1, Z_DEFAULT_STRATEGY) != Z_OK) {
				g_set_error(err, q, EIO, "deflateInit2 failed");
				return NULL;
			}
			zst.next_in = (unsigned char *) f->data;
			zst.avail_in = f->len;
			zst.next_out = outp;
			zst.avail_out = bound;
			int rc = deflate(&zst, Z_FINISH);
			if (rc != Z_STREAM_END && rc != Z_OK && rc != Z_BUF_ERROR) {
				deflateEnd(&zst);
				g_set_error(err, q, EIO, "deflate failed");
				return NULL;
			}
			gsize produced = bound - zst.avail_out;
			deflateEnd(&zst);
			if (produced >= f->len) {
				/* store */
				g_byte_array_set_size(zip, off);
				g_byte_array_set_size(zip, zip->len + f->len);
				memcpy(zip->data + off, f->data, f->len);
				produced = f->len;
				method = 0;
				/* patch method in local header (offset +8) */
				guint16 *pm = (guint16 *) (zip->data + lfh_off + 8);
				*pm = GUINT16_TO_LE(method);
				msg_debug_archive_taskless("zip: fallback to store (no encryption) - deflated=%L, original=%L",
										   (int64_t) (bound - zst.avail_out), (int64_t) f->len);
			}
			else {
				g_byte_array_set_size(zip, off + produced);
			}
			csize_for_header = (guint32) produced;
			/* patch CRC (offset +14) and compressed size (offset +18) */
			guint32 *p32 = (guint32 *) (zip->data + lfh_off + 14);
			*p32 = GUINT32_TO_LE(crc);
			p32 = (guint32 *) (zip->data + lfh_off + 18);
			*p32 = GUINT32_TO_LE(csize_for_header);
		}

		guint32 cd_off = cd->len;
		rspamd_zip_write_central_header(cd, f->name, ver_needed, gp_flags, method, f->mtime, crc,
										csize_for_header,
										(guint32) f->len,
										lfh_off, f->mode, extra_len);
		msg_debug_archive_taskless("cd_entry: off=%d lfh_off=%d name=%s csize=%d usize=%d",
								   (int) cd_off, (int) lfh_off, f->name, (int) csize_for_header, (int) f->len);
		msg_debug_archive_taskless("cd: ver_needed=%d gp_flags=%d method=%d csize=%L usize=%L",
								   (int) ver_needed, (int) gp_flags, (int) method,
								   (int64_t) csize_for_header, (int64_t) f->len);

		guint64 logged_csize = (guint64) csize_for_header;
		const char *method_str;
		method_str = (use_zipcrypto ? (method == 0 ? "store+zipcrypto" : "deflate+zipcrypto")
									: (method == 0 ? "store" : "deflate"));
		msg_debug_archive_taskless("zip: added entry '%s' (usize=%L, csize=%L, method=%s)",
								   f->name, (int64_t) f->len, (int64_t) logged_csize,
								   method_str);
	}

	/* Central directory start */
	guint32 cd_start = zip->len;
	g_byte_array_append(zip, cd->data, cd->len);
	guint32 cd_size = cd->len;
	g_byte_array_free(cd, TRUE);

	/* EOCD */
	rspamd_ba_append_u32le(zip, 0x06054b50);
	/* disk numbers */
	rspamd_ba_append_u16le(zip, 0);
	rspamd_ba_append_u16le(zip, 0);
	/* total entries on this disk / total entries */
	rspamd_ba_append_u16le(zip, (guint16) nfiles);
	rspamd_ba_append_u16le(zip, (guint16) nfiles);
	/* size of central directory */
	rspamd_ba_append_u32le(zip, cd_size);
	/* offset of central directory */
	rspamd_ba_append_u32le(zip, cd_start);
	/* zip comment length */
	rspamd_ba_append_u16le(zip, 0);

	msg_debug_archive_taskless("zip: created archive (%L bytes, cd_start=%d, cd_size=%d)",
							   (int64_t) zip->len, (int) cd_start, (int) cd_size);

	/* Debug: check archive structure */
	if (zip->len >= 4) {
		guint32 sig = GUINT32_FROM_LE(*(guint32 *) zip->data);
		msg_debug_archive_taskless("zip: first 4 bytes = %xd (should be 4034b50 for PK\\003\\004)", sig);
	}

	/* Additional validation */
	if (cd_start + cd_size + 22 != zip->len) {
		msg_debug_archive_taskless("zip: WARNING - archive size mismatch: cd_start(%d) + cd_size(%d) + eocd(22) = %d, but zip->len = %d",
								   (int) cd_start, (int) cd_size, (int) (cd_start + cd_size + 22), (int) zip->len);
	}

	/* no debug dump */

	return zip;
}

/* removed obsolete whole-archive AES-256-CBC function */

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

			return NULL;
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

			return NULL;
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

static void
rspamd_archive_process_zip(struct rspamd_task *task,
						   struct rspamd_mime_part *part)
{
	const unsigned char *p, *start, *end, *eocd = NULL, *cd;
	const uint32_t eocd_magic = 0x06054b50, cd_basic_len = 46;
	const unsigned char cd_magic[] = {0x50, 0x4b, 0x01, 0x02};
	const unsigned int max_processed = 1024;
	uint32_t cd_offset, cd_size, comp_size, uncomp_size, processed = 0;
	uint16_t extra_len, fname_len, comment_len;
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

	while (p > start + sizeof(uint32_t)) {
		uint32_t t;

		if (processed > max_processed) {
			break;
		}

		/* XXX: not an efficient approach */
		memcpy(&t, p, sizeof(t));

		if (GUINT32_FROM_LE(t) == eocd_magic) {
			eocd = p;
			break;
		}

		p--;
		processed++;
	}


	if (eocd == NULL) {
		/* Not a zip file */
		msg_info_task("zip archive is invalid (no EOCD)");

		return;
	}

	if (end - eocd < 21) {
		msg_info_task("zip archive is invalid (short EOCD)");

		return;
	}


	memcpy(&cd_size, eocd + 12, sizeof(cd_size));
	cd_size = GUINT32_FROM_LE(cd_size);
	memcpy(&cd_offset, eocd + 16, sizeof(cd_offset));
	cd_offset = GUINT32_FROM_LE(cd_offset);

	/* We need to check sanity as well */
	if (cd_offset + cd_size > (unsigned int) (eocd - start)) {
		msg_info_task("zip archive is invalid (bad size/offset for CD)");

		return;
	}

	cd = start + cd_offset;

	arch = rspamd_mempool_alloc0(task->task_pool, sizeof(*arch));
	arch->files = g_ptr_array_new();
	arch->type = RSPAMD_ARCHIVE_ZIP;
	if (part->cd) {
		arch->archive_name = &part->cd->filename;
	}
	rspamd_mempool_add_destructor(task->task_pool, rspamd_archive_dtor,
								  arch);

	while (cd < start + cd_offset + cd_size) {
		uint16_t flags;

		/* Read central directory record */
		if (eocd - cd < cd_basic_len ||
			memcmp(cd, cd_magic, sizeof(cd_magic)) != 0) {
			msg_info_task("zip archive is invalid (bad cd record)");

			return;
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

		if (cd + fname_len + comment_len + extra_len + cd_basic_len > eocd) {
			msg_info_task("zip archive is invalid (too large cd record)");

			return;
		}

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

			g_ptr_array_add(arch->files, f);
			msg_debug_archive("found file in zip archive: %v", f->fname);
		}
		else {
			g_free(f);

			return;
		}

		/* Process extra fields */
		const unsigned char *extra = cd + fname_len + cd_basic_len;
		p = extra;

		while (p + sizeof(uint16_t) * 2 < extra + extra_len) {
			uint16_t hid, hlen;

			memcpy(&hid, p, sizeof(uint16_t));
			hid = GUINT16_FROM_LE(hid);
			memcpy(&hlen, p + sizeof(uint16_t), sizeof(uint16_t));
			hlen = GUINT16_FROM_LE(hlen);

			if (hid == 0x0017) {
				f->flags |= RSPAMD_ARCHIVE_FILE_ENCRYPTED;
			}

			p += hlen + sizeof(uint16_t) * 2;
		}

		cd += fname_len + comment_len + extra_len + cd_basic_len;
	}

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

	while (p < end) {
		/* Crc16 */
		start_section = p;
		RAR_SKIP_BYTES(sizeof(uint16_t));
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
				g_ptr_array_add(arch->files, f);
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
					g_ptr_array_add(arch->files, f);
					if (f->flags & RSPAMD_ARCHIVE_FILE_OBFUSCATED) {
						arch->flags |= RSPAMD_ARCHIVE_HAS_OBFUSCATED_FILES;
					}
				}
				else {
					g_free(f);
					f = NULL;
				}

				if (f && has_extra && extra_sz > 0 &&
					p + fname_len + extra_sz < end) {
					/* Try to find encryption record in extra field */
					const unsigned char *ex = p + fname_len;

					while (ex < p + extra_sz) {
						const unsigned char *t;
						int64_t cur_sz = 0, sec_type = 0;

						r = rspamd_archive_rar_read_vint(ex, extra_sz, &cur_sz);
						if (r == -1) {
							msg_debug_archive("rar archive is invalid (bad vint)");
							return;
						}

						t = ex + r;

						r = rspamd_archive_rar_read_vint(t, extra_sz - r, &sec_type);
						if (r == -1) {
							msg_debug_archive("rar archive is invalid (bad vint)");
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
		uint64_t tgt;

		while (cur_bit > 0) {
			if (!isset(&t, cur_bit)) {
				if (remain >= intlen + 1) {
					memcpy(&tgt, start + 1, intlen);
					tgt = GUINT64_FROM_LE(tgt);
					/* Shift back */
					tgt >>= sizeof(tgt) - NBBY * intlen;
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
		/* Codec ID */
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

			if (*p != 0) {
				/* External folders */
				SZ_SKIP_BYTES(1);
				SZ_READ_VINT(tmp);
			}
			else {
				SZ_SKIP_BYTES(1);

				if (num_folders > 8192) {
					/* Gah */
					return NULL;
				}

				if (folder_nstreams) {
					g_free(folder_nstreams);
				}

				folder_nstreams = g_malloc(sizeof(int) * num_folders);

				for (i = 0; i < num_folders && p != NULL && p < end; i++) {
					p = rspamd_7zip_read_folder(task, p, end, arch,
												&folder_nstreams[i], &num_digests);
				}
			}
			break;
		case kCodersUnPackSize:
			for (i = 0; i < num_folders && p != NULL && p < end; i++) {
				if (folder_nstreams) {
					for (unsigned int j = 0; j < folder_nstreams[i]; j++) {
						SZ_READ_VINT(tmp); /* Unpacked size */
						msg_debug_archive("7zip: unpacked size "
										  "(folder=%d, stream=%d) = %L",
										  (int) i, j, tmp);
					}
				}
				else {
					msg_err_task("internal 7zip error");
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
		*pnum_folders = num_folders;
	}

	if (folder_nstreams) {
		g_free(folder_nstreams);
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

	folder_nstreams = g_alloca(sizeof(uint64_t) * num_folders);
	memset(folder_nstreams, 0, sizeof(uint64_t) * num_folders);

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
		case kCRC:
			/*
			 * Read the comment in the rspamd_7zip_read_coders_info
			 */
			p = rspamd_7zip_read_digest(task, p, end, arch, num_nodigest,
										NULL);
			break;
		case kSize:
			/*
			 * Another brain damaged logic, but we have to support it
			 * as there are no ways to proceed without it.
			 * In fact, it is just absent in the real life...
			 */
			for (i = 0; i < num_folders; i++) {
				for (unsigned int j = 0; j < folder_nstreams[i]; j++) {
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

	while (p != NULL && p < end) {
		t = *p;
		SZ_SKIP_BYTES(1);
		msg_debug_archive("7zip: read main streams info %xd", t);

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
rspamd_7zip_ucs2_to_utf8(struct rspamd_task *task, const unsigned char *p,
						 const unsigned char *end)
{
	GString *res;
	goffset dest_pos = 0, src_pos = 0;
	const gsize len = (end - p) / sizeof(uint16_t);
	uint16_t *up;
	UChar32 wc;
	UBool is_error = 0;

	res = g_string_sized_new((end - p) * 3 / 2 + sizeof(wc) + 1);
	up = (uint16_t *) p;

	while (src_pos < len) {
		U16_NEXT(up, src_pos, len, wc);

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
		case kName:
			/* The most useful part in this whole bloody format */
			b = *p; /* External flag */
			SZ_SKIP_BYTES(1);

			if (b) {
				/* TODO: for the god sake, do something about external
				 * filenames...
				 */
				uint64_t tmp;

				SZ_READ_VINT(tmp);
			}
			else {
				for (i = 0; i < nfiles; i++) {
					/* Zero terminated wchar_t: happy converting... */
					/* First, find terminator */
					const unsigned char *fend = NULL, *tp = p;
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
						msg_debug_archive("bad 7zip name; %s", G_STRLOC);
						goto end;
					}

					res = rspamd_7zip_ucs2_to_utf8(task, p, fend);

					if (res != NULL) {
						fentry = g_malloc0(sizeof(*fentry));
						fentry->fname = res;
						g_ptr_array_add(arch->files, fentry);
						msg_debug_archive("7zip: found file %v", res);
					}
					else {
						msg_debug_archive("bad 7zip name; %s", G_STRLOC);
					}
					/* Skip zero terminating character */
					p = fend + 2;
				}
			}
			break;
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

static const unsigned char *
rspamd_7zip_read_next_section(struct rspamd_task *task,
							  const unsigned char *p, const unsigned char *end,
							  struct rspamd_archive *arch,
							  struct rspamd_mime_part *part)
{
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
			rspamd_archive_dtor(arch);
			arch->files = g_ptr_array_new();

			struct archive_entry *ae;

			while (archive_read_next_header(a, &ae) == ARCHIVE_OK) {
				const char *name = archive_entry_pathname_utf8(ae);
				if (name) {
					msg_debug_archive("7zip: found file %s", name);
					struct rspamd_archive_file *f = g_malloc0(sizeof(*f));
					f->fname = g_string_new(name);
					g_ptr_array_add(arch->files, f);
				}
				archive_read_data_skip(a);
			}

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
						g_ptr_array_add(arch->files, f);

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

				g_ptr_array_add(arch->files, f);

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

				g_ptr_array_add(arch->files, f);

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
