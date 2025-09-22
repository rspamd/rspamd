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
#ifndef SRC_LIBMIME_ARCHIVES_H_
#define SRC_LIBMIME_ARCHIVES_H_

#include "config.h"

#ifdef __cplusplus
extern "C" {
#endif

enum rspamd_archive_type {
	RSPAMD_ARCHIVE_ZIP,
	RSPAMD_ARCHIVE_RAR,
	RSPAMD_ARCHIVE_7ZIP,
	RSPAMD_ARCHIVE_GZIP,
};

enum rspamd_archive_flags {
	RSPAMD_ARCHIVE_ENCRYPTED = (1u << 0u),
	RSPAMD_ARCHIVE_CANNOT_READ = (1u << 1u),
	RSPAMD_ARCHIVE_HAS_OBFUSCATED_FILES = (1u << 2u),
};

enum rspamd_archive_file_flags {
	RSPAMD_ARCHIVE_FILE_ENCRYPTED = (1u << 0u),
	RSPAMD_ARCHIVE_FILE_OBFUSCATED = (1u << 1u),
};

struct rspamd_archive_file {
	GString *fname;
	gsize compressed_size;
	gsize uncompressed_size;
	enum rspamd_archive_file_flags flags;
};

struct rspamd_archive {
	enum rspamd_archive_type type;
	const rspamd_ftok_t *archive_name;
	gsize size;
	enum rspamd_archive_flags flags;
	GPtrArray *files; /* Array of struct rspamd_archive_file */
};

/* Writer API */
struct rspamd_zip_file_spec {
	const char *name;          /* UTF-8 relative path */
	const unsigned char *data; /* file content */
	gsize len;                 /* content length */
	/* Optional attrs */
	time_t mtime; /* 0 means now */
	guint32 mode; /* UNIX perm bits; 0 means 0644 */
};

/**
 * Create a ZIP archive in-memory from provided files (DEFLATE compression)
 * If password is non-NULL, the ZIP is created normally and then encrypted as a whole
 * using AES-256-CBC with PBKDF2-HMAC-SHA256 and a random salt/IV. The result format is:
 *  [ 'RZAE0001' (8 bytes) | salt (16 bytes) | iv (16 bytes) | ciphertext ]
 * Returns newly allocated GByteArray on success, NULL on error and sets err
 */
GByteArray *rspamd_archives_zip_write(const struct rspamd_zip_file_spec *files,
									  gsize nfiles,
									  const char *password,
									  GError **err);

/**
 * AES-256-CBC encrypts arbitrary data buffer using PBKDF2-HMAC-SHA256 derived key.
 * Output format: [ 'RZAE0001' | salt(16) | iv(16) | ciphertext ]
 */
GByteArray *rspamd_archives_encrypt_aes256_cbc(const unsigned char *in,
											   gsize inlen,
											   const char *password,
											   GError **err);

/**
 * Process archives from a worker task
 */
void rspamd_archives_process(struct rspamd_task *task);

/**
 * Get textual representation of an archive's type
 */
const char *rspamd_archive_type_str(enum rspamd_archive_type type);

#ifdef __cplusplus
}
#endif

#endif /* SRC_LIBMIME_ARCHIVES_H_ */
