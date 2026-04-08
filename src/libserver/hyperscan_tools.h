/*
 * Copyright 2023 Vsevolod Stakhov
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

#ifndef RSPAMD_HYPERSCAN_TOOLS_H
#define RSPAMD_HYPERSCAN_TOOLS_H

#ifdef WITH_HYPERSCAN

#include "hs.h"
#include "logger.h"

G_BEGIN_DECLS

EXTERN_LOG_MODULE_DEF(hyperscan);

#define HYPERSCAN_LOG_TAG "hsxxxx"

#define msg_debug_hyperscan(...) rspamd_conditional_debug_fast(NULL, NULL,                                              \
															   rspamd_hyperscan_log_id, "hyperscan", HYPERSCAN_LOG_TAG, \
															   RSPAMD_LOG_FUNC, __VA_ARGS__)

/**
 * Opaque structure that represents hyperscan (maybe shared/cached database)
 */
typedef struct rspamd_hyperscan_s rspamd_hyperscan_t;

/**
 * Maybe load or mmap shared a hyperscan from a file
 * @param filename
 * @return cached database if available
 */
rspamd_hyperscan_t *rspamd_hyperscan_maybe_load(const char *filename, goffset offset);

/**
 * Creates a wrapper for a raw hs db. Ownership is transferred to the enclosing object returned
 * @param filename
 * @return
 */
rspamd_hyperscan_t *rspamd_hyperscan_from_raw_db(hs_database_t *db, const char *fname);
/**
 * Get the internal database
 * @param db
 * @return
 */
hs_database_t *rspamd_hyperscan_get_database(rspamd_hyperscan_t *db);
/**
 * Free the database
 * @param db
 */
void rspamd_hyperscan_free(rspamd_hyperscan_t *db, bool invalid);

/**
 * Notice a known hyperscan file (e.g. externally serialized)
 * @param fname
 */
void rspamd_hyperscan_notice_known(const char *fname);

/**
 * Notice that hyperscan files are all loaded (e.g. in the main process), so we can cleanup old files on termination
 */
void rspamd_hyperscan_notice_loaded(void);

/**
 * Cleans up old files. This method should be called on config free (in the main process)
 */
void rspamd_hyperscan_cleanup_maybe(void);

/**
 * Check if a file is known to the hyperscan cache (has been noticed)
 * @param fname path to check
 * @return TRUE if the file is known
 */
gboolean rspamd_hyperscan_is_file_known(const char *fname);

/**
 * Get a platform identifier string for hyperscan cache keys.
 * This includes the hyperscan version, platform tune, and CPU features.
 * The returned string is owned by the library and should not be freed.
 * @return platform identifier string (e.g., "hs54_haswell_avx2_abc123")
 */
const char *rspamd_hyperscan_get_platform_id(void);

/**
 * Create a hyperscan database wrapper from a file descriptor pointing to
 * an unserialized (ready to use) hyperscan database. The FD should be
 * suitable for mmap with MAP_SHARED.
 * @param fd file descriptor to mmap
 * @param size size of the mapped region
 * @return database wrapper or NULL on error
 */
rspamd_hyperscan_t *rspamd_hyperscan_from_fd(int fd, gsize size);

/**
 * Create a shared memory region containing an unserialized hyperscan database.
 * The returned FD can be passed to other processes via SCM_RIGHTS and used
 * with rspamd_hyperscan_from_fd(). The temp file is unlinked immediately
 * so it will be cleaned up when all FDs are closed.
 * @param serialized_data pointer to serialized hyperscan database
 * @param serialized_size size of serialized data
 * @param[out] out_fd output file descriptor
 * @param[out] out_size output size of unserialized database
 * @return TRUE on success
 */
gboolean rspamd_hyperscan_create_shared_unser(const char *serialized_data,
											  gsize serialized_size,
											  int *out_fd,
											  gsize *out_size);

/**
 * Serialize a hyperscan database with unified header format.
 * Format: [magic 8][platform][count][ids][flags][crc64][hs_blob]
 * @param db hyperscan database to serialize
 * @param ids array of pattern IDs (can be NULL)
 * @param flags array of pattern flags (can be NULL)
 * @param n number of patterns (0 if ids/flags not provided)
 * @param[out] out_data pointer to allocated data (caller must g_free)
 * @param[out] out_len size of serialized data
 * @return TRUE on success
 */
gboolean rspamd_hyperscan_serialize_with_header(hs_database_t *db,
												const unsigned int *ids,
												const unsigned int *flags,
												unsigned int n,
												char **out_data,
												gsize *out_len);

/**
 * Load a hyperscan database from unified format blob.
 * Validates magic, platform, and CRC before deserializing.
 * @param data serialized data with header
 * @param len size of data
 * @param[out] err error message if validation fails (can be NULL)
 * @return database wrapper or NULL on error
 */
rspamd_hyperscan_t *rspamd_hyperscan_load_from_header(const char *data,
													  gsize len,
													  GError **err);

/**
 * Validate a unified format blob without deserializing.
 * @param data serialized data with header
 * @param len size of data
 * @param[out] err error message if validation fails (can be NULL)
 * @return TRUE if valid
 */
gboolean rspamd_hyperscan_validate_header(const char *data,
										  gsize len,
										  GError **err);

/**
 * Get the hyperscan serialization magic bytes.
 * Used to include magic in hash computations so that version bumps
 * invalidate cached databases.
 * @param[out] len length of magic bytes
 * @return pointer to magic bytes (static storage)
 */
const unsigned char *rspamd_hyperscan_get_magic(gsize *len);

G_END_DECLS

#endif

#endif
