/*-
 * Copyright 2022 Vsevolod Stakhov
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

#ifndef RSPAMD_HYPERSCAN_TOOLS_H
#define RSPAMD_HYPERSCAN_TOOLS_H

#ifdef WITH_HYPERSCAN

#include "hs.h"

G_BEGIN_DECLS

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
 * Cleans up old files. This method should be called on config free (in the main process)
 */
void rspamd_hyperscan_cleanup_maybe(void);

G_END_DECLS

#endif

#endif
