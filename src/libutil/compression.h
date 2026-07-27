/*
 * Copyright 2026 Vsevolod Stakhov
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
#ifndef RSPAMD_COMPRESSION_H
#define RSPAMD_COMPRESSION_H

#include "config.h"
#include "fstring.h"

#ifdef SYS_ZSTD
#include "zstd.h"
#else
#include "contrib/zstd/zstd.h"
#endif

#ifdef __cplusplus
extern "C" {
#endif

enum rspamd_decompress_error {
	RSPAMD_DECOMPRESS_ERROR_INIT = 0,
	RSPAMD_DECOMPRESS_ERROR_DATA,
	RSPAMD_DECOMPRESS_ERROR_TOO_LARGE,
};

GQuark rspamd_decompress_quark(void);

/**
 * Decompress a zstd payload enforcing a hard ceiling on the output size.
 *
 * The frame-advertised decompressed size is validated before any allocation,
 * the output buffer never grows beyond `max_out` and pending decoder output is
 * drained after the input is consumed, so the returned length is always within
 * the limit.
 *
 * @param zstream stream to use; its state is not reset by this function.
 *        Pass NULL to use a temporary stream created and freed internally
 * @param in compressed input
 * @param inlen input length
 * @param max_out maximum allowed decompressed size, 0 means unlimited
 * @param err error output (enum rspamd_decompress_error codes)
 * @return decompressed payload to be freed with rspamd_fstring_free,
 *         or NULL on error
 */
rspamd_fstring_t *rspamd_zstd_decompress_bounded(ZSTD_DStream *zstream,
												 const void *in, gsize inlen,
												 gsize max_out,
												 GError **err)
	G_GNUC_WARN_UNUSED_RESULT;

#ifdef __cplusplus
}
#endif

#endif /* RSPAMD_COMPRESSION_H */
