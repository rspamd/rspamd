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
#include "config.h"
#include "compression.h"

GQuark
rspamd_decompress_quark(void)
{
	return g_quark_from_static_string("rspamd-decompress");
}

rspamd_fstring_t *
rspamd_zstd_decompress_bounded(ZSTD_DStream *zstream,
							   const void *in, gsize inlen,
							   gsize max_out, GError **err)
{
	ZSTD_DStream *own_stream = NULL;
	ZSTD_inBuffer zin;
	ZSTD_outBuffer zout;
	rspamd_fstring_t *body;
	gsize outlen, r;

	if (zstream == NULL) {
		own_stream = ZSTD_createDStream();

		if (own_stream == NULL || ZSTD_isError(ZSTD_initDStream(own_stream))) {
			g_set_error(err, rspamd_decompress_quark(),
						RSPAMD_DECOMPRESS_ERROR_INIT,
						"cannot initialize zstd decompressor");
			if (own_stream != NULL) {
				ZSTD_freeDStream(own_stream);
			}

			return NULL;
		}

		zstream = own_stream;
	}

	zin.src = in;
	zin.size = inlen;
	zin.pos = 0;

	outlen = ZSTD_getDecompressedSize(in, inlen);

	if (outlen == 0) {
		outlen = ZSTD_DStreamOutSize();

		if (max_out > 0 && outlen > max_out) {
			outlen = max_out;
		}
	}
	else if (max_out > 0 && outlen > max_out) {
		g_set_error(err, rspamd_decompress_quark(),
					RSPAMD_DECOMPRESS_ERROR_TOO_LARGE,
					"declared decompressed size %" G_GSIZE_FORMAT
					" exceeds limit %" G_GSIZE_FORMAT,
					outlen, max_out);
		if (own_stream != NULL) {
			ZSTD_freeDStream(own_stream);
		}

		return NULL;
	}

	body = rspamd_fstring_sized_new(outlen);
	zout.dst = body->str;
	zout.pos = 0;
	zout.size = body->allocated;

	if (max_out > 0 && zout.size > max_out) {
		zout.size = max_out;
	}

	for (;;) {
		r = ZSTD_decompressStream(zstream, &zout, &zin);

		if (ZSTD_isError(r)) {
			g_set_error(err, rspamd_decompress_quark(),
						RSPAMD_DECOMPRESS_ERROR_DATA,
						"decompression error: %s", ZSTD_getErrorName(r));
			rspamd_fstring_free(body);
			if (own_stream != NULL) {
				ZSTD_freeDStream(own_stream);
			}

			return NULL;
		}

		if (zin.pos == zin.size && r == 0) {
			/* All input consumed and the last frame is complete */
			break;
		}

		if (zout.pos == zout.size) {
			/* Need a larger output buffer */
			if (max_out > 0 && zout.size >= max_out) {
				g_set_error(err, rspamd_decompress_quark(),
							RSPAMD_DECOMPRESS_ERROR_TOO_LARGE,
							"decompressed size exceeds limit %" G_GSIZE_FORMAT,
							max_out);
				rspamd_fstring_free(body);
				if (own_stream != NULL) {
					ZSTD_freeDStream(own_stream);
				}

				return NULL;
			}

			body = rspamd_fstring_grow(body, zout.size + 1);
			zout.dst = body->str;
			zout.size = body->allocated;

			if (max_out > 0 && zout.size > max_out) {
				zout.size = max_out;
			}
		}
		else if (zin.pos == zin.size) {
			/*
			 * Input is exhausted mid-frame and the decoder has nothing more
			 * to flush: truncated input; keep the partial output as the
			 * legacy per-caller loops did
			 */
			break;
		}
	}

	body->len = zout.pos;

	if (own_stream != NULL) {
		ZSTD_freeDStream(own_stream);
	}

	return body;
}
