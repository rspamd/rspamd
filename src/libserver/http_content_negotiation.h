/*
 * Copyright 2026 Vsevolod Stakhov
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
#ifndef RSPAMD_HTTP_CONTENT_NEGOTIATION_H
#define RSPAMD_HTTP_CONTENT_NEGOTIATION_H

#include "config.h"
#include "fstring.h"
#include "http/http_message.h"

#ifdef __cplusplus
extern "C" {
#endif

enum rspamd_http_content_type {
	RSPAMD_HTTP_CTYPE_JSON = 0,
	RSPAMD_HTTP_CTYPE_MSGPACK,
	RSPAMD_HTTP_CTYPE_OPENMETRICS,
	RSPAMD_HTTP_CTYPE_TEXT_PLAIN,
	RSPAMD_HTTP_CTYPE_OCTET_STREAM,
	RSPAMD_HTTP_CTYPE_UNKNOWN
};

enum rspamd_http_compression {
	RSPAMD_HTTP_COMPRESS_NONE = 0,
	RSPAMD_HTTP_COMPRESS_GZIP = (1 << 0),
	RSPAMD_HTTP_COMPRESS_ZSTD = (1 << 1),
	RSPAMD_HTTP_COMPRESS_DEFLATE = (1 << 2)
};

struct rspamd_content_negotiation_result {
	enum rspamd_http_content_type content_type;
	const char *content_type_str;
	unsigned int compression_flags;
	enum rspamd_http_compression preferred_compression;
	double content_type_quality;
	gboolean negotiation_success;
	int ucl_emit_type;
};

/**
 * Negotiate content type and encoding from HTTP request
 *
 * @param msg HTTP message containing Accept and Accept-Encoding headers
 * @param desired Array of desired content types in preference order,
 *                terminated with RSPAMD_HTTP_CTYPE_UNKNOWN
 * @param fallback Fallback content type if negotiation fails (can be UNKNOWN for no fallback)
 * @param result Output: negotiation result structure
 * @return TRUE if negotiation produced a valid result, FALSE on error
 */
gboolean rspamd_http_negotiate_content(
	struct rspamd_http_message *msg,
	const enum rspamd_http_content_type *desired,
	enum rspamd_http_content_type fallback,
	struct rspamd_content_negotiation_result *result);

/**
 * Simplified negotiation for single desired type with fallback
 *
 * @param msg HTTP message
 * @param desired Single desired content type
 * @param fallback Fallback type if client doesn't accept desired
 * @param result Output: negotiation result
 * @return TRUE on success
 */
gboolean rspamd_http_negotiate_content_simple(
	struct rspamd_http_message *msg,
	enum rspamd_http_content_type desired,
	enum rspamd_http_content_type fallback,
	struct rspamd_content_negotiation_result *result);

/**
 * Parse Accept header and return best matching content type
 *
 * @param accept_hdr Accept header value (can be NULL)
 * @param desired Array of desired types, terminated with UNKNOWN
 * @param out_quality Output: quality factor of best match (can be NULL)
 * @return Best matching content type or RSPAMD_HTTP_CTYPE_UNKNOWN
 */
enum rspamd_http_content_type rspamd_http_parse_accept_header(
	const rspamd_ftok_t *accept_hdr,
	const enum rspamd_http_content_type *desired,
	double *out_quality);

/**
 * Parse Accept-Encoding header
 *
 * @param encoding_hdr Accept-Encoding header value (can be NULL)
 * @return Bitfield of supported compression types
 */
unsigned int rspamd_http_parse_accept_encoding(
	const rspamd_ftok_t *encoding_hdr);

/**
 * Get content type string for a given enum value
 *
 * @param ctype Content type enum
 * @return Static string for Content-Type header (with parameters like charset)
 */
const char *rspamd_http_content_type_string(
	enum rspamd_http_content_type ctype);

/**
 * Get MIME type string (without parameters) for a given enum value
 *
 * @param ctype Content type enum
 * @return Static MIME type string (e.g., "application/json")
 */
const char *rspamd_http_content_type_mime(
	enum rspamd_http_content_type ctype);

#ifdef __cplusplus
}
#endif

#endif /* RSPAMD_HTTP_CONTENT_NEGOTIATION_H */
