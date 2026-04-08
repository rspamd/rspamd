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

#include "config.h"
#include "http_content_negotiation.h"
#include "http/http_message.h"
#include "str_util.h"
#include "ucl.h"

#include <string.h>
#include <stdlib.h>
#include <ctype.h>

struct rspamd_content_type_mapping {
	const char *mime_type;
	const char *full_type_str;
	enum rspamd_http_content_type type_enum;
	int ucl_emit_type;
};

static const struct rspamd_content_type_mapping content_type_map[] = {
	{
		.mime_type = "application/json",
		.full_type_str = "application/json",
		.type_enum = RSPAMD_HTTP_CTYPE_JSON,
		.ucl_emit_type = UCL_EMIT_JSON_COMPACT,
	},
	{
		.mime_type = "application/msgpack",
		.full_type_str = "application/msgpack",
		.type_enum = RSPAMD_HTTP_CTYPE_MSGPACK,
		.ucl_emit_type = UCL_EMIT_MSGPACK,
	},
	{
		.mime_type = "application/openmetrics-text",
		.full_type_str = "application/openmetrics-text; version=1.0.0; charset=utf-8",
		.type_enum = RSPAMD_HTTP_CTYPE_OPENMETRICS,
		.ucl_emit_type = -1,
	},
	{
		.mime_type = "text/plain",
		.full_type_str = "text/plain; version=0.0.4; charset=utf-8",
		.type_enum = RSPAMD_HTTP_CTYPE_TEXT_PLAIN,
		.ucl_emit_type = -1,
	},
	{
		.mime_type = "application/octet-stream",
		.full_type_str = "application/octet-stream",
		.type_enum = RSPAMD_HTTP_CTYPE_OCTET_STREAM,
		.ucl_emit_type = -1,
	},
	{NULL, NULL, RSPAMD_HTTP_CTYPE_UNKNOWN, -1},
};

const char *
rspamd_http_content_type_string(enum rspamd_http_content_type ctype)
{
	for (gsize i = 0; content_type_map[i].mime_type != NULL; i++) {
		if (content_type_map[i].type_enum == ctype) {
			return content_type_map[i].full_type_str;
		}
	}

	return "application/octet-stream";
}

const char *
rspamd_http_content_type_mime(enum rspamd_http_content_type ctype)
{
	for (gsize i = 0; content_type_map[i].mime_type != NULL; i++) {
		if (content_type_map[i].type_enum == ctype) {
			return content_type_map[i].mime_type;
		}
	}

	return "application/octet-stream";
}

static int
rspamd_http_content_type_ucl_emit(enum rspamd_http_content_type ctype)
{
	for (gsize i = 0; content_type_map[i].mime_type != NULL; i++) {
		if (content_type_map[i].type_enum == ctype) {
			return content_type_map[i].ucl_emit_type;
		}
	}

	return -1;
}

static gboolean
rspamd_http_content_type_matches(const char *media_type, gsize media_len,
								 enum rspamd_http_content_type desired)
{
	const char *desired_mime = rspamd_http_content_type_mime(desired);
	const char *slash;
	gsize desired_len;

	if (media_len == 3 && memcmp(media_type, "*/*", 3) == 0) {
		return TRUE;
	}

	slash = memchr(media_type, '/', media_len);
	if (slash && media_len > 2) {
		gsize type_len = slash - media_type;
		if (media_len >= type_len + 2 && media_type[type_len + 1] == '*') {
			const char *desired_slash = strchr(desired_mime, '/');
			if (desired_slash) {
				gsize desired_type_len = desired_slash - desired_mime;
				if (type_len == desired_type_len &&
					g_ascii_strncasecmp(media_type, desired_mime, type_len) == 0) {
					return TRUE;
				}
			}
		}
	}

	desired_len = strlen(desired_mime);
	if (media_len == desired_len &&
		g_ascii_strncasecmp(media_type, desired_mime, media_len) == 0) {
		return TRUE;
	}

	return FALSE;
}

static gboolean
rspamd_http_parse_media_range(const char *start, gsize len,
							  const enum rspamd_http_content_type *desired,
							  enum rspamd_http_content_type *out_type,
							  double *out_quality)
{
	const char *end = start + len;
	const char *semicolon;
	const char *q_pos;
	gsize mime_len;
	double quality = 1.0;

	while (start < end && g_ascii_isspace(*start)) {
		start++;
	}
	while (end > start && g_ascii_isspace(*(end - 1))) {
		end--;
	}

	if (start >= end) {
		return FALSE;
	}

	semicolon = memchr(start, ';', end - start);

	if (semicolon) {
		mime_len = semicolon - start;

		while (mime_len > 0 && g_ascii_isspace(start[mime_len - 1])) {
			mime_len--;
		}

		q_pos = semicolon + 1;
		while (q_pos < end) {
			while (q_pos < end && g_ascii_isspace(*q_pos)) {
				q_pos++;
			}

			if (q_pos + 2 <= end &&
				(q_pos[0] == 'q' || q_pos[0] == 'Q') &&
				q_pos[1] == '=') {
				char *endptr;
				double q;

				q_pos += 2;
				q = strtod(q_pos, &endptr);
				if (endptr > q_pos) {
					quality = CLAMP(q, 0.0, 1.0);
				}
				break;
			}

			q_pos = memchr(q_pos, ';', end - q_pos);
			if (q_pos) {
				q_pos++;
			}
			else {
				break;
			}
		}
	}
	else {
		mime_len = end - start;
	}

	if (mime_len == 0) {
		return FALSE;
	}

	for (const enum rspamd_http_content_type *d = desired;
		 *d != RSPAMD_HTTP_CTYPE_UNKNOWN; d++) {
		if (rspamd_http_content_type_matches(start, mime_len, *d)) {
			*out_type = *d;
			*out_quality = quality;
			return TRUE;
		}
	}

	return FALSE;
}

enum rspamd_http_content_type
rspamd_http_parse_accept_header(const rspamd_ftok_t *accept_hdr,
								const enum rspamd_http_content_type *desired,
								double *out_quality)
{
	if (!accept_hdr || accept_hdr->len == 0 || !desired) {
		if (out_quality) {
			*out_quality = 1.0;
		}
		return RSPAMD_HTTP_CTYPE_UNKNOWN;
	}

	double best_quality = -1.0;
	enum rspamd_http_content_type best_type = RSPAMD_HTTP_CTYPE_UNKNOWN;

	const char *cur = accept_hdr->begin;
	const char *end = accept_hdr->begin + accept_hdr->len;

	while (cur < end) {
		const char *comma = memchr(cur, ',', end - cur);
		gsize range_len = comma ? (gsize) (comma - cur) : (gsize) (end - cur);

		enum rspamd_http_content_type match_type;
		double match_quality;

		if (rspamd_http_parse_media_range(cur, range_len, desired,
										  &match_type, &match_quality)) {
			if (match_quality > best_quality) {
				best_quality = match_quality;
				best_type = match_type;
			}
		}

		cur = comma ? comma + 1 : end;
	}

	if (out_quality) {
		*out_quality = best_quality > 0 ? best_quality : 1.0;
	}

	return best_type;
}

unsigned int
rspamd_http_parse_accept_encoding(const rspamd_ftok_t *encoding_hdr)
{
	unsigned int flags = RSPAMD_HTTP_COMPRESS_NONE;

	if (!encoding_hdr || encoding_hdr->len == 0) {
		return flags;
	}

	if (rspamd_substring_search_caseless(encoding_hdr->begin, encoding_hdr->len,
										 "gzip", 4) != -1) {
		flags |= RSPAMD_HTTP_COMPRESS_GZIP;
	}

	if (rspamd_substring_search_caseless(encoding_hdr->begin, encoding_hdr->len,
										 "zstd", 4) != -1) {
		flags |= RSPAMD_HTTP_COMPRESS_ZSTD;
	}

	if (rspamd_substring_search_caseless(encoding_hdr->begin, encoding_hdr->len,
										 "deflate", 7) != -1) {
		flags |= RSPAMD_HTTP_COMPRESS_DEFLATE;
	}

	return flags;
}

gboolean
rspamd_http_negotiate_content(struct rspamd_http_message *msg,
							  const enum rspamd_http_content_type *desired,
							  enum rspamd_http_content_type fallback,
							  struct rspamd_content_negotiation_result *result)
{
	const rspamd_ftok_t *accept_hdr;
	const rspamd_ftok_t *encoding_hdr;

	if (!result || !desired) {
		return FALSE;
	}

	memset(result, 0, sizeof(*result));
	result->content_type = desired[0];
	result->content_type_str = rspamd_http_content_type_string(desired[0]);
	result->compression_flags = RSPAMD_HTTP_COMPRESS_NONE;
	result->preferred_compression = RSPAMD_HTTP_COMPRESS_NONE;
	result->content_type_quality = 1.0;
	result->negotiation_success = FALSE;
	result->ucl_emit_type = rspamd_http_content_type_ucl_emit(desired[0]);

	if (!msg) {
		result->negotiation_success = TRUE;
		return TRUE;
	}

	accept_hdr = rspamd_http_message_find_header(msg, "Accept");

	if (accept_hdr && accept_hdr->len > 0) {
		double quality;
		enum rspamd_http_content_type matched =
			rspamd_http_parse_accept_header(accept_hdr, desired, &quality);

		if (matched != RSPAMD_HTTP_CTYPE_UNKNOWN && quality > 0) {
			result->content_type = matched;
			result->content_type_str = rspamd_http_content_type_string(matched);
			result->content_type_quality = quality;
			result->negotiation_success = TRUE;
			result->ucl_emit_type = rspamd_http_content_type_ucl_emit(matched);
		}
		else if (fallback != RSPAMD_HTTP_CTYPE_UNKNOWN) {
			result->content_type = fallback;
			result->content_type_str = rspamd_http_content_type_string(fallback);
			result->content_type_quality = 0.0;
			result->negotiation_success = FALSE;
			result->ucl_emit_type = rspamd_http_content_type_ucl_emit(fallback);
		}
	}
	else {
		result->negotiation_success = TRUE;
	}

	encoding_hdr = rspamd_http_message_find_header(msg, "Accept-Encoding");

	if (encoding_hdr && encoding_hdr->len > 0) {
		result->compression_flags = rspamd_http_parse_accept_encoding(encoding_hdr);

		if (result->compression_flags & RSPAMD_HTTP_COMPRESS_ZSTD) {
			result->preferred_compression = RSPAMD_HTTP_COMPRESS_ZSTD;
		}
		else if (result->compression_flags & RSPAMD_HTTP_COMPRESS_GZIP) {
			result->preferred_compression = RSPAMD_HTTP_COMPRESS_GZIP;
		}
		else if (result->compression_flags & RSPAMD_HTTP_COMPRESS_DEFLATE) {
			result->preferred_compression = RSPAMD_HTTP_COMPRESS_DEFLATE;
		}
	}

	return TRUE;
}

gboolean
rspamd_http_negotiate_content_simple(struct rspamd_http_message *msg,
									 enum rspamd_http_content_type desired,
									 enum rspamd_http_content_type fallback,
									 struct rspamd_content_negotiation_result *result)
{
	enum rspamd_http_content_type desired_arr[] = {
		desired,
		RSPAMD_HTTP_CTYPE_UNKNOWN,
	};

	return rspamd_http_negotiate_content(msg, desired_arr, fallback, result);
}
