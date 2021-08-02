/*-
 * Copyright 2021 Vsevolod Stakhov
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

#pragma once

#ifndef RSPAMD_UTF8_UTIL_H
#define RSPAMD_UTF8_UTIL_H

#include "config.h"
#include "mem_pool.h"

#ifdef  __cplusplus
extern "C" {
#endif

/**
 * Removes all unicode spaces from a string
 * @param str start of the string
 * @param len length
 * @return new length of the string trimmed
 */
const char* rspamd_string_unicode_trim_inplace (const char *str, size_t *len);

enum rspamd_normalise_result {
	RSPAMD_UNICODE_NORM_NORMAL = 0,
	RSPAMD_UNICODE_NORM_UNNORMAL = (1 << 0),
	RSPAMD_UNICODE_NORM_ZERO_SPACES = (1 << 1),
	RSPAMD_UNICODE_NORM_ERROR = (1 << 2),
	RSPAMD_UNICODE_NORM_OVERFLOW = (1 << 3)
};

/**
 * Gets a string in UTF8 and normalises it to NFKC_Casefold form
 * @param pool optional memory pool used for logging purposes
 * @param start
 * @param len
 * @return TRUE if a string has been normalised
 */
enum rspamd_normalise_result rspamd_normalise_unicode_inplace(gchar *start, gsize *len);

/**
 * Compare two strings using libicu collator
 * @param s1
 * @param s2
 * @param n
 * @return an integer greater than, equal to, or less than 0, according as the string s1 is greater than, equal to, or less than the string s2.
 */
int rspamd_utf8_strcmp(const char *s1, const char *s2, gsize n);
/**
 * Similar to rspamd_utf8_strcmp but accepts two sizes
 * @param s1
 * @param n1
 * @param s2
 * @param n2
 * @return
 */
int rspamd_utf8_strcmp_sizes(const char *s1, gsize n1, const char *s2, gsize n2);

#ifdef  __cplusplus
}
#endif

#endif //RSPAMD_UTF8_UTIL_H
