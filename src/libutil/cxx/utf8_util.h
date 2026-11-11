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

struct rspamd_unicode_spoof_checker;

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Removes all unicode spaces from a string
 * @param str start of the string
 * @param len length
 * @return new length of the string trimmed
 */
const char *rspamd_string_unicode_trim_inplace(const char *str, size_t *len);

enum rspamd_utf8_normalise_result {
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
enum rspamd_utf8_normalise_result rspamd_normalise_unicode_inplace(char *start, gsize *len);

/**
 * Normalises a string like rspamd_normalise_unicode_inplace but writes the
 * result to another buffer, so that it may be longer than the input.
 * @param in input string
 * @param in_len length of the input
 * @param out output buffer, may be NULL if out_cap is zero
 * @param out_cap size of the output buffer
 * @param out_len set to the number of bytes written to the output
 * @param needed set to the size of the complete result: if it is greater than
 * out_cap, the output holds only its first out_len bytes and the call should be
 * repeated with a larger buffer
 * @return normalisation flags; on RSPAMD_UNICODE_NORM_ERROR nothing is written
 */
enum rspamd_utf8_normalise_result rspamd_normalise_unicode_to(const char *in, gsize in_len,
															  char *out, gsize out_cap,
															  gsize *out_len, gsize *needed);

/**
 * Transliterate a string to ASCII
 * @param start
 * @param len
 * @param target_len
 * @return a new string that should be freed with g_free
 */
char *rspamd_utf8_transliterate(const char *start, gsize len, gsize *target_len);

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

enum rspamd_unicode_spoof_flags {
	RSPAMD_UNICODE_SPOOF_NONE = 0,
	RSPAMD_UNICODE_SPOOF_RESTRICTION = (1 << 0),
	RSPAMD_UNICODE_SPOOF_INVISIBLE = (1 << 1),
	RSPAMD_UNICODE_SPOOF_MIXED_NUMBERS = (1 << 2),
};

/**
 * Create an immutable ICU spoof checker using the Highly Restrictive profile.
 * The returned checker can be shared by concurrent readers.
 */
struct rspamd_unicode_spoof_checker *rspamd_unicode_spoof_checker_create(void);

/** Destroy a checker created by rspamd_unicode_spoof_checker_create. */
void rspamd_unicode_spoof_checker_destroy(void *checker);

/**
 * Check a UTF-8 identifier. Returns rspamd_unicode_spoof_flags, or -1 on error.
 */
int rspamd_unicode_spoof_check(const struct rspamd_unicode_spoof_checker *checker,
							   const char *start, gsize len);

/**
 * Generate the UTS #39 confusable skeleton for a UTF-8 identifier.
 * Returns the complete output length, or -1 on error. A too-small destination
 * is reported by returning the required length.
 */
gssize rspamd_unicode_spoof_skeleton(const struct rspamd_unicode_spoof_checker *checker,
									 const char *start, gsize len,
									 char *dest, gsize dest_capacity);

#ifdef __cplusplus
}
#endif

#endif//RSPAMD_UTF8_UTIL_H
