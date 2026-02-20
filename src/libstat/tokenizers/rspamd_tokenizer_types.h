/*
 * Copyright 2025 Vsevolod Stakhov
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

#ifndef RSPAMD_TOKENIZER_TYPES_H
#define RSPAMD_TOKENIZER_TYPES_H

/*
 * Standalone type definitions for custom tokenizers
 * This header is completely self-contained and does not depend on any external libraries.
 * Custom tokenizers should include only this header to get access to all necessary types.
 */

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Basic string token structure
 */
typedef struct rspamd_ftok {
	size_t len;
	const char *begin;
} rspamd_ftok_t;

/**
 * Unicode string token structure
 */
typedef struct rspamd_ftok_unicode {
	size_t len;
	const uint32_t *begin;
} rspamd_ftok_unicode_t;

/* Word flags */
#define RSPAMD_WORD_FLAG_TEXT (1u << 0u)
#define RSPAMD_WORD_FLAG_META (1u << 1u)
#define RSPAMD_WORD_FLAG_LUA_META (1u << 2u)
#define RSPAMD_WORD_FLAG_EXCEPTION (1u << 3u)
#define RSPAMD_WORD_FLAG_HEADER (1u << 4u)
#define RSPAMD_WORD_FLAG_UNIGRAM (1u << 5u)
#define RSPAMD_WORD_FLAG_UTF (1u << 6u)
#define RSPAMD_WORD_FLAG_NORMALISED (1u << 7u)
#define RSPAMD_WORD_FLAG_STEMMED (1u << 8u)
#define RSPAMD_WORD_FLAG_BROKEN_UNICODE (1u << 9u)
#define RSPAMD_WORD_FLAG_STOP_WORD (1u << 10u)
#define RSPAMD_WORD_FLAG_SKIPPED (1u << 11u)
#define RSPAMD_WORD_FLAG_INVISIBLE_SPACES (1u << 12u)
#define RSPAMD_WORD_FLAG_EMOJI (1u << 13u)

/**
 * Word structure
 */
typedef struct rspamd_word {
	rspamd_ftok_t original;
	rspamd_ftok_unicode_t unicode;
	rspamd_ftok_t normalized;
	rspamd_ftok_t stemmed;
	unsigned int flags;
} rspamd_word_t;

/**
 * Array of words
 */
typedef struct rspamd_words {
	rspamd_word_t *a;
	size_t n;
	size_t m;
} rspamd_words_t;

#ifdef __cplusplus
}
#endif

#endif /* RSPAMD_TOKENIZER_TYPES_H */
