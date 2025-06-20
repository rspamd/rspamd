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

#ifndef RSPAMD_WORD_H
#define RSPAMD_WORD_H

#include "config.h"
#include "fstring.h"
#include "contrib/libucl/kvec.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @file word.h
 * Word processing structures and definitions
 */

/* Word flags */
#define RSPAMD_WORD_FLAG_TEXT (1u << 0)
#define RSPAMD_WORD_FLAG_META (1u << 1)
#define RSPAMD_WORD_FLAG_LUA_META (1u << 2)
#define RSPAMD_WORD_FLAG_EXCEPTION (1u << 3)
#define RSPAMD_WORD_FLAG_HEADER (1u << 4)
#define RSPAMD_WORD_FLAG_UNIGRAM (1u << 5)
#define RSPAMD_WORD_FLAG_UTF (1u << 6)
#define RSPAMD_WORD_FLAG_NORMALISED (1u << 7)
#define RSPAMD_WORD_FLAG_STEMMED (1u << 8)
#define RSPAMD_WORD_FLAG_BROKEN_UNICODE (1u << 9)
#define RSPAMD_WORD_FLAG_STOP_WORD (1u << 10)
#define RSPAMD_WORD_FLAG_SKIPPED (1u << 11)
#define RSPAMD_WORD_FLAG_INVISIBLE_SPACES (1u << 12)
#define RSPAMD_WORD_FLAG_EMOJI (1u << 13)

/**
 * Word structure representing tokenized text
 */
typedef struct rspamd_word_s {
	rspamd_ftok_t original;        /* utf8 raw */
	rspamd_ftok_unicode_t unicode; /* array of unicode characters, normalized, lowercased */
	rspamd_ftok_t normalized;      /* normalized and lowercased utf8 */
	rspamd_ftok_t stemmed;         /* stemmed utf8 */
	unsigned int flags;
} rspamd_word_t;

/**
 * Vector of words using kvec
 */
typedef kvec_t(rspamd_word_t) rspamd_words_t;

/* Legacy typedefs for backward compatibility */
typedef rspamd_word_t rspamd_stat_token_t;

/* Legacy flag aliases for backward compatibility */
#define RSPAMD_STAT_TOKEN_FLAG_TEXT RSPAMD_WORD_FLAG_TEXT
#define RSPAMD_STAT_TOKEN_FLAG_META RSPAMD_WORD_FLAG_META
#define RSPAMD_STAT_TOKEN_FLAG_LUA_META RSPAMD_WORD_FLAG_LUA_META
#define RSPAMD_STAT_TOKEN_FLAG_EXCEPTION RSPAMD_WORD_FLAG_EXCEPTION
#define RSPAMD_STAT_TOKEN_FLAG_HEADER RSPAMD_WORD_FLAG_HEADER
#define RSPAMD_STAT_TOKEN_FLAG_UNIGRAM RSPAMD_WORD_FLAG_UNIGRAM
#define RSPAMD_STAT_TOKEN_FLAG_UTF RSPAMD_WORD_FLAG_UTF
#define RSPAMD_STAT_TOKEN_FLAG_NORMALISED RSPAMD_WORD_FLAG_NORMALISED
#define RSPAMD_STAT_TOKEN_FLAG_STEMMED RSPAMD_WORD_FLAG_STEMMED
#define RSPAMD_STAT_TOKEN_FLAG_BROKEN_UNICODE RSPAMD_WORD_FLAG_BROKEN_UNICODE
#define RSPAMD_STAT_TOKEN_FLAG_STOP_WORD RSPAMD_WORD_FLAG_STOP_WORD
#define RSPAMD_STAT_TOKEN_FLAG_SKIPPED RSPAMD_WORD_FLAG_SKIPPED
#define RSPAMD_STAT_TOKEN_FLAG_INVISIBLE_SPACES RSPAMD_WORD_FLAG_INVISIBLE_SPACES
#define RSPAMD_STAT_TOKEN_FLAG_EMOJI RSPAMD_WORD_FLAG_EMOJI

#ifdef __cplusplus
}
#endif

#endif /* RSPAMD_WORD_H */
