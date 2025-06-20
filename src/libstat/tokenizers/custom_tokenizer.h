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

#ifndef RSPAMD_CUSTOM_TOKENIZER_H
#define RSPAMD_CUSTOM_TOKENIZER_H

#include "config.h"
#include "ucl.h"
#include "libserver/word.h"

#ifdef __cplusplus
extern "C" {
#endif

#define RSPAMD_CUSTOM_TOKENIZER_API_VERSION 1

/**
 * Tokenization result - kvec of rspamd_word_t
 * Uses kvec to avoid exposing GLIB structures to external API
 */
typedef rspamd_words_t rspamd_tokenizer_result_t;

/**
 * Custom tokenizer API that must be implemented by language-specific tokenizer plugins
 * All functions use only plain C types to ensure clean boundaries
 */
typedef struct rspamd_custom_tokenizer_api {
	/* API version for compatibility checking */
	unsigned int api_version;

	/* Name of the tokenizer (e.g., "japanese_mecab") */
	const char *name;

	/**
	 * Global initialization function called once when the tokenizer is loaded
	 * @param config UCL configuration object for this tokenizer (may be NULL)
	 * @param error_buf Buffer for error message (at least 256 bytes)
	 * @return 0 on success, non-zero on failure
	 */
	int (*init)(const ucl_object_t *config, char *error_buf, size_t error_buf_size);

	/**
	 * Global cleanup function called when the tokenizer is unloaded
	 */
	void (*deinit)(void);

	/**
	 * Quick language detection to check if this tokenizer can handle the text
	 * @param text UTF-8 text to analyze
	 * @param len Length of the text in bytes
	 * @return Confidence score 0.0-1.0, or -1.0 if cannot handle
	 */
	double (*detect_language)(const char *text, size_t len);

	/**
	 * Main tokenization function
	 * @param text UTF-8 text to tokenize
	 * @param len Length of the text in bytes
	 * @param result Output kvec to fill with rspamd_word_t elements
	 * @return 0 on success, non-zero on failure
	 *
	 * The tokenizer should allocate result->a using its own allocator
	 * Rspamd will call cleanup_result() to free it after processing
	 */
	int (*tokenize)(const char *text, size_t len,
					rspamd_tokenizer_result_t *result);

	/**
	 * Cleanup the result from tokenize()
	 * @param result Result kvec returned by tokenize()
	 *
	 * This function should free result->a using the same allocator
	 * that was used in tokenize() and reset the kvec fields.
	 * This ensures proper memory management across DLL boundaries.
	 * Note: This does NOT free the result structure itself, only its contents.
	 */
	void (*cleanup_result)(rspamd_tokenizer_result_t *result);

	/**
	 * Optional: Get language hint for better language detection
	 * @return Language code (e.g., "ja", "zh") or NULL
	 */
	const char *(*get_language_hint)(void);

	/**
	 * Optional: Get minimum confidence threshold for this tokenizer
	 * @return Minimum confidence (0.0-1.0) or -1.0 to use default
	 */
	double (*get_min_confidence)(void);

} rspamd_custom_tokenizer_api_t;

/**
 * Entry point function that plugins must export
 * Must be named "rspamd_tokenizer_get_api"
 */
typedef const rspamd_custom_tokenizer_api_t *(*rspamd_tokenizer_get_api_func)(void);

/* Internal Rspamd structures - not exposed to plugins */
#ifdef RSPAMD_TOKENIZER_INTERNAL

/**
 * Custom tokenizer instance
 */
struct rspamd_custom_tokenizer {
	char *name;                               /* Tokenizer name from config */
	char *path;                               /* Path to .so file */
	void *handle;                             /* dlopen handle */
	const rspamd_custom_tokenizer_api_t *api; /* API functions */
	double priority;                          /* Detection priority */
	double min_confidence;                    /* Minimum confidence threshold */
	gboolean enabled;                         /* Is tokenizer enabled */
	ucl_object_t *config;                     /* Tokenizer-specific config */
};

/**
 * Tokenizer manager structure
 */
struct rspamd_tokenizer_manager {
	GHashTable *tokenizers;  /* name -> rspamd_custom_tokenizer */
	GArray *detection_order; /* Ordered by priority */
	rspamd_mempool_t *pool;
	double default_threshold; /* Default confidence threshold */
};

/* Manager functions */
struct rspamd_tokenizer_manager *rspamd_tokenizer_manager_new(rspamd_mempool_t *pool);
void rspamd_tokenizer_manager_destroy(struct rspamd_tokenizer_manager *mgr);

gboolean rspamd_tokenizer_manager_load_tokenizer(struct rspamd_tokenizer_manager *mgr,
												 const char *name,
												 const ucl_object_t *config,
												 GError **err);

struct rspamd_custom_tokenizer *rspamd_tokenizer_manager_detect(
	struct rspamd_tokenizer_manager *mgr,
	const char *text, size_t len,
	double *confidence,
	const char *lang_hint,
	const char **detected_lang_hint);

/* Helper function to tokenize with exceptions handling */
rspamd_tokenizer_result_t *rspamd_custom_tokenizer_tokenize_with_exceptions(
	struct rspamd_custom_tokenizer *tokenizer,
	const char *text,
	gsize len,
	GList *exceptions,
	rspamd_mempool_t *pool);

#endif /* RSPAMD_TOKENIZER_INTERNAL */

#ifdef __cplusplus
}
#endif

#endif /* RSPAMD_CUSTOM_TOKENIZER_H */
