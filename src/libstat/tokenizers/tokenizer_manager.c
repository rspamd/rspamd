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

#include "config.h"
#include "tokenizers.h"
#define RSPAMD_TOKENIZER_INTERNAL
#include "custom_tokenizer.h"
#include "libutil/util.h"
#include "libserver/logger.h"
#include <dlfcn.h>

#define msg_err_tokenizer(...) rspamd_default_log_function(G_LOG_LEVEL_CRITICAL, \
														   "tokenizer", "",      \
														   RSPAMD_LOG_FUNC,      \
														   __VA_ARGS__)
#define msg_warn_tokenizer(...) rspamd_default_log_function(G_LOG_LEVEL_WARNING, \
															"tokenizer", "",     \
															RSPAMD_LOG_FUNC,     \
															__VA_ARGS__)
#define msg_info_tokenizer(...) rspamd_default_log_function(G_LOG_LEVEL_INFO, \
															"tokenizer", "",  \
															RSPAMD_LOG_FUNC,  \
															__VA_ARGS__)
#define msg_debug_tokenizer(...) rspamd_conditional_debug_fast(NULL, NULL,                               \
															   rspamd_tokenizer_log_id, "tokenizer", "", \
															   RSPAMD_LOG_FUNC,                          \
															   __VA_ARGS__)

INIT_LOG_MODULE(tokenizer)

static void
rspamd_custom_tokenizer_dtor(gpointer p)
{
	struct rspamd_custom_tokenizer *tok = p;

	if (tok) {
		if (tok->api && tok->api->deinit) {
			tok->api->deinit();
		}

		if (tok->handle) {
			dlclose(tok->handle);
		}

		if (tok->config) {
			ucl_object_unref(tok->config);
		}

		g_free(tok->name);
		g_free(tok->path);
		g_free(tok);
	}
}

static int
rspamd_custom_tokenizer_priority_cmp(gconstpointer a, gconstpointer b)
{
	const struct rspamd_custom_tokenizer *t1 = *(const struct rspamd_custom_tokenizer **) a;
	const struct rspamd_custom_tokenizer *t2 = *(const struct rspamd_custom_tokenizer **) b;

	/* Higher priority first */
	if (t1->priority > t2->priority) {
		return -1;
	}
	else if (t1->priority < t2->priority) {
		return 1;
	}

	return 0;
}

struct rspamd_tokenizer_manager *
rspamd_tokenizer_manager_new(rspamd_mempool_t *pool)
{
	struct rspamd_tokenizer_manager *mgr;

	mgr = rspamd_mempool_alloc0(pool, sizeof(*mgr));
	mgr->pool = pool;
	mgr->tokenizers = g_hash_table_new_full(rspamd_strcase_hash,
											rspamd_strcase_equal,
											NULL,
											rspamd_custom_tokenizer_dtor);
	mgr->detection_order = g_array_new(FALSE, FALSE, sizeof(struct rspamd_custom_tokenizer *));
	mgr->default_threshold = 0.7; /* Default confidence threshold */

	rspamd_mempool_add_destructor(pool,
								  (rspamd_mempool_destruct_t) g_hash_table_unref,
								  mgr->tokenizers);
	rspamd_mempool_add_destructor(pool,
								  (rspamd_mempool_destruct_t) rspamd_array_free_hard,
								  mgr->detection_order);

	msg_info_tokenizer("created custom tokenizer manager with default confidence threshold %.3f",
					   mgr->default_threshold);

	return mgr;
}

void rspamd_tokenizer_manager_destroy(struct rspamd_tokenizer_manager *mgr)
{
	/* Cleanup is handled by memory pool destructors */
}

gboolean
rspamd_tokenizer_manager_load_tokenizer(struct rspamd_tokenizer_manager *mgr,
										const char *name,
										const ucl_object_t *config,
										GError **err)
{
	struct rspamd_custom_tokenizer *tok;
	const ucl_object_t *elt;
	rspamd_tokenizer_get_api_func get_api;
	const rspamd_custom_tokenizer_api_t *api;
	void *handle;
	const char *path;
	gboolean enabled = TRUE;
	double priority = 50.0;
	char error_buf[256];

	g_assert(mgr != NULL);
	g_assert(name != NULL);
	g_assert(config != NULL);

	msg_info_tokenizer("starting to load custom tokenizer '%s'", name);

	/* Check if enabled */
	elt = ucl_object_lookup(config, "enabled");
	if (elt && ucl_object_type(elt) == UCL_BOOLEAN) {
		enabled = ucl_object_toboolean(elt);
	}

	if (!enabled) {
		msg_info_tokenizer("custom tokenizer '%s' is disabled", name);
		return TRUE;
	}

	/* Get path */
	elt = ucl_object_lookup(config, "path");
	if (!elt || ucl_object_type(elt) != UCL_STRING) {
		g_set_error(err, g_quark_from_static_string("tokenizer"),
					EINVAL, "missing 'path' for tokenizer %s", name);
		return FALSE;
	}
	path = ucl_object_tostring(elt);
	msg_info_tokenizer("custom tokenizer '%s' will be loaded from path: %s", name, path);

	/* Get priority */
	elt = ucl_object_lookup(config, "priority");
	if (elt) {
		priority = ucl_object_todouble(elt);
	}
	msg_info_tokenizer("custom tokenizer '%s' priority set to %.1f", name, priority);

	/* Load the shared library */
	msg_info_tokenizer("loading shared library for custom tokenizer '%s'", name);
	handle = dlopen(path, RTLD_NOW | RTLD_LOCAL);
	if (!handle) {
		g_set_error(err, g_quark_from_static_string("tokenizer"),
					EINVAL, "cannot load tokenizer %s from %s: %s",
					name, path, dlerror());
		return FALSE;
	}
	msg_info_tokenizer("successfully loaded shared library for custom tokenizer '%s'", name);

	/* Get the API entry point */
	msg_info_tokenizer("looking up API entry point for custom tokenizer '%s'", name);
	get_api = (rspamd_tokenizer_get_api_func) dlsym(handle, "rspamd_tokenizer_get_api");
	if (!get_api) {
		dlclose(handle);
		g_set_error(err, g_quark_from_static_string("tokenizer"),
					EINVAL, "cannot find entry point in %s: %s",
					path, dlerror());
		return FALSE;
	}

	/* Get the API */
	msg_info_tokenizer("calling API entry point for custom tokenizer '%s'", name);
	api = get_api();
	if (!api) {
		dlclose(handle);
		g_set_error(err, g_quark_from_static_string("tokenizer"),
					EINVAL, "tokenizer %s returned NULL API", name);
		return FALSE;
	}
	msg_info_tokenizer("successfully obtained API from custom tokenizer '%s'", name);

	/* Check API version */
	msg_info_tokenizer("checking API version for custom tokenizer '%s' (got %u, expected %u)",
					   name, api->api_version, RSPAMD_CUSTOM_TOKENIZER_API_VERSION);
	if (api->api_version != RSPAMD_CUSTOM_TOKENIZER_API_VERSION) {
		dlclose(handle);
		g_set_error(err, g_quark_from_static_string("tokenizer"),
					EINVAL, "tokenizer %s has incompatible API version %u (expected %u)",
					name, api->api_version, RSPAMD_CUSTOM_TOKENIZER_API_VERSION);
		return FALSE;
	}

	/* Create tokenizer instance */
	tok = g_malloc0(sizeof(*tok));
	tok->name = g_strdup(name);
	tok->path = g_strdup(path);
	tok->handle = handle;
	tok->api = api;
	tok->priority = priority;
	tok->enabled = enabled;

	/* Get tokenizer config */
	elt = ucl_object_lookup(config, "config");
	if (elt) {
		tok->config = ucl_object_ref(elt);
	}

	/* Get minimum confidence */
	if (api->get_min_confidence) {
		tok->min_confidence = api->get_min_confidence();
		msg_info_tokenizer("custom tokenizer '%s' provides minimum confidence threshold: %.3f",
						   name, tok->min_confidence);
	}
	else {
		tok->min_confidence = mgr->default_threshold;
		msg_info_tokenizer("custom tokenizer '%s' using default confidence threshold: %.3f",
						   name, tok->min_confidence);
	}

	/* Initialize the tokenizer */
	if (api->init) {
		msg_info_tokenizer("initializing custom tokenizer '%s'", name);
		error_buf[0] = '\0';
		if (api->init(tok->config, error_buf, sizeof(error_buf)) != 0) {
			g_set_error(err, g_quark_from_static_string("tokenizer"),
						EINVAL, "failed to initialize tokenizer %s: %s",
						name, error_buf[0] ? error_buf : "unknown error");
			rspamd_custom_tokenizer_dtor(tok);
			return FALSE;
		}
		msg_info_tokenizer("successfully initialized custom tokenizer '%s'", name);
	}
	else {
		msg_info_tokenizer("custom tokenizer '%s' does not require initialization", name);
	}

	/* Add to manager */
	g_hash_table_insert(mgr->tokenizers, tok->name, tok);
	g_array_append_val(mgr->detection_order, tok);

	/* Re-sort by priority */
	g_array_sort(mgr->detection_order, rspamd_custom_tokenizer_priority_cmp);
	msg_info_tokenizer("custom tokenizer '%s' registered and sorted by priority (total tokenizers: %u)",
					   name, mgr->detection_order->len);

	msg_info_tokenizer("successfully loaded custom tokenizer '%s' (priority %.1f) from %s",
					   name, priority, path);

	return TRUE;
}

struct rspamd_custom_tokenizer *
rspamd_tokenizer_manager_detect(struct rspamd_tokenizer_manager *mgr,
								const char *text, size_t len,
								double *confidence,
								const char *lang_hint,
								const char **detected_lang_hint)
{
	struct rspamd_custom_tokenizer *tok, *best_tok = NULL;
	double conf, best_conf = 0.0;
	unsigned int i;

	g_assert(mgr != NULL);
	g_assert(text != NULL);

	msg_debug_tokenizer("starting tokenizer detection for text of length %zu", len);

	if (confidence) {
		*confidence = 0.0;
	}

	if (detected_lang_hint) {
		*detected_lang_hint = NULL;
	}

	/* If we have a language hint, try to find a tokenizer for that language first */
	if (lang_hint) {
		msg_info_tokenizer("trying to find tokenizer for language hint: %s", lang_hint);
		for (i = 0; i < mgr->detection_order->len; i++) {
			tok = g_array_index(mgr->detection_order, struct rspamd_custom_tokenizer *, i);

			if (!tok->enabled || !tok->api->get_language_hint) {
				continue;
			}

			/* Check if this tokenizer handles the hinted language */
			const char *tok_lang = tok->api->get_language_hint();
			if (tok_lang && g_ascii_strcasecmp(tok_lang, lang_hint) == 0) {
				msg_info_tokenizer("found tokenizer '%s' for language hint '%s'", tok->name, lang_hint);
				/* Found a tokenizer for this language, check if it actually detects it */
				if (tok->api->detect_language) {
					conf = tok->api->detect_language(text, len);
					msg_info_tokenizer("tokenizer '%s' confidence for hinted language: %.3f (threshold: %.3f)",
									   tok->name, conf, tok->min_confidence);
					if (conf >= tok->min_confidence) {
						/* Use this tokenizer */
						msg_info_tokenizer("using tokenizer '%s' for language hint '%s' with confidence %.3f",
										   tok->name, lang_hint, conf);
						if (confidence) {
							*confidence = conf;
						}
						if (detected_lang_hint) {
							*detected_lang_hint = tok_lang;
						}
						return tok;
					}
				}
			}
		}
		msg_info_tokenizer("no suitable tokenizer found for language hint '%s', falling back to general detection", lang_hint);
	}

	/* Try each tokenizer in priority order */
	msg_info_tokenizer("trying %u tokenizers for general detection", mgr->detection_order->len);
	for (i = 0; i < mgr->detection_order->len; i++) {
		tok = g_array_index(mgr->detection_order, struct rspamd_custom_tokenizer *, i);

		if (!tok->enabled || !tok->api->detect_language) {
			msg_debug_tokenizer("skipping tokenizer '%s' (enabled: %s, has detect_language: %s)",
								tok->name, tok->enabled ? "yes" : "no",
								tok->api->detect_language ? "yes" : "no");
			continue;
		}

		conf = tok->api->detect_language(text, len);
		msg_info_tokenizer("tokenizer '%s' detection confidence: %.3f (threshold: %.3f, current best: %.3f)",
						   tok->name, conf, tok->min_confidence, best_conf);

		if (conf > best_conf && conf >= tok->min_confidence) {
			best_conf = conf;
			best_tok = tok;
			msg_info_tokenizer("tokenizer '%s' is new best with confidence %.3f", tok->name, best_conf);

			/* Early exit if very confident */
			if (conf >= 0.95) {
				msg_info_tokenizer("very high confidence (%.3f >= 0.95), using tokenizer '%s' immediately",
								   conf, tok->name);
				break;
			}
		}
	}

	if (best_tok) {
		msg_info_tokenizer("selected tokenizer '%s' with confidence %.3f", best_tok->name, best_conf);
		if (confidence) {
			*confidence = best_conf;
		}

		if (detected_lang_hint && best_tok->api->get_language_hint) {
			*detected_lang_hint = best_tok->api->get_language_hint();
			msg_info_tokenizer("detected language hint: %s", *detected_lang_hint);
		}
	}
	else {
		msg_info_tokenizer("no suitable tokenizer found during detection");
	}

	return best_tok;
}

/* Helper function to tokenize with a custom tokenizer handling exceptions */
rspamd_tokenizer_result_t *
rspamd_custom_tokenizer_tokenize_with_exceptions(
	struct rspamd_custom_tokenizer *tokenizer,
	const char *text,
	gsize len,
	GList *exceptions,
	rspamd_mempool_t *pool)
{
	rspamd_tokenizer_result_t *words;
	rspamd_tokenizer_result_t result;
	struct rspamd_process_exception *ex;
	GList *cur_ex = exceptions;
	gsize pos = 0;
	unsigned int i;
	int ret;

	/* Allocate result kvec in pool */
	words = rspamd_mempool_alloc(pool, sizeof(*words));
	kv_init(*words);

	/* If no exceptions, tokenize the whole text */
	if (!exceptions) {
		kv_init(result);

		ret = tokenizer->api->tokenize(text, len, &result);
		if (ret == 0 && result.a) {
			/* Copy tokens from result to output */
			for (i = 0; i < kv_size(result); i++) {
				rspamd_word_t tok = kv_A(result, i);
				kv_push(rspamd_word_t, *words, tok);
			}

			/* Use tokenizer's cleanup function */
			if (tokenizer->api->cleanup_result) {
				tokenizer->api->cleanup_result(&result);
			}
		}

		return words;
	}

	/* Process text with exceptions */
	while (pos < len && cur_ex) {
		ex = (struct rspamd_process_exception *) cur_ex->data;

		/* Tokenize text before exception */
		if (ex->pos > pos) {
			gsize segment_len = ex->pos - pos;
			kv_init(result);

			ret = tokenizer->api->tokenize(text + pos, segment_len, &result);
			if (ret == 0 && result.a) {
				/* Copy tokens from result, adjusting positions for segment offset */
				for (i = 0; i < kv_size(result); i++) {
					rspamd_word_t tok = kv_A(result, i);

					/* Adjust pointers to point to the original text */
					gsize offset_in_segment = tok.original.begin - (text + pos);
					if (offset_in_segment < segment_len) {
						tok.original.begin = text + pos + offset_in_segment;
						/* Ensure we don't go past the exception boundary */
						if (tok.original.begin + tok.original.len <= text + ex->pos) {
							kv_push(rspamd_word_t, *words, tok);
						}
					}
				}

				/* Use tokenizer's cleanup function */
				if (tokenizer->api->cleanup_result) {
					tokenizer->api->cleanup_result(&result);
				}
			}
		}

		/* Add exception as a special token */
		rspamd_word_t ex_tok;
		memset(&ex_tok, 0, sizeof(ex_tok));

		if (ex->type == RSPAMD_EXCEPTION_URL) {
			ex_tok.original.begin = "!!EX!!";
			ex_tok.original.len = 6;
		}
		else {
			ex_tok.original.begin = text + ex->pos;
			ex_tok.original.len = ex->len;
		}
		ex_tok.flags = RSPAMD_STAT_TOKEN_FLAG_EXCEPTION;
		kv_push(rspamd_word_t, *words, ex_tok);

		/* Move past exception */
		pos = ex->pos + ex->len;
		cur_ex = g_list_next(cur_ex);
	}

	/* Process remaining text after last exception */
	if (pos < len) {
		kv_init(result);

		ret = tokenizer->api->tokenize(text + pos, len - pos, &result);
		if (ret == 0 && result.a) {
			/* Copy tokens from result, adjusting positions for segment offset */
			for (i = 0; i < kv_size(result); i++) {
				rspamd_word_t tok = kv_A(result, i);

				/* Adjust pointers to point to the original text */
				gsize offset_in_segment = tok.original.begin - (text + pos);
				if (offset_in_segment < (len - pos)) {
					tok.original.begin = text + pos + offset_in_segment;
					kv_push(rspamd_word_t, *words, tok);
				}
			}

			/* Use tokenizer's cleanup function */
			if (tokenizer->api->cleanup_result) {
				tokenizer->api->cleanup_result(&result);
			}
		}
	}

	return words;
}
