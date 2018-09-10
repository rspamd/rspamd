#ifndef TOKENIZERS_H
#define TOKENIZERS_H

#include "config.h"
#include "mem_pool.h"
#include "fstring.h"
#include "rspamd.h"
#include "stat_api.h"

#include <unicode/utext.h>

#define RSPAMD_DEFAULT_TOKENIZER "osb"

struct rspamd_tokenizer_runtime;
struct rspamd_stat_ctx;

/* Common tokenizer structure */
struct rspamd_stat_tokenizer {
	gchar *name;
	gpointer (*get_config) (rspamd_mempool_t *pool,
			struct rspamd_tokenizer_config *cf, gsize *len);
	gint (*tokenize_func)(struct rspamd_stat_ctx *ctx,
			rspamd_mempool_t *pool,
			GArray *words,
			gboolean is_utf,
			const gchar *prefix,
			GPtrArray *result);
};

enum rspamd_tokenize_type {
	RSPAMD_TOKENIZE_UTF = 0,
	RSPAMD_TOKENIZE_RAW,
	RSPAMD_TOKENIZE_UNICODE
};

/* Compare two token nodes */
gint token_node_compare_func (gconstpointer a, gconstpointer b);


/* Tokenize text into array of words (rspamd_stat_token_t type) */
GArray * rspamd_tokenize_text (const gchar *text, gsize len,
							   const UText *utxt,
							   enum rspamd_tokenize_type how,
							   struct rspamd_config *cfg,
							   GList *exceptions,
							   guint64 *hash);

/* OSB tokenize function */
gint rspamd_tokenizer_osb (struct rspamd_stat_ctx *ctx,
		rspamd_mempool_t *pool,
		GArray *words,
		gboolean is_utf,
		const gchar *prefix,
		GPtrArray *result);

gpointer rspamd_tokenizer_osb_get_config (rspamd_mempool_t *pool,
		struct rspamd_tokenizer_config *cf,
		gsize *len);

#endif
/*
 * vi:ts=4
 */
