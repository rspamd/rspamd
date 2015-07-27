#ifndef TOKENIZERS_H
#define TOKENIZERS_H

#include "config.h"
#include "mem_pool.h"
#include "fstring.h"
#include "main.h"
#include "stat_api.h"

#define RSPAMD_DEFAULT_TOKENIZER "osb"

struct rspamd_tokenizer_runtime;

/* Common tokenizer structure */
struct rspamd_stat_tokenizer {
	gchar *name;
	gpointer (*get_config) (struct rspamd_tokenizer_config *cf, gsize *len);
	gboolean (*compatible_config) (struct rspamd_tokenizer_runtime *rt,
			gpointer ptr, gsize len);
	gboolean (*load_config) (struct rspamd_tokenizer_runtime *rt,
			gpointer ptr, gsize len);
	gint (*tokenize_func)(struct rspamd_tokenizer_runtime *rt,
			rspamd_mempool_t *pool,
			GArray *words,
			gboolean is_utf,
			const gchar *prefix);
};

/* Compare two token nodes */
gint token_node_compare_func (gconstpointer a, gconstpointer b);


/* Tokenize text into array of words (rspamd_fstring_t type) */
GArray * rspamd_tokenize_text (gchar *text, gsize len, gboolean is_utf,
		gsize min_len, GList *exceptions, gboolean compat,
		gboolean check_signature);

/* OSB tokenize function */
gint rspamd_tokenizer_osb (struct rspamd_tokenizer_runtime *rt,
	rspamd_mempool_t *pool,
	GArray *input,
	gboolean is_utf,
	const gchar *prefix);

gpointer rspamd_tokenizer_osb_get_config (struct rspamd_tokenizer_config *cf,
		gsize *len);

gboolean
rspamd_tokenizer_osb_compatible_config (struct rspamd_tokenizer_runtime *rt,
			gpointer ptr, gsize len);

gboolean
rspamd_tokenizer_osb_load_config (struct rspamd_tokenizer_runtime *rt,
		gpointer ptr, gsize len);

#endif
/*
 * vi:ts=4
 */
