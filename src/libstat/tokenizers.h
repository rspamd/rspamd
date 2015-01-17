#ifndef TOKENIZERS_H
#define TOKENIZERS_H

#include "config.h"
#include "mem_pool.h"
#include "fstring.h"
#include "main.h"

/* Size for features pipe */
#define FEATURE_WINDOW_SIZE 5
#define MAX_DATA_LEN 64
#define MAX_VALUES 32

struct token_result {
	double value;
	struct rspamd_statfile_config *st;
	double *consolidated_value;
};

typedef struct token_node_s {
	guchar data[MAX_DATA_LEN];
	guint datalen;
	struct token_result *results;
	guint results_len;
} token_node_t;

/* Common tokenizer structure */
struct tokenizer {
	gchar *name;
	gint (*tokenize_func)(struct tokenizer *tokenizer,
			rspamd_mempool_t *pool,
			GArray *words,
			GTree **cur,
			gboolean save_token,
			gboolean is_utf,
			GList *exceptions);
	gchar * (*get_next_word)(rspamd_fstring_t *buf, rspamd_fstring_t *token, GList **exceptions);
};

/* Compare two token nodes */
int token_node_compare_func (gconstpointer a, gconstpointer b);

/* Get tokenizer structure by name or return NULL if this name is not found */
struct tokenizer * rspamd_stat_get_tokenizer (const char *name);

/* Get next word from specified f_str_t buf */
gchar * rspamd_tokenizer_get_word (rspamd_fstring_t *buf,
		rspamd_fstring_t *token, GList **exceptions);

/* Tokenize text into array of words (rspamd_fstring_t type) */
GArray * rspamd_tokenize_text (gchar *text, gsize len, gboolean is_utf,
		gsize min_len, GList **exceptions);

/* OSB tokenize function */
int osb_tokenize_text (struct tokenizer *tokenizer,
	rspamd_mempool_t *pool,
	GArray *input,
	GTree **cur,
	gboolean save_token,
	gboolean is_utf,
	GList *exceptions);

/* Make tokens for a subject */
void tokenize_subject (struct rspamd_task *task, GTree ** tree);

/* Array of all defined tokenizers */
extern struct tokenizer tokenizers[];

#endif
/*
 * vi:ts=4
 */
