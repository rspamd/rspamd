/*-
 * Copyright 2018 Vsevolod Stakhov
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

#include "map_helpers.h"
#include "map_private.h"
#include "khash.h"
#include "radix.h"
#include "rspamd.h"
#include "cryptobox.h"
#include "mempool_vars_internal.h"
#include "contrib/fastutf8/fastutf8.h"
#include "contrib/cdb/cdb.h"

#ifdef WITH_HYPERSCAN
#include "hs.h"
#endif
#ifndef WITH_PCRE2
#include <pcre.h>
#else
#include <pcre2.h>
#endif


static const guint64 map_hash_seed = 0xdeadbabeULL;
static const gchar * const hash_fill = "1";

struct rspamd_map_helper_value {
	gsize hits;
	gconstpointer key;
	gchar value[]; /* Null terminated */
};

#define rspamd_map_ftok_hash(t) (rspamd_icase_hash((t).begin, (t).len, rspamd_hash_seed ()))
#define rspamd_map_ftok_equal(a, b) ((a).len == (b).len && rspamd_lc_cmp((a).begin, (b).begin, (a).len) == 0)

KHASH_INIT (rspamd_map_hash, rspamd_ftok_t,
		struct rspamd_map_helper_value *, true,
		rspamd_map_ftok_hash, rspamd_map_ftok_equal);

struct rspamd_radix_map_helper {
	rspamd_mempool_t *pool;
	khash_t(rspamd_map_hash) *htb;
	radix_compressed_t *trie;
	struct rspamd_map *map;
	rspamd_cryptobox_fast_hash_state_t hst;
};

struct rspamd_hash_map_helper {
	rspamd_mempool_t *pool;
	khash_t(rspamd_map_hash) *htb;
	struct rspamd_map *map;
	rspamd_cryptobox_fast_hash_state_t hst;
};

struct rspamd_cdb_map_helper {
	GQueue cdbs;
	struct rspamd_map *map;
	rspamd_cryptobox_fast_hash_state_t hst;
	gsize total_size;
};

struct rspamd_regexp_map_helper {
	rspamd_cryptobox_hash_state_t hst;
	guchar re_digest[rspamd_cryptobox_HASHBYTES];
	rspamd_mempool_t *pool;
	struct rspamd_map *map;
	GPtrArray *regexps;
	GPtrArray *values;
	khash_t(rspamd_map_hash) *htb;
	enum rspamd_regexp_map_flags map_flags;
#ifdef WITH_HYPERSCAN
	hs_database_t *hs_db;
	hs_scratch_t *hs_scratch;
	gchar **patterns;
	gint *flags;
	gint *ids;
#endif
};

/**
 * FSM for parsing lists
 */

#define MAP_STORE_KEY do { \
	while (g_ascii_isspace (*c) && p > c) { c ++; } \
	key = g_malloc (p - c + 1); \
	rspamd_strlcpy (key, c, p - c + 1); \
	stripped_key = g_strstrip (key); \
} while (0)

#define MAP_STORE_VALUE do { \
	while (g_ascii_isspace (*c) && p > c) { c ++; } \
	value = g_malloc (p - c + 1); \
	rspamd_strlcpy (value, c, p - c + 1); \
	stripped_value = g_strstrip (value); \
} while (0)

gchar *
rspamd_parse_kv_list (
		gchar * chunk,
		gint len,
		struct map_cb_data *data,
		rspamd_map_insert_func func,
		const gchar *default_value,
		gboolean final)
{
	enum {
		map_skip_spaces_before_key = 0,
		map_read_key,
		map_read_key_quoted,
		map_read_key_slashed,
		map_skip_spaces_after_key,
		map_backslash_quoted,
		map_backslash_slashed,
		map_read_key_after_slash,
		map_read_value,
		map_read_comment_start,
		map_skip_comment,
		map_read_eol,
	};

	gchar *c, *p, *key = NULL, *value = NULL, *stripped_key, *stripped_value, *end;
	struct rspamd_map *map = data->map;
	guint line_number = 0;

	p = chunk;
	c = p;
	end = p + len;

	while (p < end) {
		switch (data->state) {
		case map_skip_spaces_before_key:
			if (g_ascii_isspace (*p)) {
				p ++;
			}
			else {
				if (*p == '"') {
					p++;
					c = p;
					data->state = map_read_key_quoted;
				}
				else if (*p == '/') {
					/* Note that c is on '/' here as '/' is a part of key */
					c = p;
					p++;
					data->state = map_read_key_slashed;
				}
				else {
					c = p;
					data->state = map_read_key;
				}
			}
			break;
		case map_read_key:
			/* read key */
			/* Check here comments, eol and end of buffer */
			if (*p == '#' && (p == c || *(p - 1) != '\\')) {
				if (p - c > 0) {
					/* Store a single key */
					MAP_STORE_KEY;
					func (data->cur_data, stripped_key, default_value);
					msg_debug_map ("insert key only pair: %s -> %s; line: %d",
							stripped_key, default_value, line_number);
					g_free (key);
				}

				key = NULL;
				data->state = map_read_comment_start;
			}
			else if (*p == '\r' || *p == '\n') {
				if (p - c > 0) {
					/* Store a single key */
					MAP_STORE_KEY;
					func (data->cur_data, stripped_key, default_value);
					msg_debug_map ("insert key only pair: %s -> %s; line: %d",
							stripped_key, default_value, line_number);
					g_free (key);
				}

				data->state = map_read_eol;
				key = NULL;
			}
			else if (g_ascii_isspace (*p)) {
				if (p - c > 0) {
					MAP_STORE_KEY;
					data->state = map_skip_spaces_after_key;
				}
				else {
					msg_err_map ("empty or invalid key found on line %d", line_number);
					data->state = map_skip_comment;
				}
			}
			else {
				p++;
			}
			break;
		case map_read_key_quoted:
			if (*p == '\\') {
				data->state = map_backslash_quoted;
				p ++;
			}
			else if (*p == '"') {
				/* Allow empty keys in this case */
				if (p - c >= 0) {
					MAP_STORE_KEY;
					data->state = map_skip_spaces_after_key;
				}
				else {
					g_assert_not_reached ();
				}
				p ++;
			}
			else {
				p ++;
			}
			break;
		case map_read_key_slashed:
			if (*p == '\\') {
				data->state = map_backslash_slashed;
				p ++;
			}
			else if (*p == '/') {
				/* Allow empty keys in this case */
				if (p - c >= 0) {
					data->state = map_read_key_after_slash;
				}
				else {
					g_assert_not_reached ();
				}
			}
			else {
				p ++;
			}
			break;
		case map_read_key_after_slash:
			/*
			 * This state is equal to reading of key but '/' is not
			 * treated specially
			 */
			if (*p == '#') {
				if (p - c > 0) {
					/* Store a single key */
					MAP_STORE_KEY;
					func (data->cur_data, stripped_key, default_value);
					msg_debug_map ("insert key only pair: %s -> %s; line: %d",
							stripped_key, default_value, line_number);
					g_free (key);
					key = NULL;
				}

				data->state = map_read_comment_start;
			}
			else if (*p == '\r' || *p == '\n') {
				if (p - c > 0) {
					/* Store a single key */
					MAP_STORE_KEY;
					func (data->cur_data, stripped_key, default_value);

					msg_debug_map ("insert key only pair: %s -> %s; line: %d",
							stripped_key, default_value, line_number);
					g_free (key);
					key = NULL;
				}

				data->state = map_read_eol;
				key = NULL;
			}
			else if (g_ascii_isspace (*p)) {
				if (p - c > 0) {
					MAP_STORE_KEY;
					data->state = map_skip_spaces_after_key;
				}
				else {
					msg_err_map ("empty or invalid key found on line %d", line_number);
					data->state = map_skip_comment;
				}
			}
			else {
				p ++;
			}
			break;
		case map_backslash_quoted:
			p ++;
			data->state = map_read_key_quoted;
			break;
		case map_backslash_slashed:
			p ++;
			data->state = map_read_key_slashed;
			break;
		case map_skip_spaces_after_key:
			if (*p == ' ' || *p == '\t') {
				p ++;
			}
			else {
				c = p;
				data->state = map_read_value;
			}
			break;
		case map_read_value:
			if (key == NULL) {
				/* Ignore line */
				msg_err_map ("empty or invalid key found on line %d", line_number);
				data->state = map_skip_comment;
			}
			else {
				if (*p == '#') {
					if (p - c > 0) {
						/* Store a single key */
						MAP_STORE_VALUE;
						func (data->cur_data, stripped_key, stripped_value);
						msg_debug_map ("insert key value pair: %s -> %s; line: %d",
								stripped_key, stripped_value, line_number);
						g_free (key);
						g_free (value);
						key = NULL;
						value = NULL;
					} else {
						func (data->cur_data, stripped_key, default_value);
						msg_debug_map ("insert key only pair: %s -> %s; line: %d",
								stripped_key, default_value, line_number);
						g_free (key);
						key = NULL;
					}

					data->state = map_read_comment_start;
				} else if (*p == '\r' || *p == '\n') {
					if (p - c > 0) {
						/* Store a single key */
						MAP_STORE_VALUE;
						func (data->cur_data, stripped_key, stripped_value);
						msg_debug_map ("insert key value pair: %s -> %s",
								stripped_key, stripped_value);
						g_free (key);
						g_free (value);
						key = NULL;
						value = NULL;
					} else {
						func (data->cur_data, stripped_key, default_value);
						msg_debug_map ("insert key only pair: %s -> %s",
								stripped_key, default_value);
						g_free (key);
						key = NULL;
					}

					data->state = map_read_eol;
					key = NULL;
				}
				else {
					p++;
				}
			}
			break;
		case map_read_comment_start:
			if (*p == '#') {
				data->state = map_skip_comment;
				p ++;
				key = NULL;
				value = NULL;
			}
			else {
				g_assert_not_reached ();
			}
			break;
		case map_skip_comment:
			if (*p == '\r' || *p == '\n') {
				data->state = map_read_eol;
			}
			else {
				p ++;
			}
			break;
		case map_read_eol:
			/* Skip \r\n and whitespaces */
			if (*p == '\r' || *p == '\n') {
				if (*p == '\n') {
					/* We don't care about \r only line separators, they are too rare */
					line_number ++;
				}
				p++;
			}
			else {
				data->state = map_skip_spaces_before_key;
			}
			break;
		default:
			g_assert_not_reached ();
			break;
		}
	}

	if (final) {
		/* Examine the state */
		switch (data->state) {
		case map_read_key:
			if (p - c > 0) {
				/* Store a single key */
				MAP_STORE_KEY;
				func (data->cur_data, stripped_key, default_value);
				msg_debug_map ("insert key only pair: %s -> %s",
						stripped_key, default_value);
				g_free (key);
				key = NULL;
			}
			break;
		case map_read_value:
			if (key == NULL) {
				/* Ignore line */
				msg_err_map ("empty or invalid key found on line %d", line_number);
				data->state = map_skip_comment;
			}
			else {
				if (p - c > 0) {
					/* Store a single key */
					MAP_STORE_VALUE;
					func (data->cur_data, stripped_key, stripped_value);
					msg_debug_map ("insert key value pair: %s -> %s",
							stripped_key, stripped_value);
					g_free (key);
					g_free (value);
					key = NULL;
					value = NULL;
				} else {
					func (data->cur_data, stripped_key, default_value);
					msg_debug_map ("insert key only pair: %s -> %s",
							stripped_key, default_value);
					g_free (key);
					key = NULL;
				}
			}
			break;
		}

		data->state = map_skip_spaces_before_key;
	}

	return c;
}

/**
 * Radix tree helper function
 */
void
rspamd_map_helper_insert_radix (gpointer st, gconstpointer key, gconstpointer value)
{
	struct rspamd_radix_map_helper *r = (struct rspamd_radix_map_helper *)st;
	struct rspamd_map_helper_value *val;
	gsize vlen;
	khiter_t k;
	gconstpointer nk;
	rspamd_ftok_t tok;
	gint res;
	struct rspamd_map *map;

	map = r->map;
	tok.begin = key;
	tok.len = strlen (key);

	k = kh_get (rspamd_map_hash, r->htb, tok);

	if (k == kh_end (r->htb)) {
		nk = rspamd_mempool_strdup (r->pool, key);
		tok.begin = nk;
		k = kh_put (rspamd_map_hash, r->htb, tok, &res);
	}
	else {
		val = kh_value (r->htb, k);

		if (strcmp (value, val->value) == 0) {
			/* Same element, skip */
			return;
		}
		else {
			msg_warn_map ("duplicate radix entry found for map %s: %s (old value: '%s', new: '%s')",
					map->name, key, val->value, value);
		}

		nk = kh_key (r->htb, k).begin;
		val->key = nk;
		kh_value (r->htb, k) = val;

		return; /* do not touch radix in case of exact duplicate */
	}

	vlen = strlen (value);
	val = rspamd_mempool_alloc0 (r->pool, sizeof (*val) +
										  vlen + 1);
	memcpy (val->value, value, vlen);

	nk = kh_key (r->htb, k).begin;
	val->key = nk;
	kh_value (r->htb, k) = val;
	rspamd_radix_add_iplist (key, ",", r->trie, val, FALSE,
			r->map->name);
	rspamd_cryptobox_fast_hash_update (&r->hst, nk, tok.len);
}

void
rspamd_map_helper_insert_radix_resolve (gpointer st, gconstpointer key, gconstpointer value)
{
	struct rspamd_radix_map_helper *r = (struct rspamd_radix_map_helper *)st;
	struct rspamd_map_helper_value *val;
	gsize vlen;
	khiter_t k;
	gconstpointer nk;
	rspamd_ftok_t tok;
	gint res;
	struct rspamd_map *map;

	map = r->map;
	tok.begin = key;
	tok.len = strlen (key);

	k = kh_get (rspamd_map_hash, r->htb, tok);

	if (k == kh_end (r->htb)) {
		nk = rspamd_mempool_strdup (r->pool, key);
		tok.begin = nk;
		k = kh_put (rspamd_map_hash, r->htb, tok, &res);
	}
	else {
		val = kh_value (r->htb, k);

		if (strcmp (value, val->value) == 0) {
			/* Same element, skip */
			return;
		}
		else {
			msg_warn_map ("duplicate radix entry found for map %s: %s (old value: '%s', new: '%s')",
					map->name, key, val->value, value);
		}

		nk = kh_key (r->htb, k).begin;
		val->key = nk;
		kh_value (r->htb, k) = val;

		return; /* do not touch radix in case of exact duplicate */
	}

	vlen = strlen (value);
	val = rspamd_mempool_alloc0 (r->pool, sizeof (*val) +
										  vlen + 1);
	memcpy (val->value, value, vlen);
	nk = kh_key (r->htb, k).begin;
	val->key = nk;
	kh_value (r->htb, k) = val;
	rspamd_radix_add_iplist (key, ",", r->trie, val, TRUE,
			r->map->name);
	rspamd_cryptobox_fast_hash_update (&r->hst, nk, tok.len);
}

void
rspamd_map_helper_insert_hash (gpointer st, gconstpointer key, gconstpointer value)
{
	struct rspamd_hash_map_helper *ht = st;
	struct rspamd_map_helper_value *val;
	khiter_t k;
	gconstpointer nk;
	gsize vlen;
	gint r;
	rspamd_ftok_t tok;
	struct rspamd_map *map;

	tok.begin = key;
	tok.len = strlen (key);
	map = ht->map;

	k = kh_get (rspamd_map_hash, ht->htb, tok);

	if (k == kh_end (ht->htb)) {
		nk = rspamd_mempool_strdup (ht->pool, key);
		tok.begin = nk;
		k = kh_put (rspamd_map_hash, ht->htb, tok, &r);
	}
	else {
		val = kh_value (ht->htb, k);

		if (strcmp (value, val->value) == 0) {
			/* Same element, skip */
			return;
		}
		else {
			msg_warn_map ("duplicate hash entry found for map %s: %s (old value: '%s', new: '%s')",
					map->name, key, val->value, value);
		}
	}

	/* Null termination due to alloc0 */
	vlen = strlen (value);
	val = rspamd_mempool_alloc0 (ht->pool, sizeof (*val) + vlen + 1);
	memcpy (val->value, value, vlen);

	tok = kh_key (ht->htb, k);
	nk = tok.begin;
	val->key = nk;
	kh_value (ht->htb, k) = val;

	rspamd_cryptobox_fast_hash_update (&ht->hst, nk, tok.len);
}

void
rspamd_map_helper_insert_re (gpointer st, gconstpointer key, gconstpointer value)
{
	struct rspamd_regexp_map_helper *re_map = st;
	struct rspamd_map *map;
	rspamd_regexp_t *re;
	gchar *escaped;
	GError *err = NULL;
	gint pcre_flags;
	gsize escaped_len;
	struct rspamd_map_helper_value *val;
	khiter_t k;
	rspamd_ftok_t tok;
	gconstpointer nk;
	gsize vlen;
	gint r;

	map = re_map->map;

	tok.begin = key;
	tok.len = strlen (key);

	k = kh_get (rspamd_map_hash, re_map->htb, tok);

	if (k == kh_end (re_map->htb)) {
		nk = rspamd_mempool_strdup (re_map->pool, key);
		tok.begin = nk;
		k = kh_put (rspamd_map_hash, re_map->htb, tok, &r);
	}
	else {
		val = kh_value (re_map->htb, k);

		/* Always warn about regexp duplicate as it's likely a bad mistake */
		msg_warn_map ("duplicate re entry found for map %s: %s (old value: '%s', new: '%s')",
				map->name, key, val->value, value);

		if (strcmp (val->value, value) == 0) {
			/* Same value, skip */
			return;
		}

		/* Replace value but do not touch regexp */
		nk = kh_key (re_map->htb, k).begin;
		val->key = nk;
		kh_value (re_map->htb, k) = val;

		return;
	}

	/* Check regexp stuff */
	if (re_map->map_flags & RSPAMD_REGEXP_MAP_FLAG_GLOB) {
		escaped = rspamd_str_regexp_escape (key, strlen (key), &escaped_len,
				RSPAMD_REGEXP_ESCAPE_GLOB|RSPAMD_REGEXP_ESCAPE_UTF);
		re = rspamd_regexp_new (escaped, NULL, &err);
		g_free (escaped);
	}
	else {
		re = rspamd_regexp_new (key, NULL, &err);
	}

	if (re == NULL) {
		msg_err_map ("cannot parse regexp %s: %e", key, err);

		if (err) {
			g_error_free (err);
		}

		return;
	}

	vlen = strlen (value);
	val = rspamd_mempool_alloc0 (re_map->pool, sizeof (*val) +
											   vlen + 1);
	memcpy (val->value, value, vlen); /* Null terminated due to alloc0 previously */
	nk = kh_key (re_map->htb, k).begin;
	val->key = nk;
	kh_value (re_map->htb, k) = val;
	rspamd_cryptobox_hash_update (&re_map->hst, nk, tok.len);

	pcre_flags = rspamd_regexp_get_pcre_flags (re);

#ifndef WITH_PCRE2
	if (pcre_flags & PCRE_FLAG(UTF8)) {
		re_map->map_flags |= RSPAMD_REGEXP_MAP_FLAG_UTF;
	}
#else
	if (pcre_flags & PCRE_FLAG(UTF)) {
		re_map->map_flags |= RSPAMD_REGEXP_MAP_FLAG_UTF;
	}
#endif

	g_ptr_array_add (re_map->regexps, re);
	g_ptr_array_add (re_map->values, val);
}

static void
rspamd_map_helper_traverse_regexp (void *data,
		rspamd_map_traverse_cb cb,
		gpointer cbdata,
		gboolean reset_hits)
{
	rspamd_ftok_t tok;
	struct rspamd_map_helper_value *val;
	struct rspamd_regexp_map_helper *re_map = data;

	kh_foreach (re_map->htb, tok, val, {
		if (!cb (tok.begin, val->value, val->hits, cbdata)) {
			break;
		}

		if (reset_hits) {
			val->hits = 0;
		}
	});
}

struct rspamd_hash_map_helper *
rspamd_map_helper_new_hash (struct rspamd_map *map)
{
	struct rspamd_hash_map_helper *htb;
	rspamd_mempool_t *pool;

	if (map) {
		pool = rspamd_mempool_new (rspamd_mempool_suggest_size (),
				map->tag, 0);
	}
	else {
		pool = rspamd_mempool_new (rspamd_mempool_suggest_size (),
				NULL, 0);
	}

	htb = rspamd_mempool_alloc0 (pool, sizeof (*htb));
	htb->htb = kh_init (rspamd_map_hash);
	htb->pool = pool;
	htb->map = map;
	rspamd_cryptobox_fast_hash_init (&htb->hst, map_hash_seed);

	return htb;
}

void
rspamd_map_helper_destroy_hash (struct rspamd_hash_map_helper *r)
{
	if (r == NULL || r->pool == NULL) {
		return;
	}

	rspamd_mempool_t *pool = r->pool;
	kh_destroy (rspamd_map_hash, r->htb);
	memset (r, 0, sizeof (*r));
	rspamd_mempool_delete (pool);
}

static void
rspamd_map_helper_traverse_hash (void *data,
		rspamd_map_traverse_cb cb,
		gpointer cbdata,
		gboolean reset_hits)
{
	rspamd_ftok_t tok;
	struct rspamd_map_helper_value *val;
	struct rspamd_hash_map_helper *ht = data;

	kh_foreach (ht->htb, tok, val, {
		if (!cb (tok.begin, val->value, val->hits, cbdata)) {
			break;
		}

		if (reset_hits) {
			val->hits = 0;
		}
	});
}

struct rspamd_radix_map_helper *
rspamd_map_helper_new_radix (struct rspamd_map *map)
{
	struct rspamd_radix_map_helper *r;
	rspamd_mempool_t *pool;
	const gchar *name = "unnamed";

	if (map) {
		pool = rspamd_mempool_new (rspamd_mempool_suggest_size (),
				map->tag, 0);
		name = map->name;
	}
	else {
		pool = rspamd_mempool_new (rspamd_mempool_suggest_size (),
				NULL, 0);
	}

	r = rspamd_mempool_alloc0 (pool, sizeof (*r));
	r->trie = radix_create_compressed_with_pool (pool, name);
	r->htb = kh_init (rspamd_map_hash);
	r->pool = pool;
	r->map = map;
	rspamd_cryptobox_fast_hash_init (&r->hst, map_hash_seed);

	return r;
}

void
rspamd_map_helper_destroy_radix (struct rspamd_radix_map_helper *r)
{
	if (r == NULL || !r->pool) {
		return;
	}

	kh_destroy (rspamd_map_hash, r->htb);
	rspamd_mempool_t *pool = r->pool;
	memset (r, 0, sizeof (*r));
	rspamd_mempool_delete (pool);
}

static void
rspamd_map_helper_traverse_radix (void *data,
		rspamd_map_traverse_cb cb,
		gpointer cbdata,
		gboolean reset_hits)
{
	rspamd_ftok_t tok;
	struct rspamd_map_helper_value *val;
	struct rspamd_radix_map_helper *r = data;

	kh_foreach (r->htb, tok, val, {
		if (!cb (tok.begin, val->value, val->hits, cbdata)) {
			break;
		}

		if (reset_hits) {
			val->hits = 0;
		}
	});
}

struct rspamd_regexp_map_helper *
rspamd_map_helper_new_regexp (struct rspamd_map *map,
		enum rspamd_regexp_map_flags flags)
{
	struct rspamd_regexp_map_helper *re_map;
	rspamd_mempool_t *pool;

	pool = rspamd_mempool_new (rspamd_mempool_suggest_size (),
			map->tag, 0);

	re_map = rspamd_mempool_alloc0 (pool, sizeof (*re_map));
	re_map->pool = pool;
	re_map->values = g_ptr_array_new ();
	re_map->regexps = g_ptr_array_new ();
	re_map->map = map;
	re_map->map_flags = flags;
	re_map->htb = kh_init (rspamd_map_hash);
	rspamd_cryptobox_hash_init (&re_map->hst, NULL, 0);

	return re_map;
}


void
rspamd_map_helper_destroy_regexp (struct rspamd_regexp_map_helper *re_map)
{
	rspamd_regexp_t *re;
	guint i;

	if (!re_map || !re_map->regexps) {
		return;
	}

#ifdef WITH_HYPERSCAN
	if (re_map->hs_scratch) {
		hs_free_scratch (re_map->hs_scratch);
	}
	if (re_map->hs_db) {
		hs_free_database (re_map->hs_db);
	}
	if (re_map->patterns) {
		for (i = 0; i < re_map->regexps->len; i ++) {
			g_free (re_map->patterns[i]);
		}

		g_free (re_map->patterns);
	}
	if (re_map->flags) {
		g_free (re_map->flags);
	}
	if (re_map->ids) {
		g_free (re_map->ids);
	}
#endif

	for (i = 0; i < re_map->regexps->len; i ++) {
		re = g_ptr_array_index (re_map->regexps, i);
		rspamd_regexp_unref (re);
	}

	g_ptr_array_free (re_map->regexps, TRUE);
	g_ptr_array_free (re_map->values, TRUE);
	kh_destroy (rspamd_map_hash, re_map->htb);

	rspamd_mempool_t *pool = re_map->pool;
	memset (re_map, 0, sizeof (*re_map));
	rspamd_mempool_delete (pool);
}

gchar *
rspamd_kv_list_read (
		gchar * chunk,
		gint len,
		struct map_cb_data *data,
		gboolean final)
{
	if (data->cur_data == NULL) {
		data->cur_data = rspamd_map_helper_new_hash (data->map);
	}

	return rspamd_parse_kv_list (
			chunk,
			len,
			data,
			rspamd_map_helper_insert_hash,
			"",
			final);
}

void
rspamd_kv_list_fin (struct map_cb_data *data, void **target)
{
	struct rspamd_map *map = data->map;
	struct rspamd_hash_map_helper *htb;

	if (data->cur_data) {
		htb = (struct rspamd_hash_map_helper *)data->cur_data;
		msg_info_map ("read hash of %d elements from %s", kh_size (htb->htb),
				map->name);
		data->map->traverse_function = rspamd_map_helper_traverse_hash;
		data->map->nelts = kh_size (htb->htb);
		data->map->digest = rspamd_cryptobox_fast_hash_final (&htb->hst);
	}

	if (target) {
		*target = data->cur_data;
	}

	if (data->prev_data) {
		htb = (struct rspamd_hash_map_helper *)data->prev_data;
		rspamd_map_helper_destroy_hash (htb);
	}
}

void
rspamd_kv_list_dtor (struct map_cb_data *data)
{
	struct rspamd_hash_map_helper *htb;

	if (data->cur_data) {
		htb = (struct rspamd_hash_map_helper *)data->cur_data;
		rspamd_map_helper_destroy_hash (htb);
	}
}

gchar *
rspamd_radix_read (
		gchar * chunk,
		gint len,
		struct map_cb_data *data,
		gboolean final)
{
	struct rspamd_radix_map_helper *r;
	struct rspamd_map *map = data->map;

	if (data->cur_data == NULL) {
		r = rspamd_map_helper_new_radix (map);
		data->cur_data = r;
	}

	return rspamd_parse_kv_list (
			chunk,
			len,
			data,
			rspamd_map_helper_insert_radix,
			hash_fill,
			final);
}

void
rspamd_radix_fin (struct map_cb_data *data, void **target)
{
	struct rspamd_map *map = data->map;
	struct rspamd_radix_map_helper *r;

	if (data->cur_data) {
		r = (struct rspamd_radix_map_helper *)data->cur_data;
		msg_info_map ("read radix trie of %z elements: %s",
				radix_get_size (r->trie), radix_get_info (r->trie));
		data->map->traverse_function = rspamd_map_helper_traverse_radix;
		data->map->nelts = kh_size (r->htb);
		data->map->digest = rspamd_cryptobox_fast_hash_final (&r->hst);
	}

	if (target) {
		*target = data->cur_data;
	}

	if (data->prev_data) {
		r = (struct rspamd_radix_map_helper *)data->prev_data;
		rspamd_map_helper_destroy_radix (r);
	}
}

void
rspamd_radix_dtor (struct map_cb_data *data)
{
	struct rspamd_radix_map_helper *r;

	if (data->cur_data) {
		r = (struct rspamd_radix_map_helper *)data->cur_data;
		rspamd_map_helper_destroy_radix (r);
	}
}

#ifdef WITH_HYPERSCAN
struct rspamd_re_maps_cache_dtor_cbdata {
	struct rspamd_config *cfg;
	GHashTable *valid_re_hashes;
	gchar *dirname;
};

static void
rspamd_re_maps_cache_cleanup_dtor (gpointer ud)
{
	struct rspamd_re_maps_cache_dtor_cbdata *cbd =
			(struct rspamd_re_maps_cache_dtor_cbdata *)ud;
	GPtrArray *cache_files;
	GError *err = NULL;
	struct rspamd_config *cfg;

	cfg = cbd->cfg;

	if (cfg->cur_worker != NULL) {
		/* Skip dtor, limit it to main process only */
		return;
	}

	cache_files = rspamd_glob_path (cbd->dirname, "*.hsmc", FALSE, &err);

	if (!cache_files) {
		msg_err_config ("cannot glob files in %s: %e", cbd->dirname, err);
		g_error_free (err);
	}
	else {
		const gchar *fname;
		guint i;

		PTR_ARRAY_FOREACH (cache_files, i, fname) {
			gchar *basename = g_path_get_basename (fname);

			if (g_hash_table_lookup (cbd->valid_re_hashes, basename) == NULL) {
				gchar *dir;

				dir = g_path_get_dirname (fname);

				/* Sanity check to avoid removal of something bad */
				if (strcmp (dir, cbd->dirname) != 0) {
					msg_err_config ("bogus file found: %s in %s, skip deleting",
							fname, dir);
				}
				else {
					if (unlink (fname) == -1) {
						msg_err_config ("cannot delete obsolete file %s in %s: %s",
								fname, dir, strerror (errno));
					}
					else {
						msg_info_config ("deleted obsolete file %s in %s",
								fname, dir);
					}
				}

				g_free (dir);
			}
			else {
				msg_debug_config ("valid re cache file %s", fname);
			}

			g_free (basename);
		}

		g_ptr_array_free (cache_files, TRUE);
	}

	g_hash_table_unref (cbd->valid_re_hashes);
	g_free (cbd->dirname);
}

static void
rspamd_re_map_cache_update (const gchar *fname, struct rspamd_config *cfg)
{
	GHashTable *valid_re_hashes;

	valid_re_hashes = rspamd_mempool_get_variable (cfg->cfg_pool,
			RSPAMD_MEMPOOL_RE_MAPS_CACHE);

	if (!valid_re_hashes) {
		valid_re_hashes = g_hash_table_new_full (g_str_hash, g_str_equal,
				g_free, NULL);
		rspamd_mempool_set_variable (cfg->cfg_pool,
				RSPAMD_MEMPOOL_RE_MAPS_CACHE,
				valid_re_hashes, (rspamd_mempool_destruct_t)g_hash_table_unref);

		/* We also add a cleanup dtor for all hashes */
		static struct rspamd_re_maps_cache_dtor_cbdata cbd;

		cbd.valid_re_hashes = g_hash_table_ref (valid_re_hashes);
		cbd.cfg = cfg;
		cbd.dirname = g_path_get_dirname (fname);
		rspamd_mempool_add_destructor (cfg->cfg_pool,
				rspamd_re_maps_cache_cleanup_dtor, &cbd);
	}

	g_hash_table_insert (valid_re_hashes, g_path_get_basename (fname), "1");
}

static gboolean
rspamd_try_load_re_map_cache (struct rspamd_regexp_map_helper *re_map)
{
	gchar fp[PATH_MAX];
	gpointer data;
	gsize len;
	struct rspamd_map *map;

	map = re_map->map;

	if (!map->cfg->hs_cache_dir) {
		return FALSE;
	}

	rspamd_snprintf (fp, sizeof (fp), "%s/%*xs.hsmc",
			map->cfg->hs_cache_dir,
			(gint)rspamd_cryptobox_HASHBYTES / 2, re_map->re_digest);

	if ((data = rspamd_file_xmap (fp, PROT_READ, &len, TRUE)) != NULL) {
		if (hs_deserialize_database (data, len, &re_map->hs_db) == HS_SUCCESS) {
			rspamd_re_map_cache_update (fp, map->cfg);
			munmap (data, len);

			msg_info_map ("loaded hypersan cache from %s (%Hz length) for %s",
					fp, len, map->name);

			return TRUE;
		}

		msg_info_map ("invalid hypersan cache in %s (%Hz length) for %s, removing file",
				fp, len, map->name);
		munmap (data, len);
		/* Remove stale file */
		(void)unlink (fp);
	}

	return FALSE;
}

static gboolean
rspamd_try_save_re_map_cache (struct rspamd_regexp_map_helper *re_map)
{
	gchar fp[PATH_MAX], np[PATH_MAX];
	gsize len;
	gint fd;
	char *bytes = NULL;
	struct rspamd_map *map;

	map = re_map->map;

	if (!map->cfg->hs_cache_dir) {
		return FALSE;
	}

	rspamd_snprintf (fp, sizeof (fp), "%s/%*xs.hsmc.tmp",
			re_map->map->cfg->hs_cache_dir,
			(gint)rspamd_cryptobox_HASHBYTES / 2, re_map->re_digest);

	if ((fd = rspamd_file_xopen (fp, O_WRONLY | O_CREAT | O_EXCL, 00644, 0)) != -1) {
		if (hs_serialize_database (re_map->hs_db, &bytes, &len) == HS_SUCCESS) {
			if (write (fd, bytes, len) == -1) {
				msg_warn_map ("cannot write hyperscan cache to %s: %s",
						fp, strerror (errno));
				unlink (fp);
				free (bytes);
			}
			else {
				free (bytes);
				fsync (fd);

				rspamd_snprintf (np, sizeof (np), "%s/%*xs.hsmc",
						re_map->map->cfg->hs_cache_dir,
						(gint)rspamd_cryptobox_HASHBYTES / 2, re_map->re_digest);

				if (rename (fp, np) == -1) {
					msg_warn_map ("cannot rename hyperscan cache from %s to %s: %s",
							fp, np, strerror (errno));
					unlink (fp);
				}
				else {
					msg_info_map ("written cached hyperscan data for %s to %s (%Hz length)",
							map->name, np, len);

					rspamd_re_map_cache_update (np, map->cfg);
				}
			}
		}
		else {
			msg_warn_map ("cannot serialize hyperscan cache to %s: %s",
					fp, strerror (errno));
			unlink (fp);
		}


		close (fd);
	}

	return FALSE;
}

static gboolean
rspamd_re_map_cache_cleanup_old (struct rspamd_regexp_map_helper *old_re_map)
{
	gchar fp[PATH_MAX];
	struct rspamd_map *map;

	map = old_re_map->map;

	if (!map->cfg->hs_cache_dir) {
		return FALSE;
	}

	rspamd_snprintf (fp, sizeof (fp), "%s/%*xs.hsmc",
			map->cfg->hs_cache_dir,
			(gint)rspamd_cryptobox_HASHBYTES / 2, old_re_map->re_digest);

	msg_info_map ("unlink stale cache file for %s: %s", map->name, fp);

	if (unlink (fp) == -1) {
		msg_warn_map ("cannot unlink stale cache file for %s (%s): %s",
				map->name, fp, strerror (errno));
		return FALSE;
	}

	GHashTable *valid_re_hashes;

	valid_re_hashes = rspamd_mempool_get_variable (map->cfg->cfg_pool,
			RSPAMD_MEMPOOL_RE_MAPS_CACHE);

	if (valid_re_hashes) {
		g_hash_table_remove (valid_re_hashes, fp);
	}

	return TRUE;
}

#endif

static void
rspamd_re_map_finalize (struct rspamd_regexp_map_helper *re_map)
{
#ifdef WITH_HYPERSCAN
	guint i;
	hs_platform_info_t plt;
	hs_compile_error_t *err;
	struct rspamd_map *map;
	rspamd_regexp_t *re;
	gint pcre_flags;

	map = re_map->map;

#ifndef __aarch64__
	if (!(map->cfg->libs_ctx->crypto_ctx->cpu_config & CPUID_SSSE3)) {
		msg_info_map ("disable hyperscan for map %s, ssse3 instructons are not supported by CPU",
				map->name);
		return;
	}
#endif

	if (hs_populate_platform (&plt) != HS_SUCCESS) {
		msg_err_map ("cannot populate hyperscan platform");
		return;
	}

	re_map->patterns = g_new (gchar *, re_map->regexps->len);
	re_map->flags = g_new (gint, re_map->regexps->len);
	re_map->ids = g_new (gint, re_map->regexps->len);

	for (i = 0; i < re_map->regexps->len; i ++) {
		const gchar *pat;
		gchar *escaped;
		gint pat_flags;

		re = g_ptr_array_index (re_map->regexps, i);
		pcre_flags = rspamd_regexp_get_pcre_flags (re);
		pat = rspamd_regexp_get_pattern (re);
		pat_flags = rspamd_regexp_get_flags (re);

		if (pat_flags & RSPAMD_REGEXP_FLAG_UTF) {
			escaped = rspamd_str_regexp_escape (pat, strlen (pat), NULL,
					RSPAMD_REGEXP_ESCAPE_RE|RSPAMD_REGEXP_ESCAPE_UTF);
			re_map->flags[i] |= HS_FLAG_UTF8;
		}
		else {
			escaped = rspamd_str_regexp_escape (pat, strlen (pat), NULL,
					RSPAMD_REGEXP_ESCAPE_RE);
		}

		re_map->patterns[i] = escaped;
		re_map->flags[i] = HS_FLAG_SINGLEMATCH;

#ifndef WITH_PCRE2
		if (pcre_flags & PCRE_FLAG(UTF8)) {
			re_map->flags[i] |= HS_FLAG_UTF8;
		}
#else
		if (pcre_flags & PCRE_FLAG(UTF)) {
			re_map->flags[i] |= HS_FLAG_UTF8;
		}
#endif
		if (pcre_flags & PCRE_FLAG(CASELESS)) {
			re_map->flags[i] |= HS_FLAG_CASELESS;
		}
		if (pcre_flags & PCRE_FLAG(MULTILINE)) {
			re_map->flags[i] |= HS_FLAG_MULTILINE;
		}
		if (pcre_flags & PCRE_FLAG(DOTALL)) {
			re_map->flags[i] |= HS_FLAG_DOTALL;
		}
		if (rspamd_regexp_get_maxhits (re) == 1) {
			re_map->flags[i] |= HS_FLAG_SINGLEMATCH;
		}

		re_map->ids[i] = i;
	}

	if (re_map->regexps->len > 0 && re_map->patterns) {

		if (!rspamd_try_load_re_map_cache (re_map)) {
			gdouble ts1 = rspamd_get_ticks (FALSE);

			if (hs_compile_multi ((const gchar **) re_map->patterns,
					re_map->flags,
					re_map->ids,
					re_map->regexps->len,
					HS_MODE_BLOCK,
					&plt,
					&re_map->hs_db,
					&err) != HS_SUCCESS) {

				msg_err_map ("cannot create tree of regexp when processing '%s': %s",
						err->expression >= 0 ?
						re_map->patterns[err->expression] :
						"unknown regexp", err->message);
				re_map->hs_db = NULL;
				hs_free_compile_error (err);

				return;
			}

			ts1 = (rspamd_get_ticks (FALSE) - ts1) * 1000.0;
			msg_info_map ("hyperscan compiled %d regular expressions from %s in %.1f ms",
					re_map->regexps->len, re_map->map->name, ts1);
			rspamd_try_save_re_map_cache (re_map);
		}
		else {
			msg_info_map ("hyperscan read %d cached regular expressions from %s",
					re_map->regexps->len, re_map->map->name);
		}

		if (hs_alloc_scratch (re_map->hs_db, &re_map->hs_scratch) != HS_SUCCESS) {
			msg_err_map ("cannot allocate scratch space for hyperscan");
			hs_free_database (re_map->hs_db);
			re_map->hs_db = NULL;
		}
	}
	else {
		msg_err_map ("regexp map is empty");
	}
#endif
}

gchar *
rspamd_regexp_list_read_single (
		gchar *chunk,
		gint len,
		struct map_cb_data *data,
		gboolean final)
{
	struct rspamd_regexp_map_helper *re_map;

	if (data->cur_data == NULL) {
		re_map = rspamd_map_helper_new_regexp (data->map, 0);
		data->cur_data = re_map;
	}

	return rspamd_parse_kv_list (
			chunk,
			len,
			data,
			rspamd_map_helper_insert_re,
			hash_fill,
			final);
}

gchar *
rspamd_glob_list_read_single (
		gchar *chunk,
		gint len,
		struct map_cb_data *data,
		gboolean final)
{
	struct rspamd_regexp_map_helper *re_map;

	if (data->cur_data == NULL) {
		re_map = rspamd_map_helper_new_regexp (data->map, RSPAMD_REGEXP_MAP_FLAG_GLOB);
		data->cur_data = re_map;
	}

	return rspamd_parse_kv_list (
			chunk,
			len,
			data,
			rspamd_map_helper_insert_re,
			hash_fill,
			final);
}

gchar *
rspamd_regexp_list_read_multiple (
		gchar *chunk,
		gint len,
		struct map_cb_data *data,
		gboolean final)
{
	struct rspamd_regexp_map_helper *re_map;

	if (data->cur_data == NULL) {
		re_map = rspamd_map_helper_new_regexp (data->map,
				RSPAMD_REGEXP_MAP_FLAG_MULTIPLE);
		data->cur_data = re_map;
	}

	return rspamd_parse_kv_list (
			chunk,
			len,
			data,
			rspamd_map_helper_insert_re,
			hash_fill,
			final);
}

gchar *
rspamd_glob_list_read_multiple (
		gchar *chunk,
		gint len,
		struct map_cb_data *data,
		gboolean final)
{
	struct rspamd_regexp_map_helper *re_map;

	if (data->cur_data == NULL) {
		re_map = rspamd_map_helper_new_regexp (data->map,
				RSPAMD_REGEXP_MAP_FLAG_GLOB|RSPAMD_REGEXP_MAP_FLAG_MULTIPLE);
		data->cur_data = re_map;
	}

	return rspamd_parse_kv_list (
			chunk,
			len,
			data,
			rspamd_map_helper_insert_re,
			hash_fill,
			final);
}


void
rspamd_regexp_list_fin (struct map_cb_data *data, void **target)
{
	struct rspamd_regexp_map_helper *re_map = NULL, *old_re_map;
	struct rspamd_map *map = data->map;

	if (data->cur_data) {
		re_map = data->cur_data;
		rspamd_cryptobox_hash_final (&re_map->hst, re_map->re_digest);
		memcpy (&data->map->digest, re_map->re_digest, sizeof (data->map->digest));
		rspamd_re_map_finalize (re_map);
		msg_info_map ("read regexp list of %ud elements",
				re_map->regexps->len);
		data->map->traverse_function = rspamd_map_helper_traverse_regexp;
		data->map->nelts = kh_size (re_map->htb);
	}

	if (target) {
		*target = data->cur_data;
	}

	if (data->prev_data) {
		old_re_map = data->prev_data;

#ifdef WITH_HYPERSCAN
		if (re_map && memcmp (re_map->re_digest, old_re_map->re_digest,
				sizeof (re_map->re_digest)) != 0) {
			/* Cleanup old stuff */
			rspamd_re_map_cache_cleanup_old (old_re_map);
		}
#endif

		rspamd_map_helper_destroy_regexp (old_re_map);
	}
}
void
rspamd_regexp_list_dtor (struct map_cb_data *data)
{
	if (data->cur_data) {
		rspamd_map_helper_destroy_regexp (data->cur_data);
	}
}

#ifdef WITH_HYPERSCAN
static int
rspamd_match_hs_single_handler (unsigned int id, unsigned long long from,
		unsigned long long to,
		unsigned int flags, void *context)
{
	guint *i = context;
	/* Always return non-zero as we need a single match here */

	*i = id;

	return 1;
}
#endif

gconstpointer
rspamd_match_regexp_map_single (struct rspamd_regexp_map_helper *map,
		const gchar *in, gsize len)
{
	guint i;
	rspamd_regexp_t *re;
	gint res = 0;
	gpointer ret = NULL;
	struct rspamd_map_helper_value *val;
	gboolean validated = FALSE;

	g_assert (in != NULL);

	if (map == NULL || len == 0 || map->regexps == NULL) {
		return NULL;
	}

	if (map->map_flags & RSPAMD_REGEXP_MAP_FLAG_UTF) {
		if (rspamd_fast_utf8_validate (in, len) == 0) {
			validated = TRUE;
		}
	}
	else {
		validated = TRUE;
	}

#ifdef WITH_HYPERSCAN
	if (map->hs_db && map->hs_scratch) {

		if (validated) {

			res = hs_scan (map->hs_db, in, len, 0, map->hs_scratch,
					rspamd_match_hs_single_handler, (void *)&i);

			if (res == HS_SCAN_TERMINATED) {
				res = 1;
				val = g_ptr_array_index (map->values, i);

				ret = val->value;
				val->hits ++;
			}

			return ret;
		}
	}
#endif

	if (!res) {
		/* PCRE version */
		for (i = 0; i < map->regexps->len; i ++) {
			re = g_ptr_array_index (map->regexps, i);

			if (rspamd_regexp_search (re, in, len, NULL, NULL, !validated, NULL)) {
				val = g_ptr_array_index (map->values, i);

				ret = val->value;
				val->hits ++;
				break;
			}
		}
	}

	return ret;
}

#ifdef WITH_HYPERSCAN
struct rspamd_multiple_cbdata {
	GPtrArray *ar;
	struct rspamd_regexp_map_helper *map;
};

static int
rspamd_match_hs_multiple_handler (unsigned int id, unsigned long long from,
		unsigned long long to,
		unsigned int flags, void *context)
{
	struct rspamd_multiple_cbdata *cbd = context;
	struct rspamd_map_helper_value *val;


	if (id < cbd->map->values->len) {
		val = g_ptr_array_index (cbd->map->values, id);
		val->hits ++;
		g_ptr_array_add (cbd->ar, val->value);
	}

	/* Always return zero as we need all matches here */
	return 0;
}
#endif

GPtrArray*
rspamd_match_regexp_map_all (struct rspamd_regexp_map_helper *map,
		const gchar *in, gsize len)
{
	guint i;
	rspamd_regexp_t *re;
	GPtrArray *ret;
	gint res = 0;
	gboolean validated = FALSE;
	struct rspamd_map_helper_value *val;

	if (map == NULL || map->regexps == NULL || len == 0) {
		return NULL;
	}

	g_assert (in != NULL);

	if (map->map_flags & RSPAMD_REGEXP_MAP_FLAG_UTF) {
		if (rspamd_fast_utf8_validate (in, len) == 0) {
			validated = TRUE;
		}
	}
	else {
		validated = TRUE;
	}

	ret = g_ptr_array_new ();

#ifdef WITH_HYPERSCAN
	if (map->hs_db && map->hs_scratch) {

		if (validated) {
			struct rspamd_multiple_cbdata cbd;

			cbd.ar = ret;
			cbd.map = map;

			if (hs_scan (map->hs_db, in, len, 0, map->hs_scratch,
					rspamd_match_hs_multiple_handler, &cbd) == HS_SUCCESS) {
				res = 1;
			}
		}
	}
#endif

	if (!res) {
		/* PCRE version */
		for (i = 0; i < map->regexps->len; i ++) {
			re = g_ptr_array_index (map->regexps, i);

			if (rspamd_regexp_search (re, in, len, NULL, NULL,
					!validated, NULL)) {
				val = g_ptr_array_index (map->values, i);
				val->hits ++;
				g_ptr_array_add (ret, val->value);
			}
		}
	}

	if (ret->len > 0) {
		return ret;
	}

	g_ptr_array_free (ret, TRUE);

	return NULL;
}

gconstpointer
rspamd_match_hash_map (struct rspamd_hash_map_helper *map, const gchar *in,
		gsize len)
{
	khiter_t k;
	struct rspamd_map_helper_value *val;
	rspamd_ftok_t tok;

	if (map == NULL || map->htb == NULL) {
		return NULL;
	}

	tok.begin = in;
	tok.len = len;

	k = kh_get (rspamd_map_hash, map->htb, tok);

	if (k != kh_end (map->htb)) {
		val = kh_value (map->htb, k);
		val->hits ++;

		return val->value;
	}

	return NULL;
}

gconstpointer
rspamd_match_radix_map (struct rspamd_radix_map_helper *map,
		const guchar *in, gsize inlen)
{
	struct rspamd_map_helper_value *val;

	if (map == NULL || map->trie == NULL) {
		return NULL;
	}

	val = (struct rspamd_map_helper_value *)radix_find_compressed (map->trie,
			in, inlen);

	if (val != (gconstpointer)RADIX_NO_VALUE) {
		val->hits ++;

		return val->value;
	}

	return NULL;
}

gconstpointer
rspamd_match_radix_map_addr (struct rspamd_radix_map_helper *map,
		const rspamd_inet_addr_t *addr)
{
	struct rspamd_map_helper_value *val;

	if (map == NULL || map->trie == NULL) {
		return NULL;
	}

	val = (struct rspamd_map_helper_value *)radix_find_compressed_addr (map->trie, addr);

	if (val != (gconstpointer)RADIX_NO_VALUE) {
		val->hits ++;

		return val->value;
	}

	return NULL;
}


/*
 * CBD stuff
 */

struct rspamd_cdb_map_helper *
rspamd_map_helper_new_cdb (struct rspamd_map *map)
{
	struct rspamd_cdb_map_helper *n;

	n = g_malloc0 (sizeof (*n));
	n->cdbs = (GQueue)G_QUEUE_INIT;
	n->map = map;

	rspamd_cryptobox_fast_hash_init (&n->hst, map_hash_seed);

	return n;
}

void
rspamd_map_helper_destroy_cdb (struct rspamd_cdb_map_helper *c)
{
	if (c == NULL) {
		return;
	}

	GList *cur = c->cdbs.head;

	while (cur) {
		struct cdb *cdb = (struct cdb *)cur->data;

		cdb_free (cdb);
		g_free (cdb->filename);
		close (cdb->cdb_fd);
		g_free (cdb);

		cur = g_list_next (cur);
	}

	g_queue_clear (&c->cdbs);

	g_free (c);
}

gchar *
rspamd_cdb_list_read (gchar *chunk,
					  gint len,
					  struct map_cb_data *data,
					  gboolean final)
{
	struct rspamd_cdb_map_helper *cdb_data;
	struct cdb *found = NULL;
	struct rspamd_map *map = data->map;

	g_assert (map->no_file_read);

	if (data->cur_data == NULL) {
		cdb_data = rspamd_map_helper_new_cdb (data->map);
		data->cur_data = cdb_data;
	}
	else {
		cdb_data = (struct rspamd_cdb_map_helper *)data->cur_data;
	}

	GList *cur = cdb_data->cdbs.head;

	while (cur) {
		struct cdb *elt = (struct cdb *)cur->data;

		if (strcmp (elt->filename, chunk) == 0) {
			found = elt;
			break;
		}

		cur = g_list_next (cur);
	}

	if (found == NULL) {
		/* New cdb */
		gint fd;
		struct cdb *cdb;

		fd = rspamd_file_xopen (chunk, O_RDONLY, 0, TRUE);

		if (fd == -1) {
			msg_err_map ("cannot open cdb map from %s: %s", chunk, strerror (errno));

			return NULL;
		}

		cdb = g_malloc0 (sizeof (struct cdb));

		if (cdb_init (cdb, fd) == -1) {
			g_free (cdb);
			msg_err_map ("cannot init cdb map from %s: %s", chunk, strerror (errno));

			return NULL;
		}

		cdb->filename = g_strdup (chunk);
		g_queue_push_tail (&cdb_data->cdbs, cdb);
		cdb_data->total_size += cdb->cdb_fsize;
		rspamd_cryptobox_fast_hash_update (&cdb_data->hst, chunk, len);
	}

	return chunk + len;
}

void
rspamd_cdb_list_fin (struct map_cb_data *data, void **target)
{
	struct rspamd_map *map = data->map;
	struct rspamd_cdb_map_helper *cdb_data;

	if (data->cur_data) {
		cdb_data = (struct rspamd_cdb_map_helper *)data->cur_data;
		msg_info_map ("read cdb of %Hz size", cdb_data->total_size);
		data->map->traverse_function = NULL;
		data->map->nelts = 0;
		data->map->digest = rspamd_cryptobox_fast_hash_final (&cdb_data->hst);
	}

	if (target) {
		*target = data->cur_data;
	}

	if (data->prev_data) {
		cdb_data = (struct rspamd_cdb_map_helper *)data->prev_data;
		rspamd_map_helper_destroy_cdb (cdb_data);
	}
}
void
rspamd_cdb_list_dtor (struct map_cb_data *data)
{
	if (data->cur_data) {
		rspamd_map_helper_destroy_cdb (data->cur_data);
	}
}

gconstpointer
rspamd_match_cdb_map (struct rspamd_cdb_map_helper *map,
					  const gchar *in, gsize inlen)
{
	if (map == NULL || map->cdbs.head == NULL) {
		return NULL;
	}

	GList *cur = map->cdbs.head;
	static rspamd_ftok_t found;

	while (cur) {
		struct cdb *cdb = (struct cdb *)cur->data;

		if (cdb_find (cdb, in, inlen) > 0) {
			/* Extract and push value to lua as string */
			unsigned vlen;
			gconstpointer vpos;

			vpos = cdb->cdb_mem + cdb_datapos (cdb);
			vlen = cdb_datalen (cdb);
			found.len = vlen;
			found.begin = vpos;

			return &found; /* Do not reuse! */
		}

		cur = g_list_next (cur);
	}

	return NULL;
}
