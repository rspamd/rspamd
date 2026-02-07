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
#include "libmime/message.h"
#include "re_cache.h"
#include "cryptobox.h"
#include "ref.h"
#include "libserver/url.h"
#include "libserver/task.h"
#include "libserver/cfg_file.h"
#include "libserver/hs_cache_backend.h"
#include "libutil/util.h"
#include "libutil/regexp.h"
#include "libutil/heap.h"
#include "lua/lua_common.h"
#include "libstat/stat_api.h"
#include "contrib/uthash/utlist.h"
#include "lua/lua_classnames.h"

#include "khash.h"

#ifdef WITH_HYPERSCAN
#include "hs.h"
#include "hyperscan_tools.h"
#include "rspamd_control.h"
#endif

#include "unix-std.h"
#include <signal.h>
#include <stdalign.h>
#include <math.h>
#include "contrib/libev/ev.h"

#ifndef WITH_PCRE2
#include <pcre.h>
#else
#include <pcre2.h>
#endif

#include "rspamd_simdutf.h"

#ifdef HAVE_SYS_WAIT_H
#include <sys/wait.h>
#endif

#define msg_err_re_cache(...) rspamd_default_log_function(G_LOG_LEVEL_CRITICAL,    \
														  "re_cache", cache->hash, \
														  RSPAMD_LOG_FUNC,         \
														  __VA_ARGS__)
#define msg_warn_re_cache(...) rspamd_default_log_function(G_LOG_LEVEL_WARNING,     \
														   "re_cache", cache->hash, \
														   RSPAMD_LOG_FUNC,         \
														   __VA_ARGS__)
#define msg_info_re_cache(...) rspamd_default_log_function(G_LOG_LEVEL_INFO,        \
														   "re_cache", cache->hash, \
														   RSPAMD_LOG_FUNC,         \
														   __VA_ARGS__)

#define msg_debug_re_task(...) rspamd_conditional_debug_fast(NULL, NULL,                                                   \
															 rspamd_re_cache_log_id, "re_cache", task->task_pool->tag.uid, \
															 RSPAMD_LOG_FUNC,                                              \
															 __VA_ARGS__)
#define msg_debug_re_cache(...) rspamd_conditional_debug_fast(NULL, NULL,                                      \
															  rspamd_re_cache_log_id, "re_cache", cache->hash, \
															  RSPAMD_LOG_FUNC,                                 \
															  __VA_ARGS__)

INIT_LOG_MODULE(re_cache)

#ifdef WITH_HYPERSCAN
#define RSPAMD_HS_MAGIC_LEN (sizeof(rspamd_hs_magic))
static const unsigned char rspamd_hs_magic[] = {'r', 's', 'h', 's', 'r', 'e', '1', '1'},
						   rspamd_hs_magic_vector[] = {'r', 's', 'h', 's', 'r', 'v', '1', '1'};
#endif


struct rspamd_re_class {
	uint64_t id;
	enum rspamd_re_type type;
	gboolean has_utf8; /* if there are any utf8 regexps */
	gpointer type_data;
	gsize type_len;
	GHashTable *re;
	rspamd_cryptobox_hash_state_t *st;
	struct rspamd_re_cache *cache; /* Back-reference to owning cache */

	char hash[rspamd_cryptobox_HASHBYTES + 1];

#ifdef WITH_HYPERSCAN
	rspamd_hyperscan_t *hs_db;
	hs_scratch_t *hs_scratch;
	int *hs_ids;
	unsigned int nhs;
#endif
};

enum rspamd_re_cache_elt_match_type {
	RSPAMD_RE_CACHE_PCRE = 0,
	RSPAMD_RE_CACHE_HYPERSCAN,
	RSPAMD_RE_CACHE_HYPERSCAN_PRE
};

struct rspamd_re_cache_elt {
	rspamd_regexp_t *re;
	int lua_cbref;
	enum rspamd_re_cache_elt_match_type match_type;
};

KHASH_INIT(lua_selectors_hash, char *, int, 1, kh_str_hash_func, kh_str_hash_equal);

struct rspamd_re_cache {
	GHashTable *re_classes;

	GPtrArray *re;
	khash_t(lua_selectors_hash) * selectors;
	ref_entry_t ref;
	unsigned int nre;
	unsigned int max_re_data;
	char hash[rspamd_cryptobox_HASHBYTES + 1];
	lua_State *L;

	/* Intrusive linked list for scoped caches */
	struct rspamd_re_cache *next, *prev;
	char *scope;
	unsigned int flags; /* Cache flags (loaded state, etc.) */

#ifdef WITH_HYPERSCAN
	enum rspamd_hyperscan_status hyperscan_loaded;
	gboolean disable_hyperscan;
	hs_platform_info_t plt;
#endif
};

struct rspamd_re_selector_result {
	unsigned char **scvec;
	unsigned int *lenvec;
	unsigned int cnt;
};

KHASH_INIT(selectors_results_hash, int, struct rspamd_re_selector_result, 1,
		   kh_int_hash_func, kh_int_hash_equal);

struct rspamd_re_runtime {
	unsigned char *checked;
	unsigned char *results;
	khash_t(selectors_results_hash) * sel_cache;
	struct rspamd_re_cache *cache;
	struct rspamd_re_cache_stat stat;
	gboolean has_hs;

	/* Linked list for multiple scoped runtimes */
	struct rspamd_re_runtime *next, *prev;
};

static GQuark
rspamd_re_cache_quark(void)
{
	return g_quark_from_static_string("re_cache");
}

static uint64_t
rspamd_re_cache_class_id(enum rspamd_re_type type,
						 gconstpointer type_data,
						 gsize datalen)
{
	rspamd_cryptobox_fast_hash_state_t st;

	rspamd_cryptobox_fast_hash_init(&st, 0xdeadbabe);
	rspamd_cryptobox_fast_hash_update(&st, &type, sizeof(type));

	if (datalen > 0) {
		rspamd_cryptobox_fast_hash_update(&st, type_data, datalen);
	}

	return rspamd_cryptobox_fast_hash_final(&st);
}

static struct rspamd_re_cache *
rspamd_re_cache_find_by_scope(struct rspamd_re_cache *cache_head, const char *scope)
{
	struct rspamd_re_cache *cur;

	if (!cache_head) {
		return NULL;
	}

	DL_FOREACH(cache_head, cur)
	{
		if (scope == NULL && cur->scope == NULL) {
			/* Looking for default scope */
			return cur;
		}
		else if (scope != NULL && cur->scope != NULL && strcmp(cur->scope, scope) == 0) {
			return cur;
		}
	}

	return NULL;
}

static struct rspamd_re_cache *
rspamd_re_cache_add_to_scope_list(struct rspamd_re_cache **cache_head, const char *scope)
{
	struct rspamd_re_cache *new_cache, *existing;

	if (!cache_head) {
		return NULL;
	}

	/* Check if scope already exists */
	existing = rspamd_re_cache_find_by_scope(*cache_head, scope);
	if (existing) {
		return existing;
	}

	/* Create new cache for this scope */
	new_cache = rspamd_re_cache_new();
	if (new_cache->scope) {
		g_free(new_cache->scope);
	}
	new_cache->scope = g_strdup(scope);
	new_cache->flags = 0; /* New scopes start as unloaded */

	/* Add to linked list */
	if (*cache_head) {
		DL_APPEND(*cache_head, new_cache);
	}
	else {
		*cache_head = new_cache;
	}

	return new_cache;
}

static void
rspamd_re_cache_destroy(struct rspamd_re_cache *cache)
{
	GHashTableIter it;
	gpointer k, v;
	struct rspamd_re_class *re_class;
	char *skey;
	int sref;

	g_assert(cache != NULL);
	g_hash_table_iter_init(&it, cache->re_classes);

	while (g_hash_table_iter_next(&it, &k, &v)) {
		re_class = v;
		g_hash_table_iter_steal(&it);
		g_hash_table_unref(re_class->re);

		if (re_class->type_data) {
			g_free(re_class->type_data);
		}

#ifdef WITH_HYPERSCAN
		if (re_class->hs_db) {
			rspamd_hyperscan_free(re_class->hs_db, false);
		}
		if (re_class->hs_scratch) {
			hs_free_scratch(re_class->hs_scratch);
		}
		if (re_class->hs_ids) {
			g_free(re_class->hs_ids);
		}
#endif
		g_free(re_class);
	}

	if (cache->L) {
		kh_foreach(cache->selectors, skey, sref, {
			luaL_unref(cache->L, LUA_REGISTRYINDEX, sref);
			g_free(skey);
		});

		struct rspamd_re_cache_elt *elt;
		unsigned int i;

		PTR_ARRAY_FOREACH(cache->re, i, elt)
		{
			if (elt->lua_cbref != -1) {
				luaL_unref(cache->L, LUA_REGISTRYINDEX, elt->lua_cbref);
			}
		}
	}

	kh_destroy(lua_selectors_hash, cache->selectors);

	g_hash_table_unref(cache->re_classes);
	g_ptr_array_free(cache->re, TRUE);

	if (cache->scope) {
		g_free(cache->scope);
	}

	g_free(cache);
}

static void
rspamd_re_cache_elt_dtor(gpointer e)
{
	struct rspamd_re_cache_elt *elt = e;

	rspamd_regexp_unref(elt->re);
	g_free(elt);
}

struct rspamd_re_cache *
rspamd_re_cache_new(void)
{
	struct rspamd_re_cache *cache;

	cache = g_malloc0(sizeof(*cache));
	cache->re_classes = g_hash_table_new(g_int64_hash, g_int64_equal);
	cache->nre = 0;
	cache->re = g_ptr_array_new_full(256, rspamd_re_cache_elt_dtor);
	cache->selectors = kh_init(lua_selectors_hash);
	cache->next = NULL;
	cache->prev = cache;
	cache->scope = NULL;                        /* Default scope */
	cache->flags = RSPAMD_RE_CACHE_FLAG_LOADED; /* Default scope is always loaded */
#ifdef WITH_HYPERSCAN
	cache->hyperscan_loaded = RSPAMD_HYPERSCAN_UNKNOWN;
#endif
	REF_INIT_RETAIN(cache, rspamd_re_cache_destroy);

	return cache;
}

enum rspamd_hyperscan_status
rspamd_re_cache_is_hs_loaded(struct rspamd_re_cache *cache)
{
	g_assert(cache != NULL);

#ifdef WITH_HYPERSCAN
	return cache->hyperscan_loaded;
#else
	return RSPAMD_HYPERSCAN_UNSUPPORTED;
#endif
}

rspamd_regexp_t *
rspamd_re_cache_add(struct rspamd_re_cache *cache,
					rspamd_regexp_t *re,
					enum rspamd_re_type type,
					gconstpointer type_data, gsize datalen,
					int lua_cbref)
{
	uint64_t class_id;
	struct rspamd_re_class *re_class;
	rspamd_regexp_t *nre;
	struct rspamd_re_cache_elt *elt;

	g_assert(cache != NULL);
	g_assert(re != NULL);

	class_id = rspamd_re_cache_class_id(type, type_data, datalen);
	re_class = g_hash_table_lookup(cache->re_classes, &class_id);

	if (re_class == NULL) {
		re_class = g_malloc0(sizeof(*re_class));
		re_class->id = class_id;
		re_class->type_len = datalen;
		re_class->type = type;
		re_class->cache = cache; /* Set back-reference */
		re_class->re = g_hash_table_new_full(rspamd_regexp_hash,
											 rspamd_regexp_equal, NULL, (GDestroyNotify) rspamd_regexp_unref);

		if (datalen > 0) {
			re_class->type_data = g_malloc0(datalen);
			memcpy(re_class->type_data, type_data, datalen);
		}

		g_hash_table_insert(cache->re_classes, &re_class->id, re_class);
	}

	if ((nre = g_hash_table_lookup(re_class->re, rspamd_regexp_get_id(re))) == NULL) {
		/*
		 * We set re id based on the global position in the cache
		 */
		elt = g_malloc0(sizeof(*elt));
		/* One ref for re_class */
		nre = rspamd_regexp_ref(re);
		rspamd_regexp_set_cache_id(re, cache->nre++);
		/* One ref for cache */
		elt->re = rspamd_regexp_ref(re);
		g_ptr_array_add(cache->re, elt);
		rspamd_regexp_set_class(re, re_class);
		elt->lua_cbref = lua_cbref;

		g_hash_table_insert(re_class->re, rspamd_regexp_get_id(nre), nre);
	}

	if (rspamd_regexp_get_flags(re) & RSPAMD_REGEXP_FLAG_UTF) {
		re_class->has_utf8 = TRUE;
	}

	return nre;
}

rspamd_regexp_t *
rspamd_re_cache_add_scoped(struct rspamd_re_cache **cache_head, const char *scope,
						   rspamd_regexp_t *re, enum rspamd_re_type type,
						   gconstpointer type_data, gsize datalen,
						   int lua_cbref)
{
	struct rspamd_re_cache *cache;

	g_assert(cache_head != NULL);
	g_assert(re != NULL);

	/* NULL scope is allowed for default scope */
	cache = rspamd_re_cache_add_to_scope_list(cache_head, scope);
	if (!cache) {
		return NULL;
	}

	return rspamd_re_cache_add(cache, re, type, type_data, datalen, lua_cbref);
}

void rspamd_re_cache_replace(struct rspamd_re_cache *cache,
							 rspamd_regexp_t *what,
							 rspamd_regexp_t *with)
{
	uint64_t re_id;
	struct rspamd_re_class *re_class;
	rspamd_regexp_t *src;
	struct rspamd_re_cache_elt *elt;

	g_assert(cache != NULL);
	g_assert(what != NULL);
	g_assert(with != NULL);

	re_class = rspamd_regexp_get_class(what);

	if (re_class != NULL) {
		re_id = rspamd_regexp_get_cache_id(what);

		g_assert(re_id != RSPAMD_INVALID_ID);
		src = g_hash_table_lookup(re_class->re, rspamd_regexp_get_id(what));
		elt = g_ptr_array_index(cache->re, re_id);
		g_assert(elt != NULL);
		g_assert(src != NULL);

		rspamd_regexp_set_cache_id(what, RSPAMD_INVALID_ID);
		rspamd_regexp_set_class(what, NULL);
		rspamd_regexp_set_cache_id(with, re_id);
		rspamd_regexp_set_class(with, re_class);
		/*
		 * On calling of this function, we actually unref old re (what)
		 */
		g_hash_table_insert(re_class->re,
							rspamd_regexp_get_id(what),
							rspamd_regexp_ref(with));

		rspamd_regexp_unref(elt->re);
		elt->re = rspamd_regexp_ref(with);
		/* XXX: do not touch match type here */
	}
}

void rspamd_re_cache_replace_scoped(struct rspamd_re_cache **cache_head, const char *scope,
									rspamd_regexp_t *what,
									rspamd_regexp_t *with)
{
	struct rspamd_re_cache *cache;

	g_assert(cache_head != NULL);
	g_assert(what != NULL);
	g_assert(with != NULL);

	/* NULL scope is allowed for default scope */
	cache = rspamd_re_cache_find_by_scope(*cache_head, scope);
	if (cache) {
		rspamd_re_cache_replace(cache, what, with);
	}
}

static int
rspamd_re_cache_sort_func(gconstpointer a, gconstpointer b)
{
	struct rspamd_re_cache_elt *const *re1 = a, *const *re2 = b;

	return rspamd_regexp_cmp(rspamd_regexp_get_id((*re1)->re),
							 rspamd_regexp_get_id((*re2)->re));
}

void rspamd_re_cache_init(struct rspamd_re_cache *cache, struct rspamd_config *cfg)
{
	unsigned int i, fl;
	GHashTableIter it;
	gpointer k, v;
	struct rspamd_re_class *re_class;
	rspamd_cryptobox_hash_state_t st_global;
	rspamd_regexp_t *re;
	struct rspamd_re_cache_elt *elt;
	unsigned char hash_out[rspamd_cryptobox_HASHBYTES];

	g_assert(cache != NULL);

	rspamd_cryptobox_hash_init(&st_global, NULL, 0);
	/* Resort all regexps */
	g_ptr_array_sort(cache->re, rspamd_re_cache_sort_func);

	for (i = 0; i < cache->re->len; i++) {
		elt = g_ptr_array_index(cache->re, i);
		re = elt->re;
		re_class = rspamd_regexp_get_class(re);
		g_assert(re_class != NULL);
		rspamd_regexp_set_cache_id(re, i);

		if (re_class->st == NULL) {
			(void) !posix_memalign((void **) &re_class->st, RSPAMD_ALIGNOF(rspamd_cryptobox_hash_state_t),
								   sizeof(*re_class->st));
			g_assert(re_class->st != NULL);
			rspamd_cryptobox_hash_init(re_class->st, NULL, 0);
		}

		/* Update hashes */
		/* Id of re class */
		rspamd_cryptobox_hash_update(re_class->st, (gpointer) &re_class->id,
									 sizeof(re_class->id));
		rspamd_cryptobox_hash_update(&st_global, (gpointer) &re_class->id,
									 sizeof(re_class->id));
		/* Id of re expression */
		rspamd_cryptobox_hash_update(re_class->st, rspamd_regexp_get_id(re),
									 rspamd_cryptobox_HASHBYTES);
		rspamd_cryptobox_hash_update(&st_global, rspamd_regexp_get_id(re),
									 rspamd_cryptobox_HASHBYTES);
		/* PCRE flags */
		fl = rspamd_regexp_get_pcre_flags(re);
		rspamd_cryptobox_hash_update(re_class->st, (const unsigned char *) &fl,
									 sizeof(fl));
		rspamd_cryptobox_hash_update(&st_global, (const unsigned char *) &fl,
									 sizeof(fl));
		/* Rspamd flags */
		fl = rspamd_regexp_get_flags(re);
		rspamd_cryptobox_hash_update(re_class->st, (const unsigned char *) &fl,
									 sizeof(fl));
		rspamd_cryptobox_hash_update(&st_global, (const unsigned char *) &fl,
									 sizeof(fl));
		/* Limit of hits */
		fl = rspamd_regexp_get_maxhits(re);
		rspamd_cryptobox_hash_update(re_class->st, (const unsigned char *) &fl,
									 sizeof(fl));
		rspamd_cryptobox_hash_update(&st_global, (const unsigned char *) &fl,
									 sizeof(fl));
		/* Global index - only in global hash, not per-class (to avoid
		 * class hash instability when other classes change) */
		rspamd_cryptobox_hash_update(&st_global, (const unsigned char *) &i,
									 sizeof(i));
	}

	rspamd_cryptobox_hash_final(&st_global, hash_out);
	rspamd_snprintf(cache->hash, sizeof(cache->hash), "%*xs",
					(int) rspamd_cryptobox_HASHBYTES, hash_out);

	/* Now finalize all classes */
	g_hash_table_iter_init(&it, cache->re_classes);

	while (g_hash_table_iter_next(&it, &k, &v)) {
		re_class = v;

		if (re_class->st) {
			/*
			 * We finally update all classes with the number of expressions
			 * in the cache to ensure that if even a single re has been changed
			 * we won't be broken due to id mismatch
			 */
			rspamd_cryptobox_hash_update(re_class->st,
										 (gpointer) &cache->re->len,
										 sizeof(cache->re->len));
			rspamd_cryptobox_hash_final(re_class->st, hash_out);
			rspamd_snprintf(re_class->hash, sizeof(re_class->hash), "%*xs",
							(int) rspamd_cryptobox_HASHBYTES, hash_out);
			free(re_class->st); /* Due to posix_memalign */
			re_class->st = NULL;
		}
	}

	cache->L = cfg->lua_state;

#ifdef WITH_HYPERSCAN
	const char *platform = "generic";
	rspamd_fstring_t *features = rspamd_fstring_new();

	cache->disable_hyperscan = cfg->disable_hyperscan;

	g_assert(hs_populate_platform(&cache->plt) == HS_SUCCESS);

	/* Now decode what we do have */
	switch (cache->plt.tune) {
	case HS_TUNE_FAMILY_HSW:
		platform = "haswell";
		break;
	case HS_TUNE_FAMILY_SNB:
		platform = "sandy";
		break;
	case HS_TUNE_FAMILY_BDW:
		platform = "broadwell";
		break;
	case HS_TUNE_FAMILY_IVB:
		platform = "ivy";
		break;
	default:
		break;
	}

	if (cache->plt.cpu_features & HS_CPU_FEATURES_AVX2) {
		features = rspamd_fstring_append(features, "AVX2", 4);
	}

	hs_set_allocator(g_malloc, g_free);

	msg_info_re_cache("loaded hyperscan engine with cpu tune '%s' and features '%V'",
					  platform, features);

	rspamd_fstring_free(features);
#endif
}

void rspamd_re_cache_init_scoped(struct rspamd_re_cache *cache_head,
								 struct rspamd_config *cfg)
{
	struct rspamd_re_cache *cur;

	g_assert(cache_head != NULL);

	DL_FOREACH(cache_head, cur)
	{
		/* Only initialize loaded scopes */
		if (cur->flags & RSPAMD_RE_CACHE_FLAG_LOADED) {
			rspamd_re_cache_init(cur, cfg);
		}
	}
}

static struct rspamd_re_runtime *
rspamd_re_cache_runtime_new_single(struct rspamd_re_cache *cache)
{
	struct rspamd_re_runtime *rt;
	g_assert(cache != NULL);

	rt = g_malloc0(sizeof(*rt) + NBYTES(cache->nre) + cache->nre);
	rt->cache = cache;
	REF_RETAIN(cache);
	rt->checked = ((unsigned char *) rt) + sizeof(*rt);
	rt->results = rt->checked + NBYTES(cache->nre);
	rt->stat.regexp_total = cache->nre;
#ifdef WITH_HYPERSCAN
	rt->has_hs = cache->hyperscan_loaded;
#endif
	/* Initialize the doubly-linked list pointers */
	rt->next = NULL;
	rt->prev = NULL;

	return rt;
}

struct rspamd_re_runtime *
rspamd_re_cache_runtime_new(struct rspamd_re_cache *cache)
{
	struct rspamd_re_runtime *rt_head = NULL, *rt;
	struct rspamd_re_cache *cur;

	g_assert(cache != NULL);

	/*
	 * Create runtime for all loaded scopes in the chain.
	 * This ensures task has runtimes for all available loaded scopes.
	 */
	DL_FOREACH(cache, cur)
	{
		/* Skip unloaded scopes */
		if (!(cur->flags & RSPAMD_RE_CACHE_FLAG_LOADED)) {
			continue;
		}

		rt = rspamd_re_cache_runtime_new_single(cur);
		if (rt) {
			if (rt_head) {
				DL_APPEND(rt_head, rt);
			}
			else {
				rt_head = rt;
				/* For doubly-linked list, first element's prev should point to itself */
				rt_head->prev = rt_head;
				rt_head->next = NULL;
			}
		}
	}

	return rt_head;
}

struct rspamd_re_runtime *
rspamd_re_cache_runtime_new_all_scopes(struct rspamd_re_cache *cache_head)
{
	/* This is now the same as the main function since it always creates for all scopes */
	return rspamd_re_cache_runtime_new(cache_head);
}

struct rspamd_re_runtime *
rspamd_re_cache_runtime_new_scoped(struct rspamd_re_cache *cache_head, const char *scope)
{
	struct rspamd_re_cache *cache;

	if (!cache_head) {
		return NULL;
	}

	cache = rspamd_re_cache_find_by_scope(cache_head, scope);
	if (!cache) {
		return NULL;
	}

	return rspamd_re_cache_runtime_new_single(cache);
}

const struct rspamd_re_cache_stat *
rspamd_re_cache_get_stat(struct rspamd_re_runtime *rt)
{
	g_assert(rt != NULL);

	return &rt->stat;
}

static gboolean
rspamd_re_cache_check_lua_condition(struct rspamd_task *task,
									rspamd_regexp_t *re,
									const unsigned char *in, gsize len,
									goffset start, goffset end,
									int lua_cbref)
{
	lua_State *L = (lua_State *) task->cfg->lua_state;
	GError *err = NULL;
	struct rspamd_lua_text __attribute__((unused)) * t;
	int text_pos;

	if (G_LIKELY(lua_cbref == -1)) {
		return TRUE;
	}

	t = lua_new_text(L, in, len, FALSE);
	text_pos = lua_gettop(L);

	if (!rspamd_lua_universal_pcall(L, lua_cbref,
									G_STRLOC, 1, "utii", &err,
									rspamd_task_classname, task,
									text_pos, start, end)) {
		msg_warn_task("cannot call for re_cache_check_lua_condition for re %s: %e",
					  rspamd_regexp_get_pattern(re), err);
		g_error_free(err);
		lua_settop(L, text_pos - 1);

		return TRUE;
	}

	gboolean res = lua_toboolean(L, -1);

	lua_settop(L, text_pos - 1);

	return res;
}

static unsigned int
rspamd_re_cache_process_pcre(struct rspamd_re_runtime *rt,
							 rspamd_regexp_t *re, struct rspamd_task *task,
							 const unsigned char *in, gsize len,
							 gboolean is_raw,
							 int lua_cbref)
{
	unsigned int r = 0;
	const char *start = NULL, *end = NULL;
	unsigned int max_hits = rspamd_regexp_get_maxhits(re);
	uint64_t id = rspamd_regexp_get_cache_id(re);
	double t1 = NAN, t2, pr;
	const double slow_time = 1e8;

	if (in == NULL) {
		return rt->results[id];
	}

	if (len == 0) {
		return rt->results[id];
	}

	if (rt->cache->max_re_data > 0 && len > rt->cache->max_re_data) {
		len = rt->cache->max_re_data;
	}

	r = rt->results[id];

	if (max_hits == 0 || r < max_hits) {
		pr = rspamd_random_double_fast();

		if (pr > 0.9) {
			t1 = rspamd_get_ticks(TRUE);
		}

		while (rspamd_regexp_search(re,
									in,
									len,
									&start,
									&end,
									is_raw,
									NULL)) {
			if (rspamd_re_cache_check_lua_condition(task, re, in, len,
													start - (const char *) in, end - (const char *) in, lua_cbref)) {
				r++;
				msg_debug_re_task("found regexp /%s/, total hits: %d",
								  rspamd_regexp_get_pattern(re), r);
			}

			if (max_hits > 0 && r >= max_hits) {
				break;
			}

			if (start >= end) {
				/* We found all matches, so no more hits are possible (protect from empty patterns) */
				break;
			}
		}

		rt->results[id] += r;
		rt->stat.regexp_checked++;
		rt->stat.bytes_scanned_pcre += len;
		rt->stat.bytes_scanned += len;

		if (r > 0) {
			rt->stat.regexp_matched += r;
		}

		if (!isnan(t1)) {
			t2 = rspamd_get_ticks(TRUE);

			if (t2 - t1 > slow_time) {
				rspamd_symcache_enable_profile(task);
				msg_info_task("regexp '%16s' took %.0f ticks to execute",
							  rspamd_regexp_get_pattern(re), t2 - t1);
			}
		}
	}

	return r;
}

#ifdef WITH_HYPERSCAN
struct rspamd_re_hyperscan_cbdata {
	struct rspamd_re_runtime *rt;
	const unsigned char **ins;
	const unsigned int *lens;
	unsigned int count;
	rspamd_regexp_t *re;
	struct rspamd_task *task;
};

static int
rspamd_re_cache_hyperscan_cb(unsigned int id,
							 unsigned long long from,
							 unsigned long long to,
							 unsigned int flags,
							 void *ud)
{
	struct rspamd_re_hyperscan_cbdata *cbdata = ud;
	struct rspamd_re_runtime *rt;
	struct rspamd_re_cache_elt *cache_elt;
	unsigned int ret, maxhits, i, processed;
	struct rspamd_task *task;

	rt = cbdata->rt;
	task = cbdata->task;
	cache_elt = g_ptr_array_index(rt->cache->re, id);
	maxhits = rspamd_regexp_get_maxhits(cache_elt->re);

	if (cache_elt->match_type == RSPAMD_RE_CACHE_HYPERSCAN) {
		if (rspamd_re_cache_check_lua_condition(task, cache_elt->re,
												cbdata->ins[0], cbdata->lens[0], from, to, cache_elt->lua_cbref)) {
			ret = 1;
			setbit(rt->checked, id);

			if (maxhits == 0 || rt->results[id] < maxhits) {
				rt->results[id] += ret;
				rt->stat.regexp_matched++;
			}
			msg_debug_re_task("found regexp /%s/ using hyperscan only, total hits: %d",
							  rspamd_regexp_get_pattern(cache_elt->re), rt->results[id]);
		}
	}
	else {
		if (!isset(rt->checked, id)) {
			processed = 0;

			for (i = 0; i < cbdata->count; i++) {
				rspamd_re_cache_process_pcre(rt,
											 cache_elt->re,
											 cbdata->task,
											 cbdata->ins[i],
											 cbdata->lens[i],
											 FALSE,
											 cache_elt->lua_cbref);
				setbit(rt->checked, id);

				processed += cbdata->lens[i];

				if (processed >= to) {
					break;
				}
			}
		}
	}

	return 0;
}
#endif

static unsigned int
rspamd_re_cache_process_regexp_data(struct rspamd_re_runtime *rt,
									rspamd_regexp_t *re, struct rspamd_task *task,
									const unsigned char **in, unsigned int *lens,
									unsigned int count,
									gboolean is_raw,
									gboolean *processed_hyperscan)
{
	uint64_t re_id;
	unsigned int ret = 0;
	unsigned int i;
	struct rspamd_re_cache_elt *cache_elt;

	re_id = rspamd_regexp_get_cache_id(re);

	if (count == 0 || in == NULL) {
		/* We assume this as absence of the specified data */
		setbit(rt->checked, re_id);
		rt->results[re_id] = ret;
		return ret;
	}

	cache_elt = (struct rspamd_re_cache_elt *) g_ptr_array_index(rt->cache->re, re_id);

#ifndef WITH_HYPERSCAN
	for (i = 0; i < count; i++) {
		ret = rspamd_re_cache_process_pcre(rt,
										   re,
										   task,
										   in[i],
										   lens[i],
										   is_raw,
										   cache_elt->lua_cbref);
		rt->results[re_id] = ret;
	}

	setbit(rt->checked, re_id);
#else
	struct rspamd_re_class *re_class;
	struct rspamd_re_hyperscan_cbdata cbdata;

	cache_elt = g_ptr_array_index(rt->cache->re, re_id);
	re_class = rspamd_regexp_get_class(re);

	if (rt->cache->disable_hyperscan || cache_elt->match_type == RSPAMD_RE_CACHE_PCRE ||
		!rt->has_hs || (is_raw && re_class->has_utf8)) {
		for (i = 0; i < count; i++) {
			ret = rspamd_re_cache_process_pcre(rt,
											   re,
											   task,
											   in[i],
											   lens[i],
											   is_raw,
											   cache_elt->lua_cbref);
		}

		setbit(rt->checked, re_id);
	}
	else {
		for (i = 0; i < count; i++) {
			/* For Hyperscan we can probably safely disable all those limits */
#if 0
			if (rt->cache->max_re_data > 0 && lens[i] > rt->cache->max_re_data) {
				lens[i] = rt->cache->max_re_data;
			}
#endif
			rt->stat.bytes_scanned += lens[i];
		}

		g_assert(re_class->hs_scratch != NULL);
		g_assert(re_class->hs_db != NULL);

		/* Go through hyperscan API */
		for (i = 0; i < count; i++) {
			cbdata.ins = &in[i];
			cbdata.re = re;
			cbdata.rt = rt;
			cbdata.lens = &lens[i];
			cbdata.count = 1;
			cbdata.task = task;

			if ((hs_scan(rspamd_hyperscan_get_database(re_class->hs_db),
						 in[i], lens[i], 0,
						 re_class->hs_scratch,
						 rspamd_re_cache_hyperscan_cb, &cbdata)) != HS_SUCCESS) {
				ret = 0;
			}
			else {
				ret = rt->results[re_id];
				*processed_hyperscan = TRUE;
			}
		}
	}
#endif

	return ret;
}

static void
rspamd_re_cache_finish_class(struct rspamd_task *task,
							 struct rspamd_re_runtime *rt,
							 struct rspamd_re_class *re_class,
							 const char *class_name)
{
#ifdef WITH_HYPERSCAN
	unsigned int i;
	uint64_t re_id;
	unsigned int found = 0;

	/* Set all bits that are not checked and included in hyperscan to 1 */
	for (i = 0; i < re_class->nhs; i++) {
		re_id = re_class->hs_ids[i];

		if (!isset(rt->checked, re_id)) {
			g_assert(rt->results[re_id] == 0);
			rt->results[re_id] = 0;
			setbit(rt->checked, re_id);
		}
		else {
			found++;
		}
	}

	msg_debug_re_task("finished hyperscan for class %s; %d "
					  "matches found; %d hyperscan supported regexps; %d total regexps",
					  class_name, found, re_class->nhs, (int) g_hash_table_size(re_class->re));
#endif
}

static gboolean
rspamd_re_cache_process_selector(struct rspamd_task *task,
								 struct rspamd_re_runtime *rt,
								 const char *name,
								 unsigned char ***svec,
								 unsigned int **lenvec,
								 unsigned int *n)
{
	int ref;
	khiter_t k;
	lua_State *L;
	int err_idx, ret;
	struct rspamd_task **ptask;
	gboolean result = FALSE;
	struct rspamd_re_cache *cache = rt->cache;
	struct rspamd_re_selector_result *sr;

	L = cache->L;
	k = kh_get(lua_selectors_hash, cache->selectors, (char *) name);

	if (k == kh_end(cache->selectors)) {
		msg_err_task("cannot find selector %s, not registered", name);

		return FALSE;
	}

	ref = kh_value(cache->selectors, k);

	/* First, search for the cached result */
	if (rt->sel_cache) {
		k = kh_get(selectors_results_hash, rt->sel_cache, ref);

		if (k != kh_end(rt->sel_cache)) {
			sr = &kh_value(rt->sel_cache, k);

			*svec = sr->scvec;
			*lenvec = sr->lenvec;
			*n = sr->cnt;

			return TRUE;
		}
	}
	else {
		rt->sel_cache = kh_init(selectors_results_hash);
	}

	lua_pushcfunction(L, &rspamd_lua_traceback);
	err_idx = lua_gettop(L);

	lua_rawgeti(L, LUA_REGISTRYINDEX, ref);
	ptask = lua_newuserdata(L, sizeof(*ptask));
	*ptask = task;
	rspamd_lua_setclass(L, rspamd_task_classname, -1);

	if ((ret = lua_pcall(L, 1, 1, err_idx)) != 0) {
		msg_err_task("call to selector %s "
					 "failed (%d): %s",
					 name, ret,
					 lua_tostring(L, -1));
	}
	else {
		struct rspamd_lua_text *txt;
		gsize slen;
		const char *sel_data;

		if (lua_type(L, -1) != LUA_TTABLE) {
			txt = lua_check_text_or_string(L, -1);


			if (txt) {
				msg_debug_re_cache("re selector %s returned 1 element", name);
				sel_data = txt->start;
				slen = txt->len;
				*n = 1;
				*svec = g_malloc(sizeof(unsigned char *));
				*lenvec = g_malloc(sizeof(unsigned int));
				(*svec)[0] = g_malloc(slen);
				memcpy((*svec)[0], sel_data, slen);
				(*lenvec)[0] = slen;
				result = TRUE;
			}
			else {
				msg_debug_re_cache("re selector %s returned NULL", name);
			}
		}
		else {
			*n = rspamd_lua_table_size(L, -1);

			msg_debug_re_cache("re selector %s returned %d elements", name, *n);

			if (*n > 0) {
				*svec = g_malloc(sizeof(unsigned char *) * (*n));
				*lenvec = g_malloc(sizeof(unsigned int) * (*n));

				for (int i = 0; i < *n; i++) {
					lua_rawgeti(L, -1, i + 1);

					txt = lua_check_text_or_string(L, -1);
					if (txt && txt->len > 0) {
						sel_data = txt->start;
						slen = txt->len;
						(*svec)[i] = g_malloc(slen);
						memcpy((*svec)[i], sel_data, slen);
					}
					else {
						/* A hack to avoid malloc(0) */
						sel_data = "";
						slen = 0;
						(*svec)[i] = g_malloc(1);
						memcpy((*svec)[i], sel_data, 1);
					}

					(*lenvec)[i] = slen;
					lua_pop(L, 1);
				}
			}

			/* Empty table is also a valid result */
			result = TRUE;
		}
	}

	lua_settop(L, err_idx - 1);

	if (result) {
		k = kh_put(selectors_results_hash, rt->sel_cache, ref, &ret);
		sr = &kh_value(rt->sel_cache, k);

		sr->cnt = *n;
		sr->scvec = *svec;
		sr->lenvec = *lenvec;
	}

	return result;
}


static inline unsigned int
rspamd_process_words_vector_kvec(rspamd_words_t *words,
								 const unsigned char **scvec,
								 unsigned int *lenvec,
								 struct rspamd_re_class *re_class,
								 unsigned int cnt,
								 gboolean *raw)
{
	unsigned int j;
	rspamd_word_t *tok;

	if (words && words->a) {
		for (j = 0; j < kv_size(*words); j++) {
			tok = &kv_A(*words, j);

			if (tok->flags & RSPAMD_STAT_TOKEN_FLAG_TEXT) {
				if (!(tok->flags & RSPAMD_STAT_TOKEN_FLAG_UTF)) {
					if (!re_class->has_utf8) {
						*raw = TRUE;
					}
					else {
						continue; /* Skip */
					}
				}
			}
			else {
				continue; /* Skip non text */
			}

			if (re_class->type == RSPAMD_RE_RAWWORDS) {
				if (tok->original.len > 0) {
					scvec[cnt] = tok->original.begin;
					lenvec[cnt++] = tok->original.len;
				}
			}
			else if (re_class->type == RSPAMD_RE_WORDS) {
				if (tok->normalized.len > 0) {
					scvec[cnt] = tok->normalized.begin;
					lenvec[cnt++] = tok->normalized.len;
				}
			}
			else {
				/* Stemmed words */
				if (tok->stemmed.len > 0) {
					scvec[cnt] = tok->stemmed.begin;
					lenvec[cnt++] = tok->stemmed.len;
				}
			}
		}
	}

	return cnt;
}

static unsigned int
rspamd_re_cache_process_headers_list(struct rspamd_task *task,
									 struct rspamd_re_runtime *rt,
									 rspamd_regexp_t *re,
									 struct rspamd_re_class *re_class,
									 struct rspamd_mime_header *rh,
									 gboolean is_strong,
									 gboolean *processed_hyperscan)
{
	const unsigned char **scvec, *in;
	gboolean raw = FALSE;
	unsigned int *lenvec;
	struct rspamd_mime_header *cur;
	unsigned int cnt = 0, i = 0, ret = 0;

	DL_COUNT(rh, cur, cnt);

	scvec = g_malloc(sizeof(*scvec) * cnt);
	lenvec = g_malloc(sizeof(*lenvec) * cnt);

	DL_FOREACH(rh, cur)
	{
		if (is_strong && strcmp(cur->name, re_class->type_data) != 0) {
			/* Skip a different case */
			continue;
		}

		if (re_class->type == RSPAMD_RE_RAWHEADER) {
			in = (const unsigned char *) cur->value;
			lenvec[i] = strlen(cur->value);

			if (rspamd_fast_utf8_validate(in, lenvec[i]) != 0) {
				raw = TRUE;
			}
		}
		else {
			in = (const unsigned char *) cur->decoded;
			/* Validate input^W^WNo need to validate as it is already valid */
			if (!in) {
				lenvec[i] = 0;
				scvec[i] = (unsigned char *) "";
				continue;
			}

			lenvec[i] = strlen(in);
		}

		scvec[i] = in;

		i++;
	}

	if (i > 0) {
		ret = rspamd_re_cache_process_regexp_data(rt, re,
												  task, scvec, lenvec, i, raw, processed_hyperscan);
		msg_debug_re_task("checking header %s regexp: %s=%*s -> %d",
						  re_class->type_data,
						  rspamd_regexp_get_pattern(re),
						  (int) lenvec[0], scvec[0], ret);
	}

	g_free(scvec);
	g_free(lenvec);

	return ret;
}

/*
 * Calculates the specified regexp for the specified class if it's not calculated
 */
static unsigned int
rspamd_re_cache_exec_re(struct rspamd_task *task,
						struct rspamd_re_runtime *rt,
						rspamd_regexp_t *re,
						struct rspamd_re_class *re_class,
						gboolean is_strong)
{
	unsigned int ret = 0, i, re_id;
	struct rspamd_mime_header *rh;
	const char *in;
	const unsigned char **scvec = NULL;
	unsigned int *lenvec = NULL;
	gboolean raw = FALSE, processed_hyperscan = FALSE;
	struct rspamd_mime_text_part *text_part;
	struct rspamd_mime_part *mime_part;
	struct rspamd_url *url;
	unsigned int len = 0, cnt = 0;
	const char *class_name;

	class_name = rspamd_re_cache_type_to_string(re_class->type);
	msg_debug_re_task("start check re type: %s: /%s/",
					  class_name,
					  rspamd_regexp_get_pattern(re));
	re_id = rspamd_regexp_get_cache_id(re);

	switch (re_class->type) {
	case RSPAMD_RE_HEADER:
	case RSPAMD_RE_RAWHEADER:
		/* Get list of specified headers */
		rh = rspamd_message_get_header_array(task,
											 re_class->type_data, FALSE);

		if (rh) {
			ret = rspamd_re_cache_process_headers_list(task, rt, re,
													   re_class, rh, is_strong, &processed_hyperscan);
			msg_debug_re_task("checked header(%s) regexp: %s -> %d",
							  (const char *) re_class->type_data,
							  rspamd_regexp_get_pattern(re),
							  ret);
		}
		break;
	case RSPAMD_RE_ALLHEADER:
		raw = TRUE;
		in = MESSAGE_FIELD(task, raw_headers_content).begin;
		len = MESSAGE_FIELD(task, raw_headers_content).len;
		ret = rspamd_re_cache_process_regexp_data(rt, re,
												  task, (const unsigned char **) &in, &len, 1, raw, &processed_hyperscan);
		msg_debug_re_task("checked allheader regexp: %s -> %d",
						  rspamd_regexp_get_pattern(re), ret);
		break;
	case RSPAMD_RE_MIMEHEADER:
		PTR_ARRAY_FOREACH(MESSAGE_FIELD(task, parts), i, mime_part)
		{
			if (mime_part->parent_part == NULL ||
				!IS_PART_MULTIPART(mime_part->parent_part) ||
				IS_PART_MESSAGE(mime_part)) {
				/* We filter parts that have no multipart parent or are a messages here */
				continue;
			}
			rh = rspamd_message_get_header_from_hash(mime_part->raw_headers,
													 re_class->type_data, FALSE);

			if (rh) {
				ret += rspamd_re_cache_process_headers_list(task, rt, re,
															re_class, rh, is_strong, &processed_hyperscan);
			}
			msg_debug_re_task("checked mime header(%s) regexp: %s -> %d",
							  (const char *) re_class->type_data,
							  rspamd_regexp_get_pattern(re),
							  ret);
		}
		break;
	case RSPAMD_RE_MIME:
	case RSPAMD_RE_RAWMIME:
		/* Iterate through text parts */
		if (MESSAGE_FIELD(task, text_parts)->len > 0) {
			cnt = MESSAGE_FIELD(task, text_parts)->len;
			scvec = g_malloc(sizeof(*scvec) * cnt);
			lenvec = g_malloc(sizeof(*lenvec) * cnt);

			PTR_ARRAY_FOREACH(MESSAGE_FIELD(task, text_parts), i, text_part)
			{
				/* Select data for regexp */
				if (re_class->type == RSPAMD_RE_RAWMIME) {
					if (text_part->raw.len == 0) {
						len = 0;
						in = "";
					}
					else {
						in = text_part->raw.begin;
						len = text_part->raw.len;
					}

					raw = TRUE;
				}
				else {
					/* Skip empty parts */
					if (IS_TEXT_PART_EMPTY(text_part)) {
						len = 0;
						in = "";
					}
					else {
						/* Check raw flags */
						if (!IS_TEXT_PART_UTF(text_part)) {
							raw = TRUE;
						}

						in = text_part->utf_content.begin;
						len = text_part->utf_content.len;
					}
				}

				scvec[i] = (unsigned char *) in;
				lenvec[i] = len;
			}

			ret = rspamd_re_cache_process_regexp_data(rt, re,
													  task, scvec, lenvec, cnt, raw, &processed_hyperscan);
			msg_debug_re_task("checked mime regexp: %s -> %d",
							  rspamd_regexp_get_pattern(re), ret);
			g_free(scvec);
			g_free(lenvec);
		}
		break;
	case RSPAMD_RE_URL:
		cnt = kh_size(MESSAGE_FIELD(task, urls));

		if (cnt > 0) {
			scvec = g_malloc(sizeof(*scvec) * cnt);
			lenvec = g_malloc(sizeof(*lenvec) * cnt);
			i = 0;
			raw = FALSE;

			kh_foreach_key(MESSAGE_FIELD(task, urls), url, {
				if ((url->protocol & PROTOCOL_MAILTO)) {
					continue;
				}
				in = url->string;
				len = url->urllen;

				if (len > 0 && !(url->flags & RSPAMD_URL_FLAG_IMAGE)) {
					scvec[i] = (unsigned char *) in;
					lenvec[i++] = len;
				}
			});

			/* URL regexps do not include emails, that's why the code below is commented */
#if 0
			g_hash_table_iter_init (&it, MESSAGE_FIELD (task, emails));

			while (g_hash_table_iter_next (&it, &k, &v)) {
				url = v;
				in = url->string;
				len = url->urllen;

				if (len > 0 && !(url->flags & RSPAMD_URL_FLAG_IMAGE)) {
					scvec[i] = (unsigned char *) in;
					lenvec[i++] = len;
				}
			}
#endif
			ret = rspamd_re_cache_process_regexp_data(rt, re,
													  task, scvec, lenvec, i, raw, &processed_hyperscan);
			msg_debug_re_task("checked url regexp: %s -> %d",
							  rspamd_regexp_get_pattern(re), ret);
			g_free(scvec);
			g_free(lenvec);
		}
		break;
	case RSPAMD_RE_EMAIL:
		cnt = kh_size(MESSAGE_FIELD(task, urls));

		if (cnt > 0) {
			scvec = g_malloc(sizeof(*scvec) * cnt);
			lenvec = g_malloc(sizeof(*lenvec) * cnt);
			i = 0;
			raw = FALSE;

			kh_foreach_key(MESSAGE_FIELD(task, urls), url, {
				if (!(url->protocol & PROTOCOL_MAILTO)) {
					continue;
				}
				if (url->userlen == 0 || url->hostlen == 0) {
					continue;
				}

				in = rspamd_url_user_unsafe(url);
				len = url->userlen + 1 + url->hostlen;
				scvec[i] = (unsigned char *) in;
				lenvec[i++] = len;
			});

			ret = rspamd_re_cache_process_regexp_data(rt, re,
													  task, scvec, lenvec, i, raw, &processed_hyperscan);
			msg_debug_re_task("checked email regexp: %s -> %d",
							  rspamd_regexp_get_pattern(re), ret);
			g_free(scvec);
			g_free(lenvec);
		}
		break;
	case RSPAMD_RE_BODY:
		raw = TRUE;
		in = task->msg.begin;
		len = task->msg.len;

		ret = rspamd_re_cache_process_regexp_data(rt, re, task,
												  (const unsigned char **) &in, &len, 1, raw, &processed_hyperscan);
		msg_debug_re_task("checked rawbody regexp: %s -> %d",
						  rspamd_regexp_get_pattern(re), ret);
		break;
	case RSPAMD_RE_SABODY:
		/* According to SA docs:
		 * The 'body' in this case is the textual parts of the message body;
		 * any non-text MIME parts are stripped, and the message decoded from
		 * Quoted-Printable or Base-64-encoded format if necessary. The message
		 * Subject header is considered part of the body and becomes the first
		 * paragraph when running the rules. All HTML tags and line breaks will
		 * be removed before matching.
		 */
		cnt = MESSAGE_FIELD(task, text_parts)->len + 1;
		scvec = g_malloc(sizeof(*scvec) * cnt);
		lenvec = g_malloc(sizeof(*lenvec) * cnt);

		/*
		 * Body rules also include the Subject as the first line
		 * of the body content.
		 */

		rh = rspamd_message_get_header_array(task, "Subject", FALSE);

		if (rh) {
			scvec[0] = (unsigned char *) rh->decoded;
			lenvec[0] = strlen(rh->decoded);
		}
		else {
			scvec[0] = (unsigned char *) "";
			lenvec[0] = 0;
		}

		PTR_ARRAY_FOREACH(MESSAGE_FIELD(task, text_parts), i, text_part)
		{
			if (text_part->utf_stripped_content) {
				scvec[i + 1] = (unsigned char *) text_part->utf_stripped_content->data;
				lenvec[i + 1] = text_part->utf_stripped_content->len;

				if (!IS_TEXT_PART_UTF(text_part)) {
					raw = TRUE;
				}
			}
			else {
				scvec[i + 1] = (unsigned char *) "";
				lenvec[i + 1] = 0;
			}
		}

		ret = rspamd_re_cache_process_regexp_data(rt, re,
												  task, scvec, lenvec, cnt, raw, &processed_hyperscan);
		msg_debug_re_task("checked sa body regexp: %s -> %d",
						  rspamd_regexp_get_pattern(re), ret);
		g_free(scvec);
		g_free(lenvec);
		break;
	case RSPAMD_RE_SARAWBODY:
		/* According to SA docs:
		 * The 'raw body' of a message is the raw data inside all textual
		 * parts. The text will be decoded from base64 or quoted-printable
		 * encoding, but HTML tags and line breaks will still be present.
		 * Multiline expressions will need to be used to match strings that are
		 * broken by line breaks.
		 *
		 * We always use utf_raw_content (charset-converted to UTF-8 with
		 * HTML tags preserved) so that patterns match consistently
		 * regardless of the original message encoding. This prevents
		 * trivial bypass via exotic charsets like UTF-16.
		 *
		 * If charset conversion failed (utf_raw_content is NULL), fall
		 * back to parsed content (transfer-decoded only) with raw mode.
		 */
		if (MESSAGE_FIELD(task, text_parts)->len > 0) {
			cnt = MESSAGE_FIELD(task, text_parts)->len;
			scvec = g_malloc(sizeof(*scvec) * cnt);
			lenvec = g_malloc(sizeof(*lenvec) * cnt);

			for (i = 0; i < cnt; i++) {
				text_part = g_ptr_array_index(MESSAGE_FIELD(task, text_parts), i);

				if (text_part->utf_raw_content != NULL &&
					text_part->utf_raw_content->len > 0) {
					/*
					 * Use charset-converted UTF-8 content with HTML tags
					 * preserved. This is the correct representation for
					 * SA rawbody matching.
					 */
					scvec[i] = text_part->utf_raw_content->data;
					lenvec[i] = text_part->utf_raw_content->len;

					if (!IS_TEXT_PART_UTF(text_part)) {
						raw = TRUE;
					}
				}
				else if (text_part->parsed.len > 0) {
					/*
					 * Charset conversion failed; fall back to
					 * transfer-decoded content in raw mode.
					 */
					scvec[i] = (unsigned char *) text_part->parsed.begin;
					lenvec[i] = text_part->parsed.len;
					raw = TRUE;
				}
				else {
					scvec[i] = (unsigned char *) "";
					lenvec[i] = 0;
				}
			}

			ret = rspamd_re_cache_process_regexp_data(rt, re,
													  task, scvec, lenvec, cnt, raw, &processed_hyperscan);
			msg_debug_re_task("checked sa rawbody regexp: %s -> %d",
							  rspamd_regexp_get_pattern(re), ret);
			g_free(scvec);
			g_free(lenvec);
		}
		break;
	case RSPAMD_RE_WORDS:
	case RSPAMD_RE_STEMWORDS:
	case RSPAMD_RE_RAWWORDS:
		if (MESSAGE_FIELD(task, text_parts)->len > 0) {
			cnt = 0;
			raw = FALSE;

			PTR_ARRAY_FOREACH(MESSAGE_FIELD(task, text_parts), i, text_part)
			{
				if (text_part->utf_words.a) {
					cnt += kv_size(text_part->utf_words);
				}
			}

			if (task->meta_words.a && kv_size(task->meta_words) > 0) {
				cnt += kv_size(task->meta_words);
			}

			if (cnt > 0) {
				scvec = g_malloc(sizeof(*scvec) * cnt);
				lenvec = g_malloc(sizeof(*lenvec) * cnt);

				cnt = 0;

				PTR_ARRAY_FOREACH(MESSAGE_FIELD(task, text_parts), i, text_part)
				{
					if (text_part->utf_words.a) {
						cnt = rspamd_process_words_vector_kvec(&text_part->utf_words,
															   scvec, lenvec, re_class, cnt, &raw);
					}
				}

				if (task->meta_words.a) {
					cnt = rspamd_process_words_vector_kvec(&task->meta_words,
														   scvec, lenvec, re_class, cnt, &raw);
				}

				ret = rspamd_re_cache_process_regexp_data(rt, re,
														  task, scvec, lenvec, cnt, raw, &processed_hyperscan);

				msg_debug_re_task("checked sa words regexp: %s -> %d",
								  rspamd_regexp_get_pattern(re), ret);
				g_free(scvec);
				g_free(lenvec);
			}
		}
		break;
	case RSPAMD_RE_SELECTOR:
		if (rspamd_re_cache_process_selector(task, rt,
											 re_class->type_data,
											 (unsigned char ***) &scvec,
											 &lenvec, &cnt)) {
			ret = rspamd_re_cache_process_regexp_data(rt, re,
													  task, scvec, lenvec, cnt, raw, &processed_hyperscan);
			msg_debug_re_task("checked selector(%s) regexp: %s -> %d",
							  re_class->type_data,
							  rspamd_regexp_get_pattern(re), ret);

			/* Do not free vectors as they are managed by rt->sel_cache */
		}
		break;
	case RSPAMD_RE_MAX:
		msg_err_task("regexp of class invalid has been called: %s",
					 rspamd_regexp_get_pattern(re));
		break;
	}

#if WITH_HYPERSCAN
	if (processed_hyperscan) {
		rspamd_re_cache_finish_class(task, rt, re_class, class_name);
	}
#endif

	setbit(rt->checked, re_id);

	return rt->results[re_id];
}

static int
rspamd_re_cache_process_single(struct rspamd_task *task,
							   struct rspamd_re_runtime *rt,
							   rspamd_regexp_t *re,
							   enum rspamd_re_type type,
							   gconstpointer type_data,
							   gsize datalen,
							   gboolean is_strong)
{
	uint64_t re_id;
	struct rspamd_re_class *re_class;
	struct rspamd_re_cache *cache;

	g_assert(task != NULL);
	g_assert(rt != NULL);
	g_assert(re != NULL);

	cache = rt->cache;
	re_id = rspamd_regexp_get_cache_id(re);

	if (re_id == RSPAMD_INVALID_ID || re_id > cache->nre) {
		msg_err_task("re '%s' has no valid id for the cache",
					 rspamd_regexp_get_pattern(re));
		return 0;
	}

	if (isset(rt->checked, re_id)) {
		/* Fast path */
		rt->stat.regexp_fast_cached++;
		return rt->results[re_id];
	}
	else {
		/* Slow path */
		re_class = rspamd_regexp_get_class(re);

		if (re_class == NULL) {
			msg_err_task("cannot find re class for regexp '%s'",
						 rspamd_regexp_get_pattern(re));
			return 0;
		}

		return rspamd_re_cache_exec_re(task, rt, re, re_class,
									   is_strong);
	}

	return 0;
}

int rspamd_re_cache_process(struct rspamd_task *task,
							rspamd_regexp_t *re,
							enum rspamd_re_type type,
							gconstpointer type_data,
							gsize datalen,
							gboolean is_strong)
{
	struct rspamd_re_runtime *rt_list, *rt;
	struct rspamd_re_class *re_class;
	struct rspamd_re_cache *target_cache;
	int result = 0;

	g_assert(task != NULL);
	g_assert(re != NULL);

	rt_list = task->re_rt;
	if (!rt_list) {
		return 0;
	}

	/*
	 * Since each regexp belongs to a class which belongs to a cache,
	 * we can find the correct cache and corresponding runtime
	 */
	re_class = rspamd_regexp_get_class(re);
	if (!re_class) {
		return 0;
	}

	target_cache = re_class->cache;
	if (!target_cache) {
		return 0;
	}

	/* Find the runtime that matches the cache */
	DL_FOREACH(rt_list, rt)
	{
		if (rt->cache == target_cache) {
			result = rspamd_re_cache_process_single(task, rt, re, type,
													type_data, datalen, is_strong);
			break;
		}
	}

	return result;
}

int rspamd_re_cache_process_ffi(void *ptask,
								void *pre,
								int type,
								void *type_data,
								int is_strong)
{
	struct rspamd_lua_regexp **lua_re = pre;
	struct rspamd_task **real_task = ptask;
	gsize typelen = 0;

	if (type_data) {
		typelen = strlen(type_data);
	}

	return rspamd_re_cache_process(*real_task, (*lua_re)->re,
								   type, type_data, typelen, is_strong);
}

void rspamd_re_cache_runtime_destroy(struct rspamd_re_runtime *rt)
{
	struct rspamd_re_runtime *cur, *tmp;

	g_assert(rt != NULL);

	/* Handle linked list of runtimes */
	DL_FOREACH_SAFE(rt, cur, tmp)
	{
		if (cur->sel_cache) {
			struct rspamd_re_selector_result sr;

			kh_foreach_value(cur->sel_cache, sr, {
				for (unsigned int i = 0; i < sr.cnt; i++) {
					g_free((gpointer) sr.scvec[i]);
				}

				g_free(sr.scvec);
				g_free(sr.lenvec);
			});
			kh_destroy(selectors_results_hash, cur->sel_cache);
		}

		REF_RELEASE(cur->cache);
		g_free(cur);
	}
}

void rspamd_re_cache_unref(struct rspamd_re_cache *cache)
{
	if (cache) {
		REF_RELEASE(cache);
	}
}

void rspamd_re_cache_unref_scoped(struct rspamd_re_cache *cache_head)
{
	struct rspamd_re_cache *cur, *tmp;

	if (!cache_head) {
		return;
	}

	DL_FOREACH_SAFE(cache_head, cur, tmp)
	{
		DL_DELETE(cache_head, cur);
		rspamd_re_cache_unref(cur);
	}
}

struct rspamd_re_cache *
rspamd_re_cache_ref(struct rspamd_re_cache *cache)
{
	if (cache) {
		REF_RETAIN(cache);
	}

	return cache;
}

unsigned int rspamd_re_cache_set_limit(struct rspamd_re_cache *cache, unsigned int limit)
{
	unsigned int old;

	g_assert(cache != NULL);

	old = cache->max_re_data;
	cache->max_re_data = limit;

	return old;
}

unsigned int rspamd_re_cache_set_limit_scoped(struct rspamd_re_cache *cache_head, const char *scope, unsigned int limit)
{
	struct rspamd_re_cache *cache;
	unsigned int old = 0;

	if (!cache_head || !scope) {
		return old;
	}

	cache = rspamd_re_cache_find_by_scope(cache_head, scope);
	if (cache) {
		old = rspamd_re_cache_set_limit(cache, limit);
	}

	return old;
}

const char *
rspamd_re_cache_type_to_string(enum rspamd_re_type type)
{
	const char *ret = "unknown";

	switch (type) {
	case RSPAMD_RE_HEADER:
		ret = "header";
		break;
	case RSPAMD_RE_RAWHEADER:
		ret = "raw header";
		break;
	case RSPAMD_RE_MIMEHEADER:
		ret = "mime header";
		break;
	case RSPAMD_RE_ALLHEADER:
		ret = "all headers";
		break;
	case RSPAMD_RE_MIME:
		ret = "part";
		break;
	case RSPAMD_RE_RAWMIME:
		ret = "raw part";
		break;
	case RSPAMD_RE_BODY:
		ret = "rawbody";
		break;
	case RSPAMD_RE_URL:
		ret = "url";
		break;
	case RSPAMD_RE_EMAIL:
		ret = "email";
		break;
	case RSPAMD_RE_SABODY:
		ret = "sa body";
		break;
	case RSPAMD_RE_SARAWBODY:
		ret = "sa raw body";
		break;
	case RSPAMD_RE_SELECTOR:
		ret = "selector";
		break;
	case RSPAMD_RE_WORDS:
		ret = "words";
		break;
	case RSPAMD_RE_RAWWORDS:
		ret = "raw_words";
		break;
	case RSPAMD_RE_STEMWORDS:
		ret = "stem_words";
		break;
	case RSPAMD_RE_MAX:
	default:
		ret = "invalid class";
		break;
	}

	return ret;
}

enum rspamd_re_type
rspamd_re_cache_type_from_string(const char *str)
{
	enum rspamd_re_type ret;
	uint64_t h;

	/*
	 * To optimize this function, we apply hash to input string and
	 * pre-select it from the values
	 */

	if (str != NULL) {
		h = rspamd_cryptobox_fast_hash_specific(RSPAMD_CRYPTOBOX_XXHASH64,
												str, strlen(str), 0xdeadbabe);

		switch (h) {
		case G_GUINT64_CONSTANT(0x298b9c8a58887d44): /* header */
			ret = RSPAMD_RE_HEADER;
			break;
		case G_GUINT64_CONSTANT(0x467bfb5cd7ddf890): /* rawheader */
			ret = RSPAMD_RE_RAWHEADER;
			break;
		case G_GUINT64_CONSTANT(0xda081341fb600389): /* mime */
			ret = RSPAMD_RE_MIME;
			break;
		case G_GUINT64_CONSTANT(0xc35831e067a8221d): /* rawmime */
			ret = RSPAMD_RE_RAWMIME;
			break;
		case G_GUINT64_CONSTANT(0xc625e13dbe636de2): /* body */
		case G_GUINT64_CONSTANT(0xCCDEBA43518F721C): /* message */
			ret = RSPAMD_RE_BODY;
			break;
		case G_GUINT64_CONSTANT(0x286edbe164c791d2): /* url */
		case G_GUINT64_CONSTANT(0x7D9ACDF6685661A1): /* uri */
			ret = RSPAMD_RE_URL;
			break;
		case G_GUINT64_CONSTANT(0x7e232b0f60b571be): /* email */
			ret = RSPAMD_RE_EMAIL;
			break;
		case G_GUINT64_CONSTANT(0x796d62205a8778c7): /* allheader */
			ret = RSPAMD_RE_ALLHEADER;
			break;
		case G_GUINT64_CONSTANT(0xa3c6c153b3b00a5e): /* mimeheader */
			ret = RSPAMD_RE_MIMEHEADER;
			break;
		case G_GUINT64_CONSTANT(0x7794501506e604e9): /* sabody */
			ret = RSPAMD_RE_SABODY;
			break;
		case G_GUINT64_CONSTANT(0x28828962E7D2A05F): /* sarawbody */
			ret = RSPAMD_RE_SARAWBODY;
			break;
		default:
			ret = RSPAMD_RE_MAX;
			break;
		}

		/* Fallback string checks for types not covered by the hash switch */
		if (ret == RSPAMD_RE_MAX) {
			if (g_ascii_strcasecmp(str, "selector") == 0) {
				ret = RSPAMD_RE_SELECTOR;
			}
		}
	}
	else {
		ret = RSPAMD_RE_MAX;
	}

	return ret;
}

#ifdef WITH_HYPERSCAN
static char *
rspamd_re_cache_hs_pattern_from_pcre(rspamd_regexp_t *re)
{
	/*
	 * Workaround for bug in ragel 7.0.0.11
	 * https://github.com/intel/hyperscan/issues/133
	 */
	const char *pat = rspamd_regexp_get_pattern(re);
	unsigned int flags = rspamd_regexp_get_flags(re), esc_flags = RSPAMD_REGEXP_ESCAPE_RE;
	char *escaped;
	gsize esc_len;

	if (flags & RSPAMD_REGEXP_FLAG_UTF) {
		esc_flags |= RSPAMD_REGEXP_ESCAPE_UTF;
	}

	escaped = rspamd_str_regexp_escape(pat, strlen(pat), &esc_len, esc_flags);

	return escaped;
}

static gboolean
rspamd_re_cache_is_finite(struct rspamd_re_cache *cache,
						  rspamd_regexp_t *re, int flags, double max_time)
{
	pid_t cld;
	int status;
	struct timespec ts;
	hs_compile_error_t *hs_errors;
	hs_database_t *test_db;
	double wait_time;
	const int max_tries = 10;
	int tries = 0, rc;
	void (*old_hdl)(int);

	wait_time = max_time / max_tries;
	/* We need to restore SIGCHLD processing */
	old_hdl = signal(SIGCHLD, SIG_DFL);
	cld = fork();

	if (cld == 0) {
		/* Try to compile pattern */

		char *pat = rspamd_re_cache_hs_pattern_from_pcre(re);

		if (hs_compile(pat,
					   flags | HS_FLAG_PREFILTER,
					   HS_MODE_BLOCK,
					   &cache->plt,
					   &test_db,
					   &hs_errors) != HS_SUCCESS) {
			msg_info_re_cache("cannot compile (prefilter mode) '%s' to hyperscan: '%s'",
							  pat,
							  hs_errors != NULL ? hs_errors->message : "unknown error");

			hs_free_compile_error(hs_errors);
			g_free(pat);

			exit(EXIT_FAILURE);
		}

		g_free(pat);
		exit(EXIT_SUCCESS);
	}
	else if (cld > 0) {
		double_to_ts(wait_time, &ts);

		while ((rc = waitpid(cld, &status, WNOHANG)) == 0 && tries++ < max_tries) {
			(void) nanosleep(&ts, NULL);
		}

		/* Child has been terminated */
		if (rc > 0) {
			/* Forget about SIGCHLD after this point */
			signal(SIGCHLD, old_hdl);

			if (WIFEXITED(status) && WEXITSTATUS(status) == EXIT_SUCCESS) {
				return TRUE;
			}
			else {
				msg_err_re_cache(
					"cannot approximate %s to hyperscan",
					rspamd_regexp_get_pattern(re));

				return FALSE;
			}
		}
		else {
			/* We consider that as timeout */
			kill(cld, SIGKILL);
			g_assert(waitpid(cld, &status, 0) != -1);
			msg_err_re_cache(
				"cannot approximate %s to hyperscan: timeout waiting",
				rspamd_regexp_get_pattern(re));
			signal(SIGCHLD, old_hdl);
		}
	}
	else {
		msg_err_re_cache(
			"cannot approximate %s to hyperscan: fork failed: %s",
			rspamd_regexp_get_pattern(re), strerror(errno));
		signal(SIGCHLD, old_hdl);
	}

	return FALSE;
}
#endif

#ifdef WITH_HYPERSCAN
enum rspamd_re_cache_compile_state {
	RSPAMD_RE_CACHE_COMPILE_STATE_INIT,
	RSPAMD_RE_CACHE_COMPILE_STATE_CHECK_EXISTS,
	RSPAMD_RE_CACHE_COMPILE_STATE_COMPILING,
	RSPAMD_RE_CACHE_COMPILE_STATE_SAVING
};

/* Heap element for priority compilation queue */
struct rspamd_re_compile_queue_elt {
	unsigned int pri; /* Priority: lower = compile first */
	unsigned int idx; /* Heap index (managed by heap) */
	struct rspamd_re_class *re_class;
};

RSPAMD_HEAP_DECLARE(re_compile_queue, struct rspamd_re_compile_queue_elt);

struct rspamd_re_cache_hs_compile_cbdata {
	re_compile_queue_t compile_queue; /* Priority queue of re_classes to compile */
	struct rspamd_re_cache *cache;
	const char *cache_dir;
	double max_time;
	gboolean silent;
	unsigned int total;
	struct rspamd_worker *worker;
	struct ev_loop *event_loop;
	ev_timer *timer;

	void (*cb)(unsigned int ncompiled, GError *err, void *cbd);

	void *cbd;

	/* Async state */
	struct rspamd_re_class *current_class;
	enum rspamd_re_cache_compile_state state;
	ref_entry_t ref;
};

struct rspamd_re_cache_async_ctx {
	struct rspamd_re_cache_hs_compile_cbdata *cbdata;
	struct ev_loop *loop;
	ev_timer *w;
	int n;
	gboolean callback_processed;
};

static void
rspamd_re_cache_compile_err(EV_P_ ev_timer *w, GError *err,
							struct rspamd_re_cache_hs_compile_cbdata *cbdata, bool is_fatal);

static void
rspamd_re_cache_hs_compile_cbdata_dtor(void *p)
{
	struct rspamd_re_cache_hs_compile_cbdata *cbdata = p;

	if (cbdata->timer && ev_is_active(cbdata->timer)) {
		ev_timer_stop(cbdata->event_loop, cbdata->timer);
	}
	rspamd_heap_destroy(re_compile_queue, &cbdata->compile_queue);
	g_free(cbdata->timer);
	g_free(cbdata);
}

static void
rspamd_re_cache_exists_cb(gboolean success, const unsigned char *data, gsize len, const char *err, void *ud)
{
	struct rspamd_re_cache_async_ctx *ctx = ud;
	struct rspamd_re_cache_hs_compile_cbdata *cbdata;
	const gboolean lua_backend = rspamd_hs_cache_has_lua_backend();
	char path[PATH_MAX];

	if (ctx->callback_processed) {
		return;
	}
	ctx->callback_processed = TRUE;
	cbdata = ctx->cbdata;

	if (cbdata->worker && cbdata->worker->state != rspamd_worker_state_running) {
		g_free(ctx);
		REF_RELEASE(cbdata);
		return;
	}

	if (success && len > 0) {
		/* Exists */
		struct rspamd_re_class *re_class = cbdata->current_class;
		struct rspamd_re_cache *cache = cbdata->cache;
		int n = g_hash_table_size(re_class->re);

		if (!lua_backend) {
			rspamd_snprintf(path, sizeof(path), "%s%c%s.hs", cbdata->cache_dir,
							G_DIR_SEPARATOR, re_class->hash);
		}

		if (re_class->type_len > 0) {
			if (!cbdata->silent) {
				msg_info_re_cache(
					"skip already valid class %s(%*s) to cache %6s (%s), %d regexps%s%s%s",
					rspamd_re_cache_type_to_string(re_class->type),
					(int) re_class->type_len - 1,
					re_class->type_data,
					re_class->hash,
					lua_backend ? "Lua backend" : path,
					n,
					cache->scope ? " for scope '" : "",
					cache->scope ? cache->scope : "",
					cache->scope ? "'" : "");
			}
		}
		else {
			if (!cbdata->silent) {
				msg_info_re_cache(
					"skip already valid class %s to cache %6s (%s), %d regexps%s%s%s",
					rspamd_re_cache_type_to_string(re_class->type),
					re_class->hash,
					lua_backend ? "Lua backend" : path,
					n,
					cache->scope ? " for scope '" : "",
					cache->scope ? cache->scope : "",
					cache->scope ? "'" : "");
			}
		}

		/* Skip compilation */
		cbdata->state = RSPAMD_RE_CACHE_COMPILE_STATE_INIT;
		cbdata->current_class = NULL;
	}
	else {
		/* Not exists, proceed */
		if (err) {
			msg_warn("cache check failed: %s", err);
		}
		cbdata->state = RSPAMD_RE_CACHE_COMPILE_STATE_COMPILING;
	}

	ev_timer_again(cbdata->event_loop, cbdata->timer);
	g_free(ctx);
	REF_RELEASE(cbdata);
}

static void
rspamd_re_cache_save_cb(gboolean success, const unsigned char *data, gsize len, const char *err, void *ud)
{
	struct rspamd_re_cache_async_ctx *ctx = ud;
	struct rspamd_re_cache_hs_compile_cbdata *cbdata;

	if (ctx->callback_processed) {
		return;
	}
	ctx->callback_processed = TRUE;
	cbdata = ctx->cbdata;

	if (cbdata->worker && cbdata->worker->state != rspamd_worker_state_running) {
		g_free(ctx);
		REF_RELEASE(cbdata);
		return;
	}

	if (!success) {
		GError *gerr = g_error_new(rspamd_re_cache_quark(), EINVAL,
								   "backend save failed: %s", err ? err : "unknown error");
		rspamd_re_cache_compile_err(cbdata->event_loop, cbdata->timer, gerr, cbdata, false);
	}
	else {
		struct rspamd_re_class *re_class = cbdata->current_class;
		struct rspamd_re_cache *cache = cbdata->cache;
		int n = ctx->n;

		if (re_class->type_len > 0) {
			msg_info_re_cache(
				"compiled class %s(%*s) to cache %6s (Lua backend), %d/%d regexps%s%s%s",
				rspamd_re_cache_type_to_string(re_class->type),
				(int) re_class->type_len - 1,
				re_class->type_data,
				re_class->hash,
				n,
				(int) g_hash_table_size(re_class->re),
				cache->scope ? " for scope '" : "",
				cache->scope ? cache->scope : "",
				cache->scope ? "'" : "");
		}
		else {
			msg_info_re_cache(
				"compiled class %s to cache %6s (Lua backend), %d/%d regexps%s%s%s",
				rspamd_re_cache_type_to_string(re_class->type),
				re_class->hash,
				n,
				(int) g_hash_table_size(re_class->re),
				cache->scope ? " for scope '" : "",
				cache->scope ? cache->scope : "",
				cache->scope ? "'" : "");
		}
		cbdata->total += n;
	}

	cbdata->state = RSPAMD_RE_CACHE_COMPILE_STATE_INIT;
	cbdata->current_class = NULL;

	ev_timer_again(cbdata->event_loop, cbdata->timer);
	g_free(ctx);
	REF_RELEASE(cbdata);
}

static void
rspamd_re_cache_compile_err(EV_P_ ev_timer *w, GError *err,
							struct rspamd_re_cache_hs_compile_cbdata *cbdata, bool is_fatal)
{
	if (is_fatal) {
		cbdata->cb(cbdata->total, err, cbdata->cbd);
		REF_RELEASE(cbdata);
	}
	else {
		msg_err("hyperscan compilation error: %s", err->message);
		cbdata->state = RSPAMD_RE_CACHE_COMPILE_STATE_INIT;
		cbdata->current_class = NULL;
		ev_timer_again(EV_A_ w);
	}
	g_error_free(err);
}

static void
rspamd_re_cache_compile_timer_cb(EV_P_ ev_timer *w, int revents)
{
	struct rspamd_re_cache_hs_compile_cbdata *cbdata =
		(struct rspamd_re_cache_hs_compile_cbdata *) w->data;
	GHashTableIter cit;
	gpointer k, v;
	struct rspamd_re_class *re_class;
	char path[PATH_MAX];
	hs_database_t *test_db;
	int fd, i, n, *hs_ids = NULL, pcre_flags, re_flags;
	rspamd_cryptobox_fast_hash_state_t crc_st;
	uint64_t crc;
	rspamd_regexp_t *re;
	hs_compile_error_t *hs_errors = NULL;
	unsigned int *hs_flags = NULL;
	const hs_expr_ext_t **hs_exts = NULL;
	char **hs_pats = NULL;
	char *hs_serialized = NULL;
	gsize serialized_len;
	struct iovec iov[7];
	struct rspamd_re_cache *cache;
	GError *err;

	cache = cbdata->cache;

	/* Stop if worker is terminating */
	if (cbdata->worker && cbdata->worker->state != rspamd_worker_state_running) {
		cbdata->cb(cbdata->total, NULL, cbdata->cbd);
		REF_RELEASE(cbdata);
		return;
	}

	if (cbdata->current_class) {
		re_class = cbdata->current_class;
	}
	else {
		/* Pop next item from priority queue */
		struct rspamd_re_compile_queue_elt *elt =
			rspamd_heap_pop(re_compile_queue, &cbdata->compile_queue);
		if (elt == NULL) {
			/* All done */
			cbdata->cb(cbdata->total, NULL, cbdata->cbd);
			REF_RELEASE(cbdata);
			return;
		}

		re_class = elt->re_class;
		cbdata->current_class = re_class;
		cbdata->state = RSPAMD_RE_CACHE_COMPILE_STATE_CHECK_EXISTS;
	}

	if (cbdata->state == RSPAMD_RE_CACHE_COMPILE_STATE_CHECK_EXISTS) {
		/* Check via Lua backend (handles file, redis, http) */
		struct rspamd_re_cache_async_ctx *ctx = g_malloc0(sizeof(*ctx));
		ctx->cbdata = cbdata;
		ctx->loop = loop;
		ctx->w = w;
		char entity_name[256];
		if (re_class->type_len > 0) {
			rspamd_snprintf(entity_name, sizeof(entity_name), "re_class:%s(%*s)",
							rspamd_re_cache_type_to_string(re_class->type),
							(int) re_class->type_len - 1, re_class->type_data);
		}
		else {
			rspamd_snprintf(entity_name, sizeof(entity_name), "re_class:%s",
							rspamd_re_cache_type_to_string(re_class->type));
		}
		/*
		 * Stop timer while async operation is pending to prevent
		 * multiple concurrent exists_async calls for the same class.
		 * The callback will restart the timer with ev_timer_again.
		 */
		ev_timer_stop(EV_A_ w);
		REF_RETAIN(cbdata);
		rspamd_hs_cache_lua_exists_async(re_class->hash, entity_name, rspamd_re_cache_exists_cb, ctx);
		return;
	}

	fd = -1; /* Not using direct file I/O, Lua backend handles storage */

	g_hash_table_iter_init(&cit, re_class->re);
	n = g_hash_table_size(re_class->re);
	hs_flags = g_new0(unsigned int, n);
	hs_ids = g_new0(unsigned int, n);
	hs_pats = g_new0(char *, n);
	hs_exts = g_new0(const hs_expr_ext_t *, n);
	i = 0;

	while (g_hash_table_iter_next(&cit, &k, &v)) {
		re = v;

		pcre_flags = rspamd_regexp_get_pcre_flags(re);
		re_flags = rspamd_regexp_get_flags(re);

		if (re_flags & RSPAMD_REGEXP_FLAG_PCRE_ONLY) {
			/* Do not try to compile bad regexp */
			msg_info_re_cache(
				"do not try compile %s to hyperscan as it is PCRE only",
				rspamd_regexp_get_pattern(re));
			continue;
		}

		hs_flags[i] = 0;
		hs_exts[i] = NULL;
#ifndef WITH_PCRE2
		if (pcre_flags & PCRE_FLAG(UTF8)) {
			hs_flags[i] |= HS_FLAG_UTF8;
		}
#else
		if (pcre_flags & PCRE_FLAG(UTF)) {
			hs_flags[i] |= HS_FLAG_UTF8;
		}
#endif
		if (pcre_flags & PCRE_FLAG(CASELESS)) {
			hs_flags[i] |= HS_FLAG_CASELESS;
		}
		if (pcre_flags & PCRE_FLAG(MULTILINE)) {
			hs_flags[i] |= HS_FLAG_MULTILINE;
		}
		if (pcre_flags & PCRE_FLAG(DOTALL)) {
			hs_flags[i] |= HS_FLAG_DOTALL;
		}


		if (re_flags & RSPAMD_REGEXP_FLAG_LEFTMOST) {
			hs_flags[i] |= HS_FLAG_SOM_LEFTMOST;
		}
		else if (rspamd_regexp_get_maxhits(re) == 1) {
			hs_flags[i] |= HS_FLAG_SINGLEMATCH;
		}

		char *pat = rspamd_re_cache_hs_pattern_from_pcre(re);

		if (hs_compile(pat,
					   hs_flags[i],
					   HS_MODE_BLOCK,
					   &cache->plt,
					   &test_db,
					   &hs_errors) != HS_SUCCESS) {
			msg_info_re_cache("cannot compile '%s' to hyperscan: '%s', try prefilter match",
							  pat,
							  hs_errors != NULL ? hs_errors->message : "unknown error");
			hs_free_compile_error(hs_errors);

			/* The approximation operation might take a significant
			 * amount of time, so we need to check if it's finite
			 */
			if (rspamd_re_cache_is_finite(cache, re, hs_flags[i], cbdata->max_time)) {
				hs_flags[i] |= HS_FLAG_PREFILTER;
				hs_ids[i] = rspamd_regexp_get_cache_id(re);
				hs_pats[i] = pat;
				i++;
			}
			else {
				g_free(pat); /* Avoid leak */
			}
		}
		else {
			hs_ids[i] = rspamd_regexp_get_cache_id(re);
			hs_pats[i] = pat;
			i++;
			hs_free_database(test_db);
		}
	}
	/* Adjust real re number */
	n = i;

#define CLEANUP_ALLOCATED(is_err)                            \
	do {                                                     \
		g_free(hs_flags);                                    \
		g_free(hs_ids);                                      \
		for (unsigned int j = 0; j < i; j++) {               \
			g_free(hs_pats[j]);                              \
		}                                                    \
		g_free(hs_pats);                                     \
		g_free(hs_exts);                                     \
		if (is_err) {                                        \
			close(fd);                                       \
			unlink(path);                                    \
			if (hs_errors) hs_free_compile_error(hs_errors); \
		}                                                    \
	} while (0)

	if (n > 0) {
		hs_errors = NULL;

		if (cbdata->worker &&
			cbdata->worker->state != rspamd_worker_state_running) {
			CLEANUP_ALLOCATED(false);
			ev_timer_stop(EV_A_ w);
			cbdata->cb(cbdata->total, NULL, cbdata->cbd);
			g_free(w);
			g_free(cbdata);
			return;
		}

		if (cbdata->worker) {
			rspamd_worker_set_busy(cbdata->worker, EV_A, "compile hyperscan");
		}

		hs_error_t compile_result = hs_compile_ext_multi((const char **) hs_pats,
														 hs_flags,
														 hs_ids,
														 hs_exts,
														 n,
														 HS_MODE_BLOCK,
														 &cache->plt,
														 &test_db,
														 &hs_errors);

		if (cbdata->worker) {
			rspamd_worker_set_busy(cbdata->worker, EV_A, NULL);
		}

		if (cbdata->worker &&
			cbdata->worker->state != rspamd_worker_state_running) {
			if (test_db) {
				hs_free_database(test_db);
			}
			CLEANUP_ALLOCATED(false);
			ev_timer_stop(EV_A_ w);
			cbdata->cb(cbdata->total, NULL, cbdata->cbd);
			g_free(w);
			g_free(cbdata);
			return;
		}

		if (compile_result != HS_SUCCESS) {
			err = g_error_new(rspamd_re_cache_quark(), EINVAL,
							  "cannot create tree of regexp when processing '%s': %s",
							  hs_pats[hs_errors->expression], hs_errors->message);
			CLEANUP_ALLOCATED(true);
			rspamd_re_cache_compile_err(EV_A_ w, err, cbdata, false);

			return;
		}

		if (hs_serialize_database(test_db, &hs_serialized,
								  &serialized_len) != HS_SUCCESS) {
			err = g_error_new(rspamd_re_cache_quark(),
							  errno,
							  "cannot serialize tree of regexp for %s",
							  re_class->hash);

			CLEANUP_ALLOCATED(true);
			hs_free_database(test_db);
			rspamd_re_cache_compile_err(EV_A_ w, err, cbdata, false);
			return;
		}

		hs_free_database(test_db);

		/*
		 * Magic - 8 bytes
		 * Platform - sizeof (platform)
		 * n - number of regexps
		 * n * <regexp ids>
		 * n * <regexp flags>
		 * crc - 8 bytes checksum
		 * <hyperscan blob>
		 */
		rspamd_cryptobox_fast_hash_init(&crc_st, 0xdeadbabe);
		/* IDs -> Flags -> Hs blob */
		rspamd_cryptobox_fast_hash_update(&crc_st,
										  hs_ids, sizeof(*hs_ids) * n);
		rspamd_cryptobox_fast_hash_update(&crc_st,
										  hs_flags, sizeof(*hs_flags) * n);
		rspamd_cryptobox_fast_hash_update(&crc_st,
										  hs_serialized, serialized_len);
		crc = rspamd_cryptobox_fast_hash_final(&crc_st);


		iov[0].iov_base = (void *) rspamd_hs_magic;
		iov[0].iov_len = RSPAMD_HS_MAGIC_LEN;
		iov[1].iov_base = &cache->plt;
		iov[1].iov_len = sizeof(cache->plt);
		iov[2].iov_base = &n;
		iov[2].iov_len = sizeof(n);
		iov[3].iov_base = hs_ids;
		iov[3].iov_len = sizeof(*hs_ids) * n;
		iov[4].iov_base = hs_flags;
		iov[4].iov_len = sizeof(*hs_flags) * n;
		iov[5].iov_base = &crc;
		iov[5].iov_len = sizeof(crc);
		iov[6].iov_base = hs_serialized;
		iov[6].iov_len = serialized_len;

		/* Save via Lua backend (handles file, redis, http with compression) */
		gsize total_len = 0;
		for (unsigned int j = 0; j < G_N_ELEMENTS(iov); j++) {
			total_len += iov[j].iov_len;
		}

		unsigned char *combined = g_malloc(total_len);
		gsize offset = 0;
		for (unsigned int j = 0; j < G_N_ELEMENTS(iov); j++) {
			memcpy(combined + offset, iov[j].iov_base, iov[j].iov_len);
			offset += iov[j].iov_len;
		}

		struct rspamd_re_cache_async_ctx *ctx = g_malloc0(sizeof(*ctx));
		ctx->cbdata = cbdata;
		ctx->loop = loop;
		ctx->w = w;
		ctx->n = n;

		char entity_name[256];
		if (re_class->type_len > 0) {
			rspamd_snprintf(entity_name, sizeof(entity_name), "re_class:%s(%*s)",
							rspamd_re_cache_type_to_string(re_class->type),
							(int) re_class->type_len - 1, re_class->type_data);
		}
		else {
			rspamd_snprintf(entity_name, sizeof(entity_name), "re_class:%s",
							rspamd_re_cache_type_to_string(re_class->type));
		}
		/*
		 * Stop timer while async save is pending to prevent
		 * re-entry into the compilation state machine.
		 * The callback will restart the timer with ev_timer_again.
		 */
		ev_timer_stop(EV_A_ w);
		REF_RETAIN(cbdata);
		rspamd_hs_cache_lua_save_async(re_class->hash, entity_name, combined, total_len, rspamd_re_cache_save_cb, ctx);

		g_free(combined);
		CLEANUP_ALLOCATED(false);
		g_free(hs_serialized);
		return;
	}
	else {
		err = g_error_new(rspamd_re_cache_quark(),
						  errno,
						  "no suitable regular expressions %s (%d original): "
						  "remove temporary file %s",
						  rspamd_re_cache_type_to_string(re_class->type),
						  (int) g_hash_table_size(re_class->re),
						  path);

		CLEANUP_ALLOCATED(true);
		rspamd_re_cache_compile_err(EV_A_ w, err, cbdata, false);

		cbdata->state = RSPAMD_RE_CACHE_COMPILE_STATE_INIT;
		cbdata->current_class = NULL;
		return;
	}

	/* Continue process */
	ev_timer_again(EV_A_ w);
}

#endif

int rspamd_re_cache_compile_hyperscan(struct rspamd_re_cache *cache,
									  const char *cache_dir,
									  double max_time,
									  gboolean silent,
									  struct ev_loop *event_loop,
									  struct rspamd_worker *worker,
									  void (*cb)(unsigned int ncompiled, GError *err, void *cbd),
									  void *cbd)
{
	g_assert(cache != NULL);
	g_assert(cache_dir != NULL);

#ifndef WITH_HYPERSCAN
	return -1;
#else
	ev_timer *timer;
	static const ev_tstamp timer_interval = 0.1;
	struct rspamd_re_cache_hs_compile_cbdata *cbdata;
	GHashTableIter it;
	gpointer k, v;

	cbdata = g_malloc0(sizeof(*cbdata));
	rspamd_heap_init(re_compile_queue, &cbdata->compile_queue);

	/*
	 * Build priority queue for compilation order.
	 * Priority (lower = compile first):
	 * - Short lists (<100 regexps): 0 + count
	 * - URL type (TLD matching): 1000 + count
	 * - Other types: 10000 + count
	 */
	g_hash_table_iter_init(&it, cache->re_classes);
	while (g_hash_table_iter_next(&it, &k, &v)) {
		struct rspamd_re_class *re_class = v;
		struct rspamd_re_compile_queue_elt elt;
		unsigned int count = g_hash_table_size(re_class->re);
		unsigned int base_pri;

		/* Calculate priority tier */
		if (count < 100) {
			/* Short lists get highest priority */
			base_pri = 0;
		}
		else if (re_class->type == RSPAMD_RE_URL) {
			/* URL type (TLD) gets medium priority */
			base_pri = 1000;
		}
		else {
			/* All other types */
			base_pri = 10000;
		}

		elt.pri = base_pri + count;
		elt.re_class = re_class;
		rspamd_heap_push_safe(re_compile_queue, &cbdata->compile_queue, &elt, heap_error);
	}

	cbdata->cache = cache;
	cbdata->cache_dir = cache_dir;
	cbdata->cb = cb;
	cbdata->cbd = cbd;
	cbdata->max_time = max_time;
	cbdata->silent = silent;
	cbdata->total = 0;
	cbdata->worker = worker;
	cbdata->event_loop = event_loop;
	timer = g_malloc0(sizeof(*timer));
	timer->data = (void *) cbdata;
	cbdata->timer = timer;
	REF_INIT_RETAIN(cbdata, rspamd_re_cache_hs_compile_cbdata_dtor);

	ev_timer_init(timer, rspamd_re_cache_compile_timer_cb,
				  timer_interval, timer_interval);
	ev_timer_start(event_loop, timer);

	return 0;

heap_error:
	rspamd_heap_destroy(re_compile_queue, &cbdata->compile_queue);
	g_free(cbdata);
	return -1;
#endif
}

#ifdef WITH_HYPERSCAN
struct rspamd_re_cache_scoped_compile_data {
	unsigned int total_scopes;
	unsigned int completed_scopes;
	unsigned int total_compiled;
	GError *first_error;
	struct rspamd_worker *worker;

	void (*final_cb)(unsigned int ncompiled, GError *err, void *cbd);

	void *final_cbd;
};

static void
rspamd_re_cache_compile_scoped_coordination_cb(unsigned int ncompiled, GError *err, void *cbd)
{
	struct rspamd_re_cache_scoped_compile_data *coord_data =
		(struct rspamd_re_cache_scoped_compile_data *) cbd;

	coord_data->completed_scopes++;
	coord_data->total_compiled += ncompiled;

	/* Store the first error we encounter */
	if (err && !coord_data->first_error) {
		coord_data->first_error = g_error_copy(err);
	}

	/* Check if all scopes have completed */
	if (coord_data->completed_scopes >= coord_data->total_scopes) {
		/* All scopes completed, call the final callback */
		if (coord_data->final_cb) {
			coord_data->final_cb(coord_data->total_compiled, coord_data->first_error, coord_data->final_cbd);
		}

		/* Cleanup */
		if (coord_data->first_error) {
			g_error_free(coord_data->first_error);
		}
		g_free(coord_data);
	}
}
#endif

int rspamd_re_cache_compile_hyperscan_scoped(struct rspamd_re_cache *cache_head,
											 const char *cache_dir,
											 double max_time,
											 gboolean silent,
											 struct ev_loop *event_loop,
											 struct rspamd_worker *worker,
											 void (*cb)(unsigned int ncompiled, GError *err, void *cbd),
											 void *cbd)
{
#ifndef WITH_HYPERSCAN
	return -1;
#else
	struct rspamd_re_cache *cur;
	struct rspamd_re_cache_scoped_compile_data *coord_data;
	unsigned int scope_count = 0;
	int result;

	if (!cache_head) {
		return -1;
	}

	/* Count the number of scopes to compile */
	DL_COUNT(cache_head, cur, scope_count);

	if (scope_count == 0) {
		/* No scopes to compile, call callback immediately */
		if (cb) {
			cb(0, NULL, cbd);
		}
		return 0;
	}

	/* Create coordination data to track completion of all scopes */
	coord_data = g_malloc0(sizeof(*coord_data));
	coord_data->total_scopes = scope_count;
	coord_data->completed_scopes = 0;
	coord_data->total_compiled = 0;
	coord_data->first_error = NULL;
	coord_data->worker = worker;
	coord_data->final_cb = cb;
	coord_data->final_cbd = cbd;

	/*
	 * Start async compilation for each scope. Each scope will use timers
	 * and call our coordination callback when completed.
	 */
	DL_FOREACH(cache_head, cur)
	{
		result = rspamd_re_cache_compile_hyperscan(cur, cache_dir, max_time, silent,
												   event_loop, worker, rspamd_re_cache_compile_scoped_coordination_cb, coord_data);
		if (result < 0) {
			/* If we failed to start compilation for this scope, treat it as completed with error */
			GError *start_error = g_error_new(rspamd_re_cache_quark(), result,
											  "Failed to start hyperscan compilation for scope '%s'",
											  cur->scope ? cur->scope : "unknown");
			rspamd_re_cache_compile_scoped_coordination_cb(0, start_error, coord_data);
			g_error_free(start_error);
		}
	}

	return 0; /* Always return 0 for async operation */
#endif
}

gboolean
rspamd_re_cache_is_valid_hyperscan_file(struct rspamd_re_cache *cache,
										const char *path, gboolean silent, gboolean try_load, GError **err)
{
	g_assert(cache != NULL);
	g_assert(path != NULL);

#ifndef WITH_HYPERSCAN
	return FALSE;
#else
	int fd, n, ret;
	unsigned char magicbuf[RSPAMD_HS_MAGIC_LEN];
	const unsigned char *mb;
	GHashTableIter it;
	gpointer k, v;
	struct rspamd_re_class *re_class;
	struct rspamd_re_cache *cur;
	gsize len;
	const char *hash_pos;
	hs_platform_info_t test_plt;
	hs_database_t *test_db = NULL;
	unsigned char *map, *p, *end;
	rspamd_cryptobox_fast_hash_state_t crc_st;
	uint64_t crc, valid_crc;

	len = strlen(path);

	if (len < (rspamd_cryptobox_HASHBYTES + 3)) {
		if (!silent) {
			msg_err_re_cache("cannot open hyperscan cache file %s: too short filename",
							 path);
		}
		g_set_error(err, rspamd_re_cache_quark(), 0,
					"too short filename");

		return FALSE;
	}

	if (memcmp(path + len - 3, ".hs", 3) != 0) {
		if (!silent) {
			msg_err_re_cache("cannot open hyperscan cache file %s: not ending with .hs",
							 path);
		}
		g_set_error(err, rspamd_re_cache_quark(), 0,
					"not ending with .hs");
		return FALSE;
	}

	hash_pos = path + len - 3 - (sizeof(re_class->hash) - 1);

	/* Iterate through all scopes in the cache chain */
	DL_FOREACH(cache, cur)
	{
		g_hash_table_iter_init(&it, cur->re_classes);

		while (g_hash_table_iter_next(&it, &k, &v)) {
			re_class = v;

			if (memcmp(hash_pos, re_class->hash, sizeof(re_class->hash) - 1) == 0) {
				/* Open file and check magic */
				gssize r;

				fd = open(path, O_RDONLY);

				if (fd == -1) {
					if (errno != ENOENT || !silent) {
						msg_err_re_cache("cannot open hyperscan cache file %s: %s",
										 path, strerror(errno));
					}
					g_set_error(err, rspamd_re_cache_quark(), 0,
								"%s",
								strerror(errno));
					return FALSE;
				}

				if ((r = read(fd, magicbuf, sizeof(magicbuf))) != sizeof(magicbuf)) {
					if (r == -1) {
						msg_err_re_cache("cannot read magic from hyperscan "
										 "cache file %s: %s",
										 path, strerror(errno));
						g_set_error(err, rspamd_re_cache_quark(), 0,
									"cannot read magic: %s",
									strerror(errno));
					}
					else {
						msg_err_re_cache("truncated read magic from hyperscan "
										 "cache file %s: %z, %z wanted",
										 path, r, (gsize) sizeof(magicbuf));
						g_set_error(err, rspamd_re_cache_quark(), 0,
									"truncated read magic %zd, %zd wanted",
									r, (gsize) sizeof(magicbuf));
					}

					close(fd);
					return FALSE;
				}

				mb = rspamd_hs_magic;

				if (memcmp(magicbuf, mb, sizeof(magicbuf)) != 0) {
					msg_err_re_cache("cannot open hyperscan cache file %s: "
									 "bad magic ('%*xs', '%*xs' expected)",
									 path, (int) RSPAMD_HS_MAGIC_LEN, magicbuf,
									 (int) RSPAMD_HS_MAGIC_LEN, mb);

					close(fd);
					g_set_error(err, rspamd_re_cache_quark(), 0, "invalid magic");
					return FALSE;
				}

				if ((r = read(fd, &test_plt, sizeof(test_plt))) != sizeof(test_plt)) {
					if (r == -1) {
						msg_err_re_cache("cannot read platform data from hyperscan "
										 "cache file %s: %s",
										 path, strerror(errno));
					}
					else {
						msg_err_re_cache("truncated read platform data from hyperscan "
										 "cache file %s: %z, %z wanted",
										 path, r, (gsize) sizeof(magicbuf));
					}

					g_set_error(err, rspamd_re_cache_quark(), 0,
								"cannot read platform data: %s", strerror(errno));

					close(fd);
					return FALSE;
				}

				if (test_plt.cpu_features != cur->plt.cpu_features) {
					msg_err_re_cache("cannot open hyperscan cache file %s: "
									 "compiled for a different platform",
									 path);
					g_set_error(err, rspamd_re_cache_quark(), 0,
								"compiled for a different platform");

					close(fd);
					return FALSE;
				}

				close(fd);

				if (try_load) {
					map = rspamd_file_xmap(path, PROT_READ, &len, TRUE);

					if (map == NULL) {
						msg_err_re_cache("cannot mmap hyperscan cache file %s: "
										 "%s",
										 path, strerror(errno));
						g_set_error(err, rspamd_re_cache_quark(), 0,
									"mmap error: %s", strerror(errno));
						return FALSE;
					}

					p = map + RSPAMD_HS_MAGIC_LEN + sizeof(test_plt);
					end = map + len;
					memcpy(&n, p, sizeof(n));
					p += sizeof(int);

					if (n <= 0 || 2 * n * sizeof(int) +         /* IDs + flags */
										  sizeof(uint64_t) +    /* crc */
										  RSPAMD_HS_MAGIC_LEN + /* header */
										  sizeof(cur->plt) >
									  len) {
						/* Some wrong amount of regexps */
						msg_err_re_cache("bad number of expressions in %s: %d",
										 path, n);
						g_set_error(err, rspamd_re_cache_quark(), 0,
									"bad number of expressions: %d", n);
						munmap(map, len);
						return FALSE;
					}

					/*
					 * Magic - 8 bytes
					 * Platform - sizeof (platform)
					 * n - number of regexps
					 * n * <regexp ids>
					 * n * <regexp flags>
					 * crc - 8 bytes checksum
					 * <hyperscan blob>
					 */

					memcpy(&crc, p + n * 2 * sizeof(int), sizeof(crc));
					rspamd_cryptobox_fast_hash_init(&crc_st, 0xdeadbabe);
					/* IDs */
					rspamd_cryptobox_fast_hash_update(&crc_st, p, n * sizeof(int));
					/* Flags */
					rspamd_cryptobox_fast_hash_update(&crc_st, p + n * sizeof(int),
													  n * sizeof(int));
					/* HS database */
					p += n * sizeof(int) * 2 + sizeof(uint64_t);
					rspamd_cryptobox_fast_hash_update(&crc_st, p, end - p);
					valid_crc = rspamd_cryptobox_fast_hash_final(&crc_st);

					if (crc != valid_crc) {
						msg_warn_re_cache("outdated or invalid hs database in %s: "
										  "crc read %xL, crc expected %xL",
										  path, crc, valid_crc);
						g_set_error(err, rspamd_re_cache_quark(), 0,
									"outdated or invalid hs database, crc check failure");
						munmap(map, len);

						return FALSE;
					}

					if ((ret = hs_deserialize_database(p, end - p, &test_db)) != HS_SUCCESS) {
						msg_err_re_cache("bad hs database in %s: %d", path, ret);
						g_set_error(err, rspamd_re_cache_quark(), 0,
									"deserialize error: %d", ret);
						munmap(map, len);

						return FALSE;
					}

					hs_free_database(test_db);
					munmap(map, len);
				}
				/* XXX: add crc check */

				return TRUE;
			}
		}
	}

	if (!silent) {
		msg_warn_re_cache("unknown hyperscan cache file %s", path);
	}

	g_set_error(err, rspamd_re_cache_quark(), 0,
				"unknown hyperscan file");

	return FALSE;
#endif
}

/* Forward declaration - defined after rspamd_re_cache_load_hyperscan_scoped */
static gboolean
rspamd_re_cache_apply_hyperscan_blob(struct rspamd_re_cache *cache,
									 struct rspamd_re_class *re_class,
									 const unsigned char *data,
									 gsize len,
									 bool try_load);

enum rspamd_hyperscan_status
rspamd_re_cache_load_hyperscan(struct rspamd_re_cache *cache,
							   const char *cache_dir, bool try_load)
{
	g_assert(cache != NULL);
	g_assert(cache_dir != NULL);

#ifndef WITH_HYPERSCAN
	return RSPAMD_HYPERSCAN_UNSUPPORTED;
#else
	GHashTableIter it;
	gpointer k, v;
	struct rspamd_re_class *re_class;
	gboolean has_valid = FALSE, all_valid = TRUE;
	unsigned int total_classes, total_loaded = 0, total_regexps = 0;
	GString *missing_classes = NULL;

	if (cache->disable_hyperscan) {
		return RSPAMD_HYPERSCAN_UNSUPPORTED;
	}

	total_classes = g_hash_table_size(cache->re_classes);
	g_hash_table_iter_init(&it, cache->re_classes);

	/* Lua backend is required for sync loading */
	if (!rspamd_hs_cache_has_lua_backend()) {
		/*
		 * During config init (try_load=true), no event loop is available,
		 * so Lua backend can't be initialized. This is expected - use debug level.
		 * Workers will initialize the backend and load databases properly.
		 */
		if (try_load) {
			msg_debug_re_cache("no Lua backend available for synchronous hyperscan loading%s%s%s",
							   cache->scope ? " for scope '" : "",
							   cache->scope ? cache->scope : "",
							   cache->scope ? "'" : "");
		}
		else {
			msg_warn_re_cache("no Lua backend available for synchronous hyperscan loading%s%s%s",
							  cache->scope ? " for scope '" : "",
							  cache->scope ? cache->scope : "",
							  cache->scope ? "'" : "");
		}
		cache->hyperscan_loaded = RSPAMD_HYPERSCAN_LOAD_ERROR;
		return cache->hyperscan_loaded;
	}

	while (g_hash_table_iter_next(&it, &k, &v)) {
		re_class = v;
		unsigned char *data = NULL;
		gsize data_len = 0;
		char *error = NULL;
		const char *class_type_name = rspamd_re_cache_type_to_string(re_class->type);

		/* Load via Lua backend (handles files, compression, etc.) */
		if (rspamd_hs_cache_lua_load_sync(re_class->hash, "re_class", &data, &data_len, &error)) {
			msg_debug_re_cache("loaded hyperscan via Lua backend for '%s' (%uz bytes)",
							   re_class->hash, data_len);
		}
		else {
			/* Lua backend failed - async-only backend or file not found */
			if (error) {
				msg_debug_re_cache("Lua backend load failed for '%s': %s",
								   re_class->hash, error);

				/* Track missing class with reason */
				if (!missing_classes) {
					missing_classes = g_string_new(NULL);
				}
				if (missing_classes->len > 0) {
					g_string_append(missing_classes, ", ");
				}
				if (re_class->type_data && re_class->type_len > 0) {
					g_string_append_printf(missing_classes, "%s(%.*s): %s",
										   class_type_name,
										   (int) re_class->type_len - 1,
										   (const char *) re_class->type_data,
										   error);
				}
				else {
					g_string_append_printf(missing_classes, "%s: %s",
										   class_type_name, error);
				}
				g_free(error);
			}
			else {
				/* No error message - file not found */
				if (!missing_classes) {
					missing_classes = g_string_new(NULL);
				}
				if (missing_classes->len > 0) {
					g_string_append(missing_classes, ", ");
				}
				if (re_class->type_data && re_class->type_len > 0) {
					g_string_append_printf(missing_classes, "%s(%.*s): not cached",
										   class_type_name,
										   (int) re_class->type_len - 1,
										   (const char *) re_class->type_data);
				}
				else {
					g_string_append_printf(missing_classes, "%s: not cached",
										   class_type_name);
				}
			}
			all_valid = FALSE;
			continue;
		}

		if (!data || data_len == 0) {
			if (!missing_classes) {
				missing_classes = g_string_new(NULL);
			}
			if (missing_classes->len > 0) {
				g_string_append(missing_classes, ", ");
			}
			if (re_class->type_data && re_class->type_len > 0) {
				g_string_append_printf(missing_classes, "%s(%.*s): empty data",
									   class_type_name,
									   (int) re_class->type_len - 1,
									   (const char *) re_class->type_data);
			}
			else {
				g_string_append_printf(missing_classes, "%s: empty data",
									   class_type_name);
			}
			all_valid = FALSE;
			continue;
		}

		/* Process the loaded data using the blob apply function */
		if (rspamd_re_cache_apply_hyperscan_blob(cache, re_class, data, data_len, try_load)) {
			has_valid = TRUE;
			total_loaded++;
			total_regexps += re_class->nhs;
			msg_debug_re_cache("successfully applied hyperscan blob for '%s'", re_class->hash);
		}
		else {
			if (!missing_classes) {
				missing_classes = g_string_new(NULL);
			}
			if (missing_classes->len > 0) {
				g_string_append(missing_classes, ", ");
			}
			if (re_class->type_data && re_class->type_len > 0) {
				g_string_append_printf(missing_classes, "%s(%.*s): load failed",
									   class_type_name,
									   (int) re_class->type_len - 1,
									   (const char *) re_class->type_data);
			}
			else {
				g_string_append_printf(missing_classes, "%s: load failed",
									   class_type_name);
			}
			all_valid = FALSE;
			msg_debug_re_cache("failed to apply hyperscan blob for '%s'", re_class->hash);
		}

		g_free(data);
	}

	if (has_valid) {
		if (all_valid) {
			msg_info_re_cache("full hyperscan database of %ud regexps (%ud/%ud classes) has been loaded%s%s%s",
							  total_regexps,
							  total_loaded, total_classes,
							  cache->scope ? " for scope '" : "",
							  cache->scope ? cache->scope : "",
							  cache->scope ? "'" : "");
			cache->hyperscan_loaded = RSPAMD_HYPERSCAN_LOADED_FULL;
		}
		else {
			msg_info_re_cache("partial hyperscan database of %ud regexps (%ud/%ud classes) has been loaded%s%s%s",
							  total_regexps,
							  total_loaded, total_classes,
							  cache->scope ? " for scope '" : "",
							  cache->scope ? cache->scope : "",
							  cache->scope ? "'" : "");
			/* Log missing classes */
			if (missing_classes && missing_classes->len > 0) {
				msg_info_re_cache("missing hyperscan classes: %s", missing_classes->str);
			}
			cache->hyperscan_loaded = RSPAMD_HYPERSCAN_LOADED_PARTIAL;
		}
	}
	else {
		/*
		 * During startup probe (try_load=true), "no valid expressions" is expected
		 * when hs_helper hasn't finished compiling yet. Use debug level to avoid
		 * log spam. Workers will receive async notifications when databases are ready.
		 */
		if (try_load) {
			msg_debug_re_cache("hyperscan database has NOT been loaded; no valid expressions (%ud classes)%s%s%s",
							   total_classes,
							   cache->scope ? " for scope '" : "",
							   cache->scope ? cache->scope : "",
							   cache->scope ? "'" : "");
			if (missing_classes && missing_classes->len > 0) {
				msg_debug_re_cache("all classes failed (startup probe): %s", missing_classes->str);
			}
		}
		else {
			msg_info_re_cache("hyperscan database has NOT been loaded; no valid expressions (%ud classes)%s%s%s",
							  total_classes,
							  cache->scope ? " for scope '" : "",
							  cache->scope ? cache->scope : "",
							  cache->scope ? "'" : "");
			if (missing_classes && missing_classes->len > 0) {
				msg_info_re_cache("all classes failed: %s", missing_classes->str);
			}
		}
		cache->hyperscan_loaded = RSPAMD_HYPERSCAN_LOAD_ERROR;
	}

	if (missing_classes) {
		g_string_free(missing_classes, TRUE);
	}

	return cache->hyperscan_loaded;
#endif
}

enum rspamd_hyperscan_status rspamd_re_cache_load_hyperscan_scoped(
	struct rspamd_re_cache *cache_head,
	const char *cache_dir, bool try_load)
{
#ifndef WITH_HYPERSCAN
	return RSPAMD_HYPERSCAN_UNSUPPORTED;
#else
	struct rspamd_re_cache *cur;
	enum rspamd_hyperscan_status result, overall_status = RSPAMD_HYPERSCAN_UNKNOWN;
	gboolean has_loaded = FALSE, all_loaded = TRUE;

	if (!cache_head) {
		return RSPAMD_HYPERSCAN_LOAD_ERROR;
	}

	DL_FOREACH(cache_head, cur)
	{
		result = rspamd_re_cache_load_hyperscan(cur, cache_dir, try_load);

		if (result == RSPAMD_HYPERSCAN_LOADED_FULL ||
			result == RSPAMD_HYPERSCAN_LOADED_PARTIAL) {
			has_loaded = TRUE;
			if (result == RSPAMD_HYPERSCAN_LOADED_PARTIAL) {
				all_loaded = FALSE;
			}
		}
		else {
			all_loaded = FALSE;
		}
	}

	if (has_loaded) {
		overall_status = all_loaded ? RSPAMD_HYPERSCAN_LOADED_FULL : RSPAMD_HYPERSCAN_LOADED_PARTIAL;
	}
	else {
		overall_status = RSPAMD_HYPERSCAN_LOAD_ERROR;
	}

	return overall_status;
#endif
}

#ifdef WITH_HYPERSCAN
struct rspamd_re_cache_hs_load_item {
	struct rspamd_re_cache_hs_load_scope *scope_ctx;
	struct rspamd_re_cache *cache;
	struct rspamd_re_class *re_class;
	char *cache_key;
};

struct rspamd_re_cache_hs_load_scope {
	struct rspamd_re_cache *cache;
	struct ev_loop *event_loop;
	bool try_load;
	unsigned int pending;
	unsigned int total;
	unsigned int loaded;
	unsigned int total_regexps;
	gboolean all_loaded;
};

static gboolean
rspamd_re_cache_apply_hyperscan_blob(struct rspamd_re_cache *cache,
									 struct rspamd_re_class *re_class,
									 const unsigned char *data,
									 gsize len,
									 bool try_load)
{
	GError *err = NULL;
	rspamd_hyperscan_t *hs_db;
	const char *p;
	unsigned int n;
	const unsigned int *ids;
	const unsigned int *flags;
	int ret;

	hs_db = rspamd_hyperscan_load_from_header((const char *) data, len, &err);
	if (!hs_db) {
		if (!try_load) {
			msg_err_re_cache("cannot load hyperscan class %s: %s",
							 re_class->hash,
							 err ? err->message : "unknown error");
		}
		else {
			msg_debug_re_cache("cannot load hyperscan class %s: %s",
							   re_class->hash,
							   err ? err->message : "unknown error");
		}
		g_clear_error(&err);
		return FALSE;
	}

	/* Parse ids/flags from the unified header */
	if (len < RSPAMD_HS_MAGIC_LEN + sizeof(hs_platform_info_t) + sizeof(unsigned int) + sizeof(uint64_t)) {
		rspamd_hyperscan_free(hs_db, true);
		return FALSE;
	}

	p = (const char *) data + RSPAMD_HS_MAGIC_LEN + sizeof(hs_platform_info_t);
	memcpy(&n, p, sizeof(n));
	p += sizeof(n);

	if ((gsize) (p - (const char *) data) + (gsize) n * sizeof(unsigned int) * 2 + sizeof(uint64_t) > len) {
		rspamd_hyperscan_free(hs_db, true);
		return FALSE;
	}

	ids = (const unsigned int *) p;
	p += n * sizeof(unsigned int);
	flags = (const unsigned int *) p;

	/* Cleanup old */
	if (re_class->hs_scratch) {
		hs_free_scratch(re_class->hs_scratch);
		re_class->hs_scratch = NULL;
	}
	if (re_class->hs_db) {
		rspamd_hyperscan_free(re_class->hs_db, false);
		re_class->hs_db = NULL;
	}
	/*
	 * Reset match_type to PCRE for all regexps in this class.
	 * We iterate re_class->re (the hash table of regexps) rather than
	 * hs_ids because after config reload the hs_ids may point to different
	 * regexps in cache->re. By iterating the actual regexps in this class,
	 * we ensure we reset the correct cache_elts.
	 */
	{
		GHashTableIter class_it;
		gpointer class_k, class_v;

		g_hash_table_iter_init(&class_it, re_class->re);
		while (g_hash_table_iter_next(&class_it, &class_k, &class_v)) {
			rspamd_regexp_t *class_re = class_v;
			uint64_t re_cache_id = rspamd_regexp_get_cache_id(class_re);

			if (re_cache_id != RSPAMD_INVALID_ID && re_cache_id < cache->re->len) {
				struct rspamd_re_cache_elt *class_elt = g_ptr_array_index(cache->re, re_cache_id);
				class_elt->match_type = RSPAMD_RE_CACHE_PCRE;
			}
		}
	}

	if (re_class->hs_ids) {
		g_free(re_class->hs_ids);
		re_class->hs_ids = NULL;
	}
	re_class->nhs = 0;

	/*
	 * We must allocate scratch and set up the database BEFORE setting match_type
	 * on the elements. If scratch allocation fails, match_types remain PCRE.
	 */
	re_class->hs_db = hs_db;

	if ((ret = hs_alloc_scratch(rspamd_hyperscan_get_database(re_class->hs_db),
								&re_class->hs_scratch)) != HS_SUCCESS) {
		if (!try_load) {
			msg_err_re_cache("cannot allocate scratch for hs class %s: %d",
							 re_class->hash, ret);
		}
		rspamd_hyperscan_free(re_class->hs_db, true);
		re_class->hs_db = NULL;
		return FALSE;
	}

	/* Store ids */
	re_class->hs_ids = g_malloc(sizeof(int) * n);
	for (unsigned int i = 0; i < n; i++) {
		re_class->hs_ids[i] = (int) ids[i];
	}
	re_class->nhs = (int) n;

	/*
	 * First validate all IDs point to regexps in this re_class.
	 * We must do validation BEFORE setting any match_types, otherwise if
	 * validation fails mid-loop, some regexps will have match_type=HYPERSCAN
	 * but hs_scratch will be NULL.
	 */
	for (unsigned int i = 0; i < n; i++) {
		if ((int) ids[i] < 0 || ids[i] >= (unsigned int) cache->re->len) {
			continue;
		}
		struct rspamd_re_cache_elt *elt = g_ptr_array_index(cache->re, ids[i]);

		/* Verify the regexp at this ID belongs to the current re_class */
		if (rspamd_regexp_get_class(elt->re) != re_class) {
			msg_info_re_cache("stale hyperscan cache for class %s: id %ud points to "
							  "wrong re_class, will use PCRE until recompilation",
							  re_class->hash, ids[i]);
			hs_free_scratch(re_class->hs_scratch);
			re_class->hs_scratch = NULL;
			rspamd_hyperscan_free(re_class->hs_db, true);
			re_class->hs_db = NULL;
			g_free(re_class->hs_ids);
			re_class->hs_ids = NULL;
			re_class->nhs = 0;
			/* Redis cache entry will expire or be overwritten on next compilation */
			return FALSE;
		}
	}

	/*
	 * All IDs validated - now apply match types.
	 * This must be done AFTER scratch is allocated so that other workers
	 * don't try to use hyperscan with NULL scratch.
	 */
	for (unsigned int i = 0; i < n; i++) {
		if ((int) ids[i] < 0 || ids[i] >= (unsigned int) cache->re->len) {
			continue;
		}
		struct rspamd_re_cache_elt *elt = g_ptr_array_index(cache->re, ids[i]);

		if (flags[i] & HS_FLAG_PREFILTER) {
			elt->match_type = RSPAMD_RE_CACHE_HYPERSCAN_PRE;
		}
		else {
			elt->match_type = RSPAMD_RE_CACHE_HYPERSCAN;
		}
	}

	return TRUE;
}

static void
rspamd_re_cache_hs_load_item_free(struct rspamd_re_cache_hs_load_item *it)
{
	if (!it) return;
	g_free(it->cache_key);
	g_free(it);
}

static void
rspamd_re_cache_hs_load_cb(gboolean success, const unsigned char *data, gsize len,
						   const char *err, void *ud)
{
	struct rspamd_re_cache_hs_load_item *it = (struct rspamd_re_cache_hs_load_item *) ud;
	struct rspamd_re_cache_hs_load_scope *sctx = it->scope_ctx;

	if (success && data && len > 0) {
		if (rspamd_re_cache_apply_hyperscan_blob(it->cache, it->re_class, data, len, sctx->try_load)) {
			sctx->loaded++;
			sctx->total_regexps += it->re_class->nhs;
		}
		else {
			sctx->all_loaded = FALSE;
		}
	}
	else {
		/* cache miss or error */
		sctx->all_loaded = FALSE;
		(void) err;
	}

	if (sctx->pending > 0) {
		sctx->pending--;
	}

	if (sctx->pending == 0) {
		struct rspamd_re_cache *cache = sctx->cache;

		if (sctx->loaded > 0) {
			cache->hyperscan_loaded = sctx->all_loaded ? RSPAMD_HYPERSCAN_LOADED_FULL : RSPAMD_HYPERSCAN_LOADED_PARTIAL;
			if (sctx->all_loaded) {
				msg_info_re_cache("full hyperscan database of %ud regexps (%ud/%ud classes) has been loaded asynchronously%s%s%s",
								  sctx->total_regexps,
								  sctx->loaded, sctx->total,
								  cache->scope ? " for scope '" : "",
								  cache->scope ? cache->scope : "",
								  cache->scope ? "'" : "");
			}
			else {
				msg_info_re_cache("partial hyperscan database of %ud regexps (%ud/%ud classes) has been loaded asynchronously%s%s%s",
								  sctx->total_regexps,
								  sctx->loaded, sctx->total,
								  cache->scope ? " for scope '" : "",
								  cache->scope ? cache->scope : "",
								  cache->scope ? "'" : "");
			}
		}
		else {
			cache->hyperscan_loaded = RSPAMD_HYPERSCAN_LOAD_ERROR;
			msg_info_re_cache("hyperscan database has NOT been loaded asynchronously; no valid expressions (%ud classes)%s%s%s",
							  sctx->total,
							  cache->scope ? " for scope '" : "",
							  cache->scope ? cache->scope : "",
							  cache->scope ? "'" : "");
		}
		g_free(sctx);
	}

	rspamd_re_cache_hs_load_item_free(it);
}

void rspamd_re_cache_load_hyperscan_scoped_async(struct rspamd_re_cache *cache_head,
												 struct ev_loop *event_loop,
												 const char *cache_dir,
												 bool try_load)
{
	struct rspamd_re_cache *cur;

	if (!cache_head || !event_loop) {
		return;
	}

	/* Check if hyperscan is disabled */
	if (cache_head->disable_hyperscan) {
		return;
	}

	/* All file operations go through Lua backend */
	g_assert(rspamd_hs_cache_has_lua_backend());

	DL_FOREACH(cache_head, cur)
	{
		struct rspamd_re_cache_hs_load_scope *sctx = g_malloc0(sizeof(*sctx));
		GHashTableIter it;
		gpointer k, v;

		sctx->cache = cur;
		sctx->event_loop = event_loop;
		sctx->try_load = try_load;
		sctx->loaded = 0;
		sctx->all_loaded = TRUE;

		/* Count items first - for file backend, callbacks run synchronously,
		 * so we must set pending/total before starting any loads to avoid
		 * premature free when pending reaches 0 during the loop */
		sctx->total = g_hash_table_size(cur->re_classes);
		sctx->pending = sctx->total;

		if (sctx->pending == 0) {
			g_free(sctx);
			continue;
		}

		g_hash_table_iter_init(&it, cur->re_classes);
		while (g_hash_table_iter_next(&it, &k, &v)) {
			struct rspamd_re_class *re_class = (struct rspamd_re_class *) v;
			struct rspamd_re_cache_hs_load_item *item = g_malloc0(sizeof(*item));
			item->scope_ctx = sctx;
			item->cache = cur;
			item->re_class = re_class;
			item->cache_key = g_strdup(re_class->hash);
			char entity_name[256];
			if (re_class->type_len > 0) {
				rspamd_snprintf(entity_name, sizeof(entity_name), "re_class:%s(%*s)",
								rspamd_re_cache_type_to_string(re_class->type),
								(int) re_class->type_len - 1, re_class->type_data);
			}
			else {
				rspamd_snprintf(entity_name, sizeof(entity_name), "re_class:%s",
								rspamd_re_cache_type_to_string(re_class->type));
			}
			rspamd_hs_cache_lua_load_async(item->cache_key, entity_name, rspamd_re_cache_hs_load_cb, item);
		}
	}
}
#endif

void rspamd_re_cache_add_selector(struct rspamd_re_cache *cache,
								  const char *sname,
								  int ref)
{
	khiter_t k;

	k = kh_get(lua_selectors_hash, cache->selectors, (char *) sname);

	if (k == kh_end(cache->selectors)) {
		char *cpy = g_strdup(sname);
		int res;

		k = kh_put(lua_selectors_hash, cache->selectors, cpy, &res);

		kh_value(cache->selectors, k) = ref;
	}
	else {
		msg_warn_re_cache("replacing selector with name %s", sname);

		if (cache->L) {
			luaL_unref(cache->L, LUA_REGISTRYINDEX, kh_value(cache->selectors, k));
		}

		kh_value(cache->selectors, k) = ref;
	}
}

void rspamd_re_cache_add_selector_scoped(struct rspamd_re_cache **cache_head, const char *scope,
										 const char *sname, int ref)
{
	struct rspamd_re_cache *cache;

	g_assert(cache_head != NULL);
	g_assert(sname != NULL);

	/* NULL scope is allowed for default scope */
	cache = rspamd_re_cache_add_to_scope_list(cache_head, scope);
	if (cache) {
		rspamd_re_cache_add_selector(cache, sname, ref);
	}
}

struct rspamd_re_cache *rspamd_re_cache_find_scope(struct rspamd_re_cache *cache_head, const char *scope)
{
	return rspamd_re_cache_find_by_scope(cache_head, scope);
}

gboolean rspamd_re_cache_remove_scope(struct rspamd_re_cache **cache_head, const char *scope)
{
	struct rspamd_re_cache *target;

	if (!cache_head || !*cache_head) {
		return FALSE;
	}

	/* Prevent removal of default scope (NULL) to keep head stable */
	if (!scope) {
		return FALSE;
	}

	target = rspamd_re_cache_find_by_scope(*cache_head, scope);
	if (!target) {
		return FALSE;
	}

	/* Remove from linked list */
	DL_DELETE(*cache_head, target);

	/* If this was the head and there are no more elements, update head */
	if (target == *cache_head && !*cache_head) {
		*cache_head = NULL;
	}

	/* Unref the cache */
	rspamd_re_cache_unref(target);

	return TRUE;
}

unsigned int rspamd_re_cache_count_scopes(struct rspamd_re_cache *cache_head)
{
	struct rspamd_re_cache *cur;
	unsigned int count = 0;

	if (!cache_head) {
		return 0;
	}

	DL_COUNT(cache_head, cur, count);
	return count;
}

struct rspamd_re_cache *rspamd_re_cache_scope_first(struct rspamd_re_cache *cache_head)
{
	return cache_head;
}

struct rspamd_re_cache *rspamd_re_cache_scope_next(struct rspamd_re_cache *current)
{
	return current ? current->next : NULL;
}

const char *rspamd_re_cache_scope_name(struct rspamd_re_cache *scope)
{
	if (!scope) {
		return "unknown";
	}

	return scope->scope ? scope->scope : "default";
}

void rspamd_re_cache_scope_set_flags(struct rspamd_re_cache *scope, unsigned int flags)
{
	if (scope) {
		scope->flags |= flags;
	}
}

void rspamd_re_cache_scope_clear_flags(struct rspamd_re_cache *scope, unsigned int flags)
{
	if (scope) {
		scope->flags &= ~flags;
	}
}

unsigned int rspamd_re_cache_scope_get_flags(struct rspamd_re_cache *scope)
{
	return scope ? scope->flags : 0;
}

gboolean rspamd_re_cache_scope_is_loaded(struct rspamd_re_cache *scope)
{
	if (!scope) {
		return FALSE;
	}

	return (scope->flags & RSPAMD_RE_CACHE_FLAG_LOADED) != 0;
}

void rspamd_re_cache_set_flags(struct rspamd_re_cache *cache_head, const char *scope, unsigned int flags)
{
	struct rspamd_re_cache *target;

	if (!cache_head) {
		return;
	}

	target = rspamd_re_cache_find_by_scope(cache_head, scope);
	if (target) {
		target->flags |= flags;
	}
}

void rspamd_re_cache_clear_flags(struct rspamd_re_cache *cache_head, const char *scope, unsigned int flags)
{
	struct rspamd_re_cache *target;

	if (!cache_head) {
		return;
	}

	target = rspamd_re_cache_find_by_scope(cache_head, scope);
	if (target) {
		target->flags &= ~flags;
	}
}

unsigned int rspamd_re_cache_get_flags(struct rspamd_re_cache *cache_head, const char *scope)
{
	struct rspamd_re_cache *target;

	if (!cache_head) {
		return 0;
	}

	target = rspamd_re_cache_find_by_scope(cache_head, scope);
	if (target) {
		return target->flags;
	}

	return 0;
}

gboolean rspamd_re_cache_is_loaded(struct rspamd_re_cache *cache_head, const char *scope)
{
	unsigned int flags = rspamd_re_cache_get_flags(cache_head, scope);
	return (flags & RSPAMD_RE_CACHE_FLAG_LOADED) != 0;
}


static gboolean
rspamd_re_cache_create_scope_lock(const char *cache_dir, const char *scope, int *lock_fd)
{
	char lock_path[PATH_MAX];
	pid_t myself = getpid();

	if (!scope) {
		scope = "default";
	}

	rspamd_snprintf(lock_path, sizeof(lock_path), "%s%c%s.scope.lock",
					cache_dir, G_DIR_SEPARATOR, scope);

	*lock_fd = open(lock_path, O_WRONLY | O_CREAT | O_EXCL, 00600);

	if (*lock_fd == -1) {
		if (errno == EEXIST || errno == EBUSY) {
			/* Check if the lock is stale */
			int read_fd = open(lock_path, O_RDONLY);
			if (read_fd != -1) {
				pid_t lock_pid;
				gssize r = read(read_fd, &lock_pid, sizeof(lock_pid));
				close(read_fd);

				if (r == sizeof(lock_pid)) {
					/* Check if the process is still alive */
					if (lock_pid != myself && (kill(lock_pid, 0) == -1 && errno == ESRCH)) {
						/* Stale lock, remove it */
						if (unlink(lock_path) == 0) {
							/* Try to create lock again */
							*lock_fd = open(lock_path, O_WRONLY | O_CREAT | O_EXCL, 00600);
							if (*lock_fd != -1) {
								goto write_pid;
							}
						}
					}
				}
				else {
					/* Invalid lock file, remove it */
					if (unlink(lock_path) == 0) {
						*lock_fd = open(lock_path, O_WRONLY | O_CREAT | O_EXCL, 00600);
						if (*lock_fd != -1) {
							goto write_pid;
						}
					}
				}
			}
		}
		return FALSE;
	}

write_pid:
	/* Write our PID to the lock file */
	if (write(*lock_fd, &myself, sizeof(myself)) != sizeof(myself)) {
		close(*lock_fd);
		unlink(lock_path);
		return FALSE;
	}

	/* Lock the file */
	if (!rspamd_file_lock(*lock_fd, FALSE)) {
		close(*lock_fd);
		unlink(lock_path);
		return FALSE;
	}

	return TRUE;
}

static void
rspamd_re_cache_remove_scope_lock(const char *cache_dir, const char *scope, int lock_fd)
{
	char lock_path[PATH_MAX];

	if (!scope) {
		scope = "default";
	}

	rspamd_snprintf(lock_path, sizeof(lock_path), "%s%c%s.scope.lock",
					cache_dir, G_DIR_SEPARATOR, scope);

	if (lock_fd != -1) {
		rspamd_file_unlock(lock_fd, FALSE);
		close(lock_fd);
	}
	unlink(lock_path);
}

#ifdef WITH_HYPERSCAN
struct rspamd_re_cache_hs_compile_scoped_cbdata {
	struct rspamd_re_cache *cache;
	const char *cache_dir;
	const char *scope;
	double max_time;
	gboolean silent;
	int lock_fd;
	struct rspamd_worker *worker;

	void (*cb)(const char *scope, unsigned int ncompiled, GError *err, void *cbd);

	void *cbd;
};

static void
rspamd_re_cache_compile_scoped_cb(unsigned int ncompiled, GError *err, void *cbd)
{
	struct rspamd_re_cache_hs_compile_scoped_cbdata *scoped_cbd =
		(struct rspamd_re_cache_hs_compile_scoped_cbdata *) cbd;

	/* Call original callback */
	if (scoped_cbd->cb) {
		scoped_cbd->cb(scoped_cbd->scope, ncompiled, err, scoped_cbd->cbd);
	}

	/*
	 * Only free when compilation is complete (err==NULL means done).
	 * When err!=NULL, it's a per-class error and compilation continues,
	 * so we must not free yet - we'll be called again.
	 */
	if (err == NULL) {
		/* Remove lock only when done */
		rspamd_re_cache_remove_scope_lock(scoped_cbd->cache_dir, scoped_cbd->scope,
										  scoped_cbd->lock_fd);
		g_free(scoped_cbd);
	}
}

int rspamd_re_cache_compile_hyperscan_scoped_single(struct rspamd_re_cache *cache,
													const char *scope,
													const char *cache_dir,
													double max_time,
													gboolean silent,
													struct ev_loop *event_loop,
													struct rspamd_worker *worker,
													void (*cb)(const char *scope, unsigned int ncompiled, GError *err,
															   void *cbd),
													void *cbd)
{
	struct rspamd_re_cache_hs_compile_scoped_cbdata *scoped_cbd;
	int lock_fd = -1;

	g_assert(cache != NULL);
	g_assert(cache_dir != NULL);

	/* Try to acquire lock for this scope */
	if (!rspamd_re_cache_create_scope_lock(cache_dir, scope, &lock_fd)) {
		/* Another process is compiling this scope */
		if (cb) {
			cb(scope, 0, NULL, cbd);
		}
		return 0;
	}

	/* Create callback data */
	scoped_cbd = g_malloc0(sizeof(*scoped_cbd));
	scoped_cbd->cache = cache;
	scoped_cbd->cache_dir = cache_dir;
	scoped_cbd->scope = scope;
	scoped_cbd->max_time = max_time;
	scoped_cbd->silent = silent;
	scoped_cbd->lock_fd = lock_fd;
	scoped_cbd->worker = worker;
	scoped_cbd->cb = cb;
	scoped_cbd->cbd = cbd;

	return rspamd_re_cache_compile_hyperscan(cache, cache_dir, max_time, silent,
											 event_loop, worker, rspamd_re_cache_compile_scoped_cb, scoped_cbd);
}
#else
/* Non hyperscan version stub */
int rspamd_re_cache_compile_hyperscan_scoped_single(struct rspamd_re_cache *cache,
													const char *scope,
													const char *cache_dir,
													double max_time,
													gboolean silent,
													struct ev_loop *event_loop,
													struct rspamd_worker *worker,
													void (*cb)(const char *scope, unsigned int ncompiled, GError *err, void *cbd),
													void *cbd)
{
	return 0;
}
#endif
