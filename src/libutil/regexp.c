/*
 * Copyright (c) 2015, Vsevolod Stakhov
 *
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *	 * Redistributions of source code must retain the above copyright
 *	   notice, this list of conditions and the following disclaimer.
 *	 * Redistributions in binary form must reproduce the above copyright
 *	   notice, this list of conditions and the following disclaimer in the
 *	   documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY AUTHOR ''AS IS'' AND ANY
 * EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL AUTHOR BE LIABLE FOR ANY
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include "config.h"
#include "regexp.h"
#include "blake2.h"
#include "ref.h"
#include "util.h"
#include <pcre.h>

typedef guchar regexp_id_t[BLAKE2B_OUTBYTES];

#define RSPAMD_REGEXP_FLAG_RAW (1 << 1)
#define RSPAMD_REGEXP_FLAG_NOOPT (1 << 2)

struct rspamd_regexp_s {
	gdouble exec_time;
	gchar *pattern;
	pcre *re;
	pcre_extra *extra;
#ifdef HAVE_PCRE_JIT
	pcre_jit_stack *jstack;
	pcre_jit_stack *raw_jstack;
	rspamd_mutex_t *mtx;
#endif
	pcre *raw_re;
	pcre_extra *raw_extra;
	regexp_id_t id;
	ref_entry_t ref;
	gint flags;
};

struct rspamd_regexp_cache {
	GHashTable *tbl;
};

static struct rspamd_regexp_cache *global_re_cache = NULL;

static GQuark
rspamd_regexp_quark (void)
{
	return g_quark_from_static_string ("rspamd-regexp");
}

static void
rspamd_regexp_generate_id (const gchar *pattern, const gchar *flags,
		regexp_id_t out)
{
	blake2b_state st;

	blake2b_init (&st, sizeof (regexp_id_t));

	if (flags) {
		blake2b_update (&st, flags, strlen (flags));
	}

	blake2b_update (&st, pattern, strlen (pattern));
	blake2b_final (&st, out, sizeof (regexp_id_t));
}

static void
rspamd_regexp_dtor (rspamd_regexp_t *re)
{
	if (re) {
		if (re->re) {
			pcre_free_study (re->extra);
			pcre_free (re->re);
#ifdef HAVE_PCRE_JIT
			pcre_jit_stack_free (re->jstack);
#endif
		}
		if (re->raw_re) {
			pcre_free_study (re->raw_extra);
			pcre_free (re->raw_re);
#ifdef HAVE_PCRE_JIT
			pcre_jit_stack_free (re->raw_jstack);
#endif
		}
#ifdef HAVE_PCRE_JIT
		if (re->mtx) {
			rspamd_mutex_free (re->mtx);
		}
#endif
		if (re->pattern) {
			g_free (re->pattern);
		}
	}
}

rspamd_regexp_t*
rspamd_regexp_new (const gchar *pattern, const gchar *flags,
		GError **err)
{
	const gchar *start = pattern, *end, *flags_str, *err_str;
	rspamd_regexp_t *res;
	pcre *r;
	gchar sep = 0, *real_pattern;
	gint regexp_flags = 0, rspamd_flags = 0, err_off, study_flags = 0;
	gboolean strict_flags = FALSE;

	if (flags == NULL) {
		/* We need to parse pattern and detect flags set */
		if (*start == '/') {
			sep = '/';
		}
		else if (*start == 'm') {
			start ++;
			sep = *start;
		}
		if (sep == '\0' || g_ascii_isalnum (sep)) {
			/* We have no flags, no separators and just use all line as expr */
			start = pattern;
			end = start + strlen (pattern);
		}
		else {
			end = strrchr (pattern, sep);

			if (end == NULL || end <= start) {
				g_set_error (err, rspamd_regexp_quark(), EINVAL,
						"pattern is not enclosed with %c: %s",
						sep, pattern);
				return NULL;
			}
			flags = end + 1;
		}
	}
	else {
		/* Strictly check all flags */
		strict_flags = TRUE;
		start = pattern;
		end = pattern + strlen (pattern);
	}

	regexp_flags |= PCRE_UTF8;

	if (flags != NULL) {
		flags_str = flags;
		while (*flags_str) {
			switch (*flags_str) {
			case 'i':
				regexp_flags |= PCRE_CASELESS;
				break;
			case 'm':
				regexp_flags |= PCRE_MULTILINE;
				break;
			case 's':
				regexp_flags |= PCRE_DOTALL;
				break;
			case 'x':
				regexp_flags |= PCRE_EXTENDED;
				break;
			case 'u':
				regexp_flags |= PCRE_UNGREEDY;
				break;
			case 'O':
				/* We optimize all regexps by default */
				rspamd_flags |= RSPAMD_REGEXP_FLAG_NOOPT;
				break;
			case 'r':
				rspamd_flags |= RSPAMD_REGEXP_FLAG_RAW;
				regexp_flags &= ~PCRE_UTF8;
				break;
			default:
				if (strict_flags) {
					g_set_error (err, rspamd_regexp_quark(), EINVAL,
							"invalid regexp flag: %c in pattern %s",
							*flags_str, pattern);
					return NULL;
				}
				goto fin;
				break;
			}
			flags_str++;
		}
	}
fin:

	real_pattern = g_malloc (end - start + 1);
	rspamd_strlcpy (real_pattern, start, end - start + 1);

	r = pcre_compile (real_pattern, regexp_flags, &err_str, &err_off, NULL);

	if (r == NULL) {
		g_set_error (err, rspamd_regexp_quark(), EINVAL,
			"invalid regexp pattern: '%s': %s at position %d",
			pattern, err_str, err_off);
		g_free (real_pattern);

		return NULL;
	}

	/* Now allocate the target structure */
	res = g_slice_alloc0 (sizeof (*res));
	REF_INIT_RETAIN (res, rspamd_regexp_dtor);
	res->flags = rspamd_flags;
	res->pattern = real_pattern;

	if (rspamd_flags & RSPAMD_REGEXP_FLAG_RAW) {
		res->raw_re = r;
	}
	else {
		res->re = r;
		res->raw_re = pcre_compile (pattern, regexp_flags & ~PCRE_UTF8,
				&err_str, &err_off, NULL);
	}

	if (!(rspamd_flags & RSPAMD_REGEXP_FLAG_NOOPT)) {
		/* Optimize regexp */
#ifdef HAVE_PCRE_JIT
		study_flags |= PCRE_STUDY_JIT_COMPILE;
		res->mtx = rspamd_mutex_new ();
#endif
		if (res->re) {
			res->extra = pcre_study (res->re, study_flags, NULL);
#ifdef HAVE_PCRE_JIT
			res->jstack = pcre_jit_stack_alloc (32 * 1024, 512 * 1024);
			pcre_assign_jit_stack (res->extra, NULL, res->jstack);
#endif
		}
		if (res->raw_re) {
			res->raw_extra = pcre_study (res->raw_re, study_flags, NULL);
#ifdef HAVE_PCRE_JIT
			res->raw_jstack = pcre_jit_stack_alloc (32 * 1024, 512 * 1024);
			pcre_assign_jit_stack (res->raw_extra, NULL, res->raw_jstack);
#endif
		}
	}

	rspamd_regexp_generate_id (pattern, flags, res->id);

	return res;
}

gboolean
rspamd_regexp_search (rspamd_regexp_t *re, const gchar *text, gsize len,
		const gchar **start, const gchar **end, gboolean raw)
{
	pcre *r;
	pcre_extra *ext;
#ifdef HAVE_PCRE_JIT
	pcre_jit_stack *st;
#endif
	const gchar *mt;
	gsize remain;
	gint rc, match_flags = 0, ovec[10];

	g_assert (re != NULL);
	g_assert (text != NULL);

	if (end != NULL && *end != NULL) {
		/* Incremental search */
		mt = (*end) + 1;
		remain = len - (mt - text);
	}
	else {
		mt = text;
		remain = len;
	}

	match_flags = PCRE_NEWLINE_ANYCRLF;
	if ((re->flags & RSPAMD_REGEXP_FLAG_RAW) || raw) {
		r = re->raw_re;
		ext = re->raw_extra;
#ifdef HAVE_PCRE_JIT
		st = re->raw_jstack;
#endif
	}
	else {
		match_flags |= PCRE_NO_UTF8_CHECK;
		r = re->re;
		ext = re->extra;
#ifdef HAVE_PCRE_JIT
		st = re->jstack;
#endif
	}

	g_assert (r != NULL);

#ifdef HAVE_PCRE_JIT
	if (re->mtx) {
		rspamd_mutex_lock (re->mtx);
	}
#endif

	if (!(re->flags & RSPAMD_REGEXP_FLAG_NOOPT)) {
#ifdef HAVE_PCRE_JIT
		rc = pcre_jit_exec (r, ext, mt, remain, 0, match_flags, ovec,
				G_N_ELEMENTS (ovec), st);
#else
		rc = pcre_exec (r, ext, mt, remain, 0, match_flags, ovec,
				G_N_ELEMENTS (ovec));
#endif
	}
	else {
		rc = pcre_exec (r, ext, mt, remain, 0, match_flags, ovec,
				G_N_ELEMENTS (ovec));
	}
#ifdef HAVE_PCRE_JIT
	if (re->mtx) {
		rspamd_mutex_unlock (re->mtx);
	}
#endif
	if (rc > 0) {
		if (start) {
			*start = mt + ovec[0];
		}
		if (end) {
			*end = mt + ovec[0] + ovec[1];
		}

		return TRUE;
	}

	return FALSE;
}

gboolean
rspamd_regexp_match (rspamd_regexp_t *re, const gchar *text, gsize len,
		gboolean raw)
{
	const gchar *start = NULL, *end = NULL;

	g_assert (re != NULL);
	g_assert (text != NULL);

	if (rspamd_regexp_search (re, text, len, &start, &end, raw)) {
		if (start == text && end == text + len) {
			return TRUE;
		}
	}

	return FALSE;
}

void
rspamd_regexp_unref (rspamd_regexp_t *re)
{
	REF_RELEASE (re);
}

static gboolean
rspamd_regexp_equal (gconstpointer a, gconstpointer b)
{
	const guchar *ia = a, *ib = b;

	return (memcmp (ia, ib, sizeof (regexp_id_t)) == 0);
}

static guint32
rspamd_regexp_hash (gconstpointer a)
{
	const guchar *ia = a;
	guint32 res;

	memcpy (&res, ia, sizeof (res));

	return res;
}

struct rspamd_regexp_cache*
rspamd_regexp_cache_new (void)
{
	struct rspamd_regexp_cache *ncache;

	ncache = g_slice_alloc (sizeof (*ncache));
	ncache->tbl = g_hash_table_new_full (rspamd_regexp_hash, rspamd_regexp_equal,
			NULL, (GDestroyNotify)rspamd_regexp_unref);

	return ncache;
}


rspamd_regexp_t*
rspamd_regexp_cache_query (struct rspamd_regexp_cache* cache,
		const gchar *pattern,
		const gchar *flags)
{
	rspamd_regexp_t *res = NULL;
	regexp_id_t id;

	if (cache == NULL) {
		cache = global_re_cache;
	}

	g_assert (cache != NULL);
	rspamd_regexp_generate_id (pattern, flags, id);

	res = g_hash_table_lookup (cache->tbl, id);

	return res;
}


rspamd_regexp_t*
rspamd_regexp_cache_create (struct rspamd_regexp_cache *cache,
		const gchar *pattern,
		const gchar *flags, GError **err)
{
	rspamd_regexp_t *res;

	if (cache == NULL) {
		cache = global_re_cache;
	}

	g_assert (cache != NULL);
	res = rspamd_regexp_cache_query (cache, pattern, flags);

	if (res != NULL) {
		return res;
	}

	res = rspamd_regexp_new (pattern, flags, err);

	if (res) {
		g_hash_table_insert (cache->tbl, res->id, res);
	}

	return res;
}

void
rspamd_regexp_cache_destroy (struct rspamd_regexp_cache *cache)
{
	if (cache != NULL) {
		g_hash_table_destroy (cache->tbl);
	}
}

void
rspamd_regexp_library_init (void)
{
	if (global_re_cache == NULL) {
		global_re_cache = rspamd_regexp_cache_new ();
	}
}

void
rspamd_regexp_library_finalize (void)
{
	if (global_re_cache != NULL) {
		rspamd_regexp_cache_destroy (global_re_cache);
	}
}
