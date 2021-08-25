/*-
 * Copyright 2016 Vsevolod Stakhov
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
#include "config.h"
#include "regexp.h"
#include "cryptobox.h"
#include "ref.h"
#include "util.h"
#include "rspamd.h"
#include "contrib/fastutf8/fastutf8.h"

#ifndef WITH_PCRE2
/* Normal pcre path */
#include <pcre.h>
#define PCRE_T pcre
#define PCRE_EXTRA_T pcre_extra
#define PCRE_JIT_T pcre_jit_stack
#define PCRE_FREE pcre_free
#define PCRE_JIT_STACK_FREE pcre_jit_stack_free
#define PCRE_FLAG(x) G_PASTE(PCRE_, x)
#else
/* PCRE 2 path */
#ifndef PCRE2_CODE_UNIT_WIDTH
#define PCRE2_CODE_UNIT_WIDTH 8
#endif

#include <pcre2.h>
#define PCRE_T pcre2_code
#define PCRE_JIT_T pcre2_jit_stack
#define PCRE_FREE pcre2_code_free
#define PCRE_JIT_STACK_FREE pcre2_jit_stack_free

#define PCRE_FLAG(x) G_PASTE(PCRE2_, x)
#endif

typedef guchar regexp_id_t[rspamd_cryptobox_HASHBYTES];

#undef DISABLE_JIT_FAST

struct rspamd_regexp_s {
	gdouble exec_time;
	gchar *pattern;
	PCRE_T *re;
	PCRE_T *raw_re;
#ifndef WITH_PCRE2
	PCRE_EXTRA_T *extra;
	PCRE_EXTRA_T *raw_extra;
#else
	pcre2_match_context *mcontext;
	pcre2_match_context *raw_mcontext;
#endif
	regexp_id_t id;
	ref_entry_t ref;
	gpointer ud;
	gpointer re_class;
	guint64 cache_id;
	gsize match_limit;
	guint max_hits;
	gint flags;
	gint pcre_flags;
	gint ncaptures;
};

struct rspamd_regexp_cache {
	GHashTable *tbl;
#ifdef HAVE_PCRE_JIT
	PCRE_JIT_T *jstack;
#endif
};

static struct rspamd_regexp_cache *global_re_cache = NULL;
static gboolean can_jit = FALSE;
static gboolean check_jit = TRUE;

#ifdef WITH_PCRE2
static pcre2_compile_context *pcre2_ctx = NULL;
#endif

static GQuark
rspamd_regexp_quark (void)
{
	return g_quark_from_static_string ("rspamd-regexp");
}

static void
rspamd_regexp_generate_id (const gchar *pattern, const gchar *flags,
		regexp_id_t out)
{
	rspamd_cryptobox_hash_state_t st;

	rspamd_cryptobox_hash_init (&st, NULL, 0);

	if (flags) {
		rspamd_cryptobox_hash_update (&st, flags, strlen (flags));
	}

	rspamd_cryptobox_hash_update (&st, pattern, strlen (pattern));
	rspamd_cryptobox_hash_final (&st, out);
}

static void
rspamd_regexp_dtor (rspamd_regexp_t *re)
{
	if (re) {
		if (re->raw_re && re->raw_re != re->re) {
#ifndef WITH_PCRE2
#ifdef HAVE_PCRE_JIT
			if (re->raw_extra) {
				pcre_free_study (re->raw_extra);
			}
#endif
#else
			if (re->mcontext) {
				pcre2_match_context_free (re->mcontext);
			}
#endif
			PCRE_FREE (re->raw_re);
		}
		if (re->re) {
#ifndef WITH_PCRE2
#ifdef HAVE_PCRE_JIT
			if (re->extra) {
				pcre_free_study (re->extra);
			}
#endif
#else
			if (re->raw_mcontext) {
				pcre2_match_context_free (re->raw_mcontext);
			}
#endif
			PCRE_FREE (re->re);
		}

		if (re->pattern) {
			g_free (re->pattern);
		}

		g_free (re);
	}
}

static void
rspamd_regexp_post_process (rspamd_regexp_t *r)
{
	if (global_re_cache == NULL) {
		rspamd_regexp_library_init (NULL);
	}
#if defined(WITH_PCRE2)
	gsize jsz;
	static const guint max_recursion_depth = 100000, max_backtrack = 1000000;

	guint jit_flags = can_jit ? PCRE2_JIT_COMPLETE : 0;

	/* Create match context */
	r->mcontext = pcre2_match_context_create (NULL);
	g_assert (r->mcontext != NULL);
	pcre2_set_recursion_limit (r->mcontext, max_recursion_depth);
	pcre2_set_match_limit (r->mcontext, max_backtrack);

	if (r->re != r->raw_re) {
		r->raw_mcontext = pcre2_match_context_create (NULL);
		g_assert (r->raw_mcontext != NULL);
		pcre2_set_recursion_limit (r->raw_mcontext, max_recursion_depth);
		pcre2_set_match_limit (r->raw_mcontext, max_backtrack);
	}
	else {
		r->raw_mcontext = r->mcontext;
	}

#ifdef HAVE_PCRE_JIT
	if (can_jit) {
		if (pcre2_jit_compile (r->re, jit_flags) < 0) {
			msg_err ("jit compilation of %s is not supported: %d", r->pattern, jit_flags);
			r->flags |= RSPAMD_REGEXP_FLAG_DISABLE_JIT;
		}
		else {
			if (!(pcre2_pattern_info (r->re, PCRE2_INFO_JITSIZE, &jsz) >= 0 && jsz > 0)) {
				msg_err ("jit compilation of %s is not supported", r->pattern);
				r->flags |= RSPAMD_REGEXP_FLAG_DISABLE_JIT;
			}
		}
	}
	else {
		r->flags |= RSPAMD_REGEXP_FLAG_DISABLE_JIT;
	}

	if (!(r->flags & RSPAMD_REGEXP_FLAG_DISABLE_JIT)) {
		pcre2_jit_stack_assign (r->mcontext, NULL, global_re_cache->jstack);
	}

	if (r->raw_re && r->re != r->raw_re && !(r->flags & RSPAMD_REGEXP_FLAG_DISABLE_JIT)) {
		if (pcre2_jit_compile (r->raw_re, jit_flags) < 0) {
			msg_debug ("jit compilation of %s is not supported", r->pattern);
			r->flags |= RSPAMD_REGEXP_FLAG_DISABLE_JIT;
		}

		if (!(pcre2_pattern_info (r->raw_re, PCRE2_INFO_JITSIZE, &jsz) >= 0 && jsz > 0)) {
			msg_debug ("jit compilation of raw %s is not supported", r->pattern);
		}
		else if (!(r->flags & RSPAMD_REGEXP_FLAG_DISABLE_JIT)) {
			g_assert (r->raw_mcontext != NULL);
			pcre2_jit_stack_assign (r->raw_mcontext, NULL, global_re_cache->jstack);
		}
	}
#endif

#else
	const gchar *err_str = "unknown";
	gboolean try_jit = TRUE, try_raw_jit = TRUE;
	gint study_flags = 0;

#if defined(HAVE_PCRE_JIT)
	study_flags |= PCRE_STUDY_JIT_COMPILE;
#endif

	/* Pcre 1 needs study */
	if (r->re) {
		r->extra = pcre_study (r->re, study_flags, &err_str);

		if (r->extra == NULL) {
			msg_debug ("cannot optimize regexp pattern: '%s': %s",
					r->pattern, err_str);
			try_jit = FALSE;
			r->flags |= RSPAMD_REGEXP_FLAG_DISABLE_JIT;
		}
	}
	else {
		g_assert_not_reached ();
	}

	if (r->raw_re && r->raw_re != r->re) {
		r->raw_extra = pcre_study (r->re, study_flags, &err_str);
	}
	else if (r->raw_re == r->re) {
		r->raw_extra = r->extra;
	}

	if (r->raw_extra == NULL) {

		msg_debug ("cannot optimize raw regexp pattern: '%s': %s",
				r->pattern, err_str);
		try_raw_jit = FALSE;
	}
	/* JIT path */
	if (try_jit) {
#ifdef HAVE_PCRE_JIT
		gint jit, n;

		if (can_jit) {
			jit = 0;
			n = pcre_fullinfo (r->re, r->extra,
					PCRE_INFO_JIT, &jit);

			if (n != 0 || jit != 1) {
				msg_debug ("jit compilation of %s is not supported", r->pattern);
				r->flags |= RSPAMD_REGEXP_FLAG_DISABLE_JIT;
			}
			else {
				pcre_assign_jit_stack (r->extra, NULL, global_re_cache->jstack);
			}
		}
#endif
	}
	else {
		msg_debug ("cannot optimize regexp pattern: '%s': %s",
				r->pattern, err_str);
		r->flags |= RSPAMD_REGEXP_FLAG_DISABLE_JIT;
	}

	if (try_raw_jit) {
#ifdef HAVE_PCRE_JIT
		gint jit, n;

		if (can_jit) {

			if (r->raw_re != r->re) {
				jit = 0;
				n = pcre_fullinfo (r->raw_re, r->raw_extra,
						PCRE_INFO_JIT, &jit);

				if (n != 0 || jit != 1) {
					msg_debug ("jit compilation of %s is not supported", r->pattern);
					r->flags |= RSPAMD_REGEXP_FLAG_DISABLE_JIT;
				}
				else {
					pcre_assign_jit_stack (r->raw_extra, NULL,
							global_re_cache->jstack);
				}
			}
		}
#endif
	}
#endif /* WITH_PCRE2 */
}

rspamd_regexp_t*
rspamd_regexp_new_len (const gchar *pattern, gsize len, const gchar *flags,
		GError **err)
{
	const gchar *start = pattern, *end = start + len, *flags_str = NULL, *flags_end = NULL;
	gchar *err_str;
	rspamd_regexp_t *res;
	gboolean explicit_utf = FALSE;
	PCRE_T *r;
	gchar sep = 0, *real_pattern;
#ifndef WITH_PCRE2
	gint err_off;
#else
	gsize err_off;
#endif
	gint regexp_flags = 0, rspamd_flags = 0, err_code, ncaptures;
	gboolean strict_flags = FALSE;

	rspamd_regexp_library_init (NULL);

	if (pattern == NULL) {
		g_set_error (err, rspamd_regexp_quark(), EINVAL,
				"cannot create regexp from a NULL pattern");
		return NULL;
	}

	if (flags == NULL && start + 1 < end) {
		/* We need to parse pattern and detect flags set */
		if (*start == '/') {
			sep = '/';
		}
		else if (*start == 'm' && !g_ascii_isalnum(start[1])) {
			start ++;
			sep = *start;

			/* Paired braces */
			if (sep == '{') {
				sep = '}';
			}

			rspamd_flags |= RSPAMD_REGEXP_FLAG_FULL_MATCH;
		}
		if (sep == 0) {
			/* We have no flags, no separators and just use all line as expr */
			start = pattern;
			rspamd_flags &= ~RSPAMD_REGEXP_FLAG_FULL_MATCH;
		}
		else {
			gchar *last_sep = rspamd_memrchr(pattern, sep, len);

			if (last_sep == NULL || last_sep <= start) {
				g_set_error (err, rspamd_regexp_quark(), EINVAL,
						"pattern is not enclosed with %c: %s",
						sep, pattern);
				return NULL;
			}
			flags_str = last_sep + 1;
			flags_end = end;
			end = last_sep;
			start ++;
		}
	}
	else {
		/* Strictly check all flags */
		strict_flags = TRUE;
		start = pattern;
		flags_str = flags;
		if (flags) {
			flags_end = flags + strlen(flags);
		}
	}

	rspamd_flags |= RSPAMD_REGEXP_FLAG_RAW;

#ifndef WITH_PCRE2
	regexp_flags &= ~PCRE_FLAG(UTF8);
	regexp_flags |= PCRE_FLAG(NEWLINE_ANYCRLF);
#else
	regexp_flags &= ~PCRE_FLAG(UTF);
#endif

	if (flags_str != NULL) {
		while (flags_str < flags_end) {
			switch (*flags_str) {
			case 'i':
				regexp_flags |= PCRE_FLAG(CASELESS);
				break;
			case 'm':
				regexp_flags |= PCRE_FLAG(MULTILINE);
				break;
			case 's':
				regexp_flags |= PCRE_FLAG(DOTALL);
				break;
			case 'x':
				regexp_flags |= PCRE_FLAG(EXTENDED);
				break;
			case 'u':
				rspamd_flags &= ~RSPAMD_REGEXP_FLAG_RAW;
				rspamd_flags |= RSPAMD_REGEXP_FLAG_UTF;
#ifndef WITH_PCRE2
				regexp_flags |= PCRE_FLAG(UTF8);
#else
				regexp_flags |= PCRE_FLAG(UTF);
#endif
				explicit_utf = TRUE;
				break;
			case 'O':
				/* We optimize all regexps by default */
				rspamd_flags |= RSPAMD_REGEXP_FLAG_NOOPT;
				break;
			case 'L':
				/* SOM_LEFTMOST hyperscan flag */
				rspamd_flags |= RSPAMD_REGEXP_FLAG_LEFTMOST;
				break;
			case 'r':
				rspamd_flags |= RSPAMD_REGEXP_FLAG_RAW;
				rspamd_flags &= ~RSPAMD_REGEXP_FLAG_UTF;
#ifndef WITH_PCRE2
				regexp_flags &= ~PCRE_FLAG(UTF8);
#else
				regexp_flags &= ~PCRE_FLAG(UTF);
#endif
				break;
			default:
				if (strict_flags) {
					g_set_error (err, rspamd_regexp_quark(), EINVAL,
							"invalid regexp flag: %c in pattern %s",
							*flags_str, pattern);
					return NULL;
				}
				msg_warn ("invalid flag '%c' in pattern %s", *flags_str, pattern);
				goto fin;
				break;
			}
			flags_str++;
		}
	}
fin:

	real_pattern = g_malloc (end - start + 1);
	rspamd_strlcpy (real_pattern, start, end - start + 1);

#ifndef WITH_PCRE2
	r = pcre_compile (real_pattern, regexp_flags,
			(const char **)&err_str, &err_off, NULL);
	(void)err_code;
#else
	r = pcre2_compile (real_pattern, PCRE2_ZERO_TERMINATED,
			regexp_flags,
			&err_code, &err_off, pcre2_ctx);

	if (r == NULL) {
		err_str = g_alloca (1024);
		memset (err_str, 0, 1024);
		pcre2_get_error_message (err_code, err_str, 1024);
	}
#endif

	if (r == NULL) {
		g_set_error (err, rspamd_regexp_quark(), EINVAL,
			"regexp parsing error: '%s' at position %d; pattern: %s",
			err_str, (gint)err_off, real_pattern);
		g_free (real_pattern);

		return NULL;
	}

	/* Now allocate the target structure */
	res = g_malloc0 (sizeof (*res));
	REF_INIT_RETAIN (res, rspamd_regexp_dtor);
	res->flags = rspamd_flags;
	res->pattern = real_pattern;
	res->cache_id = RSPAMD_INVALID_ID;
	res->pcre_flags = regexp_flags;
	res->max_hits = 0;
	res->re = r;

	if (rspamd_flags & RSPAMD_REGEXP_FLAG_RAW) {
		res->raw_re = r;
	}
	else if (!explicit_utf) {
#ifndef WITH_PCRE2
		res->raw_re = pcre_compile (real_pattern, regexp_flags & ~PCRE_FLAG(UTF8),
				(const char **)&err_str, &err_off, NULL);
		(void)err_code;
#else
		res->raw_re = pcre2_compile (real_pattern, PCRE2_ZERO_TERMINATED,
					regexp_flags & ~PCRE_FLAG(UTF),
					&err_code, &err_off, pcre2_ctx);
		if (res->raw_re == NULL) {
			err_str = g_alloca (1024);
			memset (err_str, 0, 1024);
			pcre2_get_error_message (err_code, err_str, 1024);
		}
#endif
		if (res->raw_re == NULL) {
			msg_warn ("raw regexp parsing error: '%s': '%s' at position %d",
					err_str, real_pattern, (gint)err_off);
		}
	}

	rspamd_regexp_post_process (res);
	rspamd_regexp_generate_id (pattern, flags, res->id);

#ifndef WITH_PCRE2
	/* Check number of captures */
	if (pcre_fullinfo (res->raw_re, res->extra, PCRE_INFO_CAPTURECOUNT,
			&ncaptures) == 0) {
		res->ncaptures = ncaptures;
	}
#else
	/* Check number of captures */
	if (pcre2_pattern_info (res->raw_re, PCRE2_INFO_CAPTURECOUNT,
			&ncaptures) == 0) {
		res->ncaptures = ncaptures;
	}
#endif

	return res;
}

rspamd_regexp_t *
rspamd_regexp_new (const gchar *pattern, const gchar *flags,
									GError **err)
{
	return rspamd_regexp_new_len(pattern, strlen(pattern), flags, err);
}

#ifndef WITH_PCRE2
gboolean
rspamd_regexp_search (const rspamd_regexp_t *re, const gchar *text, gsize len,
		const gchar **start, const gchar **end, gboolean raw,
		GArray *captures)
{
	pcre *r;
	pcre_extra *ext;
#if defined(HAVE_PCRE_JIT) && defined(HAVE_PCRE_JIT_FAST) && !defined(DISABLE_JIT_FAST)
	pcre_jit_stack *st = NULL;
#endif
	const gchar *mt;
	gsize remain = 0;
	gint rc, match_flags = 0, *ovec, ncaptures, i;

	g_assert (re != NULL);
	g_assert (text != NULL);

	if (len == 0) {
		len = strlen (text);
	}

	if (re->match_limit > 0 && len > re->match_limit) {
		len = re->match_limit;
	}

	if (end != NULL && *end != NULL) {
		/* Incremental search */
		mt = (*end);

		if ((gint)len > (mt - text)) {
			remain = len - (mt - text);
		}
	}
	else {
		mt = text;
		remain = len;
	}

	if (remain == 0) {
		return FALSE;
	}

	match_flags = PCRE_NEWLINE_ANYCRLF;

	if ((re->flags & RSPAMD_REGEXP_FLAG_RAW) || raw) {
		r = re->raw_re;
		ext = re->raw_extra;
#if defined(HAVE_PCRE_JIT) && defined(HAVE_PCRE_JIT_FAST) && !defined(DISABLE_JIT_FAST)
		st = global_re_cache->jstack;
#endif
	}
	else {
		r = re->re;
		ext = re->extra;
#if defined(HAVE_PCRE_JIT) && defined(HAVE_PCRE_JIT_FAST) && !defined(DISABLE_JIT_FAST)
		if (rspamd_fast_utf8_validate (mt, remain) == 0) {
			st = global_re_cache->jstack;
		}
		else {
			msg_err ("bad utf8 input for JIT re '%s'", re->pattern);
			return FALSE;
		}
#endif
	}

	if (r == NULL) {
		/* Invalid regexp type for the specified input */
		return FALSE;
	}

	ncaptures = (re->ncaptures + 1) * 3;
	ovec = g_alloca (sizeof (gint) * ncaptures);

	if (!(re->flags & RSPAMD_REGEXP_FLAG_NOOPT)) {
#ifdef HAVE_PCRE_JIT
# if defined(HAVE_PCRE_JIT_FAST) && !defined(DISABLE_JIT_FAST)
		/* XXX: flags seems to be broken with jit fast path */
		g_assert (remain > 0);
		g_assert (mt != NULL);

		if (st != NULL && !(re->flags & RSPAMD_REGEXP_FLAG_DISABLE_JIT) && can_jit) {
			rc = pcre_jit_exec (r, ext, mt, remain, 0, 0, ovec,
					ncaptures, st);
		}
		else {
			rc = pcre_exec (r, ext, mt, remain, 0, match_flags, ovec,
					ncaptures);
		}
# else
		rc = pcre_exec (r, ext, mt, remain, 0, match_flags, ovec,
				ncaptures);
#endif
#else
		rc = pcre_exec (r, ext, mt, remain, 0, match_flags, ovec,
				ncaptures);
#endif
	}
	else {
		rc = pcre_exec (r, ext, mt, remain, 0, match_flags, ovec,
				ncaptures);
	}

	if (rc >= 0) {
		if (start) {
			*start = mt + ovec[0];
		}
		if (end) {
			*end = mt + ovec[1];
		}

		if (captures != NULL && rc >= 1) {
			struct rspamd_re_capture *elt;

			g_assert (g_array_get_element_size (captures) ==
					sizeof (struct rspamd_re_capture));
			g_array_set_size (captures, rc);

			for (i = 0; i < rc; i ++) {
				elt = &g_array_index (captures, struct rspamd_re_capture, i);
				elt->p = mt + ovec[i * 2];
				elt->len = (mt + ovec[i * 2 + 1]) - elt->p;

			}
		}

		if (re->flags & RSPAMD_REGEXP_FLAG_FULL_MATCH) {
			/* We also ensure that the match is full */
			if (ovec[0] != 0 || (guint)ovec[1] < len) {
				return FALSE;
			}
		}

		return TRUE;
	}

	return FALSE;
}
#else
/* PCRE 2 version */
gboolean
rspamd_regexp_search (const rspamd_regexp_t *re, const gchar *text, gsize len,
		const gchar **start, const gchar **end, gboolean raw,
		GArray *captures)
{
	pcre2_match_data *match_data;
	pcre2_match_context *mcontext;
	PCRE_T *r;
	const gchar *mt;
	gsize remain = 0, *ovec;
	gint rc, match_flags, novec, i;
	gboolean ret = FALSE;

	g_assert (re != NULL);
	g_assert (text != NULL);

	if (len == 0) {
		len = strlen (text);
	}

	if (re->match_limit > 0 && len > re->match_limit) {
		len = re->match_limit;
	}

	if (end != NULL && *end != NULL) {
		/* Incremental search */
		mt = (*end);

		if ((gint)len > (mt - text)) {
			remain = len - (mt - text);
		}
	}
	else {
		mt = text;
		remain = len;
	}

	if (remain == 0) {
		return FALSE;
	}

	match_flags = 0;

	if (raw || re->re == re->raw_re) {
		r = re->raw_re;
		mcontext = re->raw_mcontext;
	}
	else {
		r = re->re;
		mcontext = re->mcontext;
	}

	if (r == NULL) {
		/* Invalid regexp type for the specified input */
		return FALSE;
	}

	match_data = pcre2_match_data_create (re->ncaptures + 1, NULL);

#ifdef HAVE_PCRE_JIT
	if (!(re->flags & RSPAMD_REGEXP_FLAG_DISABLE_JIT) && can_jit) {
		if (re->re != re->raw_re && rspamd_fast_utf8_validate (mt, remain) != 0) {
			msg_err ("bad utf8 input for JIT re '%s'", re->pattern);
			return FALSE;
		}

		rc = pcre2_jit_match (r,  mt, remain, 0, match_flags, match_data,
				mcontext);
	}
	else {
		rc = pcre2_match (r,  mt, remain, 0, match_flags, match_data,
				mcontext);
	}
#else
	rc = pcre2_match (r,  mt, remain, 0, match_flags, match_data,
					mcontext);
#endif

	if (rc >= 0) {
		novec = pcre2_get_ovector_count (match_data);
		ovec = pcre2_get_ovector_pointer (match_data);

		if (start) {
			*start = mt + ovec[0];
		}
		if (end) {
			*end = mt + ovec[1];
		}

		if (captures != NULL && novec >= 1) {
			struct rspamd_re_capture *elt;

			g_assert (g_array_get_element_size (captures) ==
					sizeof (struct rspamd_re_capture));
			g_array_set_size (captures, novec);

			for (i = 0; i < novec; i ++) {
				elt = &g_array_index (captures, struct rspamd_re_capture, i);
				elt->p = mt + ovec[i * 2];
				elt->len = (mt + ovec[i * 2 + 1]) - elt->p;

			}
		}

		ret = TRUE;

		if (re->flags & RSPAMD_REGEXP_FLAG_FULL_MATCH) {
			/* We also ensure that the match is full */
			if (ovec[0] != 0 || (guint)ovec[1] < len) {
				ret = FALSE;
			}
		}
	}

	pcre2_match_data_free (match_data);

	return ret;
}
#endif

const char*
rspamd_regexp_get_pattern (const rspamd_regexp_t *re)
{
	g_assert (re != NULL);

	return re->pattern;
}

guint
rspamd_regexp_set_flags (rspamd_regexp_t *re, guint new_flags)
{
	guint old_flags;

	g_assert (re != NULL);
	old_flags = re->flags;
	re->flags = new_flags;

	return old_flags;
}

guint
rspamd_regexp_get_flags (const rspamd_regexp_t *re)
{
	g_assert (re != NULL);

	return re->flags;
}

guint
rspamd_regexp_get_pcre_flags (const rspamd_regexp_t *re)
{
	g_assert (re != NULL);

	return re->pcre_flags;
}

guint
rspamd_regexp_get_maxhits (const rspamd_regexp_t *re)
{
	g_assert (re != NULL);

	return re->max_hits;
}

guint
rspamd_regexp_set_maxhits (rspamd_regexp_t *re, guint new_maxhits)
{
	guint old_hits;

	g_assert (re != NULL);
	old_hits = re->max_hits;
	re->max_hits = new_maxhits;

	return old_hits;
}

guint64
rspamd_regexp_get_cache_id (const rspamd_regexp_t *re)
{
	g_assert (re != NULL);

	return re->cache_id;
}

guint64
rspamd_regexp_set_cache_id (rspamd_regexp_t *re, guint64 id)
{
	guint64 old;

	g_assert (re != NULL);
	old = re->cache_id;
	re->cache_id = id;

	return old;
}

gsize
rspamd_regexp_get_match_limit (const rspamd_regexp_t *re)
{
	g_assert (re != NULL);

	return re->match_limit;
}

gsize
rspamd_regexp_set_match_limit (rspamd_regexp_t *re, gsize lim)
{
	gsize old;

	g_assert (re != NULL);
	old = re->match_limit;
	re->match_limit = lim;

	return old;
}

gboolean
rspamd_regexp_match (const rspamd_regexp_t *re, const gchar *text, gsize len,
		gboolean raw)
{
	const gchar *start = NULL, *end = NULL;

	g_assert (re != NULL);
	g_assert (text != NULL);

	if (len == 0) {
		len = strlen (text);
	}

	if (rspamd_regexp_search (re, text, len, &start, &end, raw, NULL)) {
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

rspamd_regexp_t*
rspamd_regexp_ref (rspamd_regexp_t *re)
{
	g_assert (re != NULL);

	REF_RETAIN (re);

	return re;
}

void
rspamd_regexp_set_ud (rspamd_regexp_t *re, gpointer ud)
{
	g_assert (re != NULL);

	re->ud = ud;
}

gpointer
rspamd_regexp_get_ud (const rspamd_regexp_t *re)
{
	g_assert (re != NULL);

	return re->ud;
}

gboolean
rspamd_regexp_equal (gconstpointer a, gconstpointer b)
{
	const guchar *ia = a, *ib = b;

	return (memcmp (ia, ib, sizeof (regexp_id_t)) == 0);
}

guint32
rspamd_regexp_hash (gconstpointer a)
{
	const guchar *ia = a;
	guint32 res;

	memcpy (&res, ia, sizeof (res));

	return res;
}

gboolean
rspamd_regexp_cmp (gconstpointer a, gconstpointer b)
{
	const guchar *ia = a, *ib = b;

	return memcmp (ia, ib, sizeof (regexp_id_t));
}

struct rspamd_regexp_cache*
rspamd_regexp_cache_new (void)
{
	struct rspamd_regexp_cache *ncache;

	ncache = g_malloc0 (sizeof (*ncache));
	ncache->tbl = g_hash_table_new_full (rspamd_regexp_hash, rspamd_regexp_equal,
			NULL, (GDestroyNotify)rspamd_regexp_unref);
#ifdef HAVE_PCRE_JIT
#ifdef WITH_PCRE2
	ncache->jstack = pcre2_jit_stack_create (32 * 1024, 1024 * 1024, NULL);
#else
	ncache->jstack = pcre_jit_stack_alloc (32 * 1024, 1024 * 1024);
#endif
#endif
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
		rspamd_regexp_library_init (NULL);
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
		rspamd_regexp_library_init (NULL);
		cache = global_re_cache;
	}

	g_assert (cache != NULL);
	res = rspamd_regexp_cache_query (cache, pattern, flags);

	if (res != NULL) {
		return res;
	}

	res = rspamd_regexp_new (pattern, flags, err);

	if (res) {
		/* REF_RETAIN (res); */
		g_hash_table_insert (cache->tbl, res->id, res);
	}

	return res;
}

void rspamd_regexp_cache_insert (struct rspamd_regexp_cache* cache,
		const gchar *pattern,
		const gchar *flags, rspamd_regexp_t *re)
{
	g_assert (re != NULL);
	g_assert (pattern != NULL);

	if (cache == NULL) {
		rspamd_regexp_library_init (NULL);
		cache = global_re_cache;
	}

	g_assert (cache != NULL);
	/* Generate custom id */
	rspamd_regexp_generate_id (pattern, flags, re->id);

	REF_RETAIN (re);
	g_hash_table_insert (cache->tbl, re->id, re);
}

gboolean
rspamd_regexp_cache_remove (struct rspamd_regexp_cache *cache,
		rspamd_regexp_t *re)
{
	if (cache == NULL) {
		cache = global_re_cache;
	}

	g_assert (cache != NULL);
	g_assert (re != NULL);

	return g_hash_table_remove (cache->tbl, re->id);
}

void
rspamd_regexp_cache_destroy (struct rspamd_regexp_cache *cache)
{
	if (cache != NULL) {
		g_hash_table_destroy (cache->tbl);
#ifdef HAVE_PCRE_JIT
#ifdef WITH_PCRE2
		if (cache->jstack) {
			pcre2_jit_stack_free (cache->jstack);
		}
#else
		if (cache->jstack) {
			pcre_jit_stack_free (cache->jstack);
		}
#endif
#endif
		g_free (cache);
	}
}

RSPAMD_CONSTRUCTOR (rspamd_re_static_pool_ctor)
{
	global_re_cache = rspamd_regexp_cache_new ();
#ifdef WITH_PCRE2
	pcre2_ctx = pcre2_compile_context_create (NULL);
	pcre2_set_newline (pcre2_ctx, PCRE_FLAG(NEWLINE_ANY));
#endif
}

RSPAMD_DESTRUCTOR (rspamd_re_static_pool_dtor)
{
	rspamd_regexp_cache_destroy (global_re_cache);
#ifdef WITH_PCRE2
	pcre2_compile_context_free (pcre2_ctx);
#endif
}


void
rspamd_regexp_library_init (struct rspamd_config *cfg)
{
	if (cfg) {
		if (cfg->disable_pcre_jit) {
			can_jit = FALSE;
			check_jit = FALSE;
		}
		else if (!can_jit) {
			check_jit = TRUE;
		}
	}

	if (check_jit) {
#ifdef HAVE_PCRE_JIT
		gint jit, rc;
		gchar *str;

#ifndef WITH_PCRE2
			rc = pcre_config (PCRE_CONFIG_JIT, &jit);
#else
			rc = pcre2_config (PCRE2_CONFIG_JIT, &jit);
#endif

			if (rc == 0 && jit == 1) {
#ifndef WITH_PCRE2
#ifdef PCRE_CONFIG_JITTARGET
				pcre_config (PCRE_CONFIG_JITTARGET, &str);
				msg_info ("pcre is compiled with JIT for %s", str);
#else
				msg_info ("pcre is compiled with JIT for unknown target");
#endif
#else
				rc = pcre2_config (PCRE2_CONFIG_JITTARGET, NULL);

				if (rc > 0) {
					str = g_alloca (rc);
					pcre2_config (PCRE2_CONFIG_JITTARGET, str);
					msg_info ("pcre2 is compiled with JIT for %s", str);
				}
				else {
					msg_info ("pcre2 is compiled with JIT for unknown");
				}

#endif /* WITH_PCRE2 */

				if (getenv ("VALGRIND") == NULL) {
					can_jit = TRUE;
				} else {
					msg_info ("disabling PCRE jit as it does not play well with valgrind");
					can_jit = FALSE;
				}
			} else {
				msg_info ("pcre is compiled without JIT support, so many optimizations"
						  " are impossible");
				can_jit = FALSE;
			}
#else
		msg_info ("pcre is too old and has no JIT support, so many optimizations"
				  " are impossible");
		can_jit = FALSE;
#endif
		check_jit = FALSE;
	}
}

gpointer
rspamd_regexp_get_id (const rspamd_regexp_t *re)
{
	g_assert (re != NULL);

	return (gpointer)re->id;
}

gpointer
rspamd_regexp_get_class (const rspamd_regexp_t *re)
{
	g_assert (re != NULL);

	return re->re_class;
}

gpointer
rspamd_regexp_set_class (rspamd_regexp_t *re, gpointer re_class)
{
	gpointer old_class;

	g_assert (re != NULL);

	old_class = re->re_class;
	re->re_class = re_class;

	return old_class;
}

rspamd_regexp_t *
rspamd_regexp_from_glob (const gchar *gl, gsize sz, GError **err)
{
	GString *out;
	rspamd_regexp_t *re;
	const gchar *end;
	gboolean escaping = FALSE;
	gint nbraces = 0;

	g_assert (gl != NULL);

	if (sz == 0) {
		sz = strlen (gl);
	}

	end = gl + sz;
	out = g_string_sized_new (sz + 2);
	g_string_append_c (out, '^');

	while (gl < end) {
		switch (*gl) {
		case '*':
			if (escaping) {
				g_string_append (out, "\\*");
			}
			else {
				g_string_append (out, ".*");
			}

			escaping = FALSE;
			break;
		case '?':
			if (escaping) {
				g_string_append (out, "\\?");
			}
			else {
				g_string_append (out, ".");
			}

			escaping = FALSE;
			break;
		case '.':
		case '(':
		case ')':
		case '+':
		case '|':
		case '^':
		case '$':
		case '@':
		case '%':
			g_string_append_c (out, '\\');
			g_string_append_c (out, *gl);
			escaping = FALSE;
			break;
		case '\\':
			if (escaping) {
				g_string_append (out, "\\\\");
				escaping = FALSE;
			}
			else {
				escaping = TRUE;
			}
			break;
		case '{':
			if (escaping) {
				g_string_append (out, "\\{");
			}
			else {
				g_string_append_c (out, '(');
				nbraces++;
			}

			escaping = FALSE;
			break;
		case '}':
			if (nbraces > 0 && !escaping) {
				g_string_append_c (out, ')');
				nbraces--;
			}
			else if (escaping) {
				g_string_append (out, "\\}");
			}
			else {
				g_string_append (out, "}");
			}

			escaping = FALSE;
			break;
		case ',':
			if (nbraces > 0 && !escaping) {
				g_string_append_c (out, '|');
			}
			else if (escaping) {
				g_string_append (out, "\\,");
			}
			else {
				g_string_append_c (out, ',');
			}

			break;
		default:
			escaping = FALSE;
			g_string_append_c (out, *gl);
			break;
		}

		gl ++;
	}

	g_string_append_c (out, '$');
	re = rspamd_regexp_new (out->str, "i", err);
	g_string_free (out, TRUE);

	return re;
}
