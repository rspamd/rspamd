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
#include "libutil/multipattern.h"
#include "libutil/str_util.h"
#include "libcryptobox/cryptobox.h"

#ifdef WITH_HYPERSCAN
#include "logger.h"
#include "unix-std.h"
#include "hs.h"
#endif
#include "acism.h"
#include "libutil/regexp.h"
#include <stdalign.h>

#define MAX_SCRATCH 4

enum rspamd_hs_check_state {
	RSPAMD_HS_UNCHECKED = 0,
	RSPAMD_HS_SUPPORTED,
	RSPAMD_HS_UNSUPPORTED
};

static const char *hs_cache_dir = NULL;
static enum rspamd_hs_check_state hs_suitable_cpu = RSPAMD_HS_UNCHECKED;


struct RSPAMD_ALIGNED(64) rspamd_multipattern {
#ifdef WITH_HYPERSCAN
	rspamd_cryptobox_hash_state_t hash_state;
	hs_database_t *db;
	hs_scratch_t *scratch[MAX_SCRATCH];
	GArray *hs_pats;
	GArray *hs_ids;
	GArray *hs_flags;
	guint scratch_used;
#endif
	ac_trie_t *t;
	GArray *pats;
	GArray *res;

	gboolean compiled;
	guint cnt;
	enum rspamd_multipattern_flags flags;
};

static GQuark
rspamd_multipattern_quark (void)
{
	return g_quark_from_static_string ("multipattern");
}

static inline gboolean
rspamd_hs_check (void)
{
#ifdef WITH_HYPERSCAN
	if (G_UNLIKELY (hs_suitable_cpu == RSPAMD_HS_UNCHECKED)) {
		if (hs_valid_platform () == HS_SUCCESS) {
			hs_suitable_cpu = RSPAMD_HS_SUPPORTED;
		}
		else {
			hs_suitable_cpu = RSPAMD_HS_UNSUPPORTED;
		}
	}
#endif

	return hs_suitable_cpu == RSPAMD_HS_SUPPORTED;
}

void
rspamd_multipattern_library_init (const gchar *cache_dir)
{
	hs_cache_dir = cache_dir;
#ifdef WITH_HYPERSCAN
	rspamd_hs_check ();
#endif
}

#ifdef WITH_HYPERSCAN
static gchar *
rspamd_multipattern_escape_tld_hyperscan (const gchar *pattern, gsize slen,
		gsize *dst_len)
{
	gsize len;
	const gchar *p, *prefix, *suffix;
	gchar *res;

	/*
	 * We understand the following cases
	 * 1) blah -> .blah\b
	 * 2) *.blah -> ..*\\.blah\b|$
	 * 3) ???
	 */

	if (pattern[0] == '*') {
		p = strchr (pattern, '.');

		if (p == NULL) {
			/* XXX: bad */
			p = pattern;
		}
		else {
			p ++;
		}

		prefix = "\\.";
		len = slen + strlen (prefix);
	}
	else {
		prefix = "\\.";
		p = pattern;
		len = slen + strlen (prefix);
	}

	suffix = "(:?\\b|$)";
	len += strlen (suffix);

	res = g_malloc (len + 1);
	slen = rspamd_strlcpy (res, prefix, len + 1);
	slen += rspamd_strlcpy (res + slen, p, len + 1 - slen);
	slen += rspamd_strlcpy (res + slen, suffix, len + 1 - slen);

	*dst_len = slen;

	return res;
}

#endif
static gchar *
rspamd_multipattern_escape_tld_acism (const gchar *pattern, gsize len,
		gsize *dst_len)
{
	gsize dlen, slen;
	const gchar *p, *prefix;
	gchar *res;

	/*
	 * We understand the following cases
	 * 1) blah -> \\.blah
	 * 2) *.blah -> \\..*\\.blah
	 * 3) ???
	 */
	slen = len;

	if (pattern[0] == '*') {
		dlen = slen;
		p = memchr (pattern, '.', len);

		if (p == NULL) {
			/* XXX: bad */
			p = pattern;
		}
		else {
			p ++;
		}

		dlen -= p - pattern;
		prefix = ".";
		dlen ++;
	}
	else {
		dlen = slen + 1;
		prefix = ".";
		p = pattern;
	}

	res = g_malloc (dlen + 1);
	slen = strlen (prefix);
	memcpy (res, prefix, slen);
	rspamd_strlcpy (res + slen, p, dlen - slen + 1);

	*dst_len = dlen;

	return res;
}

/*
 * Escapes special characters from specific pattern
 */
static gchar *
rspamd_multipattern_pattern_filter (const gchar *pattern, gsize len,
		enum rspamd_multipattern_flags flags,
		gsize *dst_len)
{
	gchar *ret = NULL;
	gint gl_flags = RSPAMD_REGEXP_ESCAPE_ASCII;

	if (flags & RSPAMD_MULTIPATTERN_UTF8) {
		gl_flags |= RSPAMD_REGEXP_ESCAPE_UTF;
	}

#ifdef WITH_HYPERSCAN
	if (rspamd_hs_check ()) {
		if (flags & RSPAMD_MULTIPATTERN_TLD) {
			gchar *tmp;
			gsize tlen;
			tmp = rspamd_multipattern_escape_tld_hyperscan (pattern, len, &tlen);

			ret = rspamd_str_regexp_escape (tmp, tlen, dst_len,
					gl_flags|RSPAMD_REGEXP_ESCAPE_RE);
			g_free (tmp);
		}
		else if (flags & RSPAMD_MULTIPATTERN_RE) {
			ret = rspamd_str_regexp_escape (pattern, len, dst_len, gl_flags |
					RSPAMD_REGEXP_ESCAPE_RE);
		}
		else if (flags & RSPAMD_MULTIPATTERN_GLOB) {
			ret = rspamd_str_regexp_escape (pattern, len, dst_len,
					gl_flags | RSPAMD_REGEXP_ESCAPE_GLOB);
		}
		else {
			ret = rspamd_str_regexp_escape (pattern, len, dst_len, gl_flags);
		}

		return ret;
	}
#endif

	if (flags & RSPAMD_MULTIPATTERN_TLD) {
		ret = rspamd_multipattern_escape_tld_acism (pattern, len, dst_len);
	}
	else if (flags & RSPAMD_MULTIPATTERN_RE) {
		ret = rspamd_str_regexp_escape (pattern, len, dst_len, gl_flags |
															   RSPAMD_REGEXP_ESCAPE_RE);
	}
	else if (flags & RSPAMD_MULTIPATTERN_GLOB) {
		ret = rspamd_str_regexp_escape (pattern, len, dst_len,
				gl_flags | RSPAMD_REGEXP_ESCAPE_GLOB);
	}
	else {
		ret = malloc (len + 1);
		*dst_len = rspamd_strlcpy (ret, pattern, len + 1);
	}

	return ret;
}

struct rspamd_multipattern *
rspamd_multipattern_create (enum rspamd_multipattern_flags flags)
{
	struct rspamd_multipattern *mp;

	/* Align due to blake2b state */
	(void) !posix_memalign((void **)&mp, _Alignof (struct rspamd_multipattern),
			sizeof (*mp));
	g_assert (mp != NULL);
	memset (mp, 0, sizeof (*mp));
	mp->flags = flags;

#ifdef WITH_HYPERSCAN
	if (rspamd_hs_check ()) {
		mp->hs_pats = g_array_new (FALSE, TRUE, sizeof (gchar *));
		mp->hs_flags = g_array_new (FALSE, TRUE, sizeof (gint));
		mp->hs_ids = g_array_new (FALSE, TRUE, sizeof (gint));
		rspamd_cryptobox_hash_init (&mp->hash_state, NULL, 0);

		return mp;
	}
#endif

	mp->pats = g_array_new (FALSE, TRUE, sizeof (ac_trie_pat_t));

	return mp;
}

struct rspamd_multipattern *
rspamd_multipattern_create_sized (guint npatterns,
		enum rspamd_multipattern_flags flags)
{
	struct rspamd_multipattern *mp;

	/* Align due to blake2b state */
	(void) !posix_memalign((void **)&mp, _Alignof (struct rspamd_multipattern), sizeof (*mp));
	g_assert (mp != NULL);
	memset (mp, 0, sizeof (*mp));
	mp->flags = flags;

#ifdef WITH_HYPERSCAN
	if (rspamd_hs_check ()) {
		mp->hs_pats = g_array_sized_new (FALSE, TRUE, sizeof (gchar *), npatterns);
		mp->hs_flags = g_array_sized_new (FALSE, TRUE, sizeof (gint), npatterns);
		mp->hs_ids = g_array_sized_new (FALSE, TRUE, sizeof (gint), npatterns);
		rspamd_cryptobox_hash_init (&mp->hash_state, NULL, 0);

		return mp;
	}
#endif

	mp->pats = g_array_sized_new (FALSE, TRUE, sizeof (ac_trie_pat_t), npatterns);

	return mp;
}

void
rspamd_multipattern_add_pattern (struct rspamd_multipattern *mp,
		const gchar *pattern, gint flags)
{
	g_assert (pattern != NULL);

	rspamd_multipattern_add_pattern_len (mp, pattern, strlen (pattern), flags);
}

void
rspamd_multipattern_add_pattern_len (struct rspamd_multipattern *mp,
		const gchar *pattern, gsize patlen, gint flags)
{
	gsize dlen;

	g_assert (pattern != NULL);
	g_assert (mp != NULL);
	g_assert (!mp->compiled);

#ifdef WITH_HYPERSCAN
	if (rspamd_hs_check ()) {
		gchar *np;
		gint fl = HS_FLAG_SOM_LEFTMOST;
		gint adjusted_flags = mp->flags | flags;

		if (adjusted_flags & RSPAMD_MULTIPATTERN_ICASE) {
			fl |= HS_FLAG_CASELESS;
		}
		if (adjusted_flags & RSPAMD_MULTIPATTERN_UTF8) {
			if (adjusted_flags & RSPAMD_MULTIPATTERN_TLD) {
				fl |= HS_FLAG_UTF8;
			}
			else {
				fl |= HS_FLAG_UTF8 | HS_FLAG_UCP;
			}
		}
		if (adjusted_flags & RSPAMD_MULTIPATTERN_DOTALL) {
			fl |= HS_FLAG_DOTALL;
		}
		if (adjusted_flags & RSPAMD_MULTIPATTERN_SINGLEMATCH) {
			fl |= HS_FLAG_SINGLEMATCH;
			fl &= ~HS_FLAG_SOM_LEFTMOST; /* According to hyperscan docs */
		}
		if (adjusted_flags & RSPAMD_MULTIPATTERN_NO_START) {
			fl &= ~HS_FLAG_SOM_LEFTMOST;
		}

		g_array_append_val (mp->hs_flags, fl);
		np = rspamd_multipattern_pattern_filter (pattern, patlen, flags, &dlen);
		g_array_append_val (mp->hs_pats, np);
		fl = mp->cnt;
		g_array_append_val (mp->hs_ids, fl);
		rspamd_cryptobox_hash_update (&mp->hash_state, np, dlen);

		mp->cnt ++;

		return;
	}
#endif
	ac_trie_pat_t pat;

	pat.ptr = rspamd_multipattern_pattern_filter (pattern, patlen, flags, &dlen);
	pat.len = dlen;

	g_array_append_val (mp->pats, pat);

	mp->cnt ++;
}

struct rspamd_multipattern *
rspamd_multipattern_create_full (const gchar **patterns,
		guint npatterns, enum rspamd_multipattern_flags flags)
{
	struct rspamd_multipattern *mp;
	guint i;

	g_assert (npatterns > 0);
	g_assert (patterns != NULL);

	mp = rspamd_multipattern_create_sized (npatterns, flags);

	for (i = 0; i < npatterns; i++) {
		rspamd_multipattern_add_pattern (mp, patterns[i], flags);
	}

	return mp;
}

#ifdef WITH_HYPERSCAN
static gboolean
rspamd_multipattern_try_load_hs (struct rspamd_multipattern *mp,
		const guchar *hash)
{
	gchar fp[PATH_MAX];
	gpointer map;
	gsize len;

	if (hs_cache_dir == NULL) {
		return FALSE;
	}

	rspamd_snprintf (fp, sizeof (fp), "%s/%*xs.hsmp", hs_cache_dir,
			(gint)rspamd_cryptobox_HASHBYTES / 2, hash);

	if ((map = rspamd_file_xmap (fp, PROT_READ, &len, TRUE)) != NULL) {
		if (hs_deserialize_database (map, len, &mp->db) == HS_SUCCESS) {
			munmap (map, len);
			return TRUE;
		}

		munmap (map, len);
		/* Remove stale file */
		(void)unlink (fp);
	}

	return FALSE;
}

static void
rspamd_multipattern_try_save_hs (struct rspamd_multipattern *mp,
		const guchar *hash)
{
	gchar fp[PATH_MAX], np[PATH_MAX];
	char *bytes = NULL;
	gsize len;
	gint fd;

	if (hs_cache_dir == NULL) {
		return;
	}

	rspamd_snprintf (fp, sizeof (fp), "%s/%*xs.hsmp.tmp", hs_cache_dir,
			(gint)rspamd_cryptobox_HASHBYTES / 2, hash);

	if ((fd = rspamd_file_xopen (fp, O_WRONLY | O_CREAT | O_EXCL, 00644, 0)) != -1) {
		if (hs_serialize_database (mp->db, &bytes, &len) == HS_SUCCESS) {
			if (write (fd, bytes, len) == -1) {
				msg_warn ("cannot write hyperscan cache to %s: %s",
						fp, strerror (errno));
				unlink (fp);
				free (bytes);
			}
			else {
				free (bytes);
				fsync (fd);

				rspamd_snprintf (np, sizeof (np), "%s/%*xs.hsmp", hs_cache_dir,
						(gint)rspamd_cryptobox_HASHBYTES / 2, hash);

				if (rename (fp, np) == -1) {
					msg_warn ("cannot rename hyperscan cache from %s to %s: %s",
							fp, np, strerror (errno));
					unlink (fp);
				}
			}
		}
		else {
			msg_warn ("cannot serialize hyperscan cache to %s: %s",
					fp, strerror (errno));
			unlink (fp);
		}


		close (fd);
	}
}
#endif

gboolean
rspamd_multipattern_compile (struct rspamd_multipattern *mp, GError **err)
{
	g_assert (mp != NULL);
	g_assert (!mp->compiled);

#ifdef WITH_HYPERSCAN
	if (rspamd_hs_check ()) {
		guint i;
		hs_platform_info_t plt;
		hs_compile_error_t *hs_errors;
		guchar hash[rspamd_cryptobox_HASHBYTES];

		if (mp->cnt > 0) {
			g_assert (hs_populate_platform (&plt) == HS_SUCCESS);
			rspamd_cryptobox_hash_update (&mp->hash_state, (void *)&plt, sizeof (plt));
			rspamd_cryptobox_hash_final (&mp->hash_state, hash);

			if (!rspamd_multipattern_try_load_hs (mp, hash)) {
				if (hs_compile_multi ((const char *const *)mp->hs_pats->data,
						(const unsigned int *)mp->hs_flags->data,
						(const unsigned int *)mp->hs_ids->data,
						mp->cnt,
						HS_MODE_BLOCK,
						&plt,
						&mp->db,
						&hs_errors) != HS_SUCCESS) {

					g_set_error (err, rspamd_multipattern_quark (), EINVAL,
							"cannot create tree of regexp when processing '%s': %s",
							g_array_index (mp->hs_pats, char *, hs_errors->expression),
							hs_errors->message);
					hs_free_compile_error (hs_errors);

					return FALSE;
				}
			}

			rspamd_multipattern_try_save_hs (mp, hash);

			for (i = 0; i < MAX_SCRATCH; i ++) {
				g_assert (hs_alloc_scratch (mp->db, &mp->scratch[i]) == HS_SUCCESS);
			}
		}

		mp->compiled = TRUE;

		return TRUE;
	}
#endif

	if (mp->cnt > 0) {

		if (mp->flags & (RSPAMD_MULTIPATTERN_GLOB|RSPAMD_MULTIPATTERN_RE)) {
			/* Fallback to pcre... */
			rspamd_regexp_t *re;
			mp->res = g_array_sized_new (FALSE, TRUE,
					sizeof (rspamd_regexp_t *), mp->cnt);

			for (guint i = 0; i < mp->cnt; i ++) {
				const ac_trie_pat_t *pat;
				const gchar *pat_flags = NULL;

				if (mp->flags & RSPAMD_MULTIPATTERN_UTF8) {
					pat_flags = "u";
				}

				pat = &g_array_index (mp->pats, ac_trie_pat_t, i);
				re = rspamd_regexp_new (pat->ptr, pat_flags, err);

				if (re == NULL) {
					return FALSE;
				}

				g_array_append_val (mp->res, re);
			}
		}
		else {
			mp->t = acism_create ((const ac_trie_pat_t *) mp->pats->data, mp->cnt);
		}
	}

	mp->compiled = TRUE;

	return TRUE;
}

struct rspamd_multipattern_cbdata {
	struct rspamd_multipattern *mp;
	const gchar *in;
	gsize len;
	rspamd_multipattern_cb_t cb;
	gpointer ud;
	guint nfound;
	gint ret;
};

#ifdef WITH_HYPERSCAN
static gint
rspamd_multipattern_hs_cb (unsigned int id,
		unsigned long long from,
		unsigned long long to,
		unsigned int flags,
		void *ud)
{
	struct rspamd_multipattern_cbdata *cbd = ud;
	gint ret = 0;

	if (to > 0) {

		if (from == HS_OFFSET_PAST_HORIZON) {
			from = 0;
		}

		ret = cbd->cb (cbd->mp, id, from, to, cbd->in, cbd->len, cbd->ud);

		cbd->nfound ++;
		cbd->ret = ret;
	}

	return ret;
}
#endif

static gint
rspamd_multipattern_acism_cb (int strnum, int textpos, void *context)
{
	struct rspamd_multipattern_cbdata *cbd = context;
	gint ret;
	ac_trie_pat_t pat;

	pat = g_array_index (cbd->mp->pats, ac_trie_pat_t, strnum);
	ret = cbd->cb (cbd->mp, strnum, textpos - pat.len,
			textpos, cbd->in, cbd->len, cbd->ud);

	cbd->nfound ++;
	cbd->ret = ret;

	return ret;
}

gint
rspamd_multipattern_lookup (struct rspamd_multipattern *mp,
		const gchar *in, gsize len, rspamd_multipattern_cb_t cb,
		gpointer ud, guint *pnfound)
{
	struct rspamd_multipattern_cbdata cbd;
	gint ret = 0;

	g_assert (mp != NULL);

	if (mp->cnt == 0 || !mp->compiled || len == 0) {
		return 0;
	}

	cbd.mp = mp;
	cbd.in = in;
	cbd.len = len;
	cbd.cb = cb;
	cbd.ud = ud;
	cbd.nfound = 0;
	cbd.ret = 0;

#ifdef WITH_HYPERSCAN
	if (rspamd_hs_check ()) {
		hs_scratch_t *scr = NULL;
		guint i;

		for (i = 0; i < MAX_SCRATCH; i ++) {
			if (!(mp->scratch_used & (1 << i))) {
				mp->scratch_used |= (1 << i);
				scr = mp->scratch[i];
				break;
			}
		}

		g_assert (scr != NULL);

		ret = hs_scan (mp->db, in, len, 0, scr,
				rspamd_multipattern_hs_cb, &cbd);

		mp->scratch_used &= ~(1 << i);

		if (ret == HS_SUCCESS) {
			ret = 0;
		}
		else if (ret == HS_SCAN_TERMINATED) {
			ret = cbd.ret;
		}

		if (pnfound) {
			*pnfound = cbd.nfound;
		}

		return ret;
	}
#endif

	gint state = 0;

	if (mp->flags & (RSPAMD_MULTIPATTERN_GLOB|RSPAMD_MULTIPATTERN_RE)) {
		/* Terribly inefficient, but who cares - just use hyperscan */
		for (guint i = 0; i < mp->cnt; i ++) {
			rspamd_regexp_t *re = g_array_index (mp->res, rspamd_regexp_t *, i);
			const gchar *start = NULL, *end = NULL;

			while (rspamd_regexp_search (re,
					in,
					len,
					&start,
					&end,
					TRUE,
					NULL)) {
				if (rspamd_multipattern_acism_cb (i, end - in, &cbd)) {
					goto out;
				}
			}
		}
out:
		ret = cbd.ret;

		if (pnfound) {
			*pnfound = cbd.nfound;
		}
	}
	else {
		/* Plain trie */
		ret = acism_lookup (mp->t, in, len, rspamd_multipattern_acism_cb, &cbd,
				&state, mp->flags & RSPAMD_MULTIPATTERN_ICASE);

		if (pnfound) {
			*pnfound = cbd.nfound;
		}
	}

	return ret;
}


void
rspamd_multipattern_destroy (struct rspamd_multipattern *mp)
{
	guint i;

	if (mp) {
#ifdef WITH_HYPERSCAN
		if (rspamd_hs_check ()) {
			gchar *p;

			if (mp->compiled && mp->cnt > 0) {
				for (i = 0; i < MAX_SCRATCH; i ++) {
					hs_free_scratch (mp->scratch[i]);
				}

				hs_free_database (mp->db);
			}

			for (i = 0; i < mp->cnt; i ++) {
				p = g_array_index (mp->hs_pats, gchar *, i);
				g_free (p);
			}

			g_array_free (mp->hs_pats, TRUE);
			g_array_free (mp->hs_ids, TRUE);
			g_array_free (mp->hs_flags, TRUE);
			free (mp); /* Due to posix_memalign */

			return;
		}
#endif
		ac_trie_pat_t pat;

		if (mp->compiled && mp->cnt > 0) {
			acism_destroy (mp->t);
		}

		for (i = 0; i < mp->cnt; i ++) {
			pat = g_array_index (mp->pats, ac_trie_pat_t, i);
			g_free ((gchar *)pat.ptr);
		}

		g_array_free (mp->pats, TRUE);

		g_free (mp);
	}
}

const gchar*
rspamd_multipattern_get_pattern (struct rspamd_multipattern *mp,
		guint index)
{
	g_assert (mp != NULL);
	g_assert (index < mp->cnt);

#ifdef WITH_HYPERSCAN
	if (rspamd_hs_check ()) {
		return g_array_index (mp->hs_pats, gchar *, index);
	}
#endif

	ac_trie_pat_t pat;

	pat = g_array_index (mp->pats, ac_trie_pat_t, index);

	return pat.ptr;
}

guint
rspamd_multipattern_get_npatterns (struct rspamd_multipattern *mp)
{
	g_assert (mp != NULL);

	return mp->cnt;
}

gboolean
rspamd_multipattern_has_hyperscan (void)
{
	return rspamd_hs_check ();
}
