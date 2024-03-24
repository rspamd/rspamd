/*
 * Copyright 2024 Vsevolod Stakhov
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
#include "libutil/multipattern.h"
#include "libutil/str_util.h"
#include "libcryptobox/cryptobox.h"

#ifdef WITH_HYPERSCAN
#include "logger.h"
#include "unix-std.h"
#include "hs.h"
#include "libserver/hyperscan_tools.h"
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
	rspamd_hyperscan_t *hs_db;
	hs_scratch_t *scratch[MAX_SCRATCH];
	GArray *hs_pats;
	GArray *hs_ids;
	GArray *hs_flags;
	unsigned int scratch_used;
#endif
	ac_trie_t *t;
	GArray *pats;
	GArray *res;

	gboolean compiled;
	unsigned int cnt;
	enum rspamd_multipattern_flags flags;
};

static GQuark
rspamd_multipattern_quark(void)
{
	return g_quark_from_static_string("multipattern");
}

static inline gboolean
rspamd_hs_check(void)
{
#ifdef WITH_HYPERSCAN
	if (G_UNLIKELY(hs_suitable_cpu == RSPAMD_HS_UNCHECKED)) {
		if (hs_valid_platform() == HS_SUCCESS) {
			hs_suitable_cpu = RSPAMD_HS_SUPPORTED;
		}
		else {
			hs_suitable_cpu = RSPAMD_HS_UNSUPPORTED;
		}
	}
#endif

	return hs_suitable_cpu == RSPAMD_HS_SUPPORTED;
}

void rspamd_multipattern_library_init(const char *cache_dir)
{
	hs_cache_dir = cache_dir;
#ifdef WITH_HYPERSCAN
	rspamd_hs_check();
#endif
}

#ifdef WITH_HYPERSCAN
static char *
rspamd_multipattern_escape_tld_hyperscan(const char *pattern, gsize slen,
										 gsize *dst_len)
{
	gsize len;
	const char *p, *prefix, *suffix;
	char *res;

	/*
	 * We understand the following cases
	 * 1) blah -> .blah\b
	 * 2) *.blah -> ..*\\.blah\b|$
	 * 3) ???
	 */

	if (pattern[0] == '*') {
		p = strchr(pattern, '.');

		if (p == NULL) {
			/* XXX: bad */
			p = pattern;
		}
		else {
			p++;
		}

		prefix = "\\.";
		len = slen + strlen(prefix);
	}
	else {
		prefix = "\\.";
		p = pattern;
		len = slen + strlen(prefix);
	}

	suffix = "(:?\\b|$)";
	len += strlen(suffix);

	res = g_malloc(len + 1);
	slen = rspamd_strlcpy(res, prefix, len + 1);
	slen += rspamd_strlcpy(res + slen, p, len + 1 - slen);
	slen += rspamd_strlcpy(res + slen, suffix, len + 1 - slen);

	*dst_len = slen;

	return res;
}

#endif
static char *
rspamd_multipattern_escape_tld_acism(const char *pattern, gsize len,
									 gsize *dst_len)
{
	gsize dlen, slen;
	const char *p, *prefix;
	char *res;

	/*
	 * We understand the following cases
	 * 1) blah -> \\.blah
	 * 2) *.blah -> \\..*\\.blah
	 * 3) ???
	 */
	slen = len;

	if (pattern[0] == '*') {
		dlen = slen;
		p = memchr(pattern, '.', len);

		if (p == NULL) {
			/* XXX: bad */
			p = pattern;
		}
		else {
			p++;
		}

		dlen -= p - pattern;
		prefix = ".";
		dlen++;
	}
	else {
		dlen = slen + 1;
		prefix = ".";
		p = pattern;
	}

	res = g_malloc(dlen + 1);
	slen = strlen(prefix);
	memcpy(res, prefix, slen);
	rspamd_strlcpy(res + slen, p, dlen - slen + 1);

	*dst_len = dlen;

	return res;
}

/*
 * Escapes special characters from specific pattern
 */
static char *
rspamd_multipattern_pattern_filter(const char *pattern, gsize len,
								   enum rspamd_multipattern_flags flags,
								   gsize *dst_len)
{
	char *ret = NULL;
	int gl_flags = RSPAMD_REGEXP_ESCAPE_ASCII;

	if (flags & RSPAMD_MULTIPATTERN_UTF8) {
		gl_flags |= RSPAMD_REGEXP_ESCAPE_UTF;
	}

#ifdef WITH_HYPERSCAN
	if (rspamd_hs_check()) {
		if (flags & RSPAMD_MULTIPATTERN_TLD) {
			char *tmp;
			gsize tlen;
			tmp = rspamd_multipattern_escape_tld_hyperscan(pattern, len, &tlen);

			ret = rspamd_str_regexp_escape(tmp, tlen, dst_len,
										   gl_flags | RSPAMD_REGEXP_ESCAPE_RE);
			g_free(tmp);
		}
		else if (flags & RSPAMD_MULTIPATTERN_RE) {
			ret = rspamd_str_regexp_escape(pattern, len, dst_len, gl_flags | RSPAMD_REGEXP_ESCAPE_RE);
		}
		else if (flags & RSPAMD_MULTIPATTERN_GLOB) {
			ret = rspamd_str_regexp_escape(pattern, len, dst_len,
										   gl_flags | RSPAMD_REGEXP_ESCAPE_GLOB);
		}
		else {
			ret = rspamd_str_regexp_escape(pattern, len, dst_len, gl_flags);
		}

		return ret;
	}
#endif

	if (flags & RSPAMD_MULTIPATTERN_TLD) {
		ret = rspamd_multipattern_escape_tld_acism(pattern, len, dst_len);
	}
	else if (flags & RSPAMD_MULTIPATTERN_RE) {
		ret = rspamd_str_regexp_escape(pattern, len, dst_len, gl_flags | RSPAMD_REGEXP_ESCAPE_RE);
	}
	else if (flags & RSPAMD_MULTIPATTERN_GLOB) {
		ret = rspamd_str_regexp_escape(pattern, len, dst_len,
									   gl_flags | RSPAMD_REGEXP_ESCAPE_GLOB);
	}
	else {
		ret = malloc(len + 1);
		*dst_len = rspamd_strlcpy(ret, pattern, len + 1);
	}

	return ret;
}

struct rspamd_multipattern *
rspamd_multipattern_create(enum rspamd_multipattern_flags flags)
{
	struct rspamd_multipattern *mp;

	/* Align due to blake2b state */
	(void) !posix_memalign((void **) &mp, RSPAMD_ALIGNOF(struct rspamd_multipattern),
						   sizeof(*mp));
	g_assert(mp != NULL);
	memset(mp, 0, sizeof(*mp));
	mp->flags = flags;

#ifdef WITH_HYPERSCAN
	if (rspamd_hs_check()) {
		mp->hs_pats = g_array_new(FALSE, TRUE, sizeof(char *));
		mp->hs_flags = g_array_new(FALSE, TRUE, sizeof(int));
		mp->hs_ids = g_array_new(FALSE, TRUE, sizeof(int));
		rspamd_cryptobox_hash_init(&mp->hash_state, NULL, 0);

		return mp;
	}
#endif

	mp->pats = g_array_new(FALSE, TRUE, sizeof(ac_trie_pat_t));

	return mp;
}

struct rspamd_multipattern *
rspamd_multipattern_create_sized(unsigned int npatterns,
								 enum rspamd_multipattern_flags flags)
{
	struct rspamd_multipattern *mp;

	/* Align due to blake2b state */
	(void) !posix_memalign((void **) &mp, RSPAMD_ALIGNOF(struct rspamd_multipattern), sizeof(*mp));
	g_assert(mp != NULL);
	memset(mp, 0, sizeof(*mp));
	mp->flags = flags;

#ifdef WITH_HYPERSCAN
	if (rspamd_hs_check()) {
		mp->hs_pats = g_array_sized_new(FALSE, TRUE, sizeof(char *), npatterns);
		mp->hs_flags = g_array_sized_new(FALSE, TRUE, sizeof(int), npatterns);
		mp->hs_ids = g_array_sized_new(FALSE, TRUE, sizeof(int), npatterns);
		rspamd_cryptobox_hash_init(&mp->hash_state, NULL, 0);

		return mp;
	}
#endif

	mp->pats = g_array_sized_new(FALSE, TRUE, sizeof(ac_trie_pat_t), npatterns);

	return mp;
}

void rspamd_multipattern_add_pattern(struct rspamd_multipattern *mp,
									 const char *pattern, int flags)
{
	g_assert(pattern != NULL);

	rspamd_multipattern_add_pattern_len(mp, pattern, strlen(pattern), flags);
}

void rspamd_multipattern_add_pattern_len(struct rspamd_multipattern *mp,
										 const char *pattern, gsize patlen, int flags)
{
	gsize dlen;

	g_assert(pattern != NULL);
	g_assert(mp != NULL);
	g_assert(!mp->compiled);

#ifdef WITH_HYPERSCAN
	if (rspamd_hs_check()) {
		char *np;
		int fl = HS_FLAG_SOM_LEFTMOST;
		int adjusted_flags = mp->flags | flags;

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

		g_array_append_val(mp->hs_flags, fl);
		np = rspamd_multipattern_pattern_filter(pattern, patlen, flags, &dlen);
		g_array_append_val(mp->hs_pats, np);
		fl = mp->cnt;
		g_array_append_val(mp->hs_ids, fl);
		rspamd_cryptobox_hash_update(&mp->hash_state, np, dlen);

		mp->cnt++;

		return;
	}
#endif
	ac_trie_pat_t pat;

	pat.ptr = rspamd_multipattern_pattern_filter(pattern, patlen, flags, &dlen);
	pat.len = dlen;

	g_array_append_val(mp->pats, pat);

	mp->cnt++;
}

struct rspamd_multipattern *
rspamd_multipattern_create_full(const char **patterns,
								unsigned int npatterns, enum rspamd_multipattern_flags flags)
{
	struct rspamd_multipattern *mp;
	unsigned int i;

	g_assert(npatterns > 0);
	g_assert(patterns != NULL);

	mp = rspamd_multipattern_create_sized(npatterns, flags);

	for (i = 0; i < npatterns; i++) {
		rspamd_multipattern_add_pattern(mp, patterns[i], flags);
	}

	return mp;
}

#ifdef WITH_HYPERSCAN
static gboolean
rspamd_multipattern_try_load_hs(struct rspamd_multipattern *mp,
								const unsigned char *hash)
{
	char fp[PATH_MAX];

	if (hs_cache_dir == NULL) {
		return FALSE;
	}

	rspamd_snprintf(fp, sizeof(fp), "%s/%*xs.hsmp", hs_cache_dir,
					(int) rspamd_cryptobox_HASHBYTES / 2, hash);
	mp->hs_db = rspamd_hyperscan_maybe_load(fp, 0);

	return mp->hs_db != NULL;
}

static void
rspamd_multipattern_try_save_hs(struct rspamd_multipattern *mp,
								const unsigned char *hash)
{
	char fp[PATH_MAX], np[PATH_MAX];
	char *bytes = NULL;
	gsize len;
	int fd;

	if (hs_cache_dir == NULL) {
		return;
	}

	rspamd_snprintf(fp, sizeof(fp), "%s%shsmp-XXXXXXXXXXXXX", G_DIR_SEPARATOR_S,
					hs_cache_dir);

	if ((fd = g_mkstemp_full(fp, O_CREAT | O_EXCL | O_WRONLY, 00644)) != -1) {
		int ret;
		if ((ret = hs_serialize_database(rspamd_hyperscan_get_database(mp->hs_db), &bytes, &len)) == HS_SUCCESS) {
			if (write(fd, bytes, len) == -1) {
				msg_warn("cannot write hyperscan cache to %s: %s",
						 fp, strerror(errno));
				unlink(fp);
				free(bytes);
			}
			else {
				free(bytes);
				fsync(fd);

				rspamd_snprintf(np, sizeof(np), "%s/%*xs.hsmp", hs_cache_dir,
								(int) rspamd_cryptobox_HASHBYTES / 2, hash);

				if (rename(fp, np) == -1) {
					msg_warn("cannot rename hyperscan cache from %s to %s: %s",
							 fp, np, strerror(errno));
					unlink(fp);
				}
				else {
					rspamd_hyperscan_notice_known(np);
				}
			}
		}
		else {
			msg_warn("cannot serialize hyperscan cache to %s: error code %d",
					 fp, ret);
			unlink(fp);
		}


		close(fd);
	}
	else {
		msg_warn("cannot open a temp file %s to write hyperscan cache: %s", fp, strerror(errno));
	}
}
#endif

gboolean
rspamd_multipattern_compile(struct rspamd_multipattern *mp, int flags, GError **err)
{
	g_assert(mp != NULL);
	g_assert(!mp->compiled);

#ifdef WITH_HYPERSCAN
	if (rspamd_hs_check()) {
		unsigned int i;
		hs_platform_info_t plt;
		hs_compile_error_t *hs_errors;
		unsigned char hash[rspamd_cryptobox_HASHBYTES];

		if (mp->cnt > 0) {
			g_assert(hs_populate_platform(&plt) == HS_SUCCESS);
			rspamd_cryptobox_hash_update(&mp->hash_state, (void *) &plt, sizeof(plt));
			rspamd_cryptobox_hash_final(&mp->hash_state, hash);

			if ((flags & RSPAMD_MULTIPATTERN_COMPILE_NO_FS) || !rspamd_multipattern_try_load_hs(mp, hash)) {
				hs_database_t *db = NULL;

				if (hs_compile_multi((const char *const *) mp->hs_pats->data,
									 (const unsigned int *) mp->hs_flags->data,
									 (const unsigned int *) mp->hs_ids->data,
									 mp->cnt,
									 HS_MODE_BLOCK,
									 &plt,
									 &db,
									 &hs_errors) != HS_SUCCESS) {

					g_set_error(err, rspamd_multipattern_quark(), EINVAL,
								"cannot create tree of regexp when processing '%s': %s",
								g_array_index(mp->hs_pats, char *, hs_errors->expression),
								hs_errors->message);
					hs_free_compile_error(hs_errors);

					return FALSE;
				}

				if (!(flags & RSPAMD_MULTIPATTERN_COMPILE_NO_FS)) {
					if (hs_cache_dir != NULL) {
						char fpath[PATH_MAX];
						rspamd_snprintf(fpath, sizeof(fpath), "%s/%*xs.hsmp", hs_cache_dir,
										(int) rspamd_cryptobox_HASHBYTES / 2, hash);
						mp->hs_db = rspamd_hyperscan_from_raw_db(db, fpath);
					}
					else {
						/* Should not happen in the real life */
						mp->hs_db = rspamd_hyperscan_from_raw_db(db, NULL);
					}

					rspamd_multipattern_try_save_hs(mp, hash);
				}
				else {
					mp->hs_db = rspamd_hyperscan_from_raw_db(db, NULL);
				}
			}

			for (i = 0; i < MAX_SCRATCH; i++) {
				mp->scratch[i] = NULL;
			}

			for (i = 0; i < MAX_SCRATCH; i++) {
				int ret;

				if ((ret = hs_alloc_scratch(rspamd_hyperscan_get_database(mp->hs_db), &mp->scratch[i])) != HS_SUCCESS) {
					msg_err("cannot allocate scratch space for hyperscan: error code %d", ret);

					/* Clean all scratches that are non-NULL */
					for (int ii = 0; ii < MAX_SCRATCH; ii++) {
						if (mp->scratch[ii] != NULL) {
							hs_free_scratch(mp->scratch[ii]);
						}
					}
					g_set_error(err, rspamd_multipattern_quark(), EINVAL,
								"cannot allocate scratch space for hyperscan: error code %d", ret);

					rspamd_hyperscan_free(mp->hs_db, true);
					mp->hs_db = NULL;

					return FALSE;
				}
			}
		}

		mp->compiled = TRUE;

		return TRUE;
	}
#endif

	if (mp->cnt > 0) {

		if (mp->flags & (RSPAMD_MULTIPATTERN_GLOB | RSPAMD_MULTIPATTERN_RE)) {
			/* Fallback to pcre... */
			rspamd_regexp_t *re;
			mp->res = g_array_sized_new(FALSE, TRUE,
										sizeof(rspamd_regexp_t *), mp->cnt);

			for (unsigned int i = 0; i < mp->cnt; i++) {
				const ac_trie_pat_t *pat;
				const char *pat_flags = NULL;

				if (mp->flags & RSPAMD_MULTIPATTERN_UTF8) {
					pat_flags = "u";
				}

				pat = &g_array_index(mp->pats, ac_trie_pat_t, i);
				re = rspamd_regexp_new(pat->ptr, pat_flags, err);

				if (re == NULL) {
					return FALSE;
				}

				g_array_append_val(mp->res, re);
			}
		}
		else {
			mp->t = acism_create((const ac_trie_pat_t *) mp->pats->data, mp->cnt);
		}
	}

	mp->compiled = TRUE;

	return TRUE;
}

struct rspamd_multipattern_cbdata {
	struct rspamd_multipattern *mp;
	const char *in;
	gsize len;
	rspamd_multipattern_cb_t cb;
	gpointer ud;
	unsigned int nfound;
	int ret;
};

#ifdef WITH_HYPERSCAN
static int
rspamd_multipattern_hs_cb(unsigned int id,
						  unsigned long long from,
						  unsigned long long to,
						  unsigned int flags,
						  void *ud)
{
	struct rspamd_multipattern_cbdata *cbd = ud;
	int ret = 0;

	if (to > 0) {

		if (from == HS_OFFSET_PAST_HORIZON) {
			from = 0;
		}

		ret = cbd->cb(cbd->mp, id, from, to, cbd->in, cbd->len, cbd->ud);

		cbd->nfound++;
		cbd->ret = ret;
	}

	return ret;
}
#endif

static int
rspamd_multipattern_acism_cb(int strnum, int textpos, void *context)
{
	struct rspamd_multipattern_cbdata *cbd = context;
	int ret;
	ac_trie_pat_t pat;

	pat = g_array_index(cbd->mp->pats, ac_trie_pat_t, strnum);
	ret = cbd->cb(cbd->mp, strnum, textpos - pat.len,
				  textpos, cbd->in, cbd->len, cbd->ud);

	cbd->nfound++;
	cbd->ret = ret;

	return ret;
}

int rspamd_multipattern_lookup(struct rspamd_multipattern *mp,
							   const char *in, gsize len, rspamd_multipattern_cb_t cb,
							   gpointer ud, unsigned int *pnfound)
{
	struct rspamd_multipattern_cbdata cbd;
	int ret = 0;

	g_assert(mp != NULL);

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
	if (rspamd_hs_check()) {
		hs_scratch_t *scr = NULL;
		unsigned int i;

		for (i = 0; i < MAX_SCRATCH; i++) {
			if (!(mp->scratch_used & (1 << i))) {
				mp->scratch_used |= (1 << i);
				scr = mp->scratch[i];
				break;
			}
		}

		g_assert(scr != NULL);

		ret = hs_scan(rspamd_hyperscan_get_database(mp->hs_db), in, len, 0, scr,
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

	int state = 0;

	if (mp->flags & (RSPAMD_MULTIPATTERN_GLOB | RSPAMD_MULTIPATTERN_RE)) {
		/* Terribly inefficient, but who cares - just use hyperscan */
		for (unsigned int i = 0; i < mp->cnt; i++) {
			rspamd_regexp_t *re = g_array_index(mp->res, rspamd_regexp_t *, i);
			const char *start = NULL, *end = NULL;

			while (rspamd_regexp_search(re,
										in,
										len,
										&start,
										&end,
										TRUE,
										NULL)) {
				if (start >= end) {
					/* We found all matches, so no more hits are possible (protect from empty patterns) */
					break;
				}
				if (rspamd_multipattern_acism_cb(i, end - in, &cbd)) {
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
		ret = acism_lookup(mp->t, in, len, rspamd_multipattern_acism_cb, &cbd,
						   &state, mp->flags & RSPAMD_MULTIPATTERN_ICASE);

		if (pnfound) {
			*pnfound = cbd.nfound;
		}
	}

	return ret;
}


void rspamd_multipattern_destroy(struct rspamd_multipattern *mp)
{
	unsigned int i;

	if (mp) {
#ifdef WITH_HYPERSCAN
		if (rspamd_hs_check()) {
			char *p;

			if (mp->compiled && mp->cnt > 0) {
				for (i = 0; i < MAX_SCRATCH; i++) {
					hs_free_scratch(mp->scratch[i]);
				}

				if (mp->hs_db) {
					rspamd_hyperscan_free(mp->hs_db, false);
				}
			}

			for (i = 0; i < mp->cnt; i++) {
				p = g_array_index(mp->hs_pats, char *, i);
				g_free(p);
			}

			g_array_free(mp->hs_pats, TRUE);
			g_array_free(mp->hs_ids, TRUE);
			g_array_free(mp->hs_flags, TRUE);
			free(mp); /* Due to posix_memalign */

			return;
		}
#endif
		ac_trie_pat_t pat;

		if (mp->compiled && mp->cnt > 0) {
			acism_destroy(mp->t);
		}

		for (i = 0; i < mp->cnt; i++) {
			pat = g_array_index(mp->pats, ac_trie_pat_t, i);
			g_free((char *) pat.ptr);
		}

		g_array_free(mp->pats, TRUE);

		g_free(mp);
	}
}

const char *
rspamd_multipattern_get_pattern(struct rspamd_multipattern *mp,
								unsigned int index)
{
	g_assert(mp != NULL);
	g_assert(index < mp->cnt);

#ifdef WITH_HYPERSCAN
	if (rspamd_hs_check()) {
		return g_array_index(mp->hs_pats, char *, index);
	}
#endif

	ac_trie_pat_t pat;

	pat = g_array_index(mp->pats, ac_trie_pat_t, index);

	return pat.ptr;
}

unsigned int rspamd_multipattern_get_npatterns(struct rspamd_multipattern *mp)
{
	g_assert(mp != NULL);

	return mp->cnt;
}

gboolean
rspamd_multipattern_has_hyperscan(void)
{
	return rspamd_hs_check();
}
