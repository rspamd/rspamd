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
	enum rspamd_multipattern_state state;
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
	 * 1) blah -> \.blah(?:[^a-zA-Z0-9]|$)
	 * 2) *.blah -> \.blah(?:[^a-zA-Z0-9]|$)
	 *
	 * Note: We use (?:[^a-zA-Z0-9]|$) instead of \b because \b requires
	 * HS_FLAG_UCP which we don't set for TLD patterns.
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

	/* Match end of TLD: either non-alphanumeric or end of string */
	suffix = "(?:[^a-zA-Z0-9]|$)";
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
	mp->state = RSPAMD_MP_STATE_INIT;

#ifdef WITH_HYPERSCAN
	if (rspamd_hs_check()) {
		mp->hs_pats = g_array_new(FALSE, TRUE, sizeof(char *));
		mp->hs_flags = g_array_new(FALSE, TRUE, sizeof(int));
		mp->hs_ids = g_array_new(FALSE, TRUE, sizeof(int));
		rspamd_cryptobox_hash_init(&mp->hash_state, NULL, 0);

		/* For TLD multipatterns, also create pats array for ACISM fallback */
		if (flags & RSPAMD_MULTIPATTERN_TLD) {
			mp->pats = g_array_new(FALSE, TRUE, sizeof(ac_trie_pat_t));
		}

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
	mp->state = RSPAMD_MP_STATE_INIT;

#ifdef WITH_HYPERSCAN
	if (rspamd_hs_check()) {
		mp->hs_pats = g_array_sized_new(FALSE, TRUE, sizeof(char *), npatterns);
		mp->hs_flags = g_array_sized_new(FALSE, TRUE, sizeof(int), npatterns);
		mp->hs_ids = g_array_sized_new(FALSE, TRUE, sizeof(int), npatterns);
		rspamd_cryptobox_hash_init(&mp->hash_state, NULL, 0);

		/* For TLD multipatterns, also create pats array for ACISM fallback */
		if (flags & RSPAMD_MULTIPATTERN_TLD) {
			mp->pats = g_array_sized_new(FALSE, TRUE, sizeof(ac_trie_pat_t), npatterns);
		}

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
	gboolean is_tld = (mp->flags & RSPAMD_MULTIPATTERN_TLD);

	g_assert(pattern != NULL);
	g_assert(mp != NULL);
	g_assert(!mp->compiled);

	/*
	 * For TLD multipatterns: always add to pats array for ACISM fallback
	 */
	if (is_tld) {
		ac_trie_pat_t acism_pat;

		acism_pat.ptr = rspamd_multipattern_escape_tld_acism(pattern, patlen, &dlen);
		acism_pat.len = dlen;
		g_array_append_val(mp->pats, acism_pat);
	}

#ifdef WITH_HYPERSCAN
	if (rspamd_hs_check()) {
		char *np;
		int fl = HS_FLAG_SOM_LEFTMOST;
		int adjusted_flags = mp->flags | flags;

		if (adjusted_flags & RSPAMD_MULTIPATTERN_ICASE) {
			fl |= HS_FLAG_CASELESS;
		}
		if (adjusted_flags & RSPAMD_MULTIPATTERN_UTF8) {
			if (is_tld) {
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

	/* Non-hyperscan path: add to pats for ACISM/regex fallback */
	if (!is_tld) {
		ac_trie_pat_t pat;

		pat.ptr = rspamd_multipattern_pattern_filter(pattern, patlen, flags, &dlen);
		pat.len = dlen;

		g_array_append_val(mp->pats, pat);
	}

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
	gchar *data;
	gsize len;
	GError *err = NULL;

	if (hs_cache_dir == NULL) {
		return FALSE;
	}

	rspamd_snprintf(fp, sizeof(fp), "%s/%*xs.hs", hs_cache_dir,
					(int) rspamd_cryptobox_HASHBYTES / 2, hash);

	if (!g_file_get_contents(fp, &data, &len, &err)) {
		if (err) {
			msg_debug("cannot read hyperscan cache %s: %s", fp, err->message);
			g_error_free(err);
		}
		return FALSE;
	}

	mp->hs_db = rspamd_hyperscan_load_from_header(data, len, &err);
	g_free(data);

	if (mp->hs_db == NULL) {
		if (err) {
			msg_debug("cannot load hyperscan cache %s: %s", fp, err->message);
			g_error_free(err);
		}
		return FALSE;
	}

	/* Register the file so it won't be cleaned up */
	rspamd_hyperscan_notice_known(fp);

	return TRUE;
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

	rspamd_snprintf(fp, sizeof(fp), "%s%shs-XXXXXXXXXXXXX", G_DIR_SEPARATOR_S,
					hs_cache_dir);

	if ((fd = g_mkstemp_full(fp, O_CREAT | O_EXCL | O_WRONLY, 00644)) != -1) {
		/* Serialize with unified header format (magic, platform, CRC) */
		if (rspamd_hyperscan_serialize_with_header(
				rspamd_hyperscan_get_database(mp->hs_db),
				NULL, NULL, 0, /* No IDs/flags needed for multipattern */
				&bytes, &len)) {
			if (write(fd, bytes, len) == -1) {
				msg_warn("cannot write hyperscan cache to %s: %s",
						 fp, strerror(errno));
				unlink(fp);
				g_free(bytes);
			}
			else {
				g_free(bytes);
				fsync(fd);

				rspamd_snprintf(np, sizeof(np), "%s/%*xs.hs", hs_cache_dir,
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
			msg_warn("cannot serialize hyperscan cache to %s", fp);
			unlink(fp);
		}

		close(fd);
	}
	else {
		msg_warn("cannot open a temp file %s to write hyperscan cache: %s", fp, strerror(errno));
	}
}
#endif

/*
 * Build ACISM fallback trie
 */
static gboolean
rspamd_multipattern_build_acism(struct rspamd_multipattern *mp, GError **err)
{
	if (mp->cnt == 0) {
		return TRUE;
	}

	if (mp->flags & (RSPAMD_MULTIPATTERN_GLOB | RSPAMD_MULTIPATTERN_RE)) {
		/* For RE/GLOB, use regex-based slow fallback */
		rspamd_regexp_t *re;
		mp->res = g_array_sized_new(FALSE, TRUE, sizeof(rspamd_regexp_t *), mp->cnt);

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
		/* Build ACISM trie for plain/TLD patterns */
		mp->t = acism_create((const ac_trie_pat_t *) mp->pats->data, mp->cnt);
	}

	return TRUE;
}

#ifdef WITH_HYPERSCAN
/*
 * Allocate scratch space for hyperscan database
 */
static gboolean
rspamd_multipattern_alloc_scratch(struct rspamd_multipattern *mp, GError **err)
{
	for (unsigned int i = 0; i < MAX_SCRATCH; i++) {
		mp->scratch[i] = NULL;
	}

	for (unsigned int i = 0; i < MAX_SCRATCH; i++) {
		int ret;

		if ((ret = hs_alloc_scratch(rspamd_hyperscan_get_database(mp->hs_db),
									&mp->scratch[i])) != HS_SUCCESS) {
			msg_err("cannot allocate scratch space for hyperscan: error code %d", ret);

			/* Clean all scratches that are non-NULL */
			for (unsigned int ii = 0; ii < MAX_SCRATCH; ii++) {
				if (mp->scratch[ii] != NULL) {
					hs_free_scratch(mp->scratch[ii]);
					mp->scratch[ii] = NULL;
				}
			}
			g_set_error(err, rspamd_multipattern_quark(), EINVAL,
						"cannot allocate scratch space for hyperscan: error code %d", ret);

			return FALSE;
		}
	}

	return TRUE;
}

/*
 * Compile hyperscan database synchronously
 */
static gboolean
rspamd_multipattern_compile_hs_sync(struct rspamd_multipattern *mp,
									const unsigned char *hash,
									int flags,
									GError **err)
{
	hs_platform_info_t plt;
	hs_compile_error_t *hs_errors;
	hs_database_t *db = NULL;

	g_assert(hs_populate_platform(&plt) == HS_SUCCESS);

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
		mp->state = RSPAMD_MP_STATE_FALLBACK;

		return FALSE;
	}

	if (!(flags & RSPAMD_MULTIPATTERN_COMPILE_NO_FS)) {
		if (hs_cache_dir != NULL) {
			char fpath[PATH_MAX];
			rspamd_snprintf(fpath, sizeof(fpath), "%s/%*xs.hs", hs_cache_dir,
							(int) rspamd_cryptobox_HASHBYTES / 2, hash);
			mp->hs_db = rspamd_hyperscan_from_raw_db(db, fpath);
		}
		else {
			mp->hs_db = rspamd_hyperscan_from_raw_db(db, NULL);
		}

		rspamd_multipattern_try_save_hs(mp, hash);
	}
	else {
		mp->hs_db = rspamd_hyperscan_from_raw_db(db, NULL);
	}

	if (!rspamd_multipattern_alloc_scratch(mp, err)) {
		rspamd_hyperscan_free(mp->hs_db, true);
		mp->hs_db = NULL;
		mp->state = RSPAMD_MP_STATE_FALLBACK;

		return FALSE;
	}

	mp->state = RSPAMD_MP_STATE_COMPILED;
	return TRUE;
}
#endif

gboolean
rspamd_multipattern_compile(struct rspamd_multipattern *mp, int flags, GError **err)
{
	g_assert(mp != NULL);
	g_assert(!mp->compiled);

#ifdef WITH_HYPERSCAN
	if (rspamd_hs_check() && mp->cnt > 0) {
		hs_platform_info_t plt;
		unsigned char hash[rspamd_cryptobox_HASHBYTES];
		gboolean has_tld_patterns = (mp->pats != NULL && mp->pats->len > 0);

		g_assert(hs_populate_platform(&plt) == HS_SUCCESS);
		rspamd_cryptobox_hash_update(&mp->hash_state, (void *) &plt, sizeof(plt));
		rspamd_cryptobox_hash_final(&mp->hash_state, hash);

		/* Build ACISM fallback for TLD patterns (only works if all patterns are TLD) */
		if (has_tld_patterns) {
			gboolean all_tld = (mp->pats->len == mp->cnt);

			mp->t = acism_create((const ac_trie_pat_t *) mp->pats->data, mp->pats->len);
			mp->state = RSPAMD_MP_STATE_INIT;
			mp->compiled = TRUE;

			/* Try to load from cache first */
			if (!(flags & RSPAMD_MULTIPATTERN_COMPILE_NO_FS) &&
				rspamd_multipattern_try_load_hs(mp, hash)) {
				/* Cache hit - allocate scratch and we're done */
				if (!rspamd_multipattern_alloc_scratch(mp, err)) {
					rspamd_hyperscan_free(mp->hs_db, true);
					mp->hs_db = NULL;
					mp->state = RSPAMD_MP_STATE_FALLBACK;
					g_clear_error(err);
				}
				else {
					mp->state = RSPAMD_MP_STATE_COMPILED;
				}
				return TRUE;
			}

			/* Cache miss: async compile only for TLD-only patterns */
			if (all_tld && !(flags & RSPAMD_MULTIPATTERN_COMPILE_NO_FS)) {
				mp->state = RSPAMD_MP_STATE_COMPILING;
				return TRUE;
			}

			/* Mixed patterns or NO_FS flag - sync compile */
			if (!rspamd_multipattern_compile_hs_sync(mp, hash, flags, err)) {
				/* HS failed but ACISM fallback is ready for TLD patterns */
				g_clear_error(err);
			}
			return TRUE;
		}

		/* No TLD patterns: sync compile only (original behavior) */
		if ((flags & RSPAMD_MULTIPATTERN_COMPILE_NO_FS) ||
			!rspamd_multipattern_try_load_hs(mp, hash)) {

			if (!rspamd_multipattern_compile_hs_sync(mp, hash, flags, err)) {
				return FALSE;
			}
		}
		else {
			/* Cache hit */
			if (!rspamd_multipattern_alloc_scratch(mp, err)) {
				rspamd_hyperscan_free(mp->hs_db, true);
				mp->hs_db = NULL;
				return FALSE;
			}
			mp->state = RSPAMD_MP_STATE_COMPILED;
		}

		mp->compiled = TRUE;
		return TRUE;
	}
#endif

	/* No hyperscan - build fallback */
	if (!rspamd_multipattern_build_acism(mp, err)) {
		return FALSE;
	}

	mp->state = RSPAMD_MP_STATE_INIT;
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
	/*
	 * For TLD multipatterns: strnum IS the pattern ID (0-based)
	 * All patterns in the multipattern are TLD patterns, so no offset needed
	 */
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
	/* Use hyperscan if it's compiled and ready */
	if (mp->state == RSPAMD_MP_STATE_COMPILED && mp->hs_db != NULL) {
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

	/*
	 * For multipatterns with TLD patterns: use ACISM fallback while HS is compiling
	 * pats array exists only for multipatterns that have TLD patterns
	 */
	if (mp->pats != NULL && mp->t != NULL) {
		int acism_state = 0;

		ret = acism_lookup(mp->t, in, len, rspamd_multipattern_acism_cb, &cbd,
						   &acism_state, mp->flags & RSPAMD_MULTIPATTERN_ICASE);

		if (pnfound) {
			*pnfound = cbd.nfound;
		}

		return ret;
	}
#endif

	/* No hyperscan fallback path */
	int acism_state = 0;

	if (mp->flags & (RSPAMD_MULTIPATTERN_GLOB | RSPAMD_MULTIPATTERN_RE)) {
		/* Regex-based fallback for GLOB/RE patterns */
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
		/* ACISM trie for plain/TLD patterns */
		ret = acism_lookup(mp->t, in, len, rspamd_multipattern_acism_cb, &cbd,
						   &acism_state, mp->flags & RSPAMD_MULTIPATTERN_ICASE);

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

				/* Clean up ACISM fallback if it was built */
				if (mp->t) {
					acism_destroy(mp->t);
				}
			}

			for (i = 0; i < mp->cnt; i++) {
				p = g_array_index(mp->hs_pats, char *, i);
				g_free(p);
			}

			g_array_free(mp->hs_pats, TRUE);
			g_array_free(mp->hs_ids, TRUE);
			g_array_free(mp->hs_flags, TRUE);

			/* Clean up pats array if it exists (TLD patterns) */
			if (mp->pats) {
				ac_trie_pat_t pat;

				for (i = 0; i < mp->pats->len; i++) {
					pat = g_array_index(mp->pats, ac_trie_pat_t, i);
					g_free((char *) pat.ptr);
				}

				g_array_free(mp->pats, TRUE);
			}

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

		free(mp); /* Due to posix_memalign */
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

enum rspamd_multipattern_state
rspamd_multipattern_get_state(struct rspamd_multipattern *mp)
{
	g_assert(mp != NULL);

	return mp->state;
}

gboolean
rspamd_multipattern_is_hs_ready(struct rspamd_multipattern *mp)
{
	g_assert(mp != NULL);

#ifdef WITH_HYPERSCAN
	return mp->state == RSPAMD_MP_STATE_COMPILED && mp->hs_db != NULL;
#else
	return FALSE;
#endif
}

void rspamd_multipattern_get_hash(struct rspamd_multipattern *mp,
								  unsigned char *hash_out)
{
	g_assert(mp != NULL);
	g_assert(hash_out != NULL);

#ifdef WITH_HYPERSCAN
	if (rspamd_hs_check()) {
		hs_platform_info_t plt;
		rspamd_cryptobox_hash_state_t hash_state;

		rspamd_cryptobox_hash_init(&hash_state, NULL, 0);

		/* Hash all patterns */
		for (unsigned int i = 0; i < mp->cnt; i++) {
			char *p = g_array_index(mp->hs_pats, char *, i);
			rspamd_cryptobox_hash_update(&hash_state, p, strlen(p));
		}

		/* Include platform info */
		g_assert(hs_populate_platform(&plt) == HS_SUCCESS);
		rspamd_cryptobox_hash_update(&hash_state, (void *) &plt, sizeof(plt));

		rspamd_cryptobox_hash_final(&hash_state, hash_out);
		return;
	}
#endif

	memset(hash_out, 0, rspamd_cryptobox_HASHBYTES);
}

void rspamd_multipattern_compile_async(struct rspamd_multipattern *mp,
									   int flags,
									   struct ev_loop *event_loop,
									   rspamd_multipattern_compile_cb_t cb,
									   void *ud)
{
	g_assert(mp != NULL);
	g_assert(cb != NULL);

	/* Placeholder for future hs_helper integration */
	(void) event_loop;
	(void) flags;

#ifdef WITH_HYPERSCAN
	if (mp->state == RSPAMD_MP_STATE_COMPILED) {
		cb(mp, TRUE, NULL, ud);
		return;
	}
#endif

	GError *err = g_error_new(rspamd_multipattern_quark(), ENOTSUP,
							  "async compile not yet implemented");
	cb(mp, FALSE, err, ud);
	g_error_free(err);
}

gboolean
rspamd_multipattern_set_hs_db(struct rspamd_multipattern *mp, void *hs_db)
{
	g_assert(mp != NULL);

#ifdef WITH_HYPERSCAN
	if (!rspamd_hs_check()) {
		return FALSE;
	}

	/* Free old database if exists */
	if (mp->hs_db) {
		for (unsigned int i = 0; i < MAX_SCRATCH; i++) {
			if (mp->scratch[i]) {
				hs_free_scratch(mp->scratch[i]);
				mp->scratch[i] = NULL;
			}
		}
		rspamd_hyperscan_free(mp->hs_db, false);
	}

	mp->hs_db = (rspamd_hyperscan_t *) hs_db;

	/* Allocate scratch for new database */
	GError *err = NULL;
	if (!rspamd_multipattern_alloc_scratch(mp, &err)) {
		msg_err("failed to allocate scratch for hot-swapped HS db: %s",
				err ? err->message : "unknown error");
		if (err) {
			g_error_free(err);
		}
		rspamd_hyperscan_free(mp->hs_db, true);
		mp->hs_db = NULL;
		mp->state = RSPAMD_MP_STATE_FALLBACK;
		return FALSE;
	}

	mp->state = RSPAMD_MP_STATE_COMPILED;
	return TRUE;
#else
	(void) hs_db;
	return FALSE;
#endif
}
