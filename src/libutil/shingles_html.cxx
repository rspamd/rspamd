/*-
 * Copyright 2025 Vsevolod Stakhov
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
#include "shingles.h"
#include "libserver/html/html.hxx"
#include "libserver/url.h"
#include "cryptobox.h"
#include "fstring.h"

using rspamd::html::html_content;
using rspamd::html::html_tag;

/* Forward declarations for C linkage */
extern "C" {
static unsigned char **rspamd_shingles_get_keys_cached(const unsigned char key[16]);
uint64_t rspamd_shingles_default_filter(uint64_t *input, gsize count,
										int shno, const unsigned char *key, gpointer ud);
}

#define SHINGLES_WINDOW 3

/* Helper: bucket a numeric value into discrete ranges for stability */
static inline uint8_t
bucket_value(unsigned int val, const int *buckets, int nbuckets)
{
	int i;
	for (i = 0; i < nbuckets; i++) {
		if (val < (unsigned int) buckets[i]) {
			return (uint8_t) i;
		}
	}
	return (uint8_t) nbuckets;
}

/* Helper: extract eTLD+1 from URL */
static const char *
extract_etld1_from_url(struct rspamd_url *url, rspamd_mempool_t *pool)
{
	if (!url || !url->host || url->hostlen == 0) {
		return NULL;
	}

	rspamd_ftok_t tld;
	if (rspamd_url_find_tld(url->host, url->hostlen, &tld)) {
		const char *host_start = url->host;
		const char *tld_start = tld.begin;

		/* Find start of registrable domain (before TLD) */
		const char *p = tld_start;
		while (p > host_start && *(p - 1) != '.') {
			p--;
		}

		gsize etld1_len = (url->host + url->hostlen) - p;
		char *etld1 = rspamd_mempool_alloc(pool, etld1_len + 1);
		memcpy(etld1, p, etld1_len);
		etld1[etld1_len] = '\0';

		/* Lowercase */
		for (gsize i = 0; i < etld1_len; i++) {
			etld1[i] = g_ascii_tolower(etld1[i]);
		}

		return etld1;
	}

	return NULL;
}

/* Helper: check if class name contains tracking-like tokens */
static gboolean
is_tracking_class(const char *cls, gsize len)
{
	static const char *tracking_tokens[] = {
		"utm", "track", "analytics", "pixel", "beacon",
		"campaign", "source", "medium", "guid", "uuid"};

	for (unsigned int i = 0; i < G_N_ELEMENTS(tracking_tokens); i++) {
		if (rspamd_substring_search_caseless(cls, len,
											 tracking_tokens[i],
											 strlen(tracking_tokens[i])) != -1) {
			return TRUE;
		}
	}

	return FALSE;
}

/* Helper: normalize class by removing numbers and limiting length */
static char *
normalize_class(const char *cls, gsize len, rspamd_mempool_t *pool)
{
	if (len == 0 || len > 64) {
		return NULL;
	}

	/* Skip if mostly digits */
	unsigned int digit_count = 0;
	for (gsize i = 0; i < len; i++) {
		if (g_ascii_isdigit(cls[i])) {
			digit_count++;
		}
	}
	if (digit_count > len / 2) {
		return NULL;
	}

	char *result = rspamd_mempool_alloc(pool, len + 1);
	gsize out_len = 0;

	for (gsize i = 0; i < len && out_len < 32; i++) {
		char c = cls[i];
		if (g_ascii_isalnum(c) || c == '-' || c == '_') {
			result[out_len++] = g_ascii_tolower(c);
		}
	}

	result[out_len] = '\0';
	return out_len > 0 ? result : NULL;
}

/* Helper: extract structural tokens from HTML */
static GPtrArray *
html_extract_structural_tokens(html_content *hc,
							   rspamd_mempool_t *pool,
							   GPtrArray **cta_domains_out,
							   GPtrArray **all_domains_out)
{
	GPtrArray *tokens = g_ptr_array_sized_new(hc->all_tags.size());
	GPtrArray *cta_domains = g_ptr_array_sized_new(16);
	GPtrArray *all_domains = g_ptr_array_sized_new(32);

	for (const auto &tag_ptr: hc->all_tags) {
		struct html_tag *tag = tag_ptr.get();

		/* Skip virtual/ignored/xml tags */
		if (tag->flags & (FL_VIRTUAL | FL_IGNORE | FL_XML)) {
			continue;
		}

		GString *token = g_string_sized_new(64);

		/* 1. Tag name */
		const char *tag_name = rspamd_html_tag_by_id(tag->id);
		if (tag_name) {
			g_string_append(token, tag_name);
		}
		else {
			g_string_append(token, "unknown");
		}

		/* 2. Structural class (if not tracking-related) */
		auto cls = tag->find_class();
		if (cls.has_value()) {
			auto class_sv = cls.value();
			if (!is_tracking_class(class_sv.data(), class_sv.size())) {
				char *norm_cls = normalize_class(class_sv.data(), class_sv.size(), pool);
				if (norm_cls) {
					g_string_append_printf(token, ".%s", norm_cls);
				}
			}
		}

		/* 3. Domain from URL (for links/images) */
		const char *etld1 = NULL;
		struct rspamd_url *url = NULL;

		if (std::holds_alternative<rspamd_url *>(tag->extra)) {
			url = std::get<rspamd_url *>(tag->extra);
			if (url && url->host && url->hostlen > 0) {
				etld1 = extract_etld1_from_url(url, pool);

				if (etld1) {
					g_string_append_printf(token, "@%s", etld1);

					/* Add to all_domains */
					g_ptr_array_add(all_domains, (gpointer) etld1);

					/* Check if this is a CTA link using button weights */
					auto weight_it = hc->url_button_weights.find(url);
					if (weight_it != hc->url_button_weights.end() && weight_it->second > 0.3) {
						/* This URL has significant button weight -> likely CTA */
						g_ptr_array_add(cta_domains, (gpointer) etld1);
					}
				}
			}
		}

		/* Add token */
		g_ptr_array_add(tokens, g_string_free(token, FALSE));
	}

	*cta_domains_out = cta_domains;
	*all_domains_out = all_domains;

	return tokens;
}

/* Helper: string comparison for qsort */
static int
compare_strings(gconstpointer a, gconstpointer b)
{
	return strcmp(*(const char **) a, *(const char **) b);
}

/* Helper: hash a sorted list of domains */
static uint64_t
hash_domain_list(GPtrArray *domains, const unsigned char key[16])
{
	rspamd_cryptobox_hash_state_t st;
	unsigned char digest[rspamd_cryptobox_HASHBYTES];
	uint64_t result;

	if (domains->len == 0) {
		return 0;
	}

	/* Sort domains for consistent hashing */
	g_ptr_array_sort(domains, compare_strings);

	rspamd_cryptobox_hash_init(&st, key, 16);

	/* Hash each unique domain */
	const char *prev = NULL;
	for (unsigned int i = 0; i < domains->len; i++) {
		const char *dom = (const char *) g_ptr_array_index(domains, i);
		/* Skip duplicates */
		if (prev && strcmp(dom, prev) == 0) {
			continue;
		}
		rspamd_cryptobox_hash_update(&st, dom, strlen(dom));
		prev = dom;
	}

	rspamd_cryptobox_hash_final(&st, digest);
	memcpy(&result, digest, sizeof(result));

	return result;
}

/* Helper: hash top-N most frequent domains */
static uint64_t
hash_top_domains(GPtrArray *domains, unsigned int top_n, const unsigned char key[16])
{
	if (domains->len == 0) {
		return 0;
	}

	/* Count domain frequencies */
	GHashTable *freq_table = g_hash_table_new(g_str_hash, g_str_equal);

	for (unsigned int i = 0; i < domains->len; i++) {
		const char *dom = (const char *) g_ptr_array_index(domains, i);
		gpointer count_ptr = g_hash_table_lookup(freq_table, dom);
		unsigned int count = GPOINTER_TO_UINT(count_ptr);
		g_hash_table_insert(freq_table, (gpointer) dom, GUINT_TO_POINTER(count + 1));
	}

	/* Extract and sort by frequency */
	GPtrArray *sorted_domains = g_ptr_array_sized_new(g_hash_table_size(freq_table));

	GHashTableIter iter;
	gpointer key_ptr, value_ptr;
	g_hash_table_iter_init(&iter, freq_table);

	while (g_hash_table_iter_next(&iter, &key_ptr, &value_ptr)) {
		g_ptr_array_add(sorted_domains, key_ptr);
	}

	/* Simple sort by frequency (using hash table lookup) */
	g_ptr_array_sort_with_data(sorted_domains, [](gconstpointer a, gconstpointer b, gpointer user_data) -> int {
								   GHashTable *freq = (GHashTable *) user_data;
								   unsigned int freq_a = GPOINTER_TO_UINT(g_hash_table_lookup(freq, a));
								   unsigned int freq_b = GPOINTER_TO_UINT(g_hash_table_lookup(freq, b));
								   if (freq_a != freq_b) {
									   return (int) freq_b - (int) freq_a;/* Descending */
								   }
								   return strcmp((const char *) a, (const char *) b); }, freq_table);

	/* Take top-N */
	if (sorted_domains->len > top_n) {
		g_ptr_array_set_size(sorted_domains, top_n);
	}

	/* Hash the top domains */
	uint64_t result = hash_domain_list(sorted_domains, key);

	g_ptr_array_free(sorted_domains, TRUE);
	g_hash_table_destroy(freq_table);

	return result;
}

/* Helper: hash HTML features (bucketed) */
static uint64_t
hash_html_features(html_content *hc, const unsigned char key[16])
{
	rspamd_cryptobox_hash_state_t st;
	unsigned char digest[rspamd_cryptobox_HASHBYTES];
	uint64_t result;

	rspamd_cryptobox_hash_init(&st, key, 16);

	/* Bucket numeric features for stability */
	static const int tags_buckets[] = {10, 50, 100, 200, 500};
	static const int links_buckets[] = {5, 10, 20, 50, 100};
	static const int depth_buckets[] = {5, 10, 15, 20, 30};
	static const int images_buckets[] = {1, 5, 10, 20, 50};

	uint8_t tags_bucket = bucket_value(hc->features.tags_count, tags_buckets, G_N_ELEMENTS(tags_buckets));
	uint8_t links_bucket = bucket_value(hc->features.links.total_links, links_buckets, G_N_ELEMENTS(links_buckets));
	uint8_t depth_bucket = bucket_value(hc->features.max_dom_depth, depth_buckets, G_N_ELEMENTS(depth_buckets));
	uint8_t images_bucket = bucket_value(hc->features.images_total, images_buckets, G_N_ELEMENTS(images_buckets));

	rspamd_cryptobox_hash_update(&st, &tags_bucket, 1);
	rspamd_cryptobox_hash_update(&st, &links_bucket, 1);
	rspamd_cryptobox_hash_update(&st, &depth_bucket, 1);
	rspamd_cryptobox_hash_update(&st, &images_bucket, 1);

	/* Boolean features */
	uint8_t has_forms = hc->features.forms_count > 0 ? 1 : 0;
	uint8_t has_password = hc->features.has_password_input ? 1 : 0;

	rspamd_cryptobox_hash_update(&st, &has_forms, 1);
	rspamd_cryptobox_hash_update(&st, &has_password, 1);

	rspamd_cryptobox_hash_final(&st, digest);
	memcpy(&result, digest, sizeof(result));

	return result;
}

/* Helper: generate shingles from string tokens (like text shingles but for tokens) */
static struct rspamd_shingle *
generate_shingles_from_string_tokens(GPtrArray *tokens,
									 const unsigned char key[16],
									 rspamd_shingles_filter filter,
									 gpointer filterd,
									 enum rspamd_shingle_alg alg)
{
	struct rspamd_shingle *res;
	uint64_t **hashes;
	unsigned char **keys;
	gsize hlen, ilen, beg = 0;
	unsigned int i, j;
	enum rspamd_cryptobox_fast_hash_type ht;
	uint64_t val;

	ilen = tokens->len;
	if (ilen == 0) {
		return NULL;
	}

	res = g_new0(struct rspamd_shingle, 1);
	hlen = ilen > SHINGLES_WINDOW ? (ilen - SHINGLES_WINDOW + 1) : 1;

	keys = rspamd_shingles_get_keys_cached(key);
	hashes = g_new(uint64_t *, RSPAMD_SHINGLE_SIZE);

	for (i = 0; i < RSPAMD_SHINGLE_SIZE; i++) {
		hashes[i] = g_new(uint64_t, hlen);
	}

	/* Select hash algorithm */
	switch (alg) {
	case RSPAMD_SHINGLES_XXHASH:
		ht = RSPAMD_CRYPTOBOX_XXHASH64;
		break;
	case RSPAMD_SHINGLES_MUMHASH:
		ht = RSPAMD_CRYPTOBOX_MUMHASH;
		break;
	case RSPAMD_SHINGLES_FAST:
		ht = RSPAMD_CRYPTOBOX_HASHFAST_INDEPENDENT;
		break;
	default:
		ht = RSPAMD_CRYPTOBOX_MUMHASH;
		break;
	}

	/* Generate hashes using sliding window */
	for (i = 0; i <= ilen; i++) {
		if (i - beg >= SHINGLES_WINDOW || i == ilen) {
			/* Hash the window */
			for (j = 0; j < RSPAMD_SHINGLE_SIZE; j++) {
				uint64_t seed;
				memcpy(&seed, keys[j], sizeof(seed));

				/* Combine hashes of tokens in window */
				val = 0;
				for (unsigned int k = beg; k < i && k < ilen; k++) {
					const char *token = (const char *) g_ptr_array_index(tokens, k);
					uint64_t token_hash = rspamd_cryptobox_fast_hash_specific(ht,
																			  token, strlen(token), seed);
					val ^= token_hash >> (8 * (k - beg));
				}

				g_assert(hlen > beg);
				hashes[j][beg] = val;
			}

			beg++;
		}
	}

	/* Apply filter to get final shingles */
	for (i = 0; i < RSPAMD_SHINGLE_SIZE; i++) {
		res->hashes[i] = filter(hashes[i], hlen, i, key, filterd);
		g_free(hashes[i]);
	}

	g_free(hashes);

	return res;
}

/* Main function: generate HTML shingles */
extern "C" struct rspamd_html_shingle *
rspamd_shingles_from_html(void *html_content,
						  const unsigned char key[16],
						  rspamd_mempool_t *pool,
						  rspamd_shingles_filter filter,
						  gpointer filterd,
						  enum rspamd_shingle_alg alg)
{
	struct rspamd_html_shingle *res;
	GPtrArray *tokens = NULL, *cta_domains = NULL, *all_domains = NULL;
	struct rspamd_shingle *struct_sgl = NULL;

	if (!html_content) {
		return NULL;
	}

	html_content *hc = html_content::from_ptr(html_content);

	if (!hc || hc->all_tags.empty()) {
		return NULL;
	}

	if (pool) {
		res = rspamd_mempool_alloc0(pool, sizeof(*res));
	}
	else {
		res = g_new0(struct rspamd_html_shingle, 1);
	}

	/* 1. Extract structural tokens and domain lists */
	tokens = html_extract_structural_tokens(hc, pool, &cta_domains, &all_domains);

	if (tokens->len == 0) {
		/* Empty HTML structure */
		g_ptr_array_free(tokens, TRUE);
		g_ptr_array_free(cta_domains, TRUE);
		g_ptr_array_free(all_domains, TRUE);

		if (pool == NULL) {
			g_free(res);
		}
		return NULL;
	}

	/* 2. Generate direct hash of ALL tokens (for exact matching, like text parts) */
	rspamd_cryptobox_hash_state_t st;
	rspamd_cryptobox_hash_init(&st, key, 16);

	for (unsigned int i = 0; i < tokens->len; i++) {
		const char *token = (const char *) g_ptr_array_index(tokens, i);
		rspamd_cryptobox_hash_update(&st, token, strlen(token));
	}

	rspamd_cryptobox_hash_final(&st, res->direct_hash);

	/* 3. Generate structure shingles from tokens (for fuzzy matching) */
	struct_sgl = generate_shingles_from_string_tokens(tokens, key, filter, filterd, alg);

	if (struct_sgl) {
		memcpy(&res->structure_shingles, struct_sgl, sizeof(struct rspamd_shingle));
		if (pool == NULL) {
			g_free(struct_sgl);
		}
	}
	else {
		memset(&res->structure_shingles, 0, sizeof(struct rspamd_shingle));
	}

	/* 4. Generate CTA domains hash (critical for phishing detection) */
	res->cta_domains_hash = hash_domain_list(cta_domains, key);

	/* 5. Generate all domains hash (top-10 most frequent) */
	res->all_domains_hash = hash_top_domains(all_domains, 10, key);

	/* 6. Generate features hash (bucketed statistics) */
	res->features_hash = hash_html_features(hc, key);

	/* 7. Store metadata */
	res->tags_count = hc->features.tags_count > UINT16_MAX ? UINT16_MAX : (uint16_t) hc->features.tags_count;
	res->links_count = hc->features.links.total_links > UINT16_MAX ? UINT16_MAX : (uint16_t) hc->features.links.total_links;
	res->dom_depth = hc->features.max_dom_depth > UINT8_MAX ? UINT8_MAX : (uint8_t) hc->features.max_dom_depth;

	/* Cleanup */
	for (unsigned int i = 0; i < tokens->len; i++) {
		g_free(g_ptr_array_index(tokens, i));
	}
	g_ptr_array_free(tokens, TRUE);
	g_ptr_array_free(cta_domains, TRUE);
	g_ptr_array_free(all_domains, TRUE);

	return res;
}

/* Compare two HTML shingles */
extern "C" double
rspamd_html_shingles_compare(const struct rspamd_html_shingle *a,
							 const struct rspamd_html_shingle *b)
{
	double structure_sim, cta_sim, domains_sim, features_sim;
	int i, common = 0;

	/* 1. Structure similarity (main weight) */
	for (i = 0; i < RSPAMD_SHINGLE_SIZE; i++) {
		if (a->structure_shingles.hashes[i] == b->structure_shingles.hashes[i]) {
			common++;
		}
	}
	structure_sim = (double) common / (double) RSPAMD_SHINGLE_SIZE;

	/* 2. CTA domains MUST match (critical for phishing) */
	if (a->cta_domains_hash != 0 && b->cta_domains_hash != 0) {
		cta_sim = (a->cta_domains_hash == b->cta_domains_hash) ? 1.0 : 0.0;

		/* If CTA domains differ completely, likely phishing -> penalize heavily */
		if (cta_sim < 0.5) {
			return structure_sim * 0.3; /* Heavy penalty */
		}
	}
	else {
		/* One or both have no CTA links -> neutral */
		cta_sim = 0.5;
	}

	/* 3. All domains similarity */
	domains_sim = (a->all_domains_hash == b->all_domains_hash) ? 1.0 : 0.0;

	/* 4. Features similarity (bucketed, so exact match or partial) */
	features_sim = (a->features_hash == b->features_hash) ? 1.0 : 0.5;

	/* Combined score with weights:
	 * - 50% structure (main DOM skeleton)
	 * - 30% CTA domains (critical for phishing)
	 * - 15% all domains
	 * - 5% statistical features
	 */
	double combined = 0.50 * structure_sim + 0.30 * cta_sim + 0.15 * domains_sim + 0.05 * features_sim;

	return combined;
}
