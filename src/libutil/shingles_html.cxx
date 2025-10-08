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
#include "contrib/ankerl/unordered_dense.h"
#include <vector>
#include <string>
#include <string_view>
#include <algorithm>

using rspamd::html::html_content;
using rspamd::html::html_tag;

/* Forward declarations for C linkage */
extern "C" {
uint64_t rspamd_shingles_default_filter(uint64_t *input, gsize count,
										int shno, const unsigned char *key, gpointer ud);
unsigned char **rspamd_shingles_get_keys_cached(const unsigned char key[16]);
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

/* Helper: extract eTLD+1 from URL (in Rspamd, tld is already eTLD+1/eSLD) */
static std::string_view
extract_etld1_from_url(struct rspamd_url *url)
{
	if (!url || url->tldlen == 0) {
		return {};
	}

	/* In Rspamd, tld field already contains eTLD+1 (registrable domain) */
	return {rspamd_url_tld_unsafe(url), url->tldlen};
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
		return nullptr;
	}

	/* For multiple classes (space-separated), take only first class */
	gsize first_class_len = len;
	for (gsize i = 0; i < len; i++) {
		if (g_ascii_isspace(cls[i])) {
			first_class_len = i;
			break;
		}
	}

	/* Skip if mostly digits */
	unsigned int digit_count = 0;
	for (gsize i = 0; i < first_class_len; i++) {
		if (g_ascii_isdigit(cls[i])) {
			digit_count++;
		}
	}
	if (digit_count > first_class_len / 2) {
		return nullptr;
	}

	auto *result = static_cast<char *>(rspamd_mempool_alloc(pool, first_class_len + 1));
	gsize out_len = 0;

	for (gsize i = 0; i < first_class_len && out_len < 32; i++) {
		char c = cls[i];
		if (g_ascii_isalnum(c) || c == '-' || c == '_') {
			result[out_len++] = g_ascii_tolower(c);
		}
	}

	result[out_len] = '\0';
	return out_len > 0 ? result : nullptr;
}

/* Helper: extract structural tokens from HTML */
static void
html_extract_structural_tokens(html_content *hc,
							   rspamd_mempool_t *pool,
							   std::vector<std::string> &tokens,
							   std::vector<std::string_view> &cta_domains,
							   std::vector<std::string_view> &all_domains)
{
	tokens.reserve(hc->all_tags.size());
	cta_domains.reserve(16);
	all_domains.reserve(32);

	for (const auto &tag_ptr: hc->all_tags) {
		struct html_tag *tag = tag_ptr.get();

		/* Skip virtual/ignored/xml tags */
		if (tag->flags & (FL_VIRTUAL | FL_IGNORE | FL_XML)) {
			continue;
		}

		std::string token;
		token.reserve(64);

		/* 1. Tag name */
		const char *tag_name = rspamd_html_tag_by_id(tag->id);
		if (tag_name) {
			token = tag_name;
		}
		else {
			token = "unknown";
		}

		/* 2. Structural class (if not tracking-related) */
		auto cls = tag->find_class();
		if (cls.has_value()) {
			auto class_sv = cls.value();
			if (!is_tracking_class(class_sv.data(), class_sv.size())) {
				char *norm_cls = normalize_class(class_sv.data(), class_sv.size(), pool);
				if (norm_cls) {
					token += '.';
					token += norm_cls;
				}
			}
		}

		/* 3. Domain from URL (for links/images) */
		if (std::holds_alternative<rspamd_url *>(tag->extra)) {
			auto *url = std::get<rspamd_url *>(tag->extra);
			if (url && url->tldlen > 0) {
				auto etld1 = extract_etld1_from_url(url);

				if (!etld1.empty()) {
					token += '@';
					token += etld1;

					/* Add to all_domains */
					all_domains.push_back(etld1);

					/* Check if this is a CTA link using button weights */
					auto weight_it = hc->url_button_weights.find(url);
					if (weight_it != hc->url_button_weights.end() && weight_it->second > 0.3f) {
						/* This URL has significant button weight -> likely CTA */
						cta_domains.push_back(etld1);
					}
				}
			}
		}

		/* Add token */
		tokens.emplace_back(std::move(token));
	}
}

/* Helper: hash a sorted list of domains */
static uint64_t
hash_domain_list(std::vector<std::string_view> &domains, const unsigned char key[16], bool preserve_order = false)
{
	if (domains.empty()) {
		return 0;
	}

	/* Sort domains for consistent hashing (unless order should be preserved, e.g., for frequency-sorted domains) */
	if (!preserve_order) {
		std::sort(domains.begin(), domains.end());
	}

	rspamd_cryptobox_hash_state_t st;
	unsigned char digest[rspamd_cryptobox_HASHBYTES];
	uint64_t result;

	rspamd_cryptobox_hash_init(&st, key, 16);

	/* Hash each unique non-empty domain */
	std::string_view prev;
	bool has_content = false;
	for (const auto &dom: domains) {
		/* Skip empty domains and duplicates (note: only detects consecutive duplicates if preserve_order=true) */
		if (dom.empty() || (!prev.empty() && dom == prev)) {
			continue;
		}
		rspamd_cryptobox_hash_update(&st, reinterpret_cast<const unsigned char *>(dom.data()), dom.size());
		prev = dom;
		has_content = true;
	}

	/* If no valid domains were hashed, return 0 */
	if (!has_content) {
		return 0;
	}

	rspamd_cryptobox_hash_final(&st, digest);
	std::memcpy(&result, digest, sizeof(result));

	return result;
}

/* Helper: hash top-N most frequent domains */
static uint64_t
hash_top_domains(std::vector<std::string_view> &domains, unsigned int top_n, const unsigned char key[16])
{
	if (domains.empty()) {
		return 0;
	}

	/* Count domain frequencies using modern C++ map */
	ankerl::unordered_dense::map<std::string_view, unsigned int> freq_map;
	freq_map.reserve(domains.size());

	for (const auto &dom: domains) {
		/* Skip empty domains to avoid polluting frequency map */
		if (!dom.empty()) {
			freq_map[dom]++;
		}
	}

	/* If all domains were empty, return 0 */
	if (freq_map.empty()) {
		return 0;
	}

	/* Extract domains and sort by frequency */
	std::vector<std::pair<std::string_view, unsigned int>> sorted_domains;
	sorted_domains.reserve(freq_map.size());

	for (const auto &[dom, count]: freq_map) {
		sorted_domains.emplace_back(dom, count);
	}

	/* Sort by frequency (descending), then by name (lexicographic) */
	std::sort(sorted_domains.begin(), sorted_domains.end(),
			  [](const auto &a, const auto &b) {
				  if (a.second != b.second) {
					  return a.second > b.second; /* Descending by frequency */
				  }
				  return a.first < b.first; /* Ascending by name */
			  });

	/* Take top-N */
	if (sorted_domains.size() > top_n) {
		sorted_domains.resize(top_n);
	}

	/* Extract just the domain names for hashing */
	std::vector<std::string_view> top_domain_names;
	top_domain_names.reserve(sorted_domains.size());
	for (const auto &[dom, _]: sorted_domains) {
		top_domain_names.push_back(dom);
	}

	/* Hash the top domains, preserving frequency-based order */
	return hash_domain_list(top_domain_names, key, true);
}

/* Helper: hash HTML features (bucketed) */
static uint64_t
hash_html_features(html_content *hc, const unsigned char key[16])
{
	rspamd_cryptobox_hash_state_t st;
	unsigned char digest[rspamd_cryptobox_HASHBYTES];
	uint64_t result;

	if (!hc) {
		/* Return zero hash for NULL input */
		return 0;
	}

	/* Validate that features have been populated (check version and at least one meaningful field) */
	if (hc->features.version == 0 || (hc->features.tags_count == 0 && hc->all_tags.empty())) {
		/* Features not properly initialized or HTML is empty */
		return 0;
	}

	rspamd_cryptobox_hash_init(&st, key, 16);

	/* Bucket numeric features for stability */
	static const int tags_buckets[] = {10, 50, 100, 200, 500};
	static const int links_buckets[] = {5, 10, 20, 50, 100};
	static const int depth_buckets[] = {5, 10, 15, 20, 30};
	static const int images_buckets[] = {1, 5, 10, 20, 50};

	/* Access features - values are guaranteed initialized by html_content constructor */
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
static void
generate_shingles_from_string_tokens(struct rspamd_shingle *out,
									 const std::vector<std::string> &tokens,
									 const unsigned char key[16],
									 rspamd_shingles_filter filter,
									 gpointer filterd,
									 enum rspamd_shingle_alg alg)
{
	if (tokens.empty() || !out) {
		return;
	}
	gsize ilen = tokens.size();
	gsize hlen = ilen > SHINGLES_WINDOW ? (ilen - SHINGLES_WINDOW + 1) : 1;

	auto keys = rspamd_shingles_get_keys_cached(key);

	/* Allocate hash arrays using modern C++ */
	std::vector<std::vector<uint64_t>> hashes(RSPAMD_SHINGLE_SIZE);
	for (auto &hash_vec: hashes) {
		hash_vec.resize(hlen);
	}

	/* Select hash algorithm */
	enum rspamd_cryptobox_fast_hash_type ht;
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
	gsize beg = 0;
	for (gsize i = 0; i <= ilen; i++) {
		if (i - beg >= SHINGLES_WINDOW || i == ilen) {
			/* Hash the window */
			for (unsigned int j = 0; j < RSPAMD_SHINGLE_SIZE; j++) {
				uint64_t seed;
				std::memcpy(&seed, keys[j], sizeof(seed));

				/* Combine hashes of tokens in window */
				uint64_t val = 0;
				for (gsize k = beg; k < i && k < ilen; k++) {
					const auto &token = tokens[k];
					uint64_t token_hash = rspamd_cryptobox_fast_hash_specific(ht,
																			  token.data(), token.size(), seed);
					val ^= token_hash >> (8 * (k - beg));
				}

				g_assert(hlen > beg);
				hashes[j][beg] = val;
			}

			beg++;
		}
	}

	/* Apply filter to get final shingles */
	for (unsigned int i = 0; i < RSPAMD_SHINGLE_SIZE; i++) {
		out->hashes[i] = filter(hashes[i].data(), hlen, i, key, filterd);
	}
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
	if (!html_content) {
		return nullptr;
	}

	auto *hc_ptr = html_content::from_ptr(html_content);

	if (!hc_ptr) {
		return nullptr;
	}

	if (hc_ptr->all_tags.empty()) {
		/* Empty HTML - no tags */
		return nullptr;
	}

	/* 1. Extract structural tokens and domain lists using modern C++ */
	std::vector<std::string> tokens;
	std::vector<std::string_view> cta_domains, all_domains;
	html_extract_structural_tokens(hc_ptr, pool, tokens, cta_domains, all_domains);

	if (tokens.empty()) {
		/* Empty HTML structure after filtering */
		return nullptr;
	}

	/* Pool is required for consistent memory management - avoid mixing new/delete with mempool */
	if (!pool) {
		return nullptr;
	}

	/* Allocate result after all early exit checks (zeroed) */
	struct rspamd_html_shingle *res = static_cast<rspamd_html_shingle *>(
		rspamd_mempool_alloc0(pool, sizeof(*res)));

	/* 2. Generate direct hash of ALL tokens (for exact matching, like text parts) */
	rspamd_cryptobox_hash_state_t st;
	rspamd_cryptobox_hash_init(&st, key, 16);

	for (const auto &token: tokens) {
		rspamd_cryptobox_hash_update(&st, reinterpret_cast<const unsigned char *>(token.data()), token.size());
	}

	rspamd_cryptobox_hash_final(&st, res->direct_hash);

	/* 3. Generate structure shingles from tokens (for fuzzy matching) - fill in-place */
	generate_shingles_from_string_tokens(&res->structure_shingles, tokens, key, filter, filterd, alg);

	/* 4. Generate CTA domains hash (critical for phishing detection) */
	res->cta_domains_hash = hash_domain_list(cta_domains, key);

	/* 5. Generate all domains hash (top-10 most frequent) */
	res->all_domains_hash = hash_top_domains(all_domains, 10, key);

	/* 6. Generate features hash (bucketed statistics) */
	res->features_hash = hash_html_features(hc_ptr, key);

	/* 7. Store metadata */
	res->tags_count = std::min<unsigned int>(hc_ptr->features.tags_count, UINT16_MAX);
	res->links_count = std::min<unsigned int>(hc_ptr->features.links.total_links, UINT16_MAX);
	res->dom_depth = std::min<unsigned int>(hc_ptr->features.max_dom_depth, UINT8_MAX);

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
