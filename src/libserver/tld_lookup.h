/*
 * Copyright 2026 Vsevolod Stakhov
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

#ifndef RSPAMD_TLD_LOOKUP_H
#define RSPAMD_TLD_LOOKUP_H

#include "config.h"
#include "libutil/fstring.h"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Public suffix list lookup: longest-suffix matching of hostnames against
 * the effective TLDs file with full semantics (wildcard `*.foo` rules,
 * `!exception` rules, ICANN/private sections).
 *
 * Matching is ASCII case-insensitive; hosts are expected in UTF-8 or
 * punycode form (the suffix file contains both variants).
 */

struct rspamd_tld_lookup;

/* The matched suffix comes from a `*.foo` wildcard rule */
#define RSPAMD_TLD_SUFFIX_WILDCARD (1u << 0)
/* The host is registrable due to a `!bar.foo` exception rule */
#define RSPAMD_TLD_SUFFIX_EXCEPTION (1u << 1)
/* The rule comes from the private domains section of the file */
#define RSPAMD_TLD_SUFFIX_PRIVATE (1u << 2)

/**
 * Load the effective TLDs file (public suffix list format).
 * @return new lookup object or NULL if the file cannot be read
 */
struct rspamd_tld_lookup *rspamd_tld_lookup_new(const char *tld_file);

/**
 * Create an empty lookup to be filled with rspamd_tld_lookup_add_rule.
 * Useful for custom suffix-like rule sets (e.g. URL composition maps).
 */
struct rspamd_tld_lookup *rspamd_tld_lookup_new_empty(void);

/**
 * Add a single rule in the public suffix list syntax: `foo.bar`,
 * `*.foo.bar` or `!baz.foo.bar`. The rule is case-folded internally.
 */
void rspamd_tld_lookup_add_rule(struct rspamd_tld_lookup *lookup,
								const char *rule, gsize len);

void rspamd_tld_lookup_destroy(struct rspamd_tld_lookup *lookup);

/**
 * Number of suffix rules loaded
 */
unsigned int rspamd_tld_lookup_nrules(const struct rspamd_tld_lookup *lookup);

/**
 * Find the registrable domain (eTLD+1, the "tld" in rspamd terms) of a host:
 * the longest matching public suffix plus one preceding label. A host that is
 * itself a public suffix resolves to the whole host. A single trailing dot is
 * ignored. `out` points into `host`.
 * @return TRUE if a suffix rule matched
 */
gboolean rspamd_tld_lookup_registrable(const struct rspamd_tld_lookup *lookup,
									   const char *host, gsize len,
									   rspamd_ftok_t *out);

/**
 * Find the longest matching public suffix of a host. For a host covered by an
 * exception rule this is the exception rule minus its leftmost label.
 * `out` points into `host`; `flags` (optional) receives RSPAMD_TLD_SUFFIX_*.
 * @return TRUE if a suffix rule matched
 */
gboolean rspamd_tld_lookup_suffix(const struct rspamd_tld_lookup *lookup,
								  const char *host, gsize len,
								  rspamd_ftok_t *out, unsigned int *flags);

/**
 * Check whether `label` (a single DNS label, no dots) is the final label of
 * any suffix rule. Used to anchor URL discovery in free text.
 */
gboolean rspamd_tld_lookup_is_final_label(const struct rspamd_tld_lookup *lookup,
										  const char *label, gsize len);

#ifdef __cplusplus
}
#endif

#endif
