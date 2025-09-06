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

#ifndef RSPAMD_HTML_FEATURES_H
#define RSPAMD_HTML_FEATURES_H

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Per-message HTML link features collected during HTML parsing.
 */
struct rspamd_html_link_features {
	/* Total number of <a> / link-like elements with a parsed URL */
	unsigned int total_links;

	/* Links considered affiliated with first-party (From/DKIM/etc.) */
	unsigned int affiliated_links;
	unsigned int unaffiliated_links;

	/* Phishing-oriented link properties */
	unsigned int confusable_like_from_links; /* Unicode confusable with first-party */
	unsigned int punycode_links;             /* Host contains xn-- */
	unsigned int ip_links;                   /* Host is an IP */
	unsigned int port_links;                 /* Has explicit non-default port */
	unsigned int long_query_links;           /* Heuristically long query string */
	unsigned int trackerish_links;           /* Domain tokens dominated by tracker words */
	unsigned int display_mismatch_links;     /* Visible URL text domain != href domain */
	unsigned int js_scheme_links;            /* javascript: scheme */
	unsigned int data_scheme_links;          /* data: scheme */
	unsigned int mailto_links;               /* mailto: links */
	unsigned int http_links;                 /* http/https links */
	unsigned int query_links;                /* links with any query */
	unsigned int same_etld1_links;           /* href eTLD+1 equals first-party */

	/* Domain distribution */
	unsigned int domains_total;           /* Distinct domains among links */
	unsigned int max_links_single_domain; /* Max links observed for one domain */
};

/*
 * Aggregate HTML features for a text part; extendable in future.
 */
struct rspamd_html_features {
	/* Version of the structure for serialization/caching if needed */
	unsigned int version;

	/* Link-related features */
	struct rspamd_html_link_features links;

	/* Forms */
	unsigned int forms_count;
	unsigned int forms_post_unaffiliated;
	unsigned int forms_post_affiliated;
	unsigned int has_password_input; /* 0/1 */

	/* Images */
	unsigned int images_total;
	unsigned int images_external;
	unsigned int images_data;
	unsigned int images_tiny_external;

	/* DOM / layout */
	unsigned int tags_count;
	unsigned int max_dom_depth;

	/* Parser/quality flags mirror (bitset, reserved) */
	unsigned int flags;
};

#ifdef __cplusplus
}
#endif

#endif
