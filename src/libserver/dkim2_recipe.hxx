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

/*
 * Recipes of the DKIM2 Message-Instance header field: a strict JSON reader
 * and the application of recipe steps.
 *
 * Reference: draft-ietf-dkim-dkim2-spec-09, Section 5
 */

#ifndef RSPAMD_DKIM2_RECIPE_HXX
#define RSPAMD_DKIM2_RECIPE_HXX
#pragma once

#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include "contrib/expected/expected.hpp"

namespace rspamd::dkim2 {

/*
 * Recipes (the r= tag of Message-Instance, Section 5): JSON instructions to
 * recreate the previous message state. The spec imposes no limits on them, so
 * all limits below are internal hard caps; a recipe exceeding them is reported
 * as `unacceptably complex` (Section 14.2).
 */

struct recipe_limits_t {
	std::size_t max_recipe_len = 256 * 1024; /* decoded recipe JSON size */
	std::size_t max_steps = 256;             /* steps per recipe part */
	std::size_t max_names = 256;             /* header field names per recipe */
	std::size_t max_data_lines = 16384;      /* strings of all data steps of a recipe */
	std::size_t max_body_lines = 1000000;    /* body lines per message state */
	std::size_t max_header_instances = 1000; /* header instances per name */
};

struct recipe_step_t {
	bool is_copy = false;
	/* Copy steps: 1-based inclusive range of elements of the current state */
	std::size_t start = 0;
	std::size_t end = 0;
	/* Data steps ("d" and decoded "u"): header values or body lines */
	std::vector<std::string> data;
};

struct recipe_t {
	bool has_headers = false; /* "h" key present */
	bool has_body = false;    /* "b" key present */
	bool body_null = false;   /* "b" is null: prior body cannot be recreated */
	/* lowercase header field name -> steps */
	std::vector<std::pair<std::string, std::vector<recipe_step_t>>> headers;
	std::vector<recipe_step_t> body;

	/* Steps for a (lowercase) header field name, nullptr if there are none */
	auto find_header(std::string_view lc_name) const -> const std::vector<recipe_step_t> *;
};

enum class recipe_error_kind {
	invalid_json,   /* not JSON at all */
	invalid_recipe, /* JSON that breaks the schema or the rules of Section 5 */
	too_complex,    /* valid, but over the internal limits */
};

struct recipe_error_t {
	recipe_error_kind kind;
	std::string what;
};

/**
 * Parse a decoded (JSON) recipe, enforcing the schema, the extra rules of
 * Section 5 (lowercase unique keys, ascending copy ranges, no recipes for
 * unsigned header fields) and the limits
 */
auto parse_recipe(std::string_view json, const recipe_limits_t &limits)
	-> tl::expected<recipe_t, recipe_error_t>;

/**
 * Apply recipe steps to a list of elements (body lines or header field
 * instances of one name, index 0 corresponding to element number 1) producing
 * the previous state. Output views point into `current` elements or into the
 * data strings of the owning recipe_t, which must outlive the result.
 * `budget` is the shared work allowance in bytes for the whole chain. Recipe
 * application charges every emitted byte; reconstructed-state hashing charges
 * the same budget separately.
 */
auto apply_recipe_steps(const std::vector<std::string_view> &current,
						const std::vector<recipe_step_t> &steps,
						std::size_t max_elements,
						std::size_t &budget)
	-> tl::expected<std::vector<std::string_view>, recipe_error_t>;

}// namespace rspamd::dkim2

#endif /* RSPAMD_DKIM2_RECIPE_HXX */
