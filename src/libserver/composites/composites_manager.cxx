/*
 * Copyright 2025 Vsevolod Stakhov
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

#include <memory>
#include <vector>
#include <cmath>
#include "contrib/ankerl/unordered_dense.h"

#include "composites.h"
#include "composites_internal.hxx"
#include "libserver/cfg_file.h"
#include "libserver/logger.h"
#include "libserver/maps/map.h"
#include "libserver/rspamd_symcache.h"
#include "libutil/cxx/util.hxx"

namespace rspamd::composites {

static auto
composite_policy_from_str(const std::string_view &inp) -> enum rspamd_composite_policy
{
	const static ankerl::unordered_dense::map<std::string_view,
											  enum rspamd_composite_policy>
		names{
			{"remove", rspamd_composite_policy::RSPAMD_COMPOSITE_POLICY_REMOVE_ALL},
			{"remove_all", rspamd_composite_policy::RSPAMD_COMPOSITE_POLICY_REMOVE_ALL},
			{"default", rspamd_composite_policy::RSPAMD_COMPOSITE_POLICY_REMOVE_ALL},
			{"remove_symbol", rspamd_composite_policy::RSPAMD_COMPOSITE_POLICY_REMOVE_SYMBOL},
			{"remove_weight", rspamd_composite_policy::RSPAMD_COMPOSITE_POLICY_REMOVE_WEIGHT},
			{"leave", rspamd_composite_policy::RSPAMD_COMPOSITE_POLICY_LEAVE},
			{"remove_none", rspamd_composite_policy::RSPAMD_COMPOSITE_POLICY_LEAVE},
		};

	auto found = names.find(inp);
	if (found != names.end()) {
		return found->second;
	}

	return rspamd_composite_policy::RSPAMD_COMPOSITE_POLICY_UNKNOWN;
}// namespace rspamd::composites

auto composites_manager::add_composite(std::string_view composite_name, const ucl_object_t *obj, bool silent_duplicate) -> rspamd_composite *
{

	const auto *val = ucl_object_lookup(obj, "enabled");
	if (val != nullptr && !ucl_object_toboolean(val)) {
		msg_info_config("composite %s is disabled", composite_name.data());
		return nullptr;
	}

	if (current_gen->composites.contains(composite_name)) {
		if (silent_duplicate) {
			msg_debug_config("composite %s is redefined", composite_name.data());
			return nullptr;
		}
		else {
			msg_warn_config("composite %s is redefined", composite_name.data());
		}
	}

	const char *composite_expression = nullptr;
	val = ucl_object_lookup(obj, "expression");

	if (val == NULL || !ucl_object_tostring_safe(val, &composite_expression)) {
		msg_err_config("composite must have an expression defined in %s",
					   composite_name.data());
		return nullptr;
	}

	GError *err = nullptr;
	rspamd_expression *expr = nullptr;

	if (!rspamd_parse_expression(composite_expression, 0, &composite_expr_subr,
								 NULL, cfg->cfg_pool, &err, &expr)) {
		msg_err_config("cannot parse composite expression for %s: %e",
					   composite_name.data(), err);

		if (err) {
			g_error_free(err);
		}

		return nullptr;
	}

	const auto &composite = new_composite(composite_name, expr, composite_expression);

	auto score = std::isnan(cfg->unknown_weight) ? 0.0 : cfg->unknown_weight;
	val = ucl_object_lookup(obj, "score");

	if (val != nullptr) {
		ucl_object_todouble_safe(val, &score);
	}

	/* Also set score in the metric */
	const auto *group = "composite";
	val = ucl_object_lookup(obj, "group");
	if (val != nullptr) {
		group = ucl_object_tostring(val);
	}

	const auto *description = composite_expression;
	val = ucl_object_lookup(obj, "description");
	if (val != nullptr) {
		description = ucl_object_tostring(val);
	}

	rspamd_config_add_symbol(cfg, composite_name.data(), score,
							 description, group,
							 0,
							 ucl_object_get_priority(obj), /* No +1 as it is default... */
							 1);

	const auto *elt = ucl_object_lookup(obj, "groups");
	if (elt && ucl_object_type(elt) == UCL_ARRAY) {
		const ucl_object_t *cur_gr;
		auto *gr_it = ucl_object_iterate_new(elt);

		while ((cur_gr = ucl_object_iterate_safe(gr_it, true)) != nullptr) {
			rspamd_config_add_symbol_group(cfg, composite_name.data(),
										   ucl_object_tostring(cur_gr));
		}

		ucl_object_iterate_free(gr_it);
	}

	val = ucl_object_lookup(obj, "policy");
	if (val) {
		composite->policy = composite_policy_from_str(ucl_object_tostring(val));

		if (composite->policy == rspamd_composite_policy::RSPAMD_COMPOSITE_POLICY_UNKNOWN) {
			msg_err_config("composite %s has incorrect policy", composite_name.data());
			return nullptr;
		}
	}

	return composite.get();
}

auto composites_manager::add_composite(std::string_view composite_name,
									   std::string_view composite_expression,
									   bool silent_duplicate, double score) -> rspamd_composite *
{
	GError *err = nullptr;
	rspamd_expression *expr = nullptr;

	if (current_gen->composites.contains(composite_name)) {
		/* Duplicate composite - refuse to add */
		if (silent_duplicate) {
			msg_debug_config("composite %s is redefined", composite_name.data());
			return nullptr;
		}
		else {
			msg_warn_config("composite %s is redefined", composite_name.data());
		}
	}

	/*
	 * Copy expression string to memory pool - the expression parser stores
	 * pointers into this string in atom->str, so it must outlive the expression.
	 */
	char *expr_copy = rspamd_mempool_alloc_buffer(cfg->cfg_pool, composite_expression.size() + 1);
	memcpy(expr_copy, composite_expression.data(), composite_expression.size());
	expr_copy[composite_expression.size()] = '\0';

	if (!rspamd_parse_expression(expr_copy,
								 composite_expression.size(), &composite_expr_subr,
								 nullptr, cfg->cfg_pool, &err, &expr)) {
		msg_err_config("cannot parse composite expression for %s: %e",
					   composite_name.data(), err);

		if (err) {
			g_error_free(err);
		}

		return nullptr;
	}

	auto final_score = std::isnan(score) ? (std::isnan(cfg->unknown_weight) ? 0.0 : cfg->unknown_weight) : score;
	rspamd_config_add_symbol(cfg, composite_name.data(), final_score,
							 composite_name.data(), "composite",
							 0,
							 0,
							 1);

	return new_composite(composite_name, expr, composite_expression).get();
}

/*
 * Per-map state. Lives in cfg->cfg_pool and survives across reloads of the
 * same map. `last_names` tracks which composite names this map last
 * published so that on reload we can stub-out names that the map dropped.
 */
struct map_cbdata {
	composites_manager *cm;
	struct rspamd_config *cfg;
	std::string buf;
	ankerl::unordered_dense::set<std::string> last_names;

	explicit map_cbdata(struct rspamd_config *cfg)
		: cfg(cfg)
	{
		cm = COMPOSITE_MANAGER_FROM_PTR(cfg->composites_manager);
	}

	static char *map_read(char *chunk, int len,
						  struct map_cb_data *data,
						  gboolean _final)
	{
		if (data->cur_data == nullptr) {
			data->cur_data = data->prev_data;
			reinterpret_cast<map_cbdata *>(data->cur_data)->buf.clear();
		}

		auto *cbd = reinterpret_cast<map_cbdata *>(data->cur_data);
		cbd->buf.append(chunk, len);
		return nullptr;
	}

	static void
	map_fin(struct map_cb_data *data, void **target)
	{
		auto *cbd = reinterpret_cast<map_cbdata *>(data->cur_data);

		if (data->errored) {
			if (cbd) {
				cbd->buf.clear();
			}
			return;
		}

		if (cbd == nullptr) {
			msg_err("no data read for composites map");
			return;
		}

		if (target) {
			*target = data->cur_data;
		}

		auto *cfg = cbd->cfg;
		auto *cm = cbd->cm;

		/* Parse the buffered bytes as UCL. */
		auto *parser = ucl_parser_new(UCL_PARSER_NO_FILEVARS);
		if (!ucl_parser_add_chunk(parser,
								  reinterpret_cast<const unsigned char *>(cbd->buf.data()),
								  cbd->buf.size())) {
			msg_err_config("cannot parse composites map as UCL: %s",
						   ucl_parser_get_error(parser));
			ucl_parser_free(parser);
			cbd->buf.clear();
			return;
		}

		ucl_object_t *top = ucl_parser_get_object(parser);
		ucl_parser_free(parser);

		if (top == nullptr) {
			msg_err_config("composites map UCL is empty");
			cbd->buf.clear();
			return;
		}

		if (ucl_object_type(top) != UCL_OBJECT) {
			msg_err_config("composites map must be a UCL object, got %s",
						   ucl_object_type_to_string(ucl_object_type(top)));
			ucl_object_unref(top);
			cbd->buf.clear();
			return;
		}

		/* Build a staging generation cloned from the base. */
		auto staging = cm->build_staging();
		ankerl::unordered_dense::set<std::string> seen_in_map;
		unsigned int added = 0, updated = 0, failed = 0;

		const ucl_object_t *cur;
		auto *it = ucl_object_iterate_new(top);
		while ((cur = ucl_object_iterate_safe(it, true)) != nullptr) {
			const char *key = ucl_object_key(cur);
			if (key == nullptr) {
				continue;
			}
			std::string name{key};

			bool replacing = staging->composites.contains(name);
			auto *comp = cm->add_composite_to_staging(*staging, name, cur);
			if (comp == nullptr) {
				failed++;
				continue;
			}

			seen_in_map.insert(name);
			if (replacing) {
				updated++;
			}
			else {
				added++;
			}
		}
		ucl_object_iterate_free(it);
		ucl_object_unref(top);

		/* Names this map previously owned but no longer mentions become
		 * disabled stubs in the staging. */
		unsigned int stubbed = 0;
		for (const auto &name: cbd->last_names) {
			if (seen_in_map.contains(name)) {
				continue;
			}
			if (cm->disable_in_staging(*staging, name)) {
				stubbed++;
			}
		}

		cm->publish_generation(staging);
		cbd->last_names = std::move(seen_in_map);
		cbd->buf.clear();

		msg_info_config("dynamic composites map reloaded (gen %L): "
						"%ud added, %ud updated, %ud stubbed, %ud failed",
						(int64_t) cm->current()->generation_id,
						added, updated, stubbed, failed);
	}

	static void
	map_dtor(struct map_cb_data *data)
	{
		auto *cbd = reinterpret_cast<map_cbdata *>(data->cur_data);
		delete cbd;
	}
};
}// namespace rspamd::composites


void *
rspamd_composites_manager_create(struct rspamd_config *cfg)
{
	auto *cm = new rspamd::composites::composites_manager(cfg);

	return reinterpret_cast<void *>(cm);
}


gsize rspamd_composites_manager_nelts(void *ptr)
{
	return COMPOSITE_MANAGER_FROM_PTR(ptr)->size();
}

void *
rspamd_composites_manager_add_from_ucl(void *cm, const char *sym, const ucl_object_t *obj)
{
	return reinterpret_cast<void *>(COMPOSITE_MANAGER_FROM_PTR(cm)->add_composite(sym, obj, false));
}

void *
rspamd_composites_manager_add_from_string(void *cm, const char *sym, const char *expr)
{
	return reinterpret_cast<void *>(COMPOSITE_MANAGER_FROM_PTR(cm)->add_composite(sym, expr, false));
}

void *
rspamd_composites_manager_add_from_ucl_silent(void *cm, const char *sym, const ucl_object_t *obj)
{
	return reinterpret_cast<void *>(COMPOSITE_MANAGER_FROM_PTR(cm)->add_composite(sym, obj, true));
}

void *
rspamd_composites_manager_add_from_string_silent(void *cm, const char *sym, const char *expr)
{
	return reinterpret_cast<void *>(COMPOSITE_MANAGER_FROM_PTR(cm)->add_composite(sym, expr, true));
}


bool rspamd_composites_add_map_handlers(const ucl_object_t *obj, struct rspamd_config *cfg)
{
	auto **pcbdata = rspamd_mempool_alloc_type(cfg->cfg_pool, rspamd::composites::map_cbdata *);
	auto *cbdata = new rspamd::composites::map_cbdata{cfg};
	*pcbdata = cbdata;

	if (struct rspamd_map * m; (m = rspamd_map_add_from_ucl(cfg, obj, "composites map",
															rspamd::composites::map_cbdata::map_read, rspamd::composites::map_cbdata::map_fin,
															rspamd::composites::map_cbdata::map_dtor, (void **) pcbdata,
															nullptr, RSPAMD_MAP_DEFAULT)) == nullptr) {
		msg_err_config("cannot load composites map from %s", ucl_object_key(obj));
		return false;
	}

	return true;
}

namespace rspamd::composites {

/* Helper to check if a symbol requires second pass evaluation */
static bool
symbol_needs_second_pass(struct rspamd_config *cfg, const char *symbol_name)
{
	if (!cfg->cache) {
		return false;
	}

	auto flags = rspamd_symcache_get_symbol_flags(cfg->cache, symbol_name);

	/* Postfilters and classifiers/statistics symbols require second pass */
	return (flags & (SYMBOL_TYPE_POSTFILTER | SYMBOL_TYPE_CLASSIFIER | SYMBOL_TYPE_NOSTAT)) != 0;
}

/* Callback data for walking expression atoms to find symbol dependencies */
struct composite_dep_cbdata {
	struct rspamd_config *cfg;
	bool needs_second_pass;
	composites_generation *gen;
};

static void
composite_dep_callback(const rspamd_ftok_t *atom, gpointer ud)
{
	auto *cbd = reinterpret_cast<composite_dep_cbdata *>(ud);
	auto *cfg = cbd->cfg;

	if (cbd->needs_second_pass) {
		/* Already marked, no need to continue */
		return;
	}

	/* Convert atom to string */
	std::string_view atom_str(atom->begin, atom->len);

	/* Skip operators and special characters */
	if (atom->len == 0 || atom->begin[0] == '&' || atom->begin[0] == '|' ||
		atom->begin[0] == '!' || atom->begin[0] == '(' || atom->begin[0] == ')') {
		return;
	}

	/* Check if this is a reference to another composite within the
	 * generation being built */
	if (auto *dep_comp = cbd->gen->find(atom_str); dep_comp != nullptr) {
		/* Dependency on another composite - will be handled in transitive pass */
		return;
	}

	/* Check if the symbol itself needs second pass */
	/* Create null-terminated string for C API (rspamd_ftok_t is not null-terminated) */
	std::string symbol_name(atom->begin, atom->len);
	if (symbol_needs_second_pass(cfg, symbol_name.c_str())) {
		msg_debug_config("composite depends on second-pass symbol: %s",
						 symbol_name.c_str());
		cbd->needs_second_pass = true;
	}
}

void composites_manager::process_dependencies(composites_generation &gen)
{
	ankerl::unordered_dense::set<rspamd_composite *> second_pass_set;
	bool changed;

	msg_debug_config("analyzing composite dependencies for two-phase evaluation (gen %L)",
					 (int64_t) gen.generation_id);

	/* Reset pass buckets in case process_dependencies() is called repeatedly */
	gen.first_pass_composites.clear();
	gen.second_pass_composites.clear();

	/* Skip disabled stubs entirely — they will not be evaluated */
	for (const auto &comp: gen.all_composites) {
		if (!comp->disabled) {
			gen.first_pass_composites.push_back(comp.get());
		}
		else {
			comp->second_pass = false;
		}
	}

	/* First pass: mark composites that directly depend on postfilters/stats */
	for (auto *comp: gen.first_pass_composites) {
		composite_dep_cbdata cbd{cfg, false, &gen};

		rspamd_expression_atom_foreach(comp->expr,
									   composite_dep_callback,
									   &cbd);

		if (cbd.needs_second_pass) {
			second_pass_set.insert(comp);
			msg_debug_config("composite '%s' marked for second pass (direct dependency)",
							 comp->sym.c_str());
		}
	}

	/* Second pass: handle transitive dependencies */
	do {
		changed = false;
		for (auto *comp: gen.first_pass_composites) {
			if (second_pass_set.contains(comp)) {
				continue;
			}

			bool has_second_pass_dep = false;

			/* Helper struct for lambda capture */
			struct trans_check_data {
				composites_generation *gen;
				ankerl::unordered_dense::set<rspamd_composite *> *second_pass_set;
				bool *has_dep;
			} trans_data{&gen, &second_pass_set, &has_second_pass_dep};

			rspamd_expression_atom_foreach(comp->expr, [](const rspamd_ftok_t *atom, gpointer ud) {
											   auto *data = reinterpret_cast<trans_check_data *>(ud);
											   std::string_view atom_str(atom->begin, atom->len);
											   if (auto *dep_comp = data->gen->find(atom_str); dep_comp != nullptr) {
												   /* Cast away const since we know this points to a modifiable composite */
												   if (data->second_pass_set->contains(const_cast<rspamd_composite *>(dep_comp))) {
													   *data->has_dep = true;
												   }
											   } }, &trans_data);

			if (has_second_pass_dep) {
				second_pass_set.insert(comp);
				changed = true;
				msg_debug_config("composite '%s' marked for second pass (transitive dependency)",
								 comp->sym.c_str());
			}
		}
	} while (changed);

	/* Move second-pass composites from first_pass to second_pass vector and mark them */
	auto it = gen.first_pass_composites.begin();
	while (it != gen.first_pass_composites.end()) {
		if (second_pass_set.contains(*it)) {
			(*it)->second_pass = true;
			gen.second_pass_composites.push_back(*it);
			it = gen.first_pass_composites.erase(it);
		}
		else {
			(*it)->second_pass = false;
			++it;
		}
	}

	msg_debug_config("composite dependency analysis complete: %d first-pass, %d second-pass composites",
					 (int) gen.first_pass_composites.size(), (int) gen.second_pass_composites.size());
}

/*
 * Count NOT operations from atom to root to determine atom polarity.
 * Even number of NOTs = positive atom (must be true for expression to be true)
 * Odd number of NOTs = negative atom (must be false for expression to be true)
 */
static bool
atom_is_negated(GNode *atom_node)
{
	int not_count = 0;
	GNode *node = atom_node->parent;

	while (node != nullptr) {
		if (rspamd_expression_node_is_op(node, OP_NOT)) {
			not_count++;
		}
		node = node->parent;
	}

	/* Odd number of NOTs means atom is negated */
	return (not_count & 1) != 0;
}

/* Extract the symbol name from an expression atom string, stripping prefixes (~, -, ^)
 * and option brackets ([...]). Returns empty string for group matchers or invalid atoms. */
static std::string
extract_atom_symbol_name(const rspamd_expression_atom_t *atom)
{
	if (atom->str == nullptr || atom->len == 0) {
		return {};
	}

	std::string_view atom_str(atom->str, atom->len);

	/* Skip prefix characters (~, -, ^) */
	size_t sym_start = 0;
	while (sym_start < atom_str.size() &&
		   (atom_str[sym_start] == '~' || atom_str[sym_start] == '-' || atom_str[sym_start] == '^')) {
		++sym_start;
	}

	if (sym_start >= atom_str.size()) {
		return {};
	}

	std::string_view remaining = atom_str.substr(sym_start);

	/* Skip group matchers: g:, g+:, g-: */
	if (remaining.size() >= 2 && remaining.substr(0, 2) == "g:") {
		return {};
	}
	if (remaining.size() >= 3 && (remaining.substr(0, 3) == "g+:" || remaining.substr(0, 3) == "g-:")) {
		return {};
	}

	/* Find end of symbol name (before '[' if present for options) */
	auto bracket_pos = remaining.find('[');
	if (bracket_pos != std::string_view::npos) {
		return std::string(remaining.substr(0, bracket_pos));
	}

	return std::string(remaining);
}

/*
 * Recursively collect all non-composite (leaf) positive atom symbol names
 * for a composite. Handles transitive composite references with cycle detection.
 */
static void
collect_leaf_atoms(composites_generation &gen, const rspamd_composite *comp,
				   ankerl::unordered_dense::set<std::string> &leaf_atoms,
				   ankerl::unordered_dense::set<int> &visited)
{
	if (visited.contains(comp->id)) {
		return;
	}
	visited.insert(comp->id);

	struct walk_data {
		composites_generation *gen;
		ankerl::unordered_dense::set<std::string> *leaves;
		ankerl::unordered_dense::set<int> *visited;
	} wd{&gen, &leaf_atoms, &visited};

	rspamd_expression_atom_foreach_ex(comp->expr, [](GNode *node, rspamd_expression_atom_t *atom, gpointer ud) {
			auto *wd = reinterpret_cast<walk_data *>(ud);

			if (atom_is_negated(node)) {
				return;
			}

			auto sym = extract_atom_symbol_name(atom);
			if (sym.empty()) {
				return;
			}

			auto *ref = wd->gen->find(sym);
			if (ref != nullptr) {
				/* Atom is a composite reference - recurse into it */
				collect_leaf_atoms(*wd->gen, ref, *wd->leaves, *wd->visited);
			}
			else {
				wd->leaves->insert(std::move(sym));
			} }, &wd);
}

/* Context for building inverted index */
struct inverted_index_cbdata {
	composites_generation *gen;
	rspamd_composite *comp;
	bool has_positive;
	bool has_group_atom; /* Composite uses group matcher (g:, g+:, g-:) */
};

static void
inverted_index_atom_callback(GNode *atom_node, rspamd_expression_atom_t *atom, gpointer ud)
{
	auto *cbd = reinterpret_cast<inverted_index_cbdata *>(ud);

	/* Check atom polarity by counting NOTs to root */
	if (atom_is_negated(atom_node)) {
		/* Negated atom - don't add to inverted index */
		return;
	}

	if (atom->str == nullptr || atom->len == 0) {
		return;
	}

	/* Check for group matchers first (need to look at full atom string) */
	std::string_view atom_str(atom->str, atom->len);
	size_t sym_start = 0;
	while (sym_start < atom_str.size() &&
		   (atom_str[sym_start] == '~' || atom_str[sym_start] == '-' || atom_str[sym_start] == '^')) {
		++sym_start;
	}
	if (sym_start < atom_str.size()) {
		auto remaining = atom_str.substr(sym_start);
		if ((remaining.size() >= 2 && remaining.substr(0, 2) == "g:") ||
			(remaining.size() >= 3 && (remaining.substr(0, 3) == "g+:" || remaining.substr(0, 3) == "g-:"))) {
			cbd->has_group_atom = true;
			return;
		}
	}

	auto symbol_name = extract_atom_symbol_name(atom);
	if (symbol_name.empty()) {
		return;
	}

	/* Mark that we have at least one positive atom */
	cbd->has_positive = true;

	/* Add to inverted index in the generation being built */
	cbd->gen->symbol_to_composites[symbol_name].push_back(cbd->comp);
}

void composites_manager::build_inverted_index(composites_generation &gen)
{
	msg_debug_config("building inverted index for %d composites (gen %L)",
					 (int) gen.all_composites.size(), (int64_t) gen.generation_id);

	gen.symbol_to_composites.clear();
	gen.not_only_composites.clear();

	for (auto &comp: gen.all_composites) {
		if (comp->disabled) {
			/* Stub: contributes neither to the index nor to "always check" */
			comp->has_positive_atoms = false;
			continue;
		}

		inverted_index_cbdata cbd{&gen, comp.get(), false, false};

		rspamd_expression_atom_foreach_ex(comp->expr, inverted_index_atom_callback, &cbd);

		comp->has_positive_atoms = cbd.has_positive;

		if (!cbd.has_positive || cbd.has_group_atom) {
			/*
			 * Composite must always be checked if:
			 * - It has only negated atoms (no positive symbols to match)
			 * - It uses group matchers (we don't know which symbols will match)
			 */
			gen.not_only_composites.push_back(comp.get());
			if (cbd.has_group_atom) {
				msg_debug_config("composite '%s' uses group matcher, will always be checked",
								 comp->sym.c_str());
			}
			else {
				msg_debug_config("composite '%s' has only negated atoms, will always be checked",
								 comp->sym.c_str());
			}
		}
	}

	/*
	 * Resolve composite references in the inverted index.
	 *
	 * When a composite C references another composite D as an atom, the inverted
	 * index will have an entry D -> [C]. But D is not in the scan result at lookup
	 * time (it gets inserted during composite evaluation), so C would never be
	 * activated via the fast path.
	 *
	 * Fix: for each composite-name key in the index, recursively find its leaf
	 * (non-composite) atoms and propagate the dependents to those leaf atoms'
	 * entries. Then remove the composite-name keys.
	 */
	ankerl::unordered_dense::set<std::string> composite_keys;
	for (const auto &[sym, _]: gen.symbol_to_composites) {
		if (gen.find(sym) != nullptr) {
			composite_keys.insert(sym);
		}
	}

	if (!composite_keys.empty()) {
		msg_debug_config("resolving %d composite references in inverted index",
						 (int) composite_keys.size());

		for (const auto &comp_key: composite_keys) {
			auto it = gen.symbol_to_composites.find(comp_key);
			if (it == gen.symbol_to_composites.end()) {
				continue;
			}

			auto dependents = it->second; /* Copy before modifying the map */
			auto *ref_comp = gen.find(comp_key);

			/* Collect all leaf (non-composite) atoms reachable from this composite */
			ankerl::unordered_dense::set<std::string> leaf_atoms;
			ankerl::unordered_dense::set<int> visited;
			collect_leaf_atoms(gen, ref_comp, leaf_atoms, visited);

			/* Propagate dependents to each leaf atom's index entry */
			for (const auto &leaf: leaf_atoms) {
				auto &entry = gen.symbol_to_composites[leaf];
				for (auto *dep: dependents) {
					if (std::find(entry.begin(), entry.end(), dep) == entry.end()) {
						entry.push_back(dep);
					}
				}
			}

			/*
			 * If no leaf atoms found (e.g. composite depends only on other
			 * composites with only negated/group atoms), ensure the dependent
			 * composites are always checked.
			 */
			if (leaf_atoms.empty()) {
				for (auto *dep: dependents) {
					if (std::find(gen.not_only_composites.begin(),
								  gen.not_only_composites.end(), dep) == gen.not_only_composites.end()) {
						gen.not_only_composites.push_back(dep);
						msg_debug_config("composite '%s' depends on composite '%s' "
										 "with no leaf atoms, will always be checked",
										 dep->sym.c_str(), comp_key.c_str());
					}
				}
			}

			/* Remove the composite-name key from the index */
			gen.symbol_to_composites.erase(comp_key);

			msg_debug_config("resolved composite reference '%s': "
							 "propagated %d dependents to %d leaf atoms",
							 comp_key.c_str(), (int) dependents.size(),
							 (int) leaf_atoms.size());
		}
	}

	msg_debug_config("inverted index built: %d unique symbols, %d not-only composites",
					 (int) gen.symbol_to_composites.size(), (int) gen.not_only_composites.size());
}

/* Callback data for collecting atoms from whitelist composites */
struct whitelist_atom_cbdata {
	ankerl::unordered_dense::set<std::string> *fine_symbols;
};

static void
whitelist_atom_callback(const rspamd_ftok_t *atom, gpointer ud)
{
	auto *cbd = reinterpret_cast<whitelist_atom_cbdata *>(ud);

	if (atom->len == 0) {
		return;
	}

	std::string_view atom_str(atom->begin, atom->len);

	/* Skip operators */
	if (atom_str[0] == '&' || atom_str[0] == '|' ||
		atom_str[0] == '!' || atom_str[0] == '(' || atom_str[0] == ')') {
		return;
	}

	/* Skip prefix characters (~, -, ^) */
	size_t start = 0;
	while (start < atom_str.size() &&
		   (atom_str[start] == '~' || atom_str[start] == '-' || atom_str[start] == '^')) {
		++start;
	}

	if (start >= atom_str.size()) {
		return;
	}

	auto remaining = atom_str.substr(start);

	/* Skip group matchers (g:, g+:, g-:) - we can't determine specific symbols */
	if (remaining.starts_with("g:") || remaining.starts_with("g+:") || remaining.starts_with("g-:")) {
		return;
	}

	/* Extract symbol name (before '[' if present for options) */
	auto bracket_pos = remaining.find('[');
	std::string symbol_name;
	if (bracket_pos != std::string_view::npos) {
		symbol_name = std::string(remaining.substr(0, bracket_pos));
	}
	else {
		symbol_name = std::string(remaining);
	}

	if (!symbol_name.empty()) {
		cbd->fine_symbols->emplace(std::move(symbol_name));
	}
}

void composites_manager::mark_whitelist_dependencies(composites_generation &gen)
{
	ankerl::unordered_dense::set<std::string> fine_symbols;

	msg_debug_config("analyzing whitelist composites for FINE symbol marking (gen %L)",
					 (int64_t) gen.generation_id);

	/* Step 1: Find composites with negative score and collect their atoms */
	for (const auto &comp: gen.all_composites) {
		if (comp->disabled) {
			continue;
		}
		auto *sym_def = static_cast<struct rspamd_symbol *>(
			g_hash_table_lookup(cfg->symbols, comp->sym.c_str()));

		if (sym_def && *sym_def->weight_ptr < 0) {
			/* This is a whitelist composite - collect all its atoms */
			whitelist_atom_cbdata cbd{&fine_symbols};
			rspamd_expression_atom_foreach(comp->expr, whitelist_atom_callback, &cbd);

			msg_debug_config("composite '%s' has negative weight (%.2f), collecting dependencies",
							 comp->sym.c_str(), *sym_def->weight_ptr);
		}
	}

	/* Step 2: Transitively expand - if an atom is also a whitelist composite, add its atoms */
	bool changed;
	do {
		changed = false;
		for (const auto &comp: gen.all_composites) {
			if (comp->disabled) {
				continue;
			}
			if (fine_symbols.contains(comp->sym)) {
				size_t before = fine_symbols.size();
				whitelist_atom_cbdata cbd{&fine_symbols};
				rspamd_expression_atom_foreach(comp->expr, whitelist_atom_callback, &cbd);
				if (fine_symbols.size() > before) {
					changed = true;
				}
			}
		}
	} while (changed);

	/* Step 3: Mark all collected symbols as FINE in symcache */
	int marked_count = 0;
	for (const auto &sym_name: fine_symbols) {
		if (rspamd_symcache_set_symbol_fine(cfg->cache, sym_name.c_str())) {
			msg_debug_config("marked symbol '%s' as FINE (whitelist composite dependency)",
							 sym_name.c_str());
			marked_count++;
		}
	}

	msg_info_config("marked %d symbols as FINE for whitelist composite dependencies",
					marked_count);
}

auto composites_manager::build_staging() -> std::shared_ptr<composites_generation>
{
	auto staging = std::make_shared<composites_generation>();
	staging->generation_id = allocate_generation_id();

	if (!base_gen) {
		/* Should not happen — pin_base_generation must be called once
		 * after static load. Fall back to current_gen so the caller still
		 * gets a workable staging. */
		msg_warn_config("composites: build_staging() called before base "
						"generation was pinned, cloning current_gen instead");
	}

	const auto &source = base_gen ? *base_gen : *current_gen;

	for (const auto &orig: source.all_composites) {
		/*
		 * Deep-copy the composite struct (shared expression pointer is
		 * fine, it lives in cfg_pool). Re-derive per-generation flags
		 * via the analysis pipeline.
		 */
		auto cloned = std::make_shared<rspamd_composite>(*orig);
		cloned->id = next_id();
		cloned->second_pass = false;
		cloned->has_positive_atoms = false;
		staging->all_composites.push_back(cloned);
		staging->composites[cloned->sym] = cloned;
	}

	msg_debug_config("composites: built staging gen %L with %d cloned composites",
					 (int64_t) staging->generation_id,
					 (int) staging->all_composites.size());

	return staging;
}

auto composites_manager::add_composite_to_staging(composites_generation &staging,
												  std::string_view name,
												  const ucl_object_t *obj) -> rspamd_composite *
{
	const auto *val = ucl_object_lookup(obj, "enabled");
	if (val != nullptr && !ucl_object_toboolean(val)) {
		/* Operator wants the name present but inactive — disabled stub */
		disable_in_staging(staging, std::string(name));
		return staging.find(name) ? const_cast<rspamd_composite *>(staging.find(name)) : nullptr;
	}

	const char *composite_expression = nullptr;
	val = ucl_object_lookup(obj, "expression");

	if (val == nullptr || !ucl_object_tostring_safe(val, &composite_expression)) {
		msg_err_config("dynamic composite %*s has no expression",
					   (int) name.size(), name.data());
		return nullptr;
	}

	/* Copy the expression into cfg_pool — parser keeps pointers into it. */
	auto expr_len = strlen(composite_expression);
	char *expr_copy = rspamd_mempool_alloc_buffer(cfg->cfg_pool, expr_len + 1);
	memcpy(expr_copy, composite_expression, expr_len);
	expr_copy[expr_len] = '\0';

	GError *err = nullptr;
	rspamd_expression *expr = nullptr;

	if (!rspamd_parse_expression(expr_copy, expr_len, &composite_expr_subr,
								 nullptr, cfg->cfg_pool, &err, &expr)) {
		msg_err_config("cannot parse expression for dynamic composite %*s: %e",
					   (int) name.size(), name.data(), err);
		if (err) {
			g_error_free(err);
		}
		return nullptr;
	}

	auto composite = std::make_shared<rspamd_composite>();
	composite->id = next_id();
	composite->expr = expr;
	composite->str_expr = composite_expression;
	composite->sym = std::string(name);
	composite->second_pass = false;
	composite->has_positive_atoms = false;
	composite->disabled = false;
	composite->policy = rspamd_composite_policy::RSPAMD_COMPOSITE_POLICY_REMOVE_ALL;

	val = ucl_object_lookup(obj, "policy");
	if (val) {
		auto p = composite_policy_from_str(ucl_object_tostring(val));
		if (p == rspamd_composite_policy::RSPAMD_COMPOSITE_POLICY_UNKNOWN) {
			msg_err_config("dynamic composite %*s has unknown policy '%s'",
						   (int) name.size(), name.data(), ucl_object_tostring(val));
			return nullptr;
		}
		composite->policy = p;
	}

	/* Replace any existing entry under this name (came from base_gen
	 * clone or from an earlier entry in this same map). */
	auto sym_key = composite->sym;
	auto it = staging.composites.find(sym_key);
	if (it != staging.composites.end()) {
		/* Find and replace in all_composites */
		for (auto &slot: staging.all_composites) {
			if (slot.get() == it->second.get()) {
				slot = composite;
				break;
			}
		}
		it->second = composite;
	}
	else {
		staging.all_composites.push_back(composite);
		staging.composites[sym_key] = composite;
	}

	/* Reflect the composite in cfg->symbols so scoring and FINE-flag
	 * propagation work for both static and dynamic composites. Safe to
	 * mutate the GHashTable here because we're on the libev thread with
	 * no scan in progress. */
	auto score = std::isnan(cfg->unknown_weight) ? 0.0 : cfg->unknown_weight;
	val = ucl_object_lookup(obj, "score");
	if (val != nullptr) {
		ucl_object_todouble_safe(val, &score);
	}

	const char *group = "composite";
	val = ucl_object_lookup(obj, "group");
	if (val != nullptr) {
		group = ucl_object_tostring(val);
	}

	const char *description = composite_expression;
	val = ucl_object_lookup(obj, "description");
	if (val != nullptr) {
		description = ucl_object_tostring(val);
	}

	rspamd_config_add_symbol(cfg, composite->sym.c_str(), score,
							 description, group,
							 0, ucl_object_get_priority(obj),
							 1);

	const auto *groups = ucl_object_lookup(obj, "groups");
	if (groups && ucl_object_type(groups) == UCL_ARRAY) {
		const ucl_object_t *cur_gr;
		auto *gr_it = ucl_object_iterate_new(groups);

		while ((cur_gr = ucl_object_iterate_safe(gr_it, true)) != nullptr) {
			rspamd_config_add_symbol_group(cfg, composite->sym.c_str(),
										   ucl_object_tostring(cur_gr));
		}

		ucl_object_iterate_free(gr_it);
	}

	return composite.get();
}

auto composites_manager::disable_in_staging(composites_generation &staging,
											const std::string &name) -> bool
{
	auto it = staging.composites.find(name);
	if (it == staging.composites.end()) {
		/* Name never existed — create an inert stub so find() works */
		auto stub = std::make_shared<rspamd_composite>();
		stub->id = next_id();
		stub->expr = nullptr;
		stub->sym = name;
		stub->second_pass = false;
		stub->has_positive_atoms = false;
		stub->disabled = true;
		stub->policy = rspamd_composite_policy::RSPAMD_COMPOSITE_POLICY_LEAVE;
		staging.all_composites.push_back(stub);
		staging.composites[name] = stub;
		return true;
	}

	auto stub = std::make_shared<rspamd_composite>(*it->second);
	stub->id = next_id();
	stub->expr = nullptr;
	stub->second_pass = false;
	stub->has_positive_atoms = false;
	stub->disabled = true;
	for (auto &slot: staging.all_composites) {
		if (slot.get() == it->second.get()) {
			slot = stub;
			break;
		}
	}
	it->second = stub;
	return true;
}

auto composites_manager::publish_generation(std::shared_ptr<composites_generation> staging) -> void
{
	if (!staging) {
		return;
	}

	/* Register newly-introduced composite names with the symcache. cfg->symbols
	 * was already updated by add_composite_to_staging(). ever_seen_names gates
	 * the one-time symcache add. */
	bool symcache_changed = false;
	for (const auto &[name, comp]: staging->composites) {
		if (comp->disabled) {
			continue;
		}
		if (ever_seen_names.contains(name)) {
			continue;
		}
		if (cfg->cache) {
			rspamd_symcache_add_symbol(cfg->cache, name.c_str(), 0,
									   nullptr, comp.get(),
									   SYMBOL_TYPE_COMPOSITE, -1);
			symcache_changed = true;
		}
		/* Pin the shared_ptr so the symcache's ud never dangles even if
		 * the composite is replaced in a later generation. */
		symcache_pinned[name] = comp;
		ever_seen_names.insert(name);
	}

	if (symcache_changed && cfg->cache) {
		rspamd_symcache_promote_resort(cfg->cache);
	}

	/* Run the analysis pipeline on the staging gen. */
	process_dependencies(*staging);
	build_inverted_index(*staging);
	mark_whitelist_dependencies(*staging);

	/* Atomic swap (single-threaded libev: assignment is the swap). */
	current_gen = std::move(staging);
}

auto composites_manager::seal_static_load() -> void
{
	if (base_gen) {
		return; /* Already sealed */
	}
	base_gen = current_gen;
	for (const auto &[name, comp]: current_gen->composites) {
		ever_seen_names.insert(name);
		/* Static composites are pinned via base_gen → all_composites, no
		 * extra pinning required for the symcache ud. */
	}
	msg_debug_config("composites: sealed static load (gen %L, %d composites)",
					 (int64_t) current_gen->generation_id,
					 (int) current_gen->all_composites.size());
}

}// namespace rspamd::composites

void rspamd_composites_process_deps(void *cm_ptr, struct rspamd_config *cfg)
{
	auto *cm = COMPOSITE_MANAGER_FROM_PTR(cm_ptr);
	cm->process_dependencies();
	cm->build_inverted_index();
}

void rspamd_composites_set_inverted_index(void *cm_ptr, gboolean enabled)
{
	auto *cm = COMPOSITE_MANAGER_FROM_PTR(cm_ptr);
	cm->use_inverted_index = enabled;
}

gboolean rspamd_composites_get_inverted_index(void *cm_ptr)
{
	auto *cm = COMPOSITE_MANAGER_FROM_PTR(cm_ptr);
	return cm->use_inverted_index;
}

void rspamd_composites_get_stats(void *cm_ptr, struct rspamd_composites_stats_export *stats)
{
	auto *cm = COMPOSITE_MANAGER_FROM_PTR(cm_ptr);

	stats->checked_slow = cm->stats.checked_slow;
	stats->checked_fast = cm->stats.checked_fast;
	stats->matched = cm->stats.matched;

	stats->time_slow_mean = cm->stats.time_slow.mean;
	stats->time_slow_stddev = cm->stats.time_slow.stddev;
	stats->time_slow_count = cm->stats.time_slow.number;

	stats->time_fast_mean = cm->stats.time_fast.mean;
	stats->time_fast_stddev = cm->stats.time_fast.stddev;
	stats->time_fast_count = cm->stats.time_fast.number;
}

void rspamd_composites_mark_whitelist_deps(void *cm_ptr, struct rspamd_config *cfg)
{
	auto *cm = COMPOSITE_MANAGER_FROM_PTR(cm_ptr);
	cm->mark_whitelist_dependencies();
	/* Last step of static load: snapshot base generation and ever-seen
	 * names so dynamic map publishes can clone from a stable base. */
	cm->seal_static_load();
}

bool rspamd_composites_add_dynamic_map(void *cm_ptr, const ucl_object_t *obj,
									   struct rspamd_config *cfg)
{
	auto *cm = COMPOSITE_MANAGER_FROM_PTR(cm_ptr);
	(void) cm;
	return rspamd_composites_add_map_handlers(obj, cfg);
}

uint64_t rspamd_composites_current_generation(void *cm_ptr)
{
	auto *cm = COMPOSITE_MANAGER_FROM_PTR(cm_ptr);
	auto *gen = cm->current();
	return gen ? gen->generation_id : 0;
}