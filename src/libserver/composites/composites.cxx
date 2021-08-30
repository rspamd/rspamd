/*-
 * Copyright 2021 Vsevolod Stakhov
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
#include "logger.h"
#include "expression.h"
#include "task.h"
#include "utlist.h"
#include "scan_result.h"
#include "composites.h"

#include <cmath>
#include <vector>
#include <variant>
#include "libutil/cxx/util.hxx"
#include "contrib/robin-hood/robin_hood.h"

#include "composites_internal.hxx"

#define msg_err_composites(...) rspamd_default_log_function (G_LOG_LEVEL_CRITICAL, \
        "composites", task->task_pool->tag.uid, \
        G_STRFUNC, \
        __VA_ARGS__)
#define msg_warn_composites(...)   rspamd_default_log_function (G_LOG_LEVEL_WARNING, \
        "composites", task->task_pool->tag.uid, \
        G_STRFUNC, \
        __VA_ARGS__)
#define msg_info_composites(...)   rspamd_default_log_function (G_LOG_LEVEL_INFO, \
        "composites", task->task_pool->tag.uid, \
        G_STRFUNC, \
        __VA_ARGS__)

#define msg_debug_composites(...)  rspamd_conditional_debug_fast (NULL, task->from_addr, \
        rspamd_composites_log_id, "composites", task->task_pool->tag.uid, \
        __FUNCTION__, \
        __VA_ARGS__)

INIT_LOG_MODULE(composites)


namespace rspamd::composites {
static rspamd_expression_atom_t *rspamd_composite_expr_parse(const gchar *line, gsize len,
															 rspamd_mempool_t *pool,
															 gpointer ud, GError **err);
static gdouble rspamd_composite_expr_process(void *ud, rspamd_expression_atom_t *atom);
static gint rspamd_composite_expr_priority(rspamd_expression_atom_t *atom);
static void rspamd_composite_expr_destroy(rspamd_expression_atom_t *atom);
static void composites_foreach_callback(gpointer key, gpointer value, void *data);

const struct rspamd_atom_subr composite_expr_subr = {
		.parse = rspamd::composites::rspamd_composite_expr_parse,
		.process = rspamd::composites::rspamd_composite_expr_process,
		.priority = rspamd::composites::rspamd_composite_expr_priority,
		.destroy = rspamd::composites::rspamd_composite_expr_destroy
};
}

namespace rspamd::composites {

static constexpr const double epsilon = 0.00001;

struct symbol_remove_data {
	const char *sym;
	struct rspamd_composite *comp;
	GNode *parent;
	std::uint8_t action;
};

struct composites_data {
	struct rspamd_task *task;
	struct rspamd_composite *composite;
	struct rspamd_scan_result *metric_res;
	robin_hood::unordered_flat_map<std::string_view,
			std::vector<symbol_remove_data>> symbols_to_remove;
	std::vector<bool> checked;

	explicit composites_data(struct rspamd_task *task, struct rspamd_scan_result *mres) :
			task(task), composite(nullptr), metric_res(mres) {
		checked.resize(rspamd_composites_manager_nelts(task->cfg->composites_manager) * 2,
				false);
	}
};

struct rspamd_composite_option_match {
	rspamd_regexp_t *re;
	std::string match;

	explicit rspamd_composite_option_match(const char *start, std::size_t len) noexcept :
			re(nullptr), match(start, len) {}

	explicit rspamd_composite_option_match(rspamd_regexp_t *re) noexcept :
			re(rspamd_regexp_ref(re)) {}

	rspamd_composite_option_match(const rspamd_composite_option_match &other) noexcept
	{
		if (other.re) {
			re = rspamd_regexp_ref(other.re);
		}
		else {
			match = other.match;
			re = nullptr;
		}
	}
	rspamd_composite_option_match& operator=(const rspamd_composite_option_match &other) noexcept
	{
		if (other.re) {
			if (re) {
				rspamd_regexp_unref(re);
			}
			re = rspamd_regexp_ref(other.re);
		}
		else {
			if (re) {
				rspamd_regexp_unref(re);
			}
			re = nullptr;
			match = other.match;
		}

		return *this;
	}

	rspamd_composite_option_match(rspamd_composite_option_match &&other) noexcept
	{
		if (other.re) {
			re = other.re;
			other.re = nullptr;
		}
		else {
			re = nullptr;
			match = std::move(other.match);
		}
	}
	rspamd_composite_option_match& operator=(rspamd_composite_option_match &&other) noexcept
	{
		if (other.re) {
			if (re) {
				rspamd_regexp_unref(re);
			}
			re = other.re;
			other.re = nullptr;
		}
		else {
			if (re) {
				rspamd_regexp_unref(re);
			}
			re = nullptr;
			match = std::move(other.match);
		}

		return *this;
	}

	~rspamd_composite_option_match()
	{
		if (re) {
			rspamd_regexp_unref(re);
		}
	}

	auto match_opt(const std::string_view &data) const -> bool
	{
		if (re) {
			return rspamd_regexp_search(re,
					data.data(), data.size(),
					nullptr, nullptr, false, nullptr);
		}
		else {
			return data == match;
		}
	}

	auto get_pat() const -> std::string_view
	{
		if (re) {
			return std::string_view(rspamd_regexp_get_pattern(re));
		}
		else {
			return match;
		}
	}
};

enum class rspamd_composite_atom_type {
	ATOM_UNKNOWN,
	ATOM_COMPOSITE,
	ATOM_PLAIN
};

struct rspamd_composite_atom {
	std::string symbol;
	std::string_view norm_symbol;
	rspamd_composite_atom_type comp_type = rspamd_composite_atom_type::ATOM_UNKNOWN;
	const struct rspamd_composite *ncomp; /* underlying composite */
	std::vector<rspamd_composite_option_match> opts;
};

enum rspamd_composite_action : std::uint8_t {
	RSPAMD_COMPOSITE_UNTOUCH = 0,
	RSPAMD_COMPOSITE_REMOVE_SYMBOL = (1u << 0),
	RSPAMD_COMPOSITE_REMOVE_WEIGHT = (1u << 1),
	RSPAMD_COMPOSITE_REMOVE_FORCED = (1u << 2)
};

static GQuark
rspamd_composites_quark(void)
{
	return g_quark_from_static_string("composites");
}

static auto
rspamd_composite_atom_dtor(void *ptr)
{
	auto *atom = reinterpret_cast<rspamd_composite_atom *>(ptr);

	delete atom;
}

static rspamd_expression_atom_t *
rspamd_composite_expr_parse(const gchar *line, gsize len,
							rspamd_mempool_t *pool,
							gpointer ud, GError **err)
{
	gsize clen = 0;
	const gchar *p, *end;
	enum composite_expr_state {
		comp_state_read_symbol = 0,
		comp_state_read_obrace,
		comp_state_read_option,
		comp_state_read_regexp,
		comp_state_read_regexp_end,
		comp_state_read_comma,
		comp_state_read_ebrace,
		comp_state_read_end
	} state = comp_state_read_symbol;

	end = line + len;
	p = line;

	/* Find length of the atom using a reduced state machine */
	while (p < end) {
		if (state == comp_state_read_end) {
			break;
		}

		switch (state) {
		case comp_state_read_symbol:
			clen = rspamd_memcspn(p, "[; \t()><!|&\n", len);
			p += clen;

			if (*p == '[') {
				state = comp_state_read_obrace;
			}
			else {
				state = comp_state_read_end;
			}
			break;
		case comp_state_read_obrace:
			p++;

			if (*p == '/') {
				p++;
				state = comp_state_read_regexp;
			}
			else {
				state = comp_state_read_option;
			}
			break;
		case comp_state_read_regexp:
			if (*p == '\\' && p + 1 < end) {
				/* Escaping */
				p++;
			}
			else if (*p == '/') {
				/* End of regexp, possible flags */
				state = comp_state_read_regexp_end;
			}
			p++;
			break;
		case comp_state_read_option:
		case comp_state_read_regexp_end:
			if (*p == ',') {
				p++;
				state = comp_state_read_comma;
			}
			else if (*p == ']') {
				state = comp_state_read_ebrace;
			}
			else {
				p++;
			}
			break;
		case comp_state_read_comma:
			if (!g_ascii_isspace (*p)) {
				if (*p == '/') {
					state = comp_state_read_regexp;
				}
				else if (*p == ']') {
					state = comp_state_read_ebrace;
				}
				else {
					state = comp_state_read_option;
				}
			}
			else {
				/* Skip spaces after comma */
				p++;
			}
			break;
		case comp_state_read_ebrace:
			p++;
			state = comp_state_read_end;
			break;
		case comp_state_read_end:
			g_assert_not_reached ();
		}
	}

	if (state != comp_state_read_end) {
		g_set_error(err, rspamd_composites_quark(), 100, "invalid composite: %s;"
														 "parser stopped in state %d",
				line, state);
		return NULL;
	}

	clen = p - line;
	p = line;
	state = comp_state_read_symbol;

	auto *atom = new rspamd_composite_atom;
	auto *res = rspamd_mempool_alloc0_type(pool, rspamd_expression_atom_t);
	res->len = clen;
	res->str = line;

	/* Full state machine to fill a composite atom */
	const gchar *opt_start = nullptr;

	while (p < end) {
		if (state == comp_state_read_end) {
			break;
		}

		switch (state) {
		case comp_state_read_symbol: {
			clen = rspamd_memcspn(p, "[; \t()><!|&\n", len);
			p += clen;

			if (*p == '[') {
				state = comp_state_read_obrace;
			}
			else {
				state = comp_state_read_end;
			}

			atom->symbol = std::string{line, clen};
			auto norm_start = std::find_if(atom->symbol.begin(), atom->symbol.end(),
					[](char c) { return g_ascii_isalnum(c); });
			if (norm_start == atom->symbol.end()) {
				msg_err_pool("invalid composite atom: %s", atom->symbol.c_str());
			}
			atom->norm_symbol = make_string_view_from_it(norm_start, atom->symbol.end());
			break;
		}
		case comp_state_read_obrace:
			p++;

			if (*p == '/') {
				opt_start = p;
				p++; /* Starting slash */
				state = comp_state_read_regexp;
			}
			else {
				state = comp_state_read_option;
				opt_start = p;
			}

			break;
		case comp_state_read_regexp:
			if (*p == '\\' && p + 1 < end) {
				/* Escaping */
				p++;
			}
			else if (*p == '/') {
				/* End of regexp, possible flags */
				state = comp_state_read_regexp_end;
			}
			p++;
			break;
		case comp_state_read_option:
			if (*p == ',' || *p == ']') {
				/* Plain match, copy option to ensure string_view validity */
				gint opt_len = p - opt_start;
				auto *opt_buf = rspamd_mempool_alloc_buffer(pool, opt_len + 1);
				rspamd_strlcpy(opt_buf, opt_start, opt_len + 1);
				opt_buf = g_strstrip(opt_buf);
				atom->opts.emplace_back(opt_buf, strlen(opt_buf));

				if (*p == ',') {
					p++;
					state = comp_state_read_comma;
				}
				else {
					state = comp_state_read_ebrace;
				}
			}
			else {
				p++;
			}
			break;
		case comp_state_read_regexp_end:
			if (*p == ',' || *p == ']') {
				auto opt_len = p - opt_start;
				rspamd_regexp_t *re;
				GError *re_err = nullptr;

				re = rspamd_regexp_new_len(opt_start, opt_len, nullptr, &re_err);

				if (re == nullptr) {
					msg_err_pool ("cannot create regexp from string %*s: %e",
							opt_len, opt_start, re_err);

					g_error_free(re_err);
				}
				else {
					atom->opts.emplace_back(re);
					rspamd_regexp_unref(re);
				}

				if (*p == ',') {
					p++;
					state = comp_state_read_comma;
				}
				else {
					state = comp_state_read_ebrace;
				}
			}
			else {
				p++;
			}
			break;
		case comp_state_read_comma:
			if (!g_ascii_isspace (*p)) {
				if (*p == '/') {
					state = comp_state_read_regexp;
					opt_start = p;
				}
				else if (*p == ']') {
					state = comp_state_read_ebrace;
				}
				else {
					opt_start = p;
					state = comp_state_read_option;
				}
			}
			else {
				/* Skip spaces after comma */
				p++;
			}
			break;
		case comp_state_read_ebrace:
			p++;
			state = comp_state_read_end;
			break;
		case comp_state_read_end:
			g_assert_not_reached ();
		}
	}

	res->data = atom;

	return res;
}

static auto
process_symbol_removal(rspamd_expression_atom_t *atom,
					   struct composites_data *cd,
					   struct rspamd_symbol_result *ms,
					   const std::string &beg) -> void
{
	struct rspamd_task *task = cd->task;

	if (ms == nullptr) {
		return;
	}

	/*
	 * At this point we know that we need to do something about this symbol,
	 * however, we don't know whether we need to delete it unfortunately,
	 * that depends on the later decisions when the complete expression is
	 * evaluated.
	 */
	auto rd_it = cd->symbols_to_remove.find(ms->name);

	auto fill_removal_structure = [&](symbol_remove_data &nrd) {
		nrd.sym = ms->name;

		/* By default remove symbols */
		switch (cd->composite->policy) {
		case rspamd_composite_policy::RSPAMD_COMPOSITE_POLICY_REMOVE_ALL:
		default:
			nrd.action = (RSPAMD_COMPOSITE_REMOVE_SYMBOL | RSPAMD_COMPOSITE_REMOVE_WEIGHT);
			break;
		case rspamd_composite_policy::RSPAMD_COMPOSITE_POLICY_REMOVE_SYMBOL:
			nrd.action = RSPAMD_COMPOSITE_REMOVE_SYMBOL;
			break;
		case rspamd_composite_policy::RSPAMD_COMPOSITE_POLICY_REMOVE_WEIGHT:
			nrd.action = RSPAMD_COMPOSITE_REMOVE_WEIGHT;
			break;
		case rspamd_composite_policy::RSPAMD_COMPOSITE_POLICY_LEAVE:
			nrd.action = 0;
			break;
		}

		for (auto t : beg) {
			if (t == '~') {
				nrd.action &= ~RSPAMD_COMPOSITE_REMOVE_SYMBOL;
			}
			else if (t == '-') {
				nrd.action &= ~(RSPAMD_COMPOSITE_REMOVE_WEIGHT |
								RSPAMD_COMPOSITE_REMOVE_SYMBOL);
			}
			else if (t == '^') {
				nrd.action |= RSPAMD_COMPOSITE_REMOVE_FORCED;
			}
			else {
				break;
			}
		}

		nrd.comp = cd->composite;
		nrd.parent = atom->parent;
	};

	if (rd_it != cd->symbols_to_remove.end()) {
		fill_removal_structure(rd_it->second.emplace_back());
		msg_debug_composites ("%s: added symbol %s to removal: %d policy, from composite %s",
				cd->metric_res->name,
				ms->name, rd_it->second.back().action,
				cd->composite->sym.c_str());
	}
	else {
		std::vector<symbol_remove_data> nrd;
		fill_removal_structure(nrd.emplace_back());
		msg_debug_composites ("%s: added symbol %s to removal: %d policy, from composite %s",
				cd->metric_res->name,
				ms->name, nrd.front().action,
				cd->composite->sym.c_str());
		cd->symbols_to_remove[ms->name] = std::move(nrd);
	}
}

static auto
process_single_symbol(struct composites_data *cd,
					  std::string_view sym,
					  struct rspamd_symbol_result **pms,
					  struct rspamd_composite_atom *atom) -> double
{
	struct rspamd_symbol_result *ms = nullptr;
	gdouble rc = 0;
	struct rspamd_task *task = cd->task;

	if ((ms = rspamd_task_find_symbol_result(cd->task, sym.data(), cd->metric_res)) == nullptr) {
		msg_debug_composites ("not found symbol %s in composite %s", sym.data(),
				cd->composite->sym.c_str());

		if (G_UNLIKELY(atom->comp_type == rspamd_composite_atom_type::ATOM_UNKNOWN)) {
			const struct rspamd_composite *ncomp;

			if ((ncomp = COMPOSITE_MANAGER_FROM_PTR(task->cfg->composites_manager)->find(sym)) != NULL) {
				atom->comp_type = rspamd_composite_atom_type::ATOM_COMPOSITE;
				atom->ncomp = ncomp;
			}
			else {
				atom->comp_type = rspamd_composite_atom_type::ATOM_PLAIN;
			}
		}

		if (atom->comp_type == rspamd_composite_atom_type::ATOM_COMPOSITE) {
			msg_debug_composites ("symbol %s for composite %s is another composite",
					sym.data(), cd->composite->sym.c_str());

			if (!cd->checked[atom->ncomp->id * 2]) {
				msg_debug_composites("composite dependency %s for %s is not checked",
						sym.data(), cd->composite->sym.c_str());
				/* Set checked for this symbol to avoid cyclic references */
				cd->checked[cd->composite->id * 2] = true;
				auto *saved = cd->composite; /* Save the current composite */
				composites_foreach_callback((gpointer)atom->ncomp->sym.c_str(),
						(gpointer)atom->ncomp, (gpointer)cd);
				/* Restore state */
				cd->composite = saved;
				cd->checked[cd->composite->id * 2] = false;

				ms = rspamd_task_find_symbol_result(cd->task, sym.data(),
						cd->metric_res);
			}
			else {
				/*
				 * XXX: in case of cyclic references this would return 0
				 */
				if (cd->checked[atom->ncomp->id * 2 + 1]) {
					ms = rspamd_task_find_symbol_result(cd->task, sym.data(),
							cd->metric_res);
				}
			}
		}
	}

	if (ms) {
		msg_debug_composites("found symbol %s in composite %s, weight: %.3f",
				sym.data(), cd->composite->sym.c_str(), ms->score);

		/* Now check options */
		for (const auto &cur_opt : atom->opts) {
			struct rspamd_symbol_option *opt;
			auto found = false;

			DL_FOREACH (ms->opts_head, opt) {
				if (cur_opt.match_opt({opt->option, opt->optlen})) {
					found = true;
					break;
				}
			}

			if (!found) {
				auto pat = cur_opt.get_pat();
				msg_debug_composites ("symbol %s in composite %s misses required option %*s",
						sym.data(),
						cd->composite->sym.c_str(),
						(int) pat.size(), pat.data());
				ms = nullptr;

				break;
			}
		}

		if (ms) {
			if (ms->score == 0) {
				rc = epsilon * 16.0; /* Distinguish from 0 */
			}
			else {
				rc = ms->score;
			}
		}
	}

	*pms = ms;
	return rc;
}

static auto
rspamd_composite_expr_process(void *ud, rspamd_expression_atom_t *atom) -> double
{
	struct composites_data *cd = (struct composites_data *) ud;
	struct rspamd_composite_atom *comp_atom = (struct rspamd_composite_atom *) atom->data;

	struct rspamd_symbol_result *ms = NULL;
	struct rspamd_task *task = cd->task;
	gdouble rc = 0;

	if (cd->checked[cd->composite->id * 2]) {
		/* We have already checked this composite, so just return its value */
		if (cd->checked[cd->composite->id * 2 + 1]) {
			ms = rspamd_task_find_symbol_result(cd->task,
					comp_atom->norm_symbol.data(),
					cd->metric_res);
		}

		if (ms) {
			if (ms->score == 0) {
				rc = epsilon; /* Distinguish from 0 */
			}
			else {
				/* Treat negative and positive scores equally... */
				rc = fabs(ms->score);
			}
		}

		msg_debug_composites("composite %s is already checked, result: %.2f",
				cd->composite->sym.c_str(), rc);

		return rc;
	}

	/* Note: sym is zero terminated as it is a view on std::string */
	auto sym = comp_atom->norm_symbol;
	auto group_process_functor = [&](auto cond, int sub_start) -> double {
		auto max = 0.;
		GHashTableIter it;
		gpointer k, v;
		struct rspamd_symbols_group *gr;

		gr = (struct rspamd_symbols_group *) g_hash_table_lookup(cd->task->cfg->groups,
				sym.substr(sub_start).data());

		if (gr != nullptr) {
			g_hash_table_iter_init(&it, gr->symbols);

			while (g_hash_table_iter_next(&it, &k, &v)) {
				auto *sdef = (rspamd_symbol *) v;

				if (cond(sdef->score)) {
					rc = process_single_symbol(cd,
							std::string_view(sdef->name),
							&ms,
							comp_atom);

					if (fabs(rc) > epsilon) {
						process_symbol_removal(atom,
								cd,
								ms,
								comp_atom->symbol);

						if (fabs(rc) > max) {
							max = fabs(rc);
						}
					}
				}
			}
		}

		return max;
	};

	if (sym.size() > 2) {
		if (sym.substr(0, 2) == "g:") {
			rc = group_process_functor([](auto _) { return true; }, 2);
		}
		else if (sym.substr(0, 3) == "g+:") {
			/* Group, positive symbols only */
			rc = group_process_functor([](auto sc) { return sc > 0.; }, 3);
		}
		else if (sym.substr(0, 3) == "g-:") {
			rc = group_process_functor([](auto sc) { return sc < 0.; }, 3);
		}
		else {
			rc = process_single_symbol(cd, sym, &ms, comp_atom);

			if (fabs(rc) > epsilon) {
				process_symbol_removal(atom,
						cd,
						ms,
						comp_atom->symbol);
			}
		}
	}
	else {
		rc = process_single_symbol(cd, sym, &ms, comp_atom);

		if (fabs(rc) > epsilon) {
			process_symbol_removal(atom,
					cd,
					ms,
					comp_atom->symbol);
		}
	}

	msg_debug_composites ("%s: result for atom %s in composite %s is %.4f",
			cd->metric_res->name,
			comp_atom->norm_symbol.data(),
			cd->composite->sym.c_str(), rc);

	return rc;
}

/*
 * We don't have preferences for composites
 */
static gint
rspamd_composite_expr_priority(rspamd_expression_atom_t *atom)
{
	return 0;
}

static void
rspamd_composite_expr_destroy(rspamd_expression_atom_t *atom)
{
	rspamd_composite_atom_dtor(atom->data);
}

static void
composites_foreach_callback(gpointer key, gpointer value, void *data)
{
	auto *cd = (struct composites_data *) data;
	auto *comp = (struct rspamd_composite *) value;
	auto *str_key = (const gchar *)key;
	struct rspamd_task *task;
	gdouble rc;

	cd->composite = comp;
	task = cd->task;

	if (!cd->checked[cd->composite->id * 2]) {
		if (rspamd_symcache_is_checked(cd->task, cd->task->cfg->cache,
				str_key)) {
			msg_debug_composites ("composite %s is checked in symcache but not "
								  "in composites bitfield", cd->composite->sym.c_str());
			cd->checked[comp->id * 2] = true;
			cd->checked[comp->id * 2 + 1] = false;
		}
		else {
			if (rspamd_task_find_symbol_result(cd->task, str_key,
					cd->metric_res) != nullptr) {
				/* Already set, no need to check */
				msg_debug_composites ("composite %s is already in metric "
									  "in composites bitfield", cd->composite->sym.c_str());
				cd->checked[comp->id * 2] = true;
				cd->checked[comp->id * 2 + 1] = true;

				return;
			}

			msg_debug_composites ("%s: start processing composite %s",
					cd->metric_res->name,
					cd->composite->sym.c_str());

			rc = rspamd_process_expression(comp->expr, RSPAMD_EXPRESSION_FLAG_NOOPT,
					cd);

			/* Checked bit */
			cd->checked[comp->id * 2] = true;

			msg_debug_composites ("%s: final result for composite %s is %.4f",
					cd->metric_res->name,
					cd->composite->sym.c_str(), rc);

			/* Result bit */
			if (fabs(rc) > epsilon) {
				cd->checked[comp->id * 2 + 1] = true;
				rspamd_task_insert_result_full(cd->task, str_key, 1.0, NULL,
						RSPAMD_SYMBOL_INSERT_SINGLE, cd->metric_res);
			}
			else {
				cd->checked[comp->id * 2 + 1] = false;
			}
		}
	}
}


static auto
remove_symbols(const composites_data &cd, const std::vector<symbol_remove_data> &rd) -> void
{
	struct rspamd_task *task = cd.task;
	gboolean skip = FALSE,
			has_valid_op = FALSE,
			want_remove_score = TRUE,
			want_remove_symbol = TRUE,
			want_forced = FALSE;
	const gchar *disable_score_reason = "no policy",
			*disable_symbol_reason = "no policy";

	task = cd.task;

	for (const auto &cur : rd) {
		if (!cd.checked[cur.comp->id * 2 + 1]) {
			continue;
		}
		/*
		 * First of all exclude all elements with any parent that is negation:
		 * !A || B -> here we can have both !A and B matched, but we do *NOT*
		 * want to remove symbol in that case
		 */
		auto *par = cur.parent;
		skip = FALSE;

		while (par) {
			if (rspamd_expression_node_is_op(par, OP_NOT)) {
				skip = TRUE;
				break;
			}

			par = par->parent;
		}

		if (skip) {
			continue;
		}

		has_valid_op = TRUE;
		/*
		 * Now we can try to remove symbols/scores
		 *
		 * We apply the following logic here:
		 * - if no composites would like to save score then we remove score
		 * - if no composites would like to save symbol then we remove symbol
		 */
		if (!want_forced) {
			if (!(cur.action & RSPAMD_COMPOSITE_REMOVE_SYMBOL)) {
				want_remove_symbol = FALSE;
				disable_symbol_reason = cur.comp->sym.c_str();
			}

			if (!(cur.action & RSPAMD_COMPOSITE_REMOVE_WEIGHT)) {
				want_remove_score = FALSE;
				disable_score_reason = cur.comp->sym.c_str();
			}

			if (cur.action & RSPAMD_COMPOSITE_REMOVE_FORCED) {
				want_forced = TRUE;
				disable_symbol_reason = cur.comp->sym.c_str();
				disable_score_reason = cur.comp->sym.c_str();
			}
		}
	}

	auto *ms = rspamd_task_find_symbol_result(task, rd.front().sym, cd.metric_res);

	if (has_valid_op && ms && !(ms->flags & RSPAMD_SYMBOL_RESULT_IGNORED)) {

		if (want_remove_score || want_forced) {
			msg_debug_composites ("%s: %s remove symbol weight for %s (was %.2f), "
								  "score removal affected by %s, symbol removal affected by %s",
					cd.metric_res->name,
					(want_forced ? "forced" : "normal"), rd.front().sym, ms->score,
					disable_score_reason, disable_symbol_reason);
			cd.metric_res->score -= ms->score;
			ms->score = 0.0;
		}

		if (want_remove_symbol || want_forced) {
			ms->flags |= RSPAMD_SYMBOL_RESULT_IGNORED;
			msg_debug_composites ("%s: %s remove symbol %s (score %.2f), "
								  "score removal affected by %s, symbol removal affected by %s",
					cd.metric_res->name,
					(want_forced ? "forced" : "normal"), rd.front().sym, ms->score,
					disable_score_reason, disable_symbol_reason);
		}
	}
}

static void
composites_metric_callback(struct rspamd_task *task)
{
	std::vector<composites_data> comp_data_vec;
	struct rspamd_scan_result *mres;

	comp_data_vec.reserve(1);

	DL_FOREACH (task->result, mres) {
		auto &cd = comp_data_vec.emplace_back(task, mres);

		/* Process metric result */
		rspamd_symcache_composites_foreach(task,
				task->cfg->cache,
				composites_foreach_callback,
				&cd);
	}

	for (const auto &cd : comp_data_vec) {
		/* Remove symbols that are in composites */
		for (const auto &srd_it : cd.symbols_to_remove) {
			remove_symbols(cd, srd_it.second);
		}
	}
}

}


void
rspamd_composites_process_task (struct rspamd_task *task)
{
	if (task->result && !RSPAMD_TASK_IS_SKIPPED (task)) {
		rspamd::composites::composites_metric_callback(task);
	}
}

