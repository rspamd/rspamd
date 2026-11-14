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
/***MODULE:chartable
 * rspamd module that make marks based on symbol chains
 *
 * Allowed options:
 * - symbol (string): symbol to insert (default: 'R_BAD_CHARSET')
 * - threshold (double): value that would be used as threshold in expression characters_changed / total_characters
 *   (e.g. if threshold is 0.1 than charset change should occur more often than in 10 symbols), default: 0.1
 */


#include "config.h"
#include "libmime/message.h"
#include "rspamd.h"
#include "libstat/stat_api.h"
#include "libmime/lang_detection.h"
#include "libutil/cxx/utf8_util.h"
#include "libserver/cfg_dynamic.h"

#include "unicode/utf8.h"
#include "unicode/uchar.h"
#include "unicode/uscript.h"
#include "unicode/unorm2.h"
#include "unicode/uidna.h"

#include <array>
#include <cerrno>
#include <climits>
#include <cmath>
#include <cstring>
#include <string>
#include <string_view>

#define DEFAULT_SYMBOL "R_MIXED_CHARSET"
#define DEFAULT_URL_SYMBOL "R_MIXED_CHARSET_URL"
#define DEFAULT_THRESHOLD 0.1
#define DEFAULT_MAX_WORD_LEN 10

#define msg_debug_chartable(...) rspamd_conditional_debug_fast(nullptr, task->from_addr,                                       \
															   rspamd_chartable_log_id, "chartable", task->task_pool->tag.uid, \
															   G_STRFUNC,                                                      \
															   __VA_ARGS__)

INIT_LOG_MODULE(chartable)

/* Initialization */
int chartable_module_init(struct rspamd_config *cfg, struct module_ctx **ctx);

int chartable_module_config(struct rspamd_config *cfg, bool validate);

int chartable_module_reconfig(struct rspamd_config *cfg);

module_t chartable_module = {
	"chartable",
	chartable_module_init,
	chartable_module_config,
	chartable_module_reconfig,
	nullptr,
	RSPAMD_MODULE_VER,
	(unsigned int) -1,
};

struct chartable_ctx {
	struct module_ctx ctx;
	const char *symbol;
	const char *url_symbol;
	double threshold;
	unsigned int max_word_len;
	/* Values from the static configuration: the baseline for the dynamic ones */
	double static_threshold;
	unsigned int static_max_word_len;
	struct rspamd_unicode_spoof_checker *spoof_checker;
};

static inline struct chartable_ctx *
chartable_get_context(struct rspamd_config *cfg)
{
	return (struct chartable_ctx *) g_ptr_array_index(cfg->c_modules,
													  chartable_module.ctx_offset);
}

static void chartable_symbol_callback(struct rspamd_task *task,
									  struct rspamd_symcache_dynamic_item *item,
									  void *unused);

static void chartable_url_symbol_callback(struct rspamd_task *task,
										  struct rspamd_symcache_dynamic_item *item,
										  void *unused);

int chartable_module_init(struct rspamd_config *cfg, struct module_ctx **ctx)
{
	struct chartable_ctx *chartable_module_ctx;

	chartable_module_ctx = rspamd_mempool_alloc0_type(cfg->cfg_pool,
													  struct chartable_ctx);
	chartable_module_ctx->max_word_len = DEFAULT_MAX_WORD_LEN;
	chartable_module_ctx->spoof_checker = rspamd_unicode_spoof_checker_create();
	if (chartable_module_ctx->spoof_checker == nullptr) {
		msg_err_config("cannot initialise ICU spoof checker");
		return -1;
	}
	rspamd_mempool_add_destructor(cfg->cfg_pool,
								  rspamd_unicode_spoof_checker_destroy,
								  chartable_module_ctx->spoof_checker);

	*ctx = (struct module_ctx *) chartable_module_ctx;

	return 0;
}


/*
 * Dynamic options: `threshold` and `max_word_len` are plain scalars read on
 * every use. An option that is absent in `dyn_values` goes back to the value
 * of the static configuration.
 */
static gboolean
chartable_dynconf_apply(struct rspamd_config *cfg,
						const char *module,
						const ucl_object_t *dyn_values,
						void *ud,
						GError **err)
{
	auto *chartable_module_ctx = (struct chartable_ctx *) ud;
	double threshold = chartable_module_ctx->static_threshold;
	unsigned int max_word_len = chartable_module_ctx->static_max_word_len;
	const ucl_object_t *elt;

	if (dyn_values != nullptr) {
		if ((elt = ucl_object_lookup(dyn_values, "threshold")) != nullptr) {
			if (!ucl_obj_todouble_safe(elt, &threshold) || !std::isfinite(threshold)) {
				g_set_error(err, g_quark_from_static_string("chartable"), EINVAL,
							"invalid threshold");
				return FALSE;
			}
		}

		if ((elt = ucl_object_lookup(dyn_values, "max_word_len")) != nullptr) {
			int64_t v;

			if (!ucl_object_toint_safe(elt, &v) || v < 0 || v > INT_MAX) {
				g_set_error(err, g_quark_from_static_string("chartable"), EINVAL,
							"invalid max_word_len");
				return FALSE;
			}

			max_word_len = (unsigned int) v;
		}
	}

	chartable_module_ctx->threshold = threshold;
	chartable_module_ctx->max_word_len = max_word_len;

	msg_info_config("applied dynamic configuration: threshold = %.3f, max_word_len = %ud",
					threshold, max_word_len);

	return TRUE;
}

int chartable_module_config(struct rspamd_config *cfg, bool _)
{
	const ucl_object_t *value;
	int res = TRUE;
	struct chartable_ctx *chartable_module_ctx = chartable_get_context(cfg);

	if (!rspamd_config_is_module_enabled(cfg, "chartable")) {
		return TRUE;
	}

	if ((value =
			 rspamd_config_get_module_opt(cfg, "chartable", "symbol")) != nullptr) {
		chartable_module_ctx->symbol = ucl_obj_tostring(value);
	}
	else {
		chartable_module_ctx->symbol = DEFAULT_SYMBOL;
	}
	if ((value =
			 rspamd_config_get_module_opt(cfg, "chartable", "url_symbol")) != nullptr) {
		chartable_module_ctx->url_symbol = ucl_obj_tostring(value);
	}
	else {
		chartable_module_ctx->url_symbol = DEFAULT_URL_SYMBOL;
	}
	if ((value =
			 rspamd_config_get_module_opt(cfg, "chartable", "threshold")) != nullptr) {
		if (!ucl_obj_todouble_safe(value, &chartable_module_ctx->threshold)) {
			msg_warn_config("invalid numeric value");
			chartable_module_ctx->threshold = DEFAULT_THRESHOLD;
		}
	}
	else {
		chartable_module_ctx->threshold = DEFAULT_THRESHOLD;
	}
	if ((value =
			 rspamd_config_get_module_opt(cfg, "chartable", "max_word_len")) != nullptr) {
		chartable_module_ctx->max_word_len = ucl_object_toint(value);
	}
	else {
		chartable_module_ctx->max_word_len = DEFAULT_MAX_WORD_LEN;
	}

	chartable_module_ctx->static_threshold = chartable_module_ctx->threshold;
	chartable_module_ctx->static_max_word_len = chartable_module_ctx->max_word_len;

	rspamd_symcache_add_symbol(cfg->cache,
							   chartable_module_ctx->symbol,
							   0,
							   chartable_symbol_callback,
							   nullptr,
							   SYMBOL_TYPE_NORMAL,
							   -1);
	rspamd_symcache_add_symbol(cfg->cache,
							   chartable_module_ctx->url_symbol,
							   0,
							   chartable_url_symbol_callback,
							   nullptr,
							   SYMBOL_TYPE_NORMAL,
							   -1);

	static const char *const dynamic_paths[] = {"threshold", "max_word_len", nullptr};

	rspamd_dynconf_register_module(cfg, "chartable", dynamic_paths,
								   chartable_dynconf_apply, chartable_module_ctx);

	msg_info_config("init internal chartable module");

	return res;
}

int chartable_module_reconfig(struct rspamd_config *cfg)
{
	return chartable_module_config(cfg, false);
}

struct chartable_word_result {
	double badness = 0.0;
	unsigned int latin_letters = 0;
	unsigned int non_latin_letters = 0;
	bool mixed_script = false;
	bool unicode_spoof = false;
};

static auto
rspamd_chartable_get_script(UChar32 uc) -> UScriptCode
{
	if (uc < 0x80) {
		return g_ascii_isalpha(uc) ? USCRIPT_LATIN : USCRIPT_INVALID_CODE;
	}
	auto uc_err = U_ZERO_ERROR;
	auto script = uscript_getScript(uc, &uc_err);

	if (U_FAILURE(uc_err) || script == USCRIPT_COMMON ||
		script == USCRIPT_INHERITED) {
		return USCRIPT_INVALID_CODE;
	}

	return script;
}

static auto
rspamd_chartable_ascii_skeleton(struct chartable_ctx *chartable_module_ctx,
								const char *start, gsize len) -> bool
{
	std::array<char, 256> stack_buf;
	auto skeleton_len = rspamd_unicode_spoof_skeleton(
		chartable_module_ctx->spoof_checker, start, len,
		stack_buf.data(), stack_buf.size());

	if (skeleton_len < 5) {
		return false;
	}

	std::string dynamic_buf;
	const char *skeleton = stack_buf.data();
	if (static_cast<gsize>(skeleton_len) > stack_buf.size()) {
		dynamic_buf.resize(skeleton_len);
		if (rspamd_unicode_spoof_skeleton(chartable_module_ctx->spoof_checker,
										  start, len, dynamic_buf.data(), dynamic_buf.size()) != skeleton_len) {
			return false;
		}
		skeleton = dynamic_buf.data();
	}

	unsigned int nletters = 0;
	for (gssize i = 0; i < skeleton_len; i++) {
		const auto c = static_cast<unsigned char>(skeleton[i]);

		if (g_ascii_isalpha(c)) {
			nletters++;
		}
		else {
			return false;
		}
	}

	return nletters >= 5;
}

static auto
rspamd_chartable_whole_word_spoof(struct chartable_ctx *chartable_module_ctx,
								  rspamd_word_t *w) -> bool
{
	unsigned int nletters = 0;

	for (gsize i = 0; i < w->unicode.len; i++) {
		const auto uc = w->unicode.begin[i];

		if (uc < 0x80 ? g_ascii_isalpha(uc) : u_isalpha(uc)) {
			const auto script = rspamd_chartable_get_script(uc);
			if (script == USCRIPT_LATIN) {
				return false;
			}
			if (script != USCRIPT_INVALID_CODE) {
				nletters++;
			}
		}
	}

	return nletters >= 5 &&
		   rspamd_chartable_ascii_skeleton(chartable_module_ctx,
										   w->normalized.begin, w->normalized.len);
}

struct chartable_mark_probe {
	UChar32 base = 0;
	bool seen_nonspacing = false;

	auto check(UChar32 uc, unsigned int cat) -> bool
	{
		if (cat == U_NON_SPACING_MARK) {
			/* ICU checks repetitions after NFD: a precomposed base can
			 * contribute a mark even if only one is visible here. */
			const auto candidate = seen_nonspacing ||
								   (base >= 0x80 && u_getIntPropertyValue(base, UCHAR_NFD_QUICK_CHECK) == UNORM_NO);
			seen_nonspacing = true;
			return candidate;
		}
		if (cat != U_COMBINING_SPACING_MARK && cat != U_ENCLOSING_MARK) {
			base = uc;
			seen_nonspacing = false;
		}
		return false;
	}
};

/* NFKC can compose repeated marks or collapse distinct decimal digit sets.
 * Only changed words need this extra pass; ordinary ASCII bytes are cheap. */
static auto
rspamd_chartable_original_spoof_candidate(const rspamd_word_t *w) -> bool
{
	if (!(w->flags & RSPAMD_STAT_TOKEN_FLAG_NORMALISED) ||
		w->original.len > INT32_MAX) {
		return false;
	}

	int32_t offset = 0;
	int32_t digit_zero = -1;
	chartable_mark_probe marks;
	const auto len = static_cast<int32_t>(w->original.len);
	while (offset < len) {
		UChar32 uc;
		U8_NEXT(w->original.begin, offset, len, uc);
		if (uc < 0) {
			return false;
		}
		const auto cat = uc < 0x80 ? U_UNASSIGNED : u_charType(uc);
		if (marks.check(uc, cat)) {
			return true;
		}
		if (uc < 0x80 ? g_ascii_isdigit(uc) : cat == U_DECIMAL_DIGIT_NUMBER) {
			const auto zero = uc < 0x80 ? '0' : uc - u_charDigitValue(uc);
			if (digit_zero != -1 && digit_zero != zero) {
				return true;
			}
			digit_zero = zero;
		}
	}

	return false;
}

static auto
rspamd_chartable_process_word_utf(struct rspamd_task *task,
								  rspamd_word_t *w,
								  gboolean is_url,
								  unsigned int *ncap,
								  struct chartable_ctx *chartable_module_ctx,
								  gboolean ignore_diacritics) -> chartable_word_result
{
	const UChar32 *p, *end;
	chartable_word_result result;
	double script_badness = 0.0;
	UChar32 uc;
	UBlockCode sc;
	unsigned int cat;
	UScriptCode last_script = USCRIPT_INVALID_CODE;
	UScriptCode first_script = USCRIPT_INVALID_CODE;
	int32_t last_digit_zero = -1;
	bool saw_multiple_scripts = false, saw_mixed_numbers = false;
	bool saw_invisible_candidate = false;
	chartable_mark_probe marks;
	unsigned int same_script_count = 0, nsym = 0, nspecial = 0;
	enum {
		start_process = 0,
		got_alpha,
		got_digit,
		got_unknown,
	} state = start_process,
	  prev_state = start_process;

	p = w->unicode.begin;
	end = p + w->unicode.len;

	/* We assume that w is normalized */

	while (p < end) {
		uc = *p++;

		if (((int32_t) uc) < 0) {
			break;
		}

		sc = uc < 0x80 ? UBLOCK_BASIC_LATIN : ublock_getCode(uc);
		cat = uc < 0x80 ? U_UNASSIGNED : u_charType(uc);
		saw_invisible_candidate |= marks.check(uc, cat);

		const auto is_combining_mark = cat == U_NON_SPACING_MARK ||
									   cat == U_COMBINING_SPACING_MARK ||
									   cat == U_ENCLOSING_MARK;

		/* Combining marks must not reset script tracking or extend word length. */
		if (is_combining_mark) {
			if (!ignore_diacritics) {
				nspecial++;
			}

			continue;
		}

		if (!ignore_diacritics) {
			if ((sc == UBLOCK_LATIN_1_SUPPLEMENT) ||
				(sc == UBLOCK_LATIN_EXTENDED_A) ||
				(sc == UBLOCK_LATIN_EXTENDED_ADDITIONAL) ||
				(sc == UBLOCK_LATIN_EXTENDED_B) ||
				(sc == UBLOCK_COMBINING_DIACRITICAL_MARKS)) {
				nspecial++;
			}
		}

		if (uc < 0x80 ? g_ascii_isalpha(uc) : (cat >= U_UPPERCASE_LETTER && cat <= U_OTHER_LETTER)) {
			const auto script = rspamd_chartable_get_script(uc);

			if (script == USCRIPT_LATIN) {
				result.latin_letters++;
			}
			else if (script != USCRIPT_INVALID_CODE) {
				result.non_latin_letters++;
			}

			if (script != USCRIPT_LATIN && u_isupper(uc)) {
				if (ncap) {
					(*ncap)++;
				}
			}

			if (state == got_digit) {
				/* Penalize digit -> alpha translations */
				if (!is_url && script != USCRIPT_LATIN &&
					prev_state != start_process) {
					result.badness += 0.25;
				}
			}

			if (script != USCRIPT_INVALID_CODE) {
				if (first_script == USCRIPT_INVALID_CODE) {
					first_script = script;
				}
				else if (script != first_script) {
					saw_multiple_scripts = true;
				}
				if (state == got_alpha && last_script != USCRIPT_INVALID_CODE &&
					script != last_script) {
					script_badness += 1.0 / (double) MAX(same_script_count, 1u);
					same_script_count = 1;
				}
				else if (script == last_script) {
					same_script_count++;
				}
				else {
					same_script_count = 1;
				}

				last_script = script;
			}

			prev_state = state;
			state = got_alpha;
		}
		else if (uc < 0x80 ? g_ascii_isdigit(uc) : cat == U_DECIMAL_DIGIT_NUMBER) {
			const auto digit_zero = uc < 0x80 ? '0' : uc - u_charDigitValue(uc);
			if (last_digit_zero != -1 && last_digit_zero != digit_zero) {
				saw_mixed_numbers = true;
			}
			last_digit_zero = digit_zero;

			if (state != got_digit) {
				prev_state = state;
			}

			state = got_digit;
			same_script_count = 0;
			last_script = USCRIPT_INVALID_CODE;
		}
		else {
			/* We don't care about unknown characters here */
			if (state != got_unknown) {
				prev_state = state;
			}

			state = got_unknown;
			same_script_count = 0;
			last_script = USCRIPT_INVALID_CODE;
		}

		nsym++;
	}

	const auto should_check_spoof = saw_multiple_scripts || saw_mixed_numbers ||
									saw_invisible_candidate ||
									(w->flags & RSPAMD_STAT_TOKEN_FLAG_INVISIBLE_SPACES) ||
									rspamd_chartable_original_spoof_candidate(w);
	if (should_check_spoof) {
		const auto *check_start = w->original.len > 0 ? w->original.begin : w->normalized.begin;
		const auto check_len = w->original.len > 0 ? w->original.len : w->normalized.len;
		const auto spoof_flags = rspamd_unicode_spoof_check(
			chartable_module_ctx->spoof_checker, check_start, check_len);

		if (spoof_flags >= 0) {
			if (saw_multiple_scripts && (spoof_flags & RSPAMD_UNICODE_SPOOF_RESTRICTION)) {
				result.badness += MAX(script_badness, 1.0);
				result.mixed_script = true;
			}
			if (spoof_flags & RSPAMD_UNICODE_SPOOF_INVISIBLE) {
				w->flags |= RSPAMD_STAT_TOKEN_FLAG_INVISIBLE;
			}
			if (spoof_flags & RSPAMD_UNICODE_SPOOF_MIXED_NUMBERS) {
				w->flags |= RSPAMD_STAT_TOKEN_FLAG_MIXED_NUMBERS;
			}
			if (spoof_flags & (RSPAMD_UNICODE_SPOOF_INVISIBLE |
							   RSPAMD_UNICODE_SPOOF_MIXED_NUMBERS)) {
				result.badness += 1.0;
			}
			result.unicode_spoof = result.mixed_script ||
								   (spoof_flags & (RSPAMD_UNICODE_SPOOF_INVISIBLE | RSPAMD_UNICODE_SPOOF_MIXED_NUMBERS));
		}
	}

	/* The long-word exemption applies only to the diacritics component. */
	if (nsym <= chartable_module_ctx->max_word_len) {
		result.badness += nspecial;
	}

	if (result.mixed_script) {
		w->flags |= RSPAMD_STAT_TOKEN_FLAG_MIXED_SCRIPT;
	}
	if (result.unicode_spoof) {
		w->flags |= RSPAMD_STAT_TOKEN_FLAG_UNICODE_SPOOF;
	}

	if (result.badness > 4.0) {
		result.badness = 4.0;
	}

	msg_debug_chartable("word %*s, badness: %.2f",
						(int) w->normalized.len, w->normalized.begin,
						result.badness);

	return result;
}

static auto
rspamd_chartable_process_word_ascii(struct rspamd_task *task,
									rspamd_word_t *w,
									gboolean is_url) -> chartable_word_result
{
	chartable_word_result result;
	bool seen_alpha = false;
	enum {
		start_process = 0,
		got_alpha,
		got_digit,
		got_unknown,
	} state = start_process;

	const auto *p = (const unsigned char *) w->normalized.begin;
	const auto *end = p + w->normalized.len;

	/* We assume that w is normalized */
	while (p < end) {
		if (g_ascii_isalpha(*p)) {
			result.latin_letters++;

			if (state == got_digit) {
				/* Penalize digit -> alpha translations */
				if (seen_alpha && !is_url && !g_ascii_isxdigit(*p)) {
					result.badness += 0.25;
				}
			}

			seen_alpha = true;
			state = got_alpha;
		}
		else if (g_ascii_isdigit(*p)) {
			state = got_digit;
		}
		else {
			/* We don't care about unknown characters here */
			state = got_unknown;
		}

		p++;
	}

	msg_debug_chartable("word %*s, badness: %.2f",
						(int) w->normalized.len, w->normalized.begin,
						result.badness);

	return result;
}

static gboolean
rspamd_chartable_process_part(struct rspamd_task *task,
							  struct rspamd_mime_text_part *part,
							  struct chartable_ctx *chartable_module_ctx,
							  gboolean ignore_diacritics)
{
	rspamd_word_t *w;
	unsigned int i, ncap = 0, latin_letters = 0, non_latin_letters = 0;
	/* Badness of the words that mix scripts or hide characters, and of the other ones */
	double cur_score = 0.0, spoof_score = 0.0;

	if (part == nullptr || part->utf_words.a == nullptr ||
		kv_size(part->utf_words) == 0 || part->nwords == 0) {
		return FALSE;
	}

	for (i = 0; i < kv_size(part->utf_words); i++) {
		w = &kv_A(part->utf_words, i);

		if ((w->flags & RSPAMD_STAT_TOKEN_FLAG_TEXT)) {
			chartable_word_result word_result;

			if (w->flags & RSPAMD_STAT_TOKEN_FLAG_UTF) {
				word_result = rspamd_chartable_process_word_utf(task, w, FALSE,
																&ncap, chartable_module_ctx, ignore_diacritics);
			}
			else {
				word_result = rspamd_chartable_process_word_ascii(task, w, FALSE);
			}

			if (word_result.unicode_spoof) {
				spoof_score += word_result.badness;
			}
			else {
				cur_score += word_result.badness;
			}

			latin_letters += word_result.latin_letters;
			non_latin_letters += word_result.non_latin_letters;
		}
	}

	if (latin_letters > non_latin_letters) {
		for (i = 0; i < kv_size(part->utf_words); i++) {
			w = &kv_A(part->utf_words, i);
			if ((w->flags & (RSPAMD_STAT_TOKEN_FLAG_TEXT | RSPAMD_STAT_TOKEN_FLAG_UTF)) ==
					(RSPAMD_STAT_TOKEN_FLAG_TEXT | RSPAMD_STAT_TOKEN_FLAG_UTF) &&
				rspamd_chartable_whole_word_spoof(chartable_module_ctx, w)) {
				/* A skeleton match is evidence for consumers, not a verdict. */
				w->flags |= RSPAMD_STAT_TOKEN_FLAG_CONFUSABLE_CANDIDATE;
				msg_debug_chartable("whole-word confusable candidate %*s",
									(int) w->normalized.len, w->normalized.begin);
			}
		}
	}

	/*
	 * TODO: perhaps, we should do this analysis somewhere else and get
	 * something like: <SYM_SC><SYM_SC><SYM_SC> representing classes for all
	 * symbols in the text
	 */
	part->capital_letters += ncap;

	/*
	 * The score is the badness of an average word, and a text of any length
	 * can be put around the words that are bad. For the words that mix
	 * scripts or hide characters the sum is what counts past this many
	 * words, so that a few of them are seen in a long text as they are in a
	 * short one. Letters with diacritics and digits in words are a matter of
	 * their share: names with such letters in a long text are not a sign
	 */
	static const unsigned int max_words_divisor = 24;

	cur_score = cur_score / (double) part->nwords +
				spoof_score / (double) MIN(part->nwords, max_words_divisor);

	if (cur_score > 1.0) {
		cur_score = 1.0;
	}

	if (cur_score > chartable_module_ctx->threshold) {
		rspamd_task_insert_result(task, chartable_module_ctx->symbol,
								  cur_score, nullptr);
		return TRUE;
	}

	return FALSE;
}

static void
chartable_symbol_callback(struct rspamd_task *task,
						  struct rspamd_symcache_dynamic_item *item,
						  void *_)
{
	unsigned int i;
	struct rspamd_mime_text_part *part;
	struct chartable_ctx *chartable_module_ctx = chartable_get_context(task->cfg);
	gboolean ignore_meta_diacritics = FALSE, seen_violated_part = FALSE;

	/* Check if we have parts with diacritic symbols language */
	PTR_ARRAY_FOREACH(MESSAGE_FIELD(task, text_parts), i, part)
	{
		gboolean ignore_part_diacritics = TRUE;

		if (part->languages && part->languages->len > 0) {
			auto *lang = (struct rspamd_lang_detector_res *) g_ptr_array_index(part->languages, 0);
			int flags;

			flags = rspamd_language_detector_elt_flags(lang->elt);

			if ((flags & RS_LANGUAGE_DIACRITICS)) {
				ignore_part_diacritics = TRUE;
			}
			else if (lang->elt != nullptr && lang->prob > 0.75) {
				ignore_part_diacritics = FALSE;
			}
		}

		/*
		 * Metatokens have no independent language result.  Check their
		 * diacritics only when every body part confidently requires it.
		 */
		ignore_meta_diacritics |= ignore_part_diacritics;

		if (rspamd_chartable_process_part(task, part, chartable_module_ctx, ignore_part_diacritics)) {
			seen_violated_part = TRUE;
		}
	}

	if (MESSAGE_FIELD(task, text_parts)->len == 0) {
		/* No text parts, assume that we should ignore diacritics checks for metatokens */
		ignore_meta_diacritics = TRUE;
	}

	if (task->meta_words.a && kv_size(task->meta_words) > 0) {
		rspamd_word_t *w;
		double cur_score = 0;
		gsize arlen = kv_size(task->meta_words);

		for (i = 0; i < arlen; i++) {
			w = &kv_A(task->meta_words, i);
			cur_score += rspamd_chartable_process_word_utf(task, w, FALSE,
														   nullptr, chartable_module_ctx, ignore_meta_diacritics)
							 .badness;
		}

		cur_score /= (double) (arlen + 1);

		if (cur_score > 1.0) {
			cur_score = 1.0;
		}

		if (cur_score > chartable_module_ctx->threshold) {
			if (!seen_violated_part) {
				/* Further penalise */
				if (cur_score > 0.25) {
					cur_score = 0.25;
				}
			}

			rspamd_task_insert_result(task, chartable_module_ctx->symbol,
									  cur_score, "subject");
		}
	}

	rspamd_symcache_finalize_item(task, item);
}

/*
 * A host as it is shown: the labels in the ASCII form of an international
 * name (`xn--...`) are turned into the characters that a browser displays,
 * which are what can be mistaken for another name. Returns false if there
 * is nothing to convert or the name cannot be converted.
 */
static auto
rspamd_chartable_host_to_unicode(const char *start, gsize len, std::string &out) -> bool
{
	if (len < 4 || len > 1024 ||
		rspamd_substring_search_caseless(start, len, "xn--", 4) == -1) {
		return false;
	}

	static UIDNA *idna = nullptr;
	UErrorCode uc_err = U_ZERO_ERROR;

	if (idna == nullptr) {
		idna = uidna_openUTS46(UIDNA_NONTRANSITIONAL_TO_UNICODE, &uc_err);

		if (U_FAILURE(uc_err)) {
			idna = nullptr;
			return false;
		}
	}

	UIDNAInfo info = UIDNA_INFO_INITIALIZER;
	char buf[1024];
	auto converted = uidna_nameToUnicodeUTF8(idna, start, (int32_t) len, buf,
											 sizeof(buf), &info, &uc_err);

	if (U_FAILURE(uc_err) || converted <= 0 || converted > (int32_t) sizeof(buf)) {
		return false;
	}

	out.assign(buf, converted);

	return true;
}

static auto
rspamd_chartable_identifier_spoofed(struct chartable_ctx *chartable_module_ctx,
									const char *start, gsize len) -> bool
{
	std::string displayed;

	if (rspamd_chartable_host_to_unicode(start, len, displayed)) {
		start = displayed.data();
		len = displayed.size();
	}

	if (!g_utf8_validate(start, len, nullptr)) {
		return false;
	}

	const auto *p = start;
	const auto *end = start + len;
	while (p < end) {
		const auto *dot = static_cast<const char *>(memchr(p, '.', end - p));
		const auto label_len = static_cast<gsize>((dot != nullptr ? dot : end) - p);
		bool has_non_ascii = false;

		for (gsize i = 0; i < label_len; i++) {
			if (static_cast<unsigned char>(p[i]) >= 0x80) {
				has_non_ascii = true;
				break;
			}
		}

		if (has_non_ascii) {
			const auto spoof_flags = rspamd_unicode_spoof_check(
				chartable_module_ctx->spoof_checker, p, label_len);
			if (spoof_flags > RSPAMD_UNICODE_SPOOF_NONE) {
				return true;
			}
		}

		if (dot == nullptr) {
			break;
		}
		p = dot + 1;
	}

	return false;
}

static auto
rspamd_chartable_get_skeleton(struct chartable_ctx *chartable_module_ctx,
							  const char *start, gsize len,
							  std::string &out) -> bool
{
	const auto skeleton_len = rspamd_unicode_spoof_skeleton(
		chartable_module_ctx->spoof_checker, start, len, nullptr, 0);
	if (skeleton_len <= 0) {
		return false;
	}

	out.resize(skeleton_len);
	return rspamd_unicode_spoof_skeleton(chartable_module_ctx->spoof_checker,
										 start, len, out.data(), out.size()) == skeleton_len;
}

static auto
rspamd_chartable_url_text_confusable(struct chartable_ctx *chartable_module_ctx,
									 struct rspamd_url *url) -> bool
{
	if (url->ext == nullptr || url->ext->linked_url == nullptr ||
		url->hostlen == 0 || url->ext->linked_url->hostlen == 0) {
		return false;
	}

	const auto *href_host = rspamd_url_host(url);
	const auto *text_host = rspamd_url_host(url->ext->linked_url);
	gsize href_len = url->hostlen;
	gsize text_len = url->ext->linked_url->hostlen;
	if (href_len == text_len &&
		g_ascii_strncasecmp(href_host, text_host, text_len) == 0) {
		return false;
	}

	/* Compare what is displayed for each of the names */
	std::string href_displayed, text_displayed;

	if (rspamd_chartable_host_to_unicode(href_host, href_len, href_displayed)) {
		href_host = href_displayed.data();
		href_len = href_displayed.size();
	}
	if (rspamd_chartable_host_to_unicode(text_host, text_len, text_displayed)) {
		text_host = text_displayed.data();
		text_len = text_displayed.size();
	}

	std::string href_skeleton, text_skeleton;
	return rspamd_chartable_get_skeleton(chartable_module_ctx, href_host,
										 href_len, href_skeleton) &&
		   rspamd_chartable_get_skeleton(chartable_module_ctx, text_host,
										 text_len, text_skeleton) &&
		   href_skeleton == text_skeleton;
}

static void
chartable_url_symbol_callback(struct rspamd_task *task,
							  struct rspamd_symcache_dynamic_item *item,
							  void *)
{
	auto *chartable_module_ctx = chartable_get_context(task->cfg);
	struct rspamd_url *url;
	const char *bad_host = nullptr;
	gsize bad_host_len = 0;

	kh_foreach_key(MESSAGE_FIELD(task, urls), url, {
		if (bad_host == nullptr && url->hostlen > 0) {
			const auto *host = rspamd_url_host(url);
			if (rspamd_chartable_identifier_spoofed(chartable_module_ctx,
													host, url->hostlen) ||
				rspamd_chartable_url_text_confusable(chartable_module_ctx, url)) {
				bad_host = host;
				bad_host_len = url->hostlen;
			}
		}
	});

	if (bad_host != nullptr) {
		auto *option = rspamd_mempool_strdup_len(task->task_pool,
												 bad_host, bad_host_len);
		rspamd_task_insert_result(task, chartable_module_ctx->url_symbol,
								  1.0, option);
	}

	rspamd_symcache_finalize_item(task, item);
}
