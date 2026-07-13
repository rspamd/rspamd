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

#include "lua_common.h"
#include "lua_classnames.h"

/***
 * @module rspamd_static_embed
 * This module provides static token-embedding models (Model2Vec style):
 * a WordPiece subword tokenizer (BertNormalizer + Bert pre-tokenizer +
 * greedy WordPiece) combined with a precomputed float32 embedding matrix.
 * A sentence vector is the mean of the matrix rows of all subword tokens;
 * there is no neural forward pass.
 *
 * The tokenizer is internal to the vectorizer: it consumes words produced
 * by rspamd's regular tokenization pipeline and is NOT registered in the
 * global word-breaking / statistics path, so Bayes and fuzzy hashes are
 * unaffected.
 *
 * A model directory must contain:
 *   - config.json: dim, vocab_size, pooling ("mean"), unk_id,
 *     continuing_subword_prefix, normalizer flags (clean_text,
 *     handle_chinese_chars, strip_accents, lowercase), matrix (file name),
 *     matrix_dtype ("float32"); optionally max_input_chars_per_word
 *   - vocab.txt: one token per line, line i == token id i
 *   - the matrix file: raw float32, row-major [vocab_size, dim],
 *     row i == token id i (mmap-ed, shared between workers)
 *   - tokenizer.json (optional): HuggingFace tokenizer spec; when present
 *     its normalizer/pre_tokenizer/model sections take precedence and are
 *     validated strictly (only BertNormalizer, Bert/Whitespace
 *     pre-tokenizers and the WordPiece model are supported; anything else
 *     fails the load)
 *
 * @example
 * local rspamd_static_embed = require "rspamd_static_embed"
 * local model, err = rspamd_static_embed.load('/path/to/model_dir')
 * if model then
 *   local dim = model:get_dimension()
 *   -- words is a table of strings (e.g. part:get_words('norm'))
 *   local vec, ntokens = model:get_sentence_vector(words)
 *   -- per-token sequence access for external consumers (order-aware
 *   -- feature exports); the provider path uses only the pooled vector
 *   local vecs, n = model:get_token_vectors(words, {max_tokens = 128})
 *   local packed = model:get_token_vectors(words, {raw = true})
 * end
 */

#include "ucl.h"
#include "contrib/ankerl/unordered_dense.h"

#include <unicode/uchar.h>
#include <unicode/utf8.h>
#include <unicode/utf16.h>
#include <unicode/unorm2.h>
#include <unicode/ustring.h>
#include <unicode/ucasemap.h>

#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

#include <algorithm>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

/* Forward declarations */
static int lua_static_embed_load(lua_State *L);
static int lua_static_embed_tokenize(lua_State *L);
static int lua_static_embed_get_sentence_vector(lua_State *L);
static int lua_static_embed_get_token_vectors(lua_State *L);
static int lua_static_embed_get_dimension(lua_State *L);
static int lua_static_embed_get_vocab_size(lua_State *L);
static int lua_static_embed_get_unk_id(lua_State *L);
static int lua_static_embed_dtor(lua_State *L);

/* Module functions */
static const struct luaL_reg staticembedlib_f[] = {
	{"load", lua_static_embed_load},
	{nullptr, nullptr},
};

/* Model methods */
static const struct luaL_reg staticembedlib_m[] = {
	{"tokenize", lua_static_embed_tokenize},
	{"get_sentence_vector", lua_static_embed_get_sentence_vector},
	{"get_token_vectors", lua_static_embed_get_token_vectors},
	{"get_dimension", lua_static_embed_get_dimension},
	{"get_vocab_size", lua_static_embed_get_vocab_size},
	{"get_unk_id", lua_static_embed_get_unk_id},
	{"__gc", lua_static_embed_dtor},
	{"__tostring", rspamd_lua_class_tostring},
	{nullptr, nullptr},
};

namespace {

/*
 * Character classification mirrors the HF BertNormalizer/BertPreTokenizer
 * semantics (equivalently Python unicodedata as used by the reference
 * implementation); do not "fix" these predicates to look more natural,
 * tokenization must reproduce the reference bit-for-bit.
 */

/* Category C* except \t \n \r */
static bool
wp_is_control(UChar32 cp)
{
	if (cp == '\t' || cp == '\n' || cp == '\r') {
		return false;
	}

	switch (u_charType(cp)) {
	case U_UNASSIGNED:
	case U_CONTROL_CHAR:
	case U_FORMAT_CHAR:
	case U_PRIVATE_USE_CHAR:
	case U_SURROGATE:
		return true;
	default:
		return false;
	}
}

/* ' ' \t \n \r or category Zs */
static bool
wp_is_bert_ws(UChar32 cp)
{
	if (cp == ' ' || cp == '\t' || cp == '\n' || cp == '\r') {
		return true;
	}

	return u_charType(cp) == U_SPACE_SEPARATOR;
}

/*
 * Whitespace for the pre-tokenizer split: Unicode White_Space plus the
 * 0x1C-0x1F range (Python str.split() semantics used by the reference)
 */
static bool
wp_is_split_ws(UChar32 cp)
{
	if (cp >= 0x1c && cp <= 0x1f) {
		return true;
	}

	return u_hasBinaryProperty(cp, UCHAR_WHITE_SPACE);
}

/* CJK ideograph blocks as defined by the Bert normalizer */
static bool
wp_is_cjk(UChar32 cp)
{
	return (cp >= 0x4E00 && cp <= 0x9FFF) ||
		   (cp >= 0x3400 && cp <= 0x4DBF) ||
		   (cp >= 0x20000 && cp <= 0x2A6DF) ||
		   (cp >= 0x2A700 && cp <= 0x2B73F) ||
		   (cp >= 0x2B740 && cp <= 0x2B81F) ||
		   (cp >= 0x2B820 && cp <= 0x2CEAF) ||
		   (cp >= 0xF900 && cp <= 0xFAFF) ||
		   (cp >= 0x2F800 && cp <= 0x2FA1F);
}

/* ASCII symbol ranges (treated as punctuation by Bert) or category P* */
static bool
wp_is_punct(UChar32 cp)
{
	if ((cp >= 33 && cp <= 47) || (cp >= 58 && cp <= 64) ||
		(cp >= 91 && cp <= 96) || (cp >= 123 && cp <= 126)) {
		return true;
	}

	switch (u_charType(cp)) {
	case U_DASH_PUNCTUATION:
	case U_START_PUNCTUATION:
	case U_END_PUNCTUATION:
	case U_CONNECTOR_PUNCTUATION:
	case U_OTHER_PUNCTUATION:
	case U_INITIAL_PUNCTUATION:
	case U_FINAL_PUNCTUATION:
		return true;
	default:
		return false;
	}
}

static void
wp_append_utf8(std::string &out, UChar32 cp)
{
	std::uint8_t buf[U8_MAX_LENGTH];
	std::size_t off = 0;

	U8_APPEND_UNSAFE(buf, off, cp);
	out.append(reinterpret_cast<const char *>(buf), off);
}

struct wordpiece_vocab_hash {
	using is_transparent = void;
	using is_avalanching = void;
	auto operator()(std::string_view sv) const noexcept -> std::uint64_t
	{
		return ankerl::unordered_dense::hash<std::string_view>{}(sv);
	}
};

struct wordpiece_tokenizer {
	ankerl::unordered_dense::map<std::string, std::uint32_t,
								 wordpiece_vocab_hash, std::equal_to<>>
		vocab;
	std::string prefix = "##";
	std::uint32_t unk_id = 0;
	std::int64_t max_input_chars = 100;
	/* Normalizer flags; all false == null normalizer */
	bool clean_text = false;
	bool handle_chinese_chars = false;
	bool strip_accents = false;
	bool lowercase = false;

	const UNormalizer2 *nfd = nullptr;
	UCaseMap *csm = nullptr;

	wordpiece_tokenizer() = default;
	wordpiece_tokenizer(const wordpiece_tokenizer &) = delete;
	wordpiece_tokenizer &operator=(const wordpiece_tokenizer &) = delete;
	~wordpiece_tokenizer()
	{
		if (csm) {
			ucasemap_close(csm);
		}
	}

	std::string normalize(std::string_view in) const;
	void tokenize(std::string_view text, std::vector<std::uint32_t> &ids) const;

private:
	std::string do_strip_accents(const std::string &in) const;
	std::string do_lowercase(const std::string &in) const;
	void word_to_ids(std::string_view word, std::vector<std::uint32_t> &ids,
					 std::string &lookup_buf, std::vector<std::int32_t> &offs) const;
};

std::string
wordpiece_tokenizer::normalize(std::string_view in) const
{
	std::string out;
	out.reserve(in.size() + 16);

	const auto *s = reinterpret_cast<const std::uint8_t *>(in.data());
	auto len = static_cast<std::int32_t>(in.size());
	std::int32_t i = 0;

	/* clean_text and CJK padding are per-codepoint maps, fuse them in one pass */
	while (i < len) {
		UChar32 cp;

		U8_NEXT(s, i, len, cp);

		if (cp < 0) {
			/* Invalid UTF8: same as decoding with the replacement character */
			cp = 0xFFFD;
		}

		if (clean_text) {
			if (cp == 0 || cp == 0xFFFD || wp_is_control(cp)) {
				continue;
			}
			if (wp_is_bert_ws(cp)) {
				cp = ' ';
			}
		}

		if (handle_chinese_chars && wp_is_cjk(cp)) {
			out += ' ';
			wp_append_utf8(out, cp);
			out += ' ';
		}
		else {
			wp_append_utf8(out, cp);
		}
	}

	/* Reference order: strip accents first, then lowercase */
	if (strip_accents) {
		out = do_strip_accents(out);
	}
	if (lowercase) {
		out = do_lowercase(out);
	}

	return out;
}

/* NFD decomposition with all Mn (non-spacing marks) removed */
std::string
wordpiece_tokenizer::do_strip_accents(const std::string &in) const
{
	UErrorCode uc_err = U_ZERO_ERROR;

	/* UTF16 length never exceeds the UTF8 byte length */
	std::vector<UChar> u16(in.size() + 1);
	std::int32_t u16_len = 0;

	u_strFromUTF8(u16.data(), static_cast<std::int32_t>(u16.size()), &u16_len,
				  in.data(), static_cast<std::int32_t>(in.size()), &uc_err);

	if (U_FAILURE(uc_err)) {
		return in;
	}

	auto nfd_len = unorm2_normalize(nfd, u16.data(), u16_len, nullptr, 0, &uc_err);
	if (uc_err != U_BUFFER_OVERFLOW_ERROR && U_FAILURE(uc_err)) {
		return in;
	}

	uc_err = U_ZERO_ERROR;
	std::vector<UChar> decomposed(nfd_len + 1);
	nfd_len = unorm2_normalize(nfd, u16.data(), u16_len,
							   decomposed.data(),
							   static_cast<std::int32_t>(decomposed.size()),
							   &uc_err);
	if (U_FAILURE(uc_err)) {
		return in;
	}

	std::string out;
	out.reserve(in.size());
	std::int32_t i = 0;

	while (i < nfd_len) {
		UChar32 cp;

		U16_NEXT(decomposed.data(), i, nfd_len, cp);

		if (u_charType(cp) == U_NON_SPACING_MARK) {
			continue;
		}

		wp_append_utf8(out, cp);
	}

	return out;
}

/* Full (root locale) Unicode lowercasing, matches Python str.lower() */
std::string
wordpiece_tokenizer::do_lowercase(const std::string &in) const
{
	UErrorCode uc_err = U_ZERO_ERROR;
	std::string out;

	out.resize(in.size() + 16);
	auto n = ucasemap_utf8ToLower(csm, out.data(),
								  static_cast<std::int32_t>(out.size()),
								  in.data(), static_cast<std::int32_t>(in.size()),
								  &uc_err);

	if (uc_err == U_BUFFER_OVERFLOW_ERROR) {
		uc_err = U_ZERO_ERROR;
		out.resize(n);
		n = ucasemap_utf8ToLower(csm, out.data(),
								 static_cast<std::int32_t>(out.size()),
								 in.data(), static_cast<std::int32_t>(in.size()),
								 &uc_err);
	}

	if (U_FAILURE(uc_err)) {
		return in;
	}

	out.resize(n);

	return out;
}

/*
 * Greedy longest-match WordPiece for a single pre-tokenized word;
 * the whole word maps to unk_id if any piece fails to match
 */
void wordpiece_tokenizer::word_to_ids(std::string_view word,
									  std::vector<std::uint32_t> &ids,
									  std::string &lookup_buf,
									  std::vector<std::int32_t> &offs) const
{
	const auto *s = reinterpret_cast<const std::uint8_t *>(word.data());
	auto len = static_cast<std::int32_t>(word.size());

	/* Codepoint boundaries: offs[k] is the byte offset of the k-th codepoint */
	offs.clear();
	std::int32_t i = 0;
	while (i < len) {
		offs.push_back(i);
		U8_FWD_1(s, i, len);
	}
	offs.push_back(len);

	auto nchars = static_cast<std::int64_t>(offs.size()) - 1;

	if (nchars > max_input_chars) {
		ids.push_back(unk_id);
		return;
	}

	auto first_added = ids.size();
	std::size_t start = 0;

	while (start < static_cast<std::size_t>(nchars)) {
		auto end = static_cast<std::size_t>(nchars);
		std::int64_t cur = -1;

		while (start < end) {
			auto sub = word.substr(offs[start], offs[end] - offs[start]);

			if (start == 0) {
				auto it = vocab.find(sub);
				if (it != vocab.end()) {
					cur = it->second;
					break;
				}
			}
			else {
				lookup_buf.assign(prefix);
				lookup_buf.append(sub);
				auto it = vocab.find(std::string_view{lookup_buf});
				if (it != vocab.end()) {
					cur = it->second;
					break;
				}
			}

			end--;
		}

		if (cur < 0) {
			/* No match for this piece: the whole word becomes unk */
			ids.resize(first_added);
			ids.push_back(unk_id);
			return;
		}

		ids.push_back(static_cast<std::uint32_t>(cur));
		start = end;
	}
}

void wordpiece_tokenizer::tokenize(std::string_view text,
								   std::vector<std::uint32_t> &ids) const
{
	auto normalized = normalize(text);

	const auto *s = reinterpret_cast<const std::uint8_t *>(normalized.data());
	auto len = static_cast<std::int32_t>(normalized.size());
	std::int32_t i = 0, word_start = -1;
	std::string lookup_buf;
	std::vector<std::int32_t> offs;

	auto flush_word = [&](std::int32_t end_pos) {
		if (word_start >= 0) {
			word_to_ids(std::string_view{normalized}.substr(word_start, end_pos - word_start),
						ids, lookup_buf, offs);
			word_start = -1;
		}
	};

	/*
	 * Pre-tokenizer: split on whitespace, isolate each punctuation
	 * character as a separate word
	 */
	while (i < len) {
		auto cp_start = i;
		UChar32 cp;

		U8_NEXT(s, i, len, cp);

		if (cp < 0) {
			/* Treat an invalid byte as a regular character */
			cp = 0xFFFD;
		}

		if (wp_is_split_ws(cp)) {
			flush_word(cp_start);
		}
		else if (wp_is_punct(cp)) {
			flush_word(cp_start);
			word_to_ids(std::string_view{normalized}.substr(cp_start, i - cp_start),
						ids, lookup_buf, offs);
		}
		else if (word_start < 0) {
			word_start = cp_start;
		}
	}

	flush_word(len);
}

/* --- Model loading --- */

struct ucl_object_deleter {
	void operator()(ucl_object_t *obj) const
	{
		ucl_object_unref(obj);
	}
};
using ucl_object_ptr = std::unique_ptr<ucl_object_t, ucl_object_deleter>;

static ucl_object_ptr
wp_parse_json_file(const std::filesystem::path &path, std::string &err)
{
	auto *parser = ucl_parser_new(UCL_PARSER_NO_FILEVARS);

	if (!ucl_parser_add_file(parser, path.c_str())) {
		err = ucl_parser_get_error(parser);
		ucl_parser_free(parser);
		return nullptr;
	}

	auto *obj = ucl_parser_get_object(parser);
	ucl_parser_free(parser);

	return ucl_object_ptr{obj};
}

/*
 * Strict typed field access; unknown/malformed values produce an error
 * instead of being silently ignored
 */
static std::optional<std::string>
wp_get_bool(const ucl_object_t *obj, const char *key, bool &value)
{
	const auto *elt = ucl_object_lookup(obj, key);

	if (elt == nullptr || ucl_object_type(elt) == UCL_NULL) {
		return std::nullopt;
	}

	if (ucl_object_type(elt) != UCL_BOOLEAN) {
		return std::string{"field '"} + key + "' must be a boolean";
	}

	value = ucl_object_toboolean(elt);

	return std::nullopt;
}

static std::optional<std::string>
wp_get_int(const ucl_object_t *obj, const char *key, std::int64_t &value)
{
	const auto *elt = ucl_object_lookup(obj, key);

	if (elt == nullptr || ucl_object_type(elt) == UCL_NULL) {
		return std::nullopt;
	}

	if (ucl_object_type(elt) != UCL_INT) {
		return std::string{"field '"} + key + "' must be an integer";
	}

	value = ucl_object_toint(elt);

	return std::nullopt;
}

static std::optional<std::string>
wp_get_string(const ucl_object_t *obj, const char *key, std::string &value)
{
	const auto *elt = ucl_object_lookup(obj, key);

	if (elt == nullptr || ucl_object_type(elt) == UCL_NULL) {
		return std::nullopt;
	}

	if (ucl_object_type(elt) != UCL_STRING) {
		return std::string{"field '"} + key + "' must be a string";
	}

	value = ucl_object_tostring(elt);

	return std::nullopt;
}

/*
 * Parse normalizer flags from either the HF tokenizer.json normalizer
 * section ({"type": "BertNormalizer", ...}) or the frozen flags object
 * from config.json (no "type" key). null disables normalization.
 * strip_accents == null defaults to the lowercase flag (HF semantics).
 */
static std::optional<std::string>
wp_parse_normalizer(const ucl_object_t *norm_obj, wordpiece_tokenizer &tk)
{
	if (norm_obj == nullptr || ucl_object_type(norm_obj) == UCL_NULL) {
		/* Null normalizer: leave all flags false */
		return std::nullopt;
	}

	if (ucl_object_type(norm_obj) != UCL_OBJECT) {
		return std::string{"'normalizer' must be an object or null"};
	}

	std::string type;
	if (auto err = wp_get_string(norm_obj, "type", type)) {
		return err;
	}
	if (!type.empty() && type != "BertNormalizer") {
		return "unsupported normalizer type '" + type +
			   "' (only BertNormalizer is supported)";
	}

	tk.clean_text = true;
	tk.handle_chinese_chars = true;
	tk.lowercase = true;

	if (auto err = wp_get_bool(norm_obj, "clean_text", tk.clean_text)) {
		return err;
	}
	if (auto err = wp_get_bool(norm_obj, "handle_chinese_chars", tk.handle_chinese_chars)) {
		return err;
	}
	if (auto err = wp_get_bool(norm_obj, "lowercase", tk.lowercase)) {
		return err;
	}

	/* strip_accents: true/false, or null/absent -> follow lowercase */
	tk.strip_accents = tk.lowercase;
	if (auto err = wp_get_bool(norm_obj, "strip_accents", tk.strip_accents)) {
		return err;
	}

	return std::nullopt;
}

static std::optional<std::string>
wp_load_vocab(const std::filesystem::path &path, wordpiece_tokenizer &tk,
			  std::uint32_t &vocab_lines)
{
	std::ifstream in(path, std::ios::binary);

	if (!in) {
		return "cannot open vocab file " + path.string();
	}

	std::string content{std::istreambuf_iterator<char>(in),
						std::istreambuf_iterator<char>()};

	/*
	 * One token per line, line i == token id i; the reference artifact is
	 * "\n".join()-ed (no trailing newline), but tolerate a trailing newline
	 * as a line terminator rather than an extra empty token
	 */
	std::string_view rest{content};
	if (!rest.empty() && rest.back() == '\n') {
		rest.remove_suffix(1);
	}

	tk.vocab.reserve(std::count(rest.begin(), rest.end(), '\n') + 1);

	std::uint32_t id = 0;

	while (!rest.empty() || id == 0) {
		auto nl_pos = rest.find('\n');
		auto line = (nl_pos == std::string_view::npos) ? rest : rest.substr(0, nl_pos);

		/* Empty tokens keep their id slot but are not matchable */
		if (!line.empty()) {
			auto inserted = tk.vocab.emplace(std::string{line}, id).second;
			if (!inserted) {
				return "duplicate token '" + std::string{line} +
					   "' in vocab file " + path.string();
			}
		}

		id++;

		if (nl_pos == std::string_view::npos) {
			break;
		}
		rest.remove_prefix(nl_pos + 1);
	}

	if (tk.vocab.empty()) {
		return "empty vocab file " + path.string();
	}

	vocab_lines = id;

	return std::nullopt;
}

struct rspamd_lua_static_embed {
	wordpiece_tokenizer tk;
	std::uint32_t vocab_lines = 0;
	std::int64_t dim = 0;
	const float *matrix = nullptr;
	std::size_t matrix_bytes = 0;

	rspamd_lua_static_embed() = default;
	rspamd_lua_static_embed(const rspamd_lua_static_embed &) = delete;
	rspamd_lua_static_embed &operator=(const rspamd_lua_static_embed &) = delete;
	~rspamd_lua_static_embed()
	{
		if (matrix) {
			munmap(const_cast<float *>(matrix), matrix_bytes);
		}
	}
};

/*
 * Load and validate the model from a directory; returns an error message
 * on any deviation from the supported spec (fail-fast, no fallbacks)
 */
static std::optional<std::string>
wp_load_dir(const std::string &dir, rspamd_lua_static_embed &model)
{
	namespace fs = std::filesystem;

	auto &tk = model.tk;
	const auto base = fs::path{dir};
	const auto config_path = base / "config.json";
	const auto vocab_path = base / "vocab.txt";
	const auto tokenizer_path = base / "tokenizer.json";

	std::error_code ec;

	if (!fs::exists(config_path, ec)) {
		return "missing config.json in " + dir;
	}
	if (!fs::exists(vocab_path, ec)) {
		return "missing vocab.txt in " + dir;
	}

	std::string parse_err;
	auto config = wp_parse_json_file(config_path, parse_err);
	if (!config) {
		return "cannot parse " + config_path.string() + ": " + parse_err;
	}

	if (auto err = wp_load_vocab(vocab_path, tk, model.vocab_lines)) {
		return err;
	}

	std::int64_t unk_id = -1;
	std::string unk_token;

	if (fs::exists(tokenizer_path, ec)) {
		/* HF tokenizer.json takes precedence, validated strictly */
		auto tokenizer = wp_parse_json_file(tokenizer_path, parse_err);
		if (!tokenizer) {
			return "cannot parse " + tokenizer_path.string() + ": " + parse_err;
		}

		if (auto err = wp_parse_normalizer(
				ucl_object_lookup(tokenizer.get(), "normalizer"), tk)) {
			return err;
		}

		/*
		 * pre_tokenizer: all supported types (and null) behave as
		 * "whitespace split + isolate punctuation"; anything else fails
		 */
		const auto *pre_tok = ucl_object_lookup(tokenizer.get(), "pre_tokenizer");
		if (pre_tok != nullptr && ucl_object_type(pre_tok) != UCL_NULL) {
			if (ucl_object_type(pre_tok) != UCL_OBJECT) {
				return std::string{"'pre_tokenizer' must be an object or null"};
			}
			std::string type;
			if (auto err = wp_get_string(pre_tok, "type", type)) {
				return err;
			}
			if (type != "BertPreTokenizer" && type != "Whitespace" &&
				type != "WhitespaceSplit") {
				return "unsupported pre_tokenizer type '" + type + "'";
			}
		}

		const auto *tok_model = ucl_object_lookup(tokenizer.get(), "model");
		if (tok_model == nullptr || ucl_object_type(tok_model) != UCL_OBJECT) {
			return std::string{"missing 'model' section in tokenizer.json"};
		}

		std::string model_type;
		if (auto err = wp_get_string(tok_model, "type", model_type)) {
			return err;
		}
		if (model_type != "WordPiece") {
			return "unsupported model type '" + model_type +
				   "' (only WordPiece is supported)";
		}

		if (auto err = wp_get_string(tok_model, "unk_token", unk_token)) {
			return err;
		}
		if (unk_token.empty()) {
			return std::string{"missing 'unk_token' in tokenizer.json model"};
		}
		if (auto err = wp_get_string(tok_model, "continuing_subword_prefix", tk.prefix)) {
			return err;
		}
		if (auto err = wp_get_int(tok_model, "max_input_chars_per_word", tk.max_input_chars)) {
			return err;
		}

		/* post_processor is intentionally ignored (add_special_tokens=false) */
	}
	else {
		/* Frozen artifact: tokenizer spec is embedded in config.json */
		if (auto err = wp_parse_normalizer(
				ucl_object_lookup(config.get(), "normalizer"), tk)) {
			return err;
		}
		if (auto err = wp_get_string(config.get(), "continuing_subword_prefix", tk.prefix)) {
			return err;
		}
		if (auto err = wp_get_int(config.get(), "max_input_chars_per_word", tk.max_input_chars)) {
			return err;
		}
		if (auto err = wp_get_int(config.get(), "unk_id", unk_id)) {
			return err;
		}
		if (auto err = wp_get_string(config.get(), "unk_token", unk_token)) {
			return err;
		}
	}

	/* Resolve unk: explicit id or a token looked up in the vocab */
	if (unk_id < 0) {
		if (unk_token.empty()) {
			return std::string{"missing 'unk_id' (or 'unk_token') in model config"};
		}
		auto it = tk.vocab.find(std::string_view{unk_token});
		if (it == tk.vocab.end()) {
			return "unk_token '" + unk_token + "' is not in the vocab";
		}
		unk_id = it->second;
	}

	if (unk_id >= model.vocab_lines) {
		return "unk_id " + std::to_string(unk_id) + " is out of vocab range (" +
			   std::to_string(model.vocab_lines) + ")";
	}
	tk.unk_id = static_cast<std::uint32_t>(unk_id);

	if (tk.max_input_chars <= 0) {
		return std::string{"'max_input_chars_per_word' must be positive"};
	}

	std::int64_t declared_vocab_size = -1;
	if (auto err = wp_get_int(config.get(), "vocab_size", declared_vocab_size)) {
		return err;
	}
	if (declared_vocab_size >= 0 && declared_vocab_size != model.vocab_lines) {
		return "vocab_size mismatch: config declares " +
			   std::to_string(declared_vocab_size) + ", vocab.txt has " +
			   std::to_string(model.vocab_lines) + " tokens";
	}

	/* Embedding matrix spec: only mean pooling of float32 rows is supported */
	if (auto err = wp_get_int(config.get(), "dim", model.dim)) {
		return err;
	}
	if (model.dim <= 0) {
		return std::string{"missing or invalid 'dim' in config.json"};
	}

	std::string pooling;
	if (auto err = wp_get_string(config.get(), "pooling", pooling)) {
		return err;
	}
	if (pooling != "mean") {
		return "unsupported pooling '" + pooling + "' (only \"mean\" is supported)";
	}

	std::string matrix_name;
	if (auto err = wp_get_string(config.get(), "matrix", matrix_name)) {
		return err;
	}
	if (matrix_name.empty()) {
		return std::string{"missing 'matrix' file name in config.json"};
	}

	std::string dtype;
	if (auto err = wp_get_string(config.get(), "matrix_dtype", dtype)) {
		return err;
	}
	if (dtype != "float32") {
		return "unsupported matrix_dtype '" + dtype + "' (only float32 is supported)";
	}

	/* mmap the matrix read-only: shared between workers, never copied */
	const auto matrix_path = base / matrix_name;
	auto fd = open(matrix_path.c_str(), O_RDONLY);
	if (fd == -1) {
		return "cannot open matrix file " + matrix_path.string() + ": " + strerror(errno);
	}

	struct stat st;
	if (fstat(fd, &st) == -1) {
		close(fd);
		return "cannot stat matrix file " + matrix_path.string() + ": " + strerror(errno);
	}

	auto expected = static_cast<std::size_t>(model.vocab_lines) * model.dim * sizeof(float);
	if (static_cast<std::size_t>(st.st_size) != expected) {
		close(fd);
		return "matrix size mismatch in " + matrix_path.string() + ": " +
			   std::to_string(st.st_size) + " bytes, expected " +
			   std::to_string(expected) + " (" + std::to_string(model.vocab_lines) +
			   " rows x " + std::to_string(model.dim) + " dim x 4)";
	}

	auto *map = mmap(nullptr, expected, PROT_READ, MAP_SHARED, fd, 0);
	close(fd);
	if (map == MAP_FAILED) {
		return "cannot mmap matrix file " + matrix_path.string() + ": " + strerror(errno);
	}

	model.matrix = static_cast<const float *>(map);
	model.matrix_bytes = expected;

	/* ICU helpers are only needed for the corresponding normalizer flags */
	UErrorCode uc_err = U_ZERO_ERROR;

	if (tk.strip_accents) {
		tk.nfd = unorm2_getNFDInstance(&uc_err);
		if (U_FAILURE(uc_err)) {
			return std::string{"cannot obtain NFD normalizer: "} + u_errorName(uc_err);
		}
	}
	if (tk.lowercase) {
		tk.csm = ucasemap_open("", 0, &uc_err);
		if (U_FAILURE(uc_err)) {
			return std::string{"cannot create ICU case mapper: "} + u_errorName(uc_err);
		}
	}

	return std::nullopt;
}

}// namespace

#define STATIC_EMBED_CLASS rspamd_static_embed_classname

static struct rspamd_lua_static_embed *
lua_check_static_embed(lua_State *L, int pos)
{
	auto **pmodel = static_cast<struct rspamd_lua_static_embed **>(
		rspamd_lua_check_udata(L, pos, STATIC_EMBED_CLASS));
	luaL_argcheck(L, pmodel != nullptr && *pmodel != nullptr, pos,
				  "'rspamd{static_embed}' expected");
	return *pmodel;
}

/***
 * @function rspamd_static_embed.load(dir)
 * Load a static embedding model from a directory (config.json + vocab.txt
 * + matrix file + optional tokenizer.json). The supported spec subset is
 * validated strictly: any unsupported normalizer/pre-tokenizer/model type,
 * a pooling other than "mean", a non-float32 matrix or a size mismatch
 * fails the load.
 * @param {string} dir model directory path
 * @return {rspamd_static_embed|nil} model object, or nil + error message
 */
static int
lua_static_embed_load(lua_State *L)
{
	const char *dir = luaL_checkstring(L, 1);

	auto model = std::make_unique<rspamd_lua_static_embed>();

	if (auto err = wp_load_dir(dir, *model)) {
		msg_err("cannot load static embedding model from %s: %s", dir, err->c_str());
		lua_pushnil(L);
		lua_pushstring(L, err->c_str());
		return 2;
	}

	auto **pmodel = static_cast<struct rspamd_lua_static_embed **>(
		lua_newuserdata(L, sizeof(struct rspamd_lua_static_embed *)));
	*pmodel = model.release();
	rspamd_lua_setclass(L, STATIC_EMBED_CLASS, -1);

	return 1;
}

/***
 * @method model:tokenize(text)
 * Tokenize a text into an array of 0-based token ids (normalize ->
 * pre-tokenize -> greedy WordPiece); ids match the model vocab/matrix rows.
 * Mostly useful for testing and debugging.
 * @param {string|text} text input text
 * @return {table} array of integer token ids
 */
static int
lua_static_embed_tokenize(lua_State *L)
{
	auto *model = lua_check_static_embed(L, 1);
	auto *t = lua_check_text_or_string(L, 2);

	if (t == nullptr) {
		return luaL_error(L, "invalid arguments");
	}

	std::vector<std::uint32_t> ids;
	model->tk.tokenize(std::string_view{t->start, t->len}, ids);

	lua_createtable(L, static_cast<int>(ids.size()), 0);
	for (std::size_t i = 0; i < ids.size(); i++) {
		lua_pushinteger(L, static_cast<lua_Integer>(ids[i]));
		lua_rawseti(L, -2, static_cast<int>(i + 1));
	}

	return 1;
}

/*
 * Tokenize the argument at `pos` into subword ids: either a table of word
 * strings or a whole string/rspamd_text. Shared by get_sentence_vector and
 * get_token_vectors so both use exactly the same tokenization path.
 */
static void
lua_static_embed_collect_ids(lua_State *L, struct rspamd_lua_static_embed *model,
							 int pos, std::vector<std::uint32_t> &ids)
{
	if (lua_istable(L, pos)) {
		auto nwords = rspamd_lua_table_size(L, pos);

		for (auto i = 1; i <= nwords; i++) {
			lua_rawgeti(L, pos, i);

			if (lua_isstring(L, -1)) {
				std::size_t wlen;
				const char *w = lua_tolstring(L, -1, &wlen);
				if (wlen > 0) {
					model->tk.tokenize(std::string_view{w, wlen}, ids);
				}
			}

			lua_pop(L, 1);
		}
	}
	else {
		auto *t = lua_check_text_or_string(L, pos);

		if (t == nullptr) {
			luaL_error(L, "invalid arguments");
			return;
		}

		model->tk.tokenize(std::string_view{t->start, t->len}, ids);
	}
}

/***
 * @method model:get_sentence_vector(words)
 * Compute a sentence embedding: each word is tokenized into WordPiece
 * subword ids and the corresponding matrix rows are mean-pooled. Feeding
 * words from rspamd's regular tokenization (part:get_words('norm')) is
 * equivalent to tokenizing the whitespace-joined text.
 * An empty input produces a zero vector.
 * @param {table|string|text} words table of word strings, or a whole text
 * @return {table,number} table of dim floats and the number of subword tokens
 */
static int
lua_static_embed_get_sentence_vector(lua_State *L)
{
	auto *model = lua_check_static_embed(L, 1);
	std::vector<std::uint32_t> ids;

	lua_static_embed_collect_ids(L, model, 2, ids);

	auto dim = static_cast<std::size_t>(model->dim);
	std::vector<double> acc(dim, 0.0);

	for (auto id: ids) {
		const float *row = model->matrix + static_cast<std::size_t>(id) * dim;
		for (std::size_t d = 0; d < dim; d++) {
			acc[d] += row[d];
		}
	}

	if (!ids.empty()) {
		auto inv = 1.0 / static_cast<double>(ids.size());
		for (auto &v: acc) {
			v *= inv;
		}
	}

	lua_createtable(L, static_cast<int>(dim), 0);
	for (std::size_t d = 0; d < dim; d++) {
		lua_pushnumber(L, acc[d]);
		lua_rawseti(L, -2, static_cast<int>(d + 1));
	}
	lua_pushinteger(L, static_cast<lua_Integer>(ids.size()));

	return 2;
}

/***
 * @method model:get_token_vectors(words[, opts])
 * Get the per-token embedding sequence instead of the pooled mean: matrix
 * rows in token order, unk rows included exactly as the pooled path
 * includes them. Intended for offline consumers (e.g. external trainers
 * exporting order-aware text features); the neural provider itself only
 * uses the pooled get_sentence_vector.
 * Accepts the same input as get_sentence_vector and tokenizes through the
 * same code path.
 * Options:
 *   - max_tokens (positive integer): truncate AFTER tokenization to the
 *     first N tokens; the returned count is the post-truncation one
 *   - raw (boolean): return an rspamd_text with ntokens*dim little-endian
 *     float32s packed row-major (the matrix byte order) instead of a
 *     table of tables
 * An empty input produces an empty table (or empty text) and 0, never nil.
 * @param {table|string|text} words table of word strings, or a whole text
 * @param {table} opts optional {max_tokens = N, raw = true}
 * @return {table|text,number} sequence of dim-sized rows and the number of tokens
 */
static int
lua_static_embed_get_token_vectors(lua_State *L)
{
	auto *model = lua_check_static_embed(L, 1);

	/* Validate opts strictly before doing any work */
	std::int64_t max_tokens = -1;
	bool raw = false;

	if (!lua_isnoneornil(L, 3)) {
		if (!lua_istable(L, 3)) {
			return luaL_error(L, "'opts' must be a table");
		}

		lua_getfield(L, 3, "max_tokens");
		if (!lua_isnil(L, -1)) {
			if (lua_type(L, -1) != LUA_TNUMBER) {
				return luaL_error(L, "'max_tokens' must be a positive integer");
			}
			auto num = lua_tonumber(L, -1);
			max_tokens = static_cast<std::int64_t>(num);
			if (static_cast<lua_Number>(max_tokens) != num || max_tokens <= 0) {
				return luaL_error(L, "'max_tokens' must be a positive integer");
			}
		}
		lua_pop(L, 1);

		lua_getfield(L, 3, "raw");
		if (!lua_isnil(L, -1)) {
			if (!lua_isboolean(L, -1)) {
				return luaL_error(L, "'raw' must be a boolean");
			}
			raw = lua_toboolean(L, -1);
		}
		lua_pop(L, 1);
	}

	std::vector<std::uint32_t> ids;
	lua_static_embed_collect_ids(L, model, 2, ids);

	if (max_tokens > 0 && ids.size() > static_cast<std::size_t>(max_tokens)) {
		ids.resize(max_tokens);
	}

	auto dim = static_cast<std::size_t>(model->dim);

	if (raw) {
		/* Pack rows into an owned rspamd_text, row-major float32 */
		auto blen = ids.size() * dim * sizeof(float);
		auto *t = lua_new_text(L, nullptr, blen, TRUE);
		auto *out = const_cast<char *>(t->start);

		for (std::size_t i = 0; i < ids.size(); i++) {
			const float *row = model->matrix + static_cast<std::size_t>(ids[i]) * dim;
			memcpy(out + i * dim * sizeof(float), row, dim * sizeof(float));
		}
	}
	else {
		lua_createtable(L, static_cast<int>(ids.size()), 0);

		for (std::size_t i = 0; i < ids.size(); i++) {
			const float *row = model->matrix + static_cast<std::size_t>(ids[i]) * dim;

			lua_createtable(L, static_cast<int>(dim), 0);
			for (std::size_t d = 0; d < dim; d++) {
				lua_pushnumber(L, static_cast<lua_Number>(row[d]));
				lua_rawseti(L, -2, static_cast<int>(d + 1));
			}
			lua_rawseti(L, -2, static_cast<int>(i + 1));
		}
	}

	lua_pushinteger(L, static_cast<lua_Integer>(ids.size()));

	return 2;
}

/***
 * @method model:get_dimension()
 * Get the embedding dimension
 * @return {number} vector dimension
 */
static int
lua_static_embed_get_dimension(lua_State *L)
{
	auto *model = lua_check_static_embed(L, 1);

	lua_pushinteger(L, static_cast<lua_Integer>(model->dim));

	return 1;
}

/***
 * @method model:get_vocab_size()
 * Get the vocabulary size (== number of embedding matrix rows)
 * @return {number} vocab size
 */
static int
lua_static_embed_get_vocab_size(lua_State *L)
{
	auto *model = lua_check_static_embed(L, 1);

	lua_pushinteger(L, model->vocab_lines);

	return 1;
}

/***
 * @method model:get_unk_id()
 * Get the unknown token id
 * @return {number} unk token id (0-based)
 */
static int
lua_static_embed_get_unk_id(lua_State *L)
{
	auto *model = lua_check_static_embed(L, 1);

	lua_pushinteger(L, model->tk.unk_id);

	return 1;
}

static int
lua_static_embed_dtor(lua_State *L)
{
	auto **pmodel = static_cast<struct rspamd_lua_static_embed **>(
		rspamd_lua_check_udata(L, 1, STATIC_EMBED_CLASS));

	if (pmodel && *pmodel) {
		delete *pmodel;
		*pmodel = nullptr;
	}

	return 0;
}

void luaopen_static_embed(lua_State *L)
{
	/* Register the model class */
	rspamd_lua_new_class(L, STATIC_EMBED_CLASS, staticembedlib_m);
	lua_pop(L, 1);

	/* Register the module table */
	rspamd_lua_add_preload(L, "rspamd_static_embed", [](lua_State *LL) -> int {
		luaL_register(LL, "rspamd_static_embed", staticembedlib_f);
		return 1;
	});
}
