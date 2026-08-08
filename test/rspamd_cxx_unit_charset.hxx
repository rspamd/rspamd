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
 * Regression coverage for the BIG5-CP950 false positive:
 *
 *   - The Google CED emits the non-IANA label "BIG5-CP950", which ICU does
 *     not know. rspamd_mime_detect_charset must fold it to a real charset via
 *     the substitution table, otherwise ucnv_open fails with
 *     U_FILE_ACCESS_ERROR.
 *
 *   - Text that is synthetically extracted (e.g. from a PDF) is injected as a
 *     computed text/plain; charset=utf-8 part. When such a part holds bytes
 *     that are not valid UTF-8 (raw glyph codes, not a real legacy charset),
 *     rspamd_mime_text_part_maybe_convert must keep it raw instead of guessing
 *     a charset via CED and attempting a conversion that feeds noise into
 *     tokenization and language detection.
 */

#ifndef RSPAMD_CXX_UNIT_CHARSET_HXX
#define RSPAMD_CXX_UNIT_CHARSET_HXX

#define DOCTEST_CONFIG_IMPLEMENTATION_IN_DLL
#include "doctest/doctest.h"

#include "config.h"
#include "libmime/content_type.h"
#include "libmime/message.h"
#include "libmime/mime_encoding.h"
#include "libserver/task.h"
#include "libutil/mem_pool.h"

#include <cstring>
#include <string>

namespace rspamd_charset_test {

/*
 * Builds a computed text/plain; charset=utf-8 part the same way
 * task:inject_part() does, then owns the task and its pool so that a failing
 * assertion cannot leak either.
 */
class computed_part_holder {
public:
	explicit computed_part_holder(const std::string &content)
	{
		pool = rspamd_mempool_new(rspamd_mempool_suggest_size(),
								  "charset_test", 0);
		task = rspamd_task_new(nullptr, nullptr, pool, nullptr, nullptr, FALSE);

		auto *task_pool = task->task_pool;

		part = (struct rspamd_mime_part *)
			rspamd_mempool_alloc0(task_pool, sizeof(*part));
		part->part_type = RSPAMD_MIME_PART_TEXT;
		part->flags |= RSPAMD_MIME_PART_COMPUTED;

		struct rspamd_content_type *ct = (struct rspamd_content_type *)
			rspamd_mempool_alloc0(task_pool, sizeof(*ct));
		ct->type.begin = "text";
		ct->type.len = 4;
		ct->subtype.begin = "plain";
		ct->subtype.len = 5;
		ct->flags = RSPAMD_CONTENT_TYPE_TEXT;
		ct->charset.begin = "utf-8";
		ct->charset.len = 5;
		part->ct = ct;

		/* Owned, NUL-terminated copy, mirroring inject_part's parsed_data. */
		auto *data = (char *) rspamd_mempool_alloc(task_pool, content.size() + 1);
		memcpy(data, content.data(), content.size());
		data[content.size()] = '\0';
		part->parsed_data.begin = data;
		part->parsed_data.len = content.size();
		part->raw_data = part->parsed_data;

		txt = (struct rspamd_mime_text_part *)
			rspamd_mempool_alloc0(task_pool, sizeof(*txt));
		txt->mime_part = part;
		txt->raw.begin = data;
		txt->raw.len = content.size();
		txt->parsed = txt->raw;
	}

	computed_part_holder(const computed_part_holder &) = delete;
	computed_part_holder &operator=(const computed_part_holder &) = delete;

	~computed_part_holder()
	{
		rspamd_task_free(task);
		rspamd_mempool_delete(pool);
	}

	struct rspamd_task *get_task() const
	{
		return task;
	}

	struct rspamd_mime_text_part *get_text_part() const
	{
		return txt;
	}

private:
	rspamd_mempool_t *pool;
	struct rspamd_task *task;
	struct rspamd_mime_part *part;
	struct rspamd_mime_text_part *txt;
};

static rspamd_ftok_t
ftok_of(const char *s)
{
	rspamd_ftok_t tok;
	tok.begin = s;
	tok.len = strlen(s);
	return tok;
}

}// namespace rspamd_charset_test

TEST_SUITE("mime charset detection")
{
	TEST_CASE("CED non-IANA alias big5-cp950 resolves to big5")
	{
		auto *pool = rspamd_mempool_new(rspamd_mempool_suggest_size(),
										"charset_alias", 0);

		/*
		 * ICU's canonical name for the Big5 converter varies across builds
		 * (e.g. "Big5", "windows-950"), so resolve plain "big5" once and check
		 * the alias yields the same canonical name rather than a hard-coded
		 * string.
		 */
		auto big5_tok = rspamd_charset_test::ftok_of("big5");
		const auto *big5_canon = rspamd_mime_detect_charset(&big5_tok, pool);
		REQUIRE(big5_canon != nullptr);

		SUBCASE("lowercase label")
		{
			auto tok = rspamd_charset_test::ftok_of("big5-cp950");
			const auto *cs = rspamd_mime_detect_charset(&tok, pool);
			REQUIRE(cs != nullptr);
			CHECK(g_ascii_strcasecmp(cs, big5_canon) == 0);
		}

		SUBCASE("uppercase label, as emitted by CED")
		{
			auto tok = rspamd_charset_test::ftok_of("BIG5-CP950");
			const auto *cs = rspamd_mime_detect_charset(&tok, pool);
			REQUIRE(cs != nullptr);
			CHECK(g_ascii_strcasecmp(cs, big5_canon) == 0);
		}

		/* The fast path must be unaffected by the new entry. */
		SUBCASE("utf-8 fast path is untouched")
		{
			auto tok = rspamd_charset_test::ftok_of("utf-8");
			const auto *cs = rspamd_mime_detect_charset(&tok, pool);
			REQUIRE(cs != nullptr);
			CHECK(g_ascii_strcasecmp(cs, "utf-8") == 0);
		}

		rspamd_mempool_delete(pool);
	}

	TEST_CASE("CED euc-tw misnomers resolve to euc-tw")
	{
		auto *pool = rspamd_mempool_new(rspamd_mempool_suggest_size(),
										"charset_alias_euctw", 0);

		/*
		 * EUC-TW lives in the optional ICU data, so resolve it first: with no
		 * converter to fold onto there is nothing to assert.
		 */
		auto euctw_tok = rspamd_charset_test::ftok_of("euc-tw");
		const auto *euctw_canon = rspamd_mime_detect_charset(&euctw_tok, pool);

		if (euctw_canon == nullptr) {
			MESSAGE("no EUC-TW converter in this ICU build, skipping");
		}
		else {
			for (const char *label: {"cns", "CNS", "euc", "EUC"}) {
				auto tok = rspamd_charset_test::ftok_of(label);
				const auto *cs = rspamd_mime_detect_charset(&tok, pool);
				REQUIRE(cs != nullptr);
				CHECK(g_ascii_strcasecmp(cs, euctw_canon) == 0);
			}
		}

		rspamd_mempool_delete(pool);
	}
}

TEST_SUITE("mime computed text part conversion")
{
	using namespace rspamd_charset_test;

	TEST_CASE("computed part with invalid UTF-8 is kept raw, not converted")
	{
		/*
		 * 8-bit glyph garbage that is not valid UTF-8 (resembles the raw glyph
		 * codes extracted from a PDF stream). Spaces separate the escape pairs
		 * so the \x hex escapes cannot run into one another.
		 */
		std::string garbage = "glyph \xa6\xc7 \xa6\xc8 \xab\xa6 data \xb3\xa1";

		computed_part_holder holder(garbage);
		auto *txt = holder.get_text_part();

		rspamd_mime_text_part_maybe_convert(holder.get_task(), txt);

		/*
		 * The COMPUTED guard must short-circuit before CED and conversion:
		 * the part is raw (UTF flag cleared) and never reaches ucnv_open, so
		 * there is no U_FILE_ACCESS_ERROR and no bogus language detection.
		 */
		CHECK((txt->flags & RSPAMD_MIME_TEXT_PART_FLAG_UTF) == 0);
		CHECK(txt->utf_raw_content != nullptr);
	}

	TEST_CASE("computed part with valid UTF-8 still becomes utf")
	{
		/* "cafe" with a valid 2-byte UTF-8 e-acute (\xc3\xa9). */
		std::string good = "cafe \xc3\xa9";

		computed_part_holder holder(good);
		auto *txt = holder.get_text_part();

		rspamd_mime_text_part_maybe_convert(holder.get_task(), txt);

		CHECK((txt->flags & RSPAMD_MIME_TEXT_PART_FLAG_UTF) != 0);
	}
}

#endif// RSPAMD_CXX_UNIT_CHARSET_HXX
