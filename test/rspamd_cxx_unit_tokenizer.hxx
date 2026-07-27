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

#ifndef RSPAMD_RSPAMD_CXX_UNIT_TOKENIZER_HXX
#define RSPAMD_RSPAMD_CXX_UNIT_TOKENIZER_HXX

#define DOCTEST_CONFIG_IMPLEMENTATION_IN_DLL
#include "doctest/doctest.h"

/* Both headers provide their own C++ linkage guards */
#include "libstat/tokenizers/tokenizers.h"
#include <unicode/utext.h>

#include <memory>
#include <string>

/*
 * Bounds of the text tokenizer: the per part words decay and the message wide
 * words budget. Both must limit the words that are actually retained, as every
 * retained word is normalized and stemmed later on, with several allocations
 * from the task pool each.
 */
TEST_SUITE("tokenizer limits")
{
	/* Distinct words, so that nothing is deduplicated on the way */
	static auto make_words_text(unsigned int nwords) -> std::string
	{
		std::string text;

		text.reserve(nwords * 9);

		for (unsigned int i = 0; i < nwords; i++) {
			char buf[16];

			rspamd_snprintf(buf, sizeof(buf), "word%04d ", i % 10000);
			text += buf;
		}

		return text;
	}

	static auto tokenize(const std::string &text,
						 enum rspamd_tokenize_type how,
						 struct rspamd_config *cfg,
						 struct rspamd_tokenize_budget *budget,
						 rspamd_words_t *words,
						 rspamd_mempool_t *pool) -> void
	{
		UText utxt = UTEXT_INITIALIZER;
		UErrorCode uc_err = U_ZERO_ERROR;

		utext_openUTF8(&utxt, text.data(), text.size(), &uc_err);
		REQUIRE(U_SUCCESS(uc_err));

		rspamd_tokenize_text(text.data(), text.size(),
							 how == RSPAMD_TOKENIZE_UTF ? &utxt : nullptr,
							 how, cfg, nullptr, nullptr, words, budget, pool);

		utext_close(&utxt);
	}

	static auto count_skipped(const rspamd_words_t &words) -> unsigned int
	{
		unsigned int nskipped = 0;

		for (unsigned int i = 0; i < kv_size(words); i++) {
			if (kv_A(words, i).flags & RSPAMD_WORD_FLAG_SKIPPED) {
				nskipped++;
			}
		}

		return nskipped;
	}

	TEST_CASE("words decay bounds the retained words")
	{
		constexpr auto nwords = 5000;
		auto cfg = std::make_unique<struct rspamd_config>();
		auto *pool = rspamd_mempool_new(rspamd_mempool_suggest_size(), "tok", 0);
		auto text = make_words_text(nwords);

		cfg->words_decay = 50;

		for (auto how: {RSPAMD_TOKENIZE_UTF, RSPAMD_TOKENIZE_RAW}) {
			rspamd_words_t words;

			kv_init(words);
			tokenize(text, how, cfg.get(), nullptr, &words, pool);

			/*
			 * Decay keeps roughly words_decay more words after it starts, so
			 * the retained amount must be nowhere near the words in the text
			 */
			CHECK(kv_size(words) > 0);
			CHECK(kv_size(words) < nwords / 4);
			/* Decayed words must be dropped, not retained and normalized */
			CHECK(count_skipped(words) == 0);

			kv_destroy(words);
		}

		rspamd_mempool_delete(pool);
	}

	TEST_CASE("words budget bounds a single part")
	{
		auto cfg = std::make_unique<struct rspamd_config>();
		auto *pool = rspamd_mempool_new(rspamd_mempool_suggest_size(), "tok", 0);
		auto text = make_words_text(1000);
		struct rspamd_tokenize_budget budget = {};
		rspamd_words_t words;

		budget.max_words = 100;
		kv_init(words);

		tokenize(text, RSPAMD_TOKENIZE_UTF, cfg.get(), &budget, &words, pool);

		CHECK(kv_size(words) == 100);
		CHECK(budget.words == 100);
		CHECK(budget.exceeded);

		kv_destroy(words);
		rspamd_mempool_delete(pool);
	}

	TEST_CASE("words budget is shared by all parts of a message")
	{
		auto cfg = std::make_unique<struct rspamd_config>();
		auto *pool = rspamd_mempool_new(rspamd_mempool_suggest_size(), "tok", 0);
		/* Each part on its own is far too small to hit any per part limit */
		auto text = make_words_text(50);
		struct rspamd_tokenize_budget budget = {};
		uint64_t total = 0;

		budget.max_words = 120;

		for (auto i = 0; i < 10; i++) {
			rspamd_words_t words;

			kv_init(words);
			tokenize(text, RSPAMD_TOKENIZE_UTF, cfg.get(), &budget, &words, pool);
			total += kv_size(words);
			kv_destroy(words);
		}

		CHECK(total == 120);
		CHECK(budget.words == 120);
		CHECK(budget.exceeded);

		rspamd_mempool_delete(pool);
	}

	TEST_CASE("words budget bounds the retained bytes")
	{
		auto cfg = std::make_unique<struct rspamd_config>();
		auto *pool = rspamd_mempool_new(rspamd_mempool_suggest_size(), "tok", 0);
		auto text = make_words_text(1000);
		struct rspamd_tokenize_budget budget = {};
		rspamd_words_t words;
		uint64_t bytes = 0;

		budget.max_bytes = 256;
		kv_init(words);

		tokenize(text, RSPAMD_TOKENIZE_UTF, cfg.get(), &budget, &words, pool);

		for (unsigned int i = 0; i < kv_size(words); i++) {
			bytes += kv_A(words, i).original.len;
		}

		CHECK(bytes <= 256);
		CHECK(budget.bytes == bytes);
		CHECK(budget.exceeded);

		kv_destroy(words);
		rspamd_mempool_delete(pool);
	}

	TEST_CASE("no budget means no limits")
	{
		constexpr auto nwords = 1000;
		auto cfg = std::make_unique<struct rspamd_config>();
		auto *pool = rspamd_mempool_new(rspamd_mempool_suggest_size(), "tok", 0);
		auto text = make_words_text(nwords);
		rspamd_words_t words;

		kv_init(words);
		tokenize(text, RSPAMD_TOKENIZE_UTF, cfg.get(), nullptr, &words, pool);

		CHECK(kv_size(words) == nwords);

		kv_destroy(words);
		rspamd_mempool_delete(pool);
	}
}

#endif
