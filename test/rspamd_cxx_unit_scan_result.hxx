#ifndef RSPAMD_CXX_UNIT_SCAN_RESULT_HXX
#define RSPAMD_CXX_UNIT_SCAN_RESULT_HXX

#include "doctest/doctest.h"
#include "libmime/scan_result_private.h"
#include "libserver/cfg_file.h"
#include "libserver/task.h"

#include <memory>

namespace rspamd_scan_result_test {
struct fixture {
	rspamd_task task{};
	rspamd_config cfg{};
	rspamd_scan_result result{};
	rspamd_symbol_result symbol{};

	fixture()
	{
		task.task_pool = rspamd_mempool_new(rspamd_mempool_suggest_size(), "option_test", 0);
		task.cfg = &cfg;
		task.result = &result;
		cfg.max_opts_len = 4096;
		symbol.name = "OPTION_TEST";
	}

	~fixture()
	{
		if (symbol.options) {
			kh_destroy(rspamd_options_hash, symbol.options);
		}
		rspamd_mempool_delete(task.task_pool);
	}
};

TEST_CASE("safe duplicate symbol options do not allocate from the task pool")
{
	fixture f;
	constexpr auto option = "ordinary,option";
	REQUIRE(rspamd_task_add_result_option(&f.task, &f.symbol, option, strlen(option)));
	CHECK(std::string(f.symbol.opts_head->option, f.symbol.opts_head->optlen) == option);
	auto used = rspamd_mempool_get_used_size(f.task.task_pool);
	for (int i = 0; i < 100; i++) {
		CHECK_FALSE(rspamd_task_add_result_option(&f.task, &f.symbol, option, strlen(option)));
	}
	CHECK(rspamd_mempool_get_used_size(f.task.task_pool) == used);
	const char *utf8 = "café";
	REQUIRE(rspamd_task_add_result_option(&f.task, &f.symbol, utf8, strlen(utf8)));
	used = rspamd_mempool_get_used_size(f.task.task_pool);
	CHECK_FALSE(rspamd_task_add_result_option(&f.task, &f.symbol, utf8, strlen(utf8)));
	CHECK(rspamd_mempool_get_used_size(f.task.task_pool) == used);
}

TEST_CASE("oneparam symbol options do not allocate from the task pool")
{
	fixture f;
	rspamd_symbol definition{};
	definition.flags = RSPAMD_SYMBOL_FLAG_ONEPARAM;
	f.symbol.sym = &definition;
	auto used = rspamd_mempool_get_used_size(f.task.task_pool);
	CHECK_FALSE(rspamd_task_add_result_option(&f.task, &f.symbol, "ordinary", 8));
	CHECK(rspamd_mempool_get_used_size(f.task.task_pool) == used);
}

TEST_CASE("symbol options are stored verbatim except for invalid characters")
{
	const struct {
		const char *input;
		const char *expected;
	} cases[] = {
		{"95.33%", "95.33%"},
		{"%2C", "%2C"},
		{"a](0.00)[]; X[b", "a](0.00)[]; X[b"},
		{"{x};y", "{x};y"},
		{"tab\there", "tab\xEF\xBF\xBDhere"},
		{"bad\xff", "bad\xEF\xBF\xBD"},
	};

	for (const auto &c: cases) {
		fixture f;
		CAPTURE(std::string(c.input));
		// Do not provide a trailing NUL: the copy must respect the length.
		auto len = strlen(c.input);
		auto input = std::make_unique<char[]>(len);
		memcpy(input.get(), c.input, len);
		REQUIRE(rspamd_task_add_result_option(&f.task, &f.symbol, input.get(), len));
		CHECK(std::string(f.symbol.opts_head->option, f.symbol.opts_head->optlen) == std::string(c.expected));
		if (std::string(c.input) == c.expected) {
			auto used = rspamd_mempool_get_used_size(f.task.task_pool);
			CHECK_FALSE(rspamd_task_add_result_option(&f.task, &f.symbol, input.get(), len));
			CHECK(rspamd_mempool_get_used_size(f.task.task_pool) == used);
		}
	}
}
}// namespace rspamd_scan_result_test

#endif
