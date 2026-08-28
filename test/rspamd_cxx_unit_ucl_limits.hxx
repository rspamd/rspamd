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

#ifndef RSPAMD_RSPAMD_CXX_UNIT_UCL_LIMITS_HXX
#define RSPAMD_RSPAMD_CXX_UNIT_UCL_LIMITS_HXX

#define DOCTEST_CONFIG_IMPLEMENTATION_IN_DLL
#include "doctest/doctest.h"

#include "ucl.h"

#include <memory>
#include <string>

/*
 * Structural budgets for untrusted UCL/JSON input, plus the destruction path
 * they protect: freeing a tree used to recurse once per nesting level, so a
 * document that parsed fine could still take the process down on cleanup.
 */
TEST_SUITE("ucl limits")
{
	using ucl_parser_t = struct ucl_parser;
	using ucl_limits_t = struct ucl_parser_limits;

	struct parser_deleter {
		void operator()(ucl_parser_t *p) const
		{
			ucl_parser_free(p);
		}
	};

	using parser_ptr = std::unique_ptr<ucl_parser_t, parser_deleter>;

	static parser_ptr make_parser(const ucl_limits_t *limits = nullptr)
	{
		parser_ptr p{ucl_parser_new(UCL_PARSER_SAFE_FLAGS)};

		REQUIRE(p != nullptr);

		if (limits != nullptr) {
			ucl_parser_set_limits(p.get(), limits);
		}

		return p;
	}

	/* `depth` nested arrays: [[[...]]] */
	static std::string nested_arrays(unsigned depth)
	{
		return std::string(depth, '[') + std::string(depth, ']');
	}

	/* `depth` nested objects: {"a":{"a":{...}}} */
	static std::string nested_objects(unsigned depth)
	{
		std::string res;

		for (unsigned i = 0; i < depth; i++) {
			res += "{\"a\":";
		}

		res += "1";

		for (unsigned i = 0; i < depth; i++) {
			res += "}";
		}

		return res;
	}

	static bool parse(ucl_parser_t * p, const std::string &input)
	{
		return ucl_parser_add_chunk(p, (const unsigned char *) input.data(),
									input.size());
	}

	TEST_CASE("default limits reject unbounded nesting")
	{
		auto p = make_parser();
		auto input = nested_arrays(100000);

		CHECK(parse(p.get(), input) == false);
		CHECK(ucl_parser_get_error_code(p.get()) == UCL_ENESTED);
	}

	TEST_CASE("default depth limit is enforced for objects too")
	{
		auto p = make_parser();
		auto input = nested_objects(100000);

		CHECK(parse(p.get(), input) == false);
		CHECK(ucl_parser_get_error_code(p.get()) == UCL_ENESTED);
	}

	TEST_CASE("input just under the depth limit still parses and frees")
	{
		ucl_limits_t limits = {};
		limits.max_depth = 64;

		auto p = make_parser(&limits);

		REQUIRE(parse(p.get(), nested_arrays(63)) == true);

		ucl_object_t *top = ucl_parser_get_object(p.get());
		REQUIRE(top != nullptr);
		CHECK(ucl_object_type(top) == UCL_ARRAY);

		/* The interesting part: this must not recurse 63 levels deep */
		ucl_object_unref(top);
	}

	TEST_CASE("a custom depth limit overrides the default")
	{
		ucl_limits_t limits = {};
		limits.max_depth = 8;

		auto p = make_parser(&limits);

		CHECK(parse(p.get(), nested_arrays(9)) == false);
		CHECK(ucl_parser_get_error_code(p.get()) == UCL_ENESTED);
	}

	TEST_CASE("depth is measured per container, not per document")
	{
		ucl_limits_t limits = {};
		limits.max_depth = 4;

		auto p = make_parser(&limits);

		/* Many shallow siblings must not accumulate against the limit */
		std::string input = "[";

		for (int i = 0; i < 1000; i++) {
			if (i > 0) {
				input += ",";
			}

			input += "[1,2]";
		}

		input += "]";

		CHECK(parse(p.get(), input) == true);
	}

	TEST_CASE("max_nodes bounds the element count")
	{
		ucl_limits_t limits = {};
		limits.max_nodes = 16;

		auto p = make_parser(&limits);

		std::string input = "[";

		for (int i = 0; i < 1000; i++) {
			if (i > 0) {
				input += ",";
			}

			input += "1";
		}

		input += "]";

		CHECK(parse(p.get(), input) == false);
		CHECK(ucl_parser_get_error_code(p.get()) == UCL_ELIMIT);
	}

	TEST_CASE("max_nodes leaves conforming input alone")
	{
		ucl_limits_t limits = {};
		limits.max_nodes = 1000;

		auto p = make_parser(&limits);

		CHECK(parse(p.get(), "{\"a\": 1, \"b\": [1, 2, 3]}") == true);
	}

	TEST_CASE("max_alloc bounds the memory a small input can claim")
	{
		ucl_limits_t limits = {};
		limits.max_alloc = 4096;

		auto p = make_parser(&limits);

		std::string input = "{";

		for (int i = 0; i < 10000; i++) {
			if (i > 0) {
				input += ",";
			}

			input += "\"k" + std::to_string(i) + "\": \"v\"";
		}

		input += "}";

		CHECK(parse(p.get(), input) == false);
		CHECK(ucl_parser_get_error_code(p.get()) == UCL_ELIMIT);
	}

	TEST_CASE("max_key_length rejects oversized keys")
	{
		ucl_limits_t limits = {};
		limits.max_key_length = 32;

		auto p = make_parser(&limits);

		std::string input = "{\"" + std::string(64, 'k') + "\": 1}";

		CHECK(parse(p.get(), input) == false);
		CHECK(ucl_parser_get_error_code(p.get()) == UCL_ELIMIT);
	}

	TEST_CASE("max_key_length accepts keys at the limit")
	{
		ucl_limits_t limits = {};
		limits.max_key_length = 32;

		auto p = make_parser(&limits);

		std::string input = "{\"" + std::string(32, 'k') + "\": 1}";

		CHECK(parse(p.get(), input) == true);
	}

	TEST_CASE("max_string_length rejects oversized values")
	{
		ucl_limits_t limits = {};
		limits.max_string_length = 32;

		auto p = make_parser(&limits);

		std::string input = "{\"a\": \"" + std::string(64, 'v') + "\"}";

		CHECK(parse(p.get(), input) == false);
		CHECK(ucl_parser_get_error_code(p.get()) == UCL_ELIMIT);
	}

	TEST_CASE("max_string_length accepts values at the limit")
	{
		ucl_limits_t limits = {};
		limits.max_string_length = 32;

		auto p = make_parser(&limits);

		std::string input = "{\"a\": \"" + std::string(32, 'v') + "\"}";

		CHECK(parse(p.get(), input) == true);
	}

	TEST_CASE("limits round trip through the getter")
	{
		ucl_limits_t limits = {};
		limits.max_depth = 11;
		limits.max_nodes = 22;
		limits.max_alloc = 33;
		limits.max_key_length = 44;
		limits.max_string_length = 55;

		auto p = make_parser(&limits);

		ucl_limits_t got = {};
		ucl_parser_get_limits(p.get(), &got);

		CHECK(got.max_depth == 11);
		CHECK(got.max_nodes == 22);
		CHECK(got.max_alloc == 33);
		CHECK(got.max_key_length == 44);
		CHECK(got.max_string_length == 55);

		/* NULL restores the defaults */
		ucl_parser_set_limits(p.get(), nullptr);
		ucl_parser_get_limits(p.get(), &got);

		CHECK(got.max_depth == 1024);
		CHECK(got.max_nodes == 0);
	}

	TEST_CASE("zero means unlimited")
	{
		ucl_limits_t limits = {};

		/* Everything zeroed: depth included, so deep input is accepted */
		auto p = make_parser(&limits);

		REQUIRE(parse(p.get(), nested_arrays(20000)) == true);

		ucl_object_t *top = ucl_parser_get_object(p.get());
		REQUIRE(top != nullptr);

		/*
		 * 20k levels: the old recursive destructor would blow the stack right
		 * here, which is the whole point of the iterative one.
		 */
		ucl_object_unref(top);
	}

	TEST_CASE("deeply nested objects are destroyed without recursion")
	{
		ucl_limits_t limits = {};

		auto p = make_parser(&limits);

		REQUIRE(parse(p.get(), nested_objects(20000)) == true);

		ucl_object_t *top = ucl_parser_get_object(p.get());
		REQUIRE(top != nullptr);

		ucl_object_unref(top);
	}

	TEST_CASE("shared subtrees survive their container")
	{
		ucl_object_t *kept;

		{
			auto p = make_parser();

			REQUIRE(parse(p.get(), "{\"a\": {\"b\": [1, 2, 3]}}") == true);

			ucl_object_t *top = ucl_parser_get_object(p.get());
			REQUIRE(top != nullptr);

			const ucl_object_t *inner = ucl_object_lookup(top, "a");
			REQUIRE(inner != nullptr);

			/* Take our own reference on the subtree */
			kept = ucl_object_ref(inner);

			/*
			 * The tree has to actually die for this to test anything:
			 * ucl_parser_get_object() hands out a second reference, so
			 * releasing `top` alone leaves the parser owning everything.
			 * Dropping ours and then freeing the parser is what runs the
			 * destructor over the container while `kept` is still live.
			 */
			ucl_object_unref(top);
		}

		const ucl_object_t *arr = ucl_object_lookup(kept, "b");
		REQUIRE(arr != nullptr);
		CHECK(ucl_object_type(arr) == UCL_ARRAY);
		CHECK(ucl_array_size(arr) == 3);
		CHECK(ucl_object_toint(ucl_array_find_index(arr, 0)) == 1);
		CHECK(ucl_object_toint(ucl_array_find_index(arr, 2)) == 3);

		ucl_object_unref(kept);
	}

	/*
	 * MessagePack reaches the same parsers over the network (checkv3 metadata
	 * and proxy replies) and is far denser than JSON - a container costs one
	 * byte - so the budgets have to hold there too.
	 */
	static bool parse_msgpack(ucl_parser_t * p, const std::string &input)
	{
		return ucl_parser_add_chunk_full(p, (const unsigned char *) input.data(),
										 input.size(),
										 ucl_parser_get_default_priority(p),
										 UCL_DUPLICATE_APPEND, UCL_PARSE_MSGPACK);
	}

	/* `depth` fixarrays each holding one element, innermost being int 1 */
	static std::string msgpack_nested_arrays(unsigned depth)
	{
		return std::string(depth, '\x91') + std::string(1, '\x01');
	}

	/* One array16 holding `n` ints */
	static std::string msgpack_flat_array(uint16_t n)
	{
		std::string res;

		res += '\xdc';
		res += (char) (n >> 8);
		res += (char) (n & 0xff);
		res += std::string(n, '\x01');

		return res;
	}

	TEST_CASE("msgpack nesting is bounded by default")
	{
		auto p = make_parser();

		/* 100k levels in 100k bytes - JSON would need twice that */
		CHECK(parse_msgpack(p.get(), msgpack_nested_arrays(100000)) == false);
		CHECK(ucl_parser_get_error_code(p.get()) == UCL_ENESTED);
	}

	TEST_CASE("msgpack honours a custom depth limit")
	{
		ucl_limits_t limits = {};
		limits.max_depth = 8;

		auto p = make_parser(&limits);

		CHECK(parse_msgpack(p.get(), msgpack_nested_arrays(9)) == false);
		CHECK(ucl_parser_get_error_code(p.get()) == UCL_ENESTED);
	}

	TEST_CASE("msgpack within the depth limit parses and frees")
	{
		ucl_limits_t limits = {};
		limits.max_depth = 64;

		auto p = make_parser(&limits);

		REQUIRE(parse_msgpack(p.get(), msgpack_nested_arrays(60)) == true);

		ucl_object_t *top = ucl_parser_get_object(p.get());
		REQUIRE(top != nullptr);
		CHECK(ucl_object_type(top) == UCL_ARRAY);

		ucl_object_unref(top);
	}

	TEST_CASE("msgpack respects max_nodes")
	{
		ucl_limits_t limits = {};
		limits.max_nodes = 16;

		auto p = make_parser(&limits);

		CHECK(parse_msgpack(p.get(), msgpack_flat_array(1000)) == false);
		CHECK(ucl_parser_get_error_code(p.get()) == UCL_ELIMIT);
	}

	TEST_CASE("msgpack respects max_alloc")
	{
		ucl_limits_t limits = {};
		limits.max_alloc = 4096;

		auto p = make_parser(&limits);

		CHECK(parse_msgpack(p.get(), msgpack_flat_array(1000)) == false);
		CHECK(ucl_parser_get_error_code(p.get()) == UCL_ELIMIT);
	}

	TEST_CASE("msgpack respects max_string_length")
	{
		ucl_limits_t limits = {};
		limits.max_string_length = 32;

		auto p = make_parser(&limits);

		/* fixarray of one str8 of 64 bytes; msgpack has no top level scalars */
		std::string input;
		input += '\x91';
		input += '\xd9';
		input += (char) 64;
		input += std::string(64, 'v');

		CHECK(parse_msgpack(p.get(), input) == false);
		CHECK(ucl_parser_get_error_code(p.get()) == UCL_ELIMIT);
	}

	TEST_CASE("msgpack respects max_key_length")
	{
		ucl_limits_t limits = {};
		limits.max_key_length = 32;

		auto p = make_parser(&limits);

		/* fixmap with one entry whose key is a 64 byte str8 */
		std::string input;
		input += '\x81';
		input += '\xd9';
		input += (char) 64;
		input += std::string(64, 'k');
		input += '\x01';

		CHECK(parse_msgpack(p.get(), input) == false);
		CHECK(ucl_parser_get_error_code(p.get()) == UCL_ELIMIT);
	}

	TEST_CASE("conforming msgpack is unaffected by the budgets")
	{
		ucl_limits_t limits = {};
		limits.max_depth = 16;
		limits.max_nodes = 1000;
		limits.max_alloc = 1024 * 1024;
		limits.max_key_length = 64;
		limits.max_string_length = 1024;

		auto p = make_parser(&limits);

		/* fixmap{"ab": [1,1,1]} */
		std::string input;
		input += '\x81';
		input += '\xa2';
		input += "ab";
		input += '\x93';
		input += std::string(3, '\x01');

		REQUIRE(parse_msgpack(p.get(), input) == true);

		ucl_object_t *top = ucl_parser_get_object(p.get());
		REQUIRE(top != nullptr);

		const ucl_object_t *arr = ucl_object_lookup(top, "ab");
		REQUIRE(arr != nullptr);
		CHECK(ucl_array_size(arr) == 3);

		ucl_object_unref(top);
	}

	TEST_CASE("duplicate keys are charged against max_nodes")
	{
		/*
		 * SAFE_FLAGS implies NO_IMPLICIT_ARRAYS, so each repeated key converts
		 * the value into an explicit array - an extra element that has to be
		 * paid for like any other.
		 */
		ucl_limits_t limits = {};
		limits.max_nodes = 8;

		auto p = make_parser(&limits);

		std::string input;

		for (int i = 0; i < 100; i++) {
			input += "a = 1\n";
		}

		CHECK(parse(p.get(), input) == false);
		CHECK(ucl_parser_get_error_code(p.get()) == UCL_ELIMIT);
	}

	TEST_CASE("escape-heavy strings are charged for what they allocate")
	{
		/*
		 * Unescaping shrinks the contents but not the buffer, so the budget has
		 * to track the allocation rather than the decoded length.
		 */
		ucl_limits_t limits = {};
		limits.max_alloc = 8 * 1024;

		auto p = make_parser(&limits);

		/* ~60k of input decoding to ~10k of text */
		std::string input = "{\"a\": \"";

		for (int i = 0; i < 10000; i++) {
			input += "\\u0041";
		}

		input += "\"}";

		CHECK(parse(p.get(), input) == false);
		CHECK(ucl_parser_get_error_code(p.get()) == UCL_ELIMIT);
	}

	TEST_CASE("implicit array chains are fully released")
	{
		/* Duplicate keys build a `next` chain, which the worklist reuses */
		auto p = make_parser();

		REQUIRE(parse(p.get(), "a = 1\na = 2\na = 3\na = 4\n") == true);

		ucl_object_t *top = ucl_parser_get_object(p.get());
		REQUIRE(top != nullptr);

		ucl_object_unref(top);
	}
}

#endif
