/*
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

#ifndef RSPAMD_CXX_UNIT_STAT_PARTS_HXX
#define RSPAMD_CXX_UNIT_STAT_PARTS_HXX

#define DOCTEST_CONFIG_IMPLEMENTATION_IN_DLL
#include "doctest/doctest.h"

#include "libmime/content_type.h"
#include "libmime/message.h"
#include "libserver/cfg_file.h"
#include "libstat/stat_internal.h"

#include <cstring>
#include <initializer_list>
#include <string>
#include <vector>

namespace rspamd_stat_parts_test {

/*
 * Exercise the production selection loop and OSB tokenizer without a Redis
 * backend. The distance between the alternatives and their link are set as
 * MIME processing does. Expected tokens come from explicitly selected parts.
 */
struct fixture {
	rspamd_task task{};
	rspamd_message message{};
	rspamd_config cfg{};
	rspamd_stat_ctx ctx{};
	rspamd_stat_tokenizer tokenizer{};
	std::vector<GPtrArray *> children;

	fixture()
	{
		task.task_pool = rspamd_mempool_new(rspamd_mempool_suggest_size(), "stat_parts_test", 0);
		task.message = &message;
		task.cfg = &cfg;
		message.text_parts = g_ptr_array_new();
		ctx.statfiles = g_ptr_array_new();
		ctx.lua_stat_tokens_ref = -1;
		ctx.tokenizer = &tokenizer;
		tokenizer.tokenize_func = rspamd_tokenizer_osb;
		ctx.tkcf = rspamd_tokenizer_osb_get_config(task.task_pool, nullptr, nullptr);
	}

	~fixture()
	{
		for (auto *array : children) {
			g_ptr_array_unref(array);
		}
		g_ptr_array_unref(ctx.statfiles);
		g_ptr_array_unref(message.text_parts);
		rspamd_mempool_delete(task.task_pool);
	}

	fixture(const fixture &) = delete;
	fixture &operator=(const fixture &) = delete;

	template<typename T>
	T *allocate()
	{
		return static_cast<T *>(rspamd_mempool_alloc0(task.task_pool, sizeof(T)));
	}

	rspamd_ftok_t token(const std::string &value)
	{
		auto *copy = static_cast<char *>(rspamd_mempool_alloc(task.task_pool, value.size() + 1));
		memcpy(copy, value.data(), value.size());
		copy[value.size()] = '\0';
		return {value.size(), copy};
	}

	rspamd_content_type *type(const char *primary, const char *subtype)
	{
		auto *ct = allocate<rspamd_content_type>();
		ct->type = token(primary);
		ct->subtype = token(subtype);
		return ct;
	}

	void words(rspamd_mime_text_part *part, const std::vector<std::string> &values)
	{
		auto &out = part->utf_words;
		out.n = out.m = values.size();
		out.a = static_cast<rspamd_word_t *>(rspamd_mempool_alloc0(task.task_pool,
																	   (values.size() + 1) * sizeof(*out.a)));
		for (size_t i = 0; i < values.size(); i++) {
			out.a[i].original = out.a[i].normalized = out.a[i].stemmed = token(values[i]);
			out.a[i].flags = RSPAMD_STAT_TOKEN_FLAG_TEXT | RSPAMD_STAT_TOKEN_FLAG_UTF;
		}
	}

	rspamd_mime_text_part *text(bool html, const std::vector<std::string> &values = {"alpha", "beta", "gamma"})
	{
		auto *part = allocate<rspamd_mime_part>();
		auto *txt = allocate<rspamd_mime_text_part>();
		part->part_type = RSPAMD_MIME_PART_TEXT;
		part->ct = type("text", html ? "html" : "plain");
		part->specific.txt = txt;
		txt->mime_part = part;
		txt->flags = RSPAMD_MIME_TEXT_PART_FLAG_UTF;
		if (html) {
			txt->flags |= RSPAMD_MIME_TEXT_PART_FLAG_HTML;
		}
		words(txt, values);
		g_ptr_array_add(message.text_parts, txt);
		return txt;
	}

	rspamd_mime_part *group(std::initializer_list<rspamd_mime_part *> parts,
						   const char *subtype = "alternative")
	{
		auto *parent = allocate<rspamd_mime_part>();
		parent->part_type = RSPAMD_MIME_PART_MULTIPART;
		parent->ct = type("multipart", subtype);
		parent->specific.mp = allocate<rspamd_mime_multipart>();
		auto *array = g_ptr_array_new();
		children.push_back(array);
		parent->specific.mp->children = array;
		for (auto *part : parts) {
			part->parent_part = parent;
			g_ptr_array_add(array, part);
		}
		return parent;
	}

	void link(rspamd_mime_text_part *plain, rspamd_mime_text_part *html)
	{
		plain->alt_text_part = html;
		html->alt_text_part = plain;
	}

	void distance(double value, int total = 6)
	{
		auto *p = allocate<double>();
		*p = value;
		rspamd_mempool_set_variable(task.task_pool, "parts_distance", p, nullptr);
		auto *tw = allocate<int>();
		*tw = total;
		rspamd_mempool_set_variable(task.task_pool, "total_words", tw, nullptr);
	}

	void check(std::initializer_list<rspamd_mime_text_part *> selected)
	{
		auto *expected = g_ptr_array_new();
		rspamd_mempool_add_destructor(task.task_pool,
									  reinterpret_cast<rspamd_mempool_destruct_t>(g_ptr_array_unref), expected);
		for (auto *part : selected) {
			rspamd_tokenizer_osb(&ctx, &task, &part->utf_words, IS_TEXT_PART_UTF(part), nullptr, expected);
		}
		if (task.meta_words.a) {
			rspamd_tokenizer_osb(&ctx, &task, &task.meta_words, TRUE, "SUBJECT", expected);
		}

		rspamd_stat_process_tokenize(&ctx, &task);
		REQUIRE(task.tokens->len == expected->len);
		for (unsigned int i = 0; i < expected->len; i++) {
			auto *actual = static_cast<rspamd_token_t *>(g_ptr_array_index(task.tokens, i));
			auto *want = static_cast<rspamd_token_t *>(g_ptr_array_index(expected, i));
			CHECK(actual->data == want->data);
			CHECK(actual->flags == want->flags);
			CHECK(actual->window_idx == want->window_idx);
			CHECK(actual->t1 == want->t1);
			CHECK(actual->t2 == want->t2);
		}
	}
};

} // namespace rspamd_stat_parts_test

TEST_SUITE("stat parts")
{
	using rspamd_stat_parts_test::fixture;

	TEST_CASE("similar alternatives retain HTML regardless of array order")
	{
		for (bool html_first : {false, true}) {
			fixture f;
			auto *first = f.text(html_first);
			auto *second = f.text(!html_first);
			f.group({first->mime_part, second->mime_part});
			f.link(html_first ? second : first, html_first ? first : second);
			f.distance(0.15);
			f.check({html_first ? first : second});
			CHECK(f.message.text_parts->len == 2);
		}
	}

	TEST_CASE("alternatives with small differences retain HTML")
	{
		/* e.g. a URL written out in the plain text only */
		fixture f;
		auto *plain = f.text(false, {"alpha", "beta", "gamma", "example.com"});
		auto *html = f.text(true);
		plain->utf_words.a[3].flags = RSPAMD_STAT_TOKEN_FLAG_EXCEPTION;
		f.group({plain->mime_part, html->mime_part});
		f.link(plain, html);
		f.distance(1.0 / 7.0, 7);
		f.check({html});
	}

	TEST_CASE("different alternatives retain both")
	{
		for (double distance: {0.25, 1.0}) {
			fixture f;
			auto *plain = f.text(false);
			auto *html = f.text(true, {"alpha", "beta", "delta"});
			f.group({plain->mime_part, html->mime_part});
			f.link(plain, html);
			f.distance(distance);
			f.check({plain, html});
		}
	}

	TEST_CASE("alternatives without a distance retain both")
	{
		fixture f;
		auto *plain = f.text(false);
		auto *html = f.text(true);
		f.group({plain->mime_part, html->mime_part});
		f.link(plain, html);
		f.check({plain, html});
	}

	TEST_CASE("approximate distance retains both")
	{
		for (int total: {8192, 8193}) {
			fixture f;
			auto *plain = f.text(false);
			auto *html = f.text(true);
			f.group({plain->mime_part, html->mime_part});
			f.link(plain, html);
			f.distance(0.0, total);
			if (total == 8192) {
				f.check({html});
			}
			else {
				f.check({plain, html});
			}
		}
	}

	TEST_CASE("computed text and unrelated parts survive even when encountered first")
	{
		fixture f;
		auto *ocr1 = f.text(false);
		auto *extra = f.text(false, {"independent", "body", "content"});
		auto *plain = f.text(false);
		auto *html = f.text(true);
		auto *ocr2 = f.text(false, {"other", "image", "content"});
		ocr1->mime_part->flags |= RSPAMD_MIME_PART_COMPUTED;
		ocr2->mime_part->flags |= RSPAMD_MIME_PART_COMPUTED;
		f.group({plain->mime_part, html->mime_part});
		f.link(plain, html);
		f.distance(0.0);
		f.task.meta_words = extra->utf_words;
		f.check({ocr1, extra, html, ocr2});
		CHECK(f.message.text_parts->len == 5);
	}

	TEST_CASE("only the pair measured by parts_distance is deduplicated")
	{
		fixture f;
		auto *p1 = f.text(false);
		auto *h1 = f.text(true);
		auto *p2 = f.text(false);
		auto *h2 = f.text(true);
		f.group({p1->mime_part, h1->mime_part});
		f.group({p2->mime_part, h2->mime_part});
		f.link(p1, h1);
		f.link(p2, h2);
		f.distance(0.0);
		f.check({h1, p2, h2});
	}

	TEST_CASE("computed or attached alternatives are not deduplicated")
	{
		for (bool mark_html : {false, true}) {
			for (auto flag : {RSPAMD_MIME_PART_COMPUTED, RSPAMD_MIME_PART_ATTACHEMENT,
							  RSPAMD_MIME_PART_BAD_CTE}) {
				fixture f;
				auto *plain = f.text(false);
				auto *html = f.text(true);
				(mark_html ? html : plain)->mime_part->flags |= flag;
				f.group({plain->mime_part, html->mime_part});
				f.link(plain, html);
				f.distance(0.0);
				f.check({plain, html});
			}
		}
	}

	TEST_CASE("mixed nested and ambiguous MIME structures retain every text")
	{
		SUBCASE("mixed siblings") {
			fixture f;
			auto *plain = f.text(false);
			auto *html = f.text(true);
			f.group({plain->mime_part, html->mime_part}, "mixed");
			f.link(plain, html);
			f.distance(0.0);
			f.check({plain, html});
		}
		SUBCASE("three children") {
			fixture f;
			auto *p1 = f.text(false);
			auto *p2 = f.text(false);
			auto *html = f.text(true);
			f.group({p1->mime_part, p2->mime_part, html->mime_part});
			f.link(p1, html);
			f.distance(0.0);
			f.check({p1, p2, html});
		}
		SUBCASE("nested branch") {
			fixture f;
			auto *plain = f.text(false);
			auto *html = f.text(true);
			auto *related = f.group({html->mime_part}, "related");
			f.group({plain->mime_part, related});
			f.link(plain, html);
			f.distance(0.0);
			f.check({plain, html});
		}
	}

	TEST_CASE("HTML must actually be eligible for tokenization")
	{
		fixture f;
		auto *plain = f.text(false);
		auto *html = f.text(true);
		f.group({plain->mime_part, html->mime_part});
		f.link(plain, html);
		f.distance(0.0);
		html->flags |= RSPAMD_MIME_TEXT_PART_FLAG_EMPTY;
		f.check({plain});
	}
}

#endif
