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

#include "config.h"
#include "html.hxx"
#include "libserver/task.h"

#include <vector>
#include "contrib/fmt/include/fmt/core.h"


#define DOCTEST_CONFIG_IMPLEMENTATION_IN_DLL
#include "doctest/doctest.h"

namespace rspamd::html {

/*
 * Tests part
 */

TEST_SUITE("html")
{
	TEST_CASE("html parsing")
	{

		const std::vector<std::pair<std::string, std::string>> cases{
			{"<html><!DOCTYPE html><body>", "+html;++xml;++body;"},
			{"<html><div><div></div></div></html>", "+html;++div;+++div;"},
			{"<html><div><div></div></html>", "+html;++div;+++div;"},
			{"<html><div><div></div></html></div>", "+html;++div;+++div;"},
			{"<p><p><a></p></a></a>", "+p;++p;+++a;"},
			{"<div><a href=\"http://example.com\"></div></a>", "+div;++a;"},
			/* Broken, as I don't know how the hell this should be really parsed */
			//{"<html><!DOCTYPE html><body><head><body></body></html></body></html>",
			//												   "+html;++xml;++body;+++head;+++body;"}
		};

		rspamd_url_init(NULL);
		auto *pool = rspamd_mempool_new(rspamd_mempool_suggest_size(),
										"html", 0);
		struct rspamd_task fake_task;
		memset(&fake_task, 0, sizeof(fake_task));
		fake_task.task_pool = pool;

		for (const auto &c: cases) {
			SUBCASE((std::string("extract tags from: ") + c.first).c_str())
			{
				GByteArray *tmp = g_byte_array_sized_new(c.first.size());
				g_byte_array_append(tmp, (const uint8_t *) c.first.data(), c.first.size());
				auto *hc = html_process_input(&fake_task, tmp, nullptr, nullptr, nullptr, true, nullptr);
				CHECK(hc != nullptr);
				auto dump = html_debug_structure(*hc);
				CHECK(c.second == dump);
				g_byte_array_free(tmp, TRUE);
			}
		}

		rspamd_mempool_delete(pool);
	}

	TEST_CASE("html text extraction")
	{
		using namespace std::string_literals;
		const std::vector<std::pair<std::string, std::string>> cases{
			{"test", "test"},
			{"test\0"s, "test\uFFFD"s},
			{"test\0test"s, "test\uFFFDtest"s},
			{"test\0\0test"s, "test\uFFFD\uFFFDtest"s},
			{"test   ", "test"},
			{"test   foo,   bar", "test foo, bar"},
			{"<p>text</p>", "text\n"},
			{"olo<p>text</p>lolo", "olo\ntext\nlolo"},
			{"<div>foo</div><div>bar</div>", "foo\nbar\n"},
			{"<b>foo<i>bar</b>baz</i>", "foobarbaz"},
			{"<b>foo<i>bar</i>baz</b>", "foobarbaz"},
			{"foo<br>baz", "foo\nbaz"},
			{"<a href=https://example.com>test</a>", "test"},
			{"<img alt=test>", "test"},
			{"  <body>\n"
			 "    <!-- escape content -->\n"
			 "    a&nbsp;b a &gt; b a &lt; b a &amp; b &apos;a &quot;a&quot;\n"
			 "  </body>",
			 R"|(a b a > b a < b a & b 'a "a")|"},
			/* XML tags */
			{"<?xml version=\"1.0\" encoding=\"iso-8859-1\"?>\n"
			 " <!DOCTYPE html\n"
			 "   PUBLIC \"-//W3C//DTD XHTML 1.0 Strict//EN\"\n"
			 "   \"http://www.w3.org/TR/xhtml1/DTD/xhtml1-strict.dtd\">\n"
			 "<body>test</body>",
			 "test"},
			{"<html><head><meta http-equiv=\"content-type\" content=\"text/html; charset=UTF-8\"></head>"
			 "  <body>\n"
			 "    <p><br>\n"
			 "    </p>\n"
			 "    <div class=\"moz-forward-container\"><br>\n"
			 "      <br>\n"
			 "      test</div>"
			 "</body>",
			 "\n\n\ntest\n"},
			{"<div>fi<span style=\"FONT-SIZE: 0px\">le </span>"
			 "sh<span style=\"FONT-SIZE: 0px\">aring </span></div>",
			 "fish\n"},
			/* FIXME: broken until rework of css parser */
			//{"<div>fi<span style=\"FONT-SIZE: 0px\">le </span>"
			// "sh<span style=\"FONT-SIZE: 0px\">aring </div>foo</span>", "fish\nfoo"},
			/* Complex html with bad tags */
			{"<!DOCTYPE html>\n"
			 "<html lang=\"en\">\n"
			 "  <head>\n"
			 "    <meta charset=\"utf-8\">\n"
			 "    <title>title</title>\n"
			 "    <link rel=\"stylesheet\" href=\"style.css\">\n"
			 "    <script src=\"script.js\"></script>\n"
			 "  </head>\n"
			 "  <body>\n"
			 "    <!-- page content -->\n"
			 "    Hello, world! <b>test</b>\n"
			 "    <p>data<>\n"
			 "    </P>\n"
			 "    <b>stuff</p>?\n"
			 "  </body>\n"
			 "</html>",
			 "Hello, world! test \ndata<>\nstuff\n?"},
			{"<p><!--comment-->test</br></hr><br>", "test\n"},
			/* Tables */
			{"<table>\n"
			 "      <tr>\n"
			 "        <th>heada</th>\n"
			 "        <th>headb</th>\n"
			 "      </tr>\n"
			 "      <tr>\n"
			 "        <td>data1</td>\n"
			 "        <td>data2</td>\n"
			 "      </tr>\n"
			 "    </table>",
			 "heada headb\ndata1 data2\n"},
			/* Invalid closing br and hr + comment */
			{"  <body>\n"
			 "    <!-- page content -->\n"
			 "    Hello, world!<br>test</br><br>content</hr>more content<br>\n"
			 "    <div>\n"
			 "      content inside div\n"
			 "    </div>\n"
			 "  </body>",
			 "Hello, world!\ntest\ncontentmore content\ncontent inside div\n"},
			/* First closing tag */
			{"</head>\n"
			 "<body>\n"
			 "<p> Hello. I have some bad news.\n"
			 "<br /> <br /> <br /> <strong> <br /> <br /> <br /> <br /> <br /> <br /> <br /> <br /> </strong><span> <br /> </span>test</p>\n"
			 "</body>\n"
			 "</html>",
			 "Hello. I have some bad news. \n\n\n\n\n\n\n\n\n\n\n\ntest\n"},
			/* Invalid tags */
			{"lol <sht> omg </sht> oh my!\n"
			 "<name>words words</name> goodbye",
			 "lol omg oh my! words words goodbye"},
			/* Invisible stuff */
			{"<div style=\"color:#555555;font-family:Arial, 'Helvetica Neue', Helvetica, sans-serif;line-height:1.2;padding-top:10px;padding-right:10px;padding-bottom:10px;padding-left:10px;font-style: italic;\">\n"
			 "<p style=\"font-size: 11px; line-height: 1.2; color: #555555; font-family: Arial, 'Helvetica Neue', Helvetica, sans-serif; mso-line-height-alt: 14px; margin: 0;\">\n"
			 "<span style=\"color:#FFFFFF; \">F</span>Sincerely,</p>\n"
			 "<p style=\"font-size: 11px; line-height: 1.2; color: #555555; font-family: Arial, 'Helvetica Neue', Helvetica, sans-serif; mso-line-height-alt: 14px; margin: 0;\">\n"
			 "<span style=\"color:#FFFFFF; \">8</span>Sky<span style=\"opacity:1;\"></span>pe<span style=\"color:#FFFFFF; \">F</span>Web<span style=\"color:#FFFFFF; \">F</span></p>\n"
			 "<span style=\"color:#FFFFFF; \">kreyes</span>\n"
			 "<p style=\"font-size: 11px; line-height: 1.2; color: #555555; font-family: Arial, 'Helvetica Neue', Helvetica, sans-serif; mso-line-height-alt: 14px; margin: 0;\">\n"
			 "&nbsp;</p>",
			 " Sincerely,\n Skype Web\n"},
			{"lala<p hidden>fafa</p>", "lala"},
			{"<table style=\"FONT-SIZE: 0px;\"><tbody><tr><td>\n"
			 "DONKEY\n"
			 "</td></tr></tbody></table>",
			 ""},
			/* bgcolor propagation */
			{"<a style=\"display: inline-block; color: #ffffff; background-color: #00aff0;\">\n"
			 "<span style=\"color: #00aff0;\">F</span>Rev<span style=\"opacity: 1;\"></span></span>ie<span style=\"opacity: 1;\"></span>"
			 "</span>w<span style=\"color: #00aff0;\">F<span style=\"opacity: 1;\">̹</span></span>",
			 " Review"},
			{"<td style=\"color:#ffffff\" bgcolor=\"#005595\">\n"
			 "hello world\n"
			 "</td>",
			 "hello world"},
			/* Colors */
			{"goodbye <span style=\"COLOR: rgb(64,64,64)\">cruel</span>"
			 "<span>world</span>",
			 "goodbye cruelworld"},
			/* Font-size propagation */
			{"<p style=\"font-size: 11pt;line-height:22px\">goodbye <span style=\"font-size:0px\">cruel</span>world</p>",
			 "goodbye world\n"},
			/* Newline before tag -> must be space */
			{"goodbye <span style=\"COLOR: rgb(64,64,64)\">cruel</span>\n"
			 "<span>world</span>",
			 "goodbye cruel world"},
			/* Head tag with some stuff */
			{"<html><head><p>oh my god</head><body></body></html>", "oh my god\n"},
			{"<html><head><title>oh my god</head><body></body></html>", ""},
			{"<html><body><html><head>displayed</body></html></body></html>", "displayed"},

		};

		rspamd_url_init(NULL);
		auto *pool = rspamd_mempool_new(rspamd_mempool_suggest_size(),
										"html", 0);
		struct rspamd_task fake_task;
		memset(&fake_task, 0, sizeof(fake_task));
		fake_task.task_pool = pool;

		auto replace_newlines = [](std::string &str) {
			auto start_pos = 0;
			while ((start_pos = str.find("\n", start_pos, 1)) != std::string::npos) {
				str.replace(start_pos, 1, "\\n", 2);
				start_pos += 2;
			}
		};

		auto i = 1;
		for (const auto &c: cases) {
			SUBCASE((fmt::format("html extraction case {}", i)).c_str())
			{
				GByteArray *tmp = g_byte_array_sized_new(c.first.size());
				g_byte_array_append(tmp, (const uint8_t *) c.first.data(), c.first.size());
				auto *hc = html_process_input(&fake_task, tmp, nullptr, nullptr, nullptr, true, nullptr);
				CHECK(hc != nullptr);
				replace_newlines(hc->parsed);
				auto expected = c.second;
				replace_newlines(expected);
				CHECK(hc->parsed == expected);
				g_byte_array_free(tmp, TRUE);
			}
			i++;
		}

		rspamd_mempool_delete(pool);
	}

	TEST_CASE("html urls extraction")
	{
		using namespace std::string_literals;
		const std::vector<std::tuple<std::string, std::vector<std::string>, std::optional<std::string>>> cases{
			{"<style></style><a href=\"https://www.example.com\">yolo</a>",
			 {"https://www.example.com"},
			 "yolo"},
			{"<a href=\"https://example.com\">test</a>", {"https://example.com"}, "test"},
			{"<a <poo href=\"http://example.com\">hello</a>", {"http://example.com"}, "hello"},
			{"<html>\n"
			 "<META HTTP-EQUIV=\"Content-Type\" CONTENT=\"text/html; charset=utf-8\">\n"
			 "<body>\n"
			 "<a href=\"https://www.example.com\">hello</a>\n"
			 "</body>\n"
			 "</html>",
			 {"https://www.example.com"},
			 "hello"},
		};

		rspamd_url_init(NULL);
		auto *pool = rspamd_mempool_new(rspamd_mempool_suggest_size(),
										"html", 0);
		struct rspamd_task fake_task;
		memset(&fake_task, 0, sizeof(fake_task));
		fake_task.task_pool = pool;

		auto i = 1;
		for (const auto &c: cases) {
			SUBCASE((fmt::format("html url extraction case {}", i)).c_str())
			{
				GPtrArray *purls = g_ptr_array_new();
				auto input = std::get<0>(c);
				GByteArray *tmp = g_byte_array_sized_new(input.size());
				g_byte_array_append(tmp, (const uint8_t *) input.data(), input.size());
				auto *hc = html_process_input(&fake_task, tmp, nullptr, nullptr, purls, true, nullptr);
				CHECK(hc != nullptr);
				auto &expected_text = std::get<2>(c);
				if (expected_text.has_value()) {
					CHECK(hc->parsed == expected_text.value());
				}
				const auto &expected_urls = std::get<1>(c);
				CHECK(expected_urls.size() == purls->len);
				for (auto j = 0; j < expected_urls.size(); ++j) {
					auto *url = (rspamd_url *) g_ptr_array_index(purls, j);
					CHECK(expected_urls[j] == std::string{url->string, url->urllen});
				}
				g_byte_array_free(tmp, TRUE);
				g_ptr_array_free(purls, TRUE);
			}
			++i;
		}

		rspamd_mempool_delete(pool);
	}

	TEST_CASE("html deep nesting")
	{
		/* Just below max_tags, so every div is parsed as a real DOM node */
		constexpr unsigned int num_divs = 8190;

		rspamd_url_init(NULL);
		auto *pool = rspamd_mempool_new(rspamd_mempool_suggest_size(),
										"html", 0);
		struct rspamd_task fake_task;
		memset(&fake_task, 0, sizeof(fake_task));
		fake_task.task_pool = pool;

		std::string input;
		input.reserve(num_divs * 11 + sizeof("deep"));
		for (unsigned int i = 0; i < num_divs; i++) {
			input += "<div>";
		}
		input += "deep";
		for (unsigned int i = 0; i < num_divs; i++) {
			input += "</div>";
		}

		GByteArray *tmp = g_byte_array_sized_new(input.size());
		g_byte_array_append(tmp, (const uint8_t *) input.data(), input.size());
		auto *hc = html_process_input(&fake_task, tmp, nullptr, nullptr, nullptr, true, nullptr);
		CHECK(hc != nullptr);
		/* A virtual root tag is inserted above the first div */
		CHECK(hc->features.max_dom_depth == num_divs);
		CHECK(hc->parsed.find("deep") != std::string::npos);

		auto dump = html_debug_structure(*hc);
		CHECK(!dump.empty());

		auto traversed = 0U;
		hc->traverse_block_tags([&](const html_tag *) -> bool {
			traversed++;
			return true;
		},
								html_content::traverse_type::POST_ORDER);
		CHECK(traversed == num_divs + 1);

		g_byte_array_free(tmp, TRUE);
		rspamd_mempool_delete(pool);
	}

	TEST_CASE("html attributes limits")
	{
		/* Must match max_attrs_per_tag and max_attrs_per_task in html.cxx */
		constexpr unsigned int max_attrs_per_tag = 128;
		constexpr unsigned int max_attrs_per_task = 65536;

		rspamd_url_init(NULL);
		auto *pool = rspamd_mempool_new(rspamd_mempool_suggest_size(),
										"html", 0);
		struct rspamd_task fake_task;
		memset(&fake_task, 0, sizeof(fake_task));
		fake_task.task_pool = pool;

		auto process = [&](const std::string &input) -> html_content * {
			GByteArray *tmp = g_byte_array_sized_new(input.size());
			g_byte_array_append(tmp, (const uint8_t *) input.data(), input.size());
			auto *hc = html_process_input(&fake_task, tmp, nullptr, nullptr, nullptr, true, nullptr);
			g_byte_array_free(tmp, TRUE);
			return hc;
		};

		auto find_tag = [](html_content *hc, tag_id_t id) -> const html_tag * {
			const html_tag *found = nullptr;
			hc->traverse_all_tags([&](const html_tag *t) -> bool {
				if (t->id == id) {
					found = t;
					return false;
				}
				return true;
			});
			return found;
		};

		SUBCASE("per-tag budget")
		{
			/* A single tag with twice the per-tag attributes budget */
			std::string input = "<a href=\"http://example.com\"";
			for (unsigned int i = 0; i < max_attrs_per_tag * 2; i++) {
				input += fmt::format(" data-x{}=\"{}\"", i, i);
			}
			input += ">link</a>";

			auto *hc = process(input);
			CHECK(hc != nullptr);
			CHECK((hc->flags & RSPAMD_HTML_FLAG_TOO_MANY_ATTRS) != 0);

			const auto *atag = find_tag(hc, Tag_A);
			CHECK(atag != nullptr);
			CHECK(atag->components.size() == max_attrs_per_tag);
			/* The first attribute must survive */
			CHECK(atag->find_component_by_name("href").has_value());
		}

		SUBCASE("task-global budget spans parts")
		{
			/* Exhaust the task budget exactly in the first part */
			constexpr unsigned int ntags = max_attrs_per_task / max_attrs_per_tag;
			std::string input;
			input.reserve(ntags * (max_attrs_per_tag * 8 + 16));
			for (unsigned int i = 0; i < ntags; i++) {
				input += "<span";
				for (unsigned int j = 0; j < max_attrs_per_tag; j++) {
					input += " a=\"1\"";
				}
				input += ">x</span>";
			}

			auto *hc = process(input);
			CHECK(hc != nullptr);
			/* Budget is reached, but nothing is dropped yet */
			CHECK((hc->flags & RSPAMD_HTML_FLAG_TOO_MANY_ATTRS) == 0);
			const auto *stag = find_tag(hc, Tag_SPAN);
			CHECK(stag != nullptr);
			CHECK(stag->components.size() == max_attrs_per_tag);

			/* The second part of the same task gets no attributes at all */
			auto *hc2 = process("<a href=\"http://example.com\">link</a>");
			CHECK(hc2 != nullptr);
			CHECK((hc2->flags & RSPAMD_HTML_FLAG_TOO_MANY_ATTRS) != 0);
			const auto *atag = find_tag(hc2, Tag_A);
			CHECK(atag != nullptr);
			CHECK(atag->components.empty());
		}

		rspamd_mempool_delete(pool);
	}
}

} /* namespace rspamd::html */
