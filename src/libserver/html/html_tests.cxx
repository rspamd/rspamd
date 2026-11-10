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
#include "html_entities.hxx"
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
			/* A start tag of p ends the open p */
			{"<p><p><a></p></a></a>", "+p;+p;++a;"},
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
			/*
			 * NB: schemeless hrefs cannot be tested here - rspamd_url_init(NULL)
			 * leaves the TLD list empty, and html_process_url() drops every url
			 * that has both no scheme and no TLD. See the "schemeless href"
			 * cases in test/lua/unit/get_html_urls.lua instead.
			 */
			{"<a href=\"http://user@host.com/\">userinfo</a>",
			 {"http://user@host.com/"},
			 "userinfo"},
			{"<a href=\"mailto:x@y.com\">explicit</a>",
			 {"mailto:x@y.com"},
			 "explicit"},
			/* The action of a link is not where it goes */
			{"<a action=\"https://good.example.org/\" href=\"https://evil.example.net/\">click</a>",
			 {"https://evil.example.net/"},
			 "click"},
			/* A submit button goes where its formaction says */
			{"<form action=\"https://good.example.org/f\"><button formaction=\"https://evil.example.net/f\">Go</button></form>",
			 {"https://good.example.org/f", "https://evil.example.net/f"},
			 std::nullopt},
			/* An SVG link without href */
			{"<svg><a xlink:href=\"https://evil.example.net/x\"><text>x</text></a></svg>",
			 {"https://evil.example.net/x"},
			 std::nullopt},
			/* Browsers take xlink:href on SVG links only */
			{"<a xlink:href=\"https://evil.example.net/x\">x</a>", {}, "x"},
			/* Controls that do not submit the form go nowhere */
			{"<form action=\"https://good.example.org/f\">"
			 "<button type=\"Button\" formaction=\"https://evil.example.net/b\">b</button>"
			 "<button type=reset formaction=\"https://evil.example.net/r\">r</button>"
			 "<input type=text formaction=\"https://evil.example.net/t\">"
			 "<input formaction=\"https://evil.example.net/n\"></form>",
			 {"https://good.example.org/f"},
			 std::nullopt},
			{"<input type=\"IMAGE\" formaction=\"https://evil.example.net/i\">"
			 "<input formaction=\"https://evil.example.net/s\" type=submit>",
			 {"https://evil.example.net/i", "https://evil.example.net/s"},
			 std::nullopt},
			/* In svg and math they are no form controls, unless in an HTML island */
			{"<form action=\"https://good.example.org/f\">"
			 "<svg><button formaction=\"https://evil.example.net/svg\">b</button></svg>"
			 "<math><input type=submit formaction=\"https://evil.example.net/math\"></math>"
			 "<svg><foreignObject><button formaction=\"https://evil.example.net/fo\">c</button>"
			 "</foreignObject></svg></form>",
			 {"https://good.example.org/f", "https://evil.example.net/fo"},
			 std::nullopt},
			/*
			 * A quote in an unquoted value: browsers read on, rspamd up to it,
			 * unless an `@` in the authority sends browsers to another host
			 */
			{"<a href=https://good.example.org/a\"b>x</a>"
			 "<a href=3D\"https://good.example.org/qp\">y</a>",
			 {"https://good.example.org/a"},
			 std::nullopt},
			{"<a href=https://www.paypal.com\"@evil.example.net/x>x</a>",
			 {"https://www.paypal.com\"@evil.example.net/x"},
			 std::nullopt},
			{"<a href=https://www.paypal.com\"&#64;evil.example.net/x>x</a>",
			 {"https://www.paypal.com\"@evil.example.net/x"},
			 std::nullopt},
			/* Character references are decoded before the authority is looked at */
			{"<a href=https://www.paypal&#46;com\"@evil.example.net/x>x</a>"
			 "<a href=https&#58;//www.paypal.com\"@evil.example.net/y>y</a>",
			 {"https://www.paypal.com\"@evil.example.net/x", "https://www.paypal.com\"@evil.example.net/y"},
			 std::nullopt},
			/* URL parsers drop tabs and line breaks in a link */
			{"<a href=ht&#9;tps://www.paypal.com\"@evil.example.net/t>x</a>",
			 {"https://www.paypal.com\"@evil.example.net/t"},
			 std::nullopt},
			/* Media go where their src says */
			{"<video href=\"https://good.example.org/v\" src=\"https://evil.example.net/v.mp4\"></video>"
			 "<audio src=\"https://evil.example.net/a.mp3\"></audio>",
			 {"https://evil.example.net/v.mp4", "https://evil.example.net/a.mp3"},
			 std::nullopt},
			/* Frames and embedded objects go where their src says */
			{"<iframe href=\"https://good.example.org/\" src=\"https://evil.example.net/f\"></iframe>"
			 "<embed src=\"https://evil.example.net/e\">",
			 {"https://evil.example.net/f", "https://evil.example.net/e"},
			 std::nullopt},
			/* Browsers strip C0 controls around a link, also before a base applies */
			{"<a href=\"\x01https://evil.example.net/c\x1f\">x</a>",
			 {"https://evil.example.net/c"},
			 std::nullopt},
			{"<base href=\"https://base.example.org/\"><a href=\" \x01https://evil.example.net/b\">x</a>",
			 {"https://evil.example.net/b"},
			 std::nullopt},
			/* Links resolved against a base as browsers do */
			{"<base href=\"https://www.paypal.com/a/\">"
			 "<a href=\"//evil.example.net/x\">1</a>"
			 "<a href=\"\\\\evil.example.net/y\">2</a>"
			 "<a href=\"http:evil.example.net/z\">3</a>"
			 "<a href=\"/p\">4</a>"
			 "<a href=\"rel\">5</a>",
			 {"https://evil.example.net/x", "https://evil.example.net/y", "http://evil.example.net/z",
			  "https://www.paypal.com/p", "https://www.paypal.com/a/rel"},
			 std::nullopt},
			/* One slash or backslash after a special scheme is read as two by browsers */
			{"<a href=\"http:/evil.example.net/a\">1</a>"
			 "<a href=\"HTTPS:\\evil.example.net/b\">2</a>"
			 "<base href=\"https://www.paypal.com/a/\">"
			 "<a href=\"http:/&#9;evil.example.net/c\">3</a>",
			 {"http://evil.example.net/a", "https://evil.example.net/b", "http://evil.example.net/c"},
			 std::nullopt},
			/* Browsers remove tabs and line breaks before they resolve a link */
			{"<base href=\"https://www.paypal.com/a/\">"
			 "<a href=\"/&#9;/evil.example.net/x\">1</a>"
			 "<a href=\"ht&#10;tps://evil.example.net/y\">2</a>"
			 "<a href=\"https:/\r/evil.example.net/z\">3</a>",
			 {"https://evil.example.net/x", "https://evil.example.net/y", "https://evil.example.net/z"},
			 std::nullopt},
			/* A tag the input ends in */
			{"<form action=\"https://good.example.org/f\"><button formaction=\"https://evil.example.net/e\">",
			 {"https://good.example.org/f", "https://evil.example.net/e"},
			 std::nullopt},
			{"<form action=\"https://good.example.org/f\"><button formaction=\"https://evil.example.net/p\"",
			 {"https://good.example.org/f", "https://evil.example.net/p"},
			 std::nullopt},
			{"<svg><a xlink:href=\"https://evil.example.net/s\">",
			 {"https://evil.example.net/s"},
			 std::nullopt},
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
				/* Join so that doctest prints both sides on a mismatch */
				auto join = [](const std::vector<std::string> &v) -> std::string {
					std::string res;
					for (const auto &e: v) {
						if (!res.empty()) {
							res += " | ";
						}
						res += e;
					}
					return res;
				};
				std::vector<std::string> actual_urls;
				actual_urls.reserve(purls->len);
				for (auto j = 0u; j < purls->len; ++j) {
					auto *url = (rspamd_url *) g_ptr_array_index(purls, j);
					actual_urls.emplace_back(url->string, url->urllen);
				}
				CHECK(join(expected_urls) == join(actual_urls));
				g_byte_array_free(tmp, TRUE);
				g_ptr_array_free(purls, TRUE);
			}
			++i;
		}

		rspamd_mempool_delete(pool);
	}

	TEST_CASE("html parsing as in browsers")
	{
		/*
		 * Declarations, comments, raw text and elements must end where
		 * browsers end them, or what follows is hidden from the scan or
		 * taken as visible when it is not (#6321)
		 */
		struct decl_case {
			std::string input;
			std::vector<std::string> urls;
			std::string text;
			bool cdata_in_html;
		};
		const std::vector<decl_case> cases{
			/* CDATA outside SVG/MathML is a bogus comment up to the first `>` */
			{"<![CDATA[<html><body><p>Hello</p><a href=\"https://user@spam.example.com/x\">click</a></body></html>",
			 {"https://user@spam.example.com/x"},
			 "Hello\nclick",
			 true},
			/* `]]>` split by hidden tags, as seen in the wild */
			{"<![CDATA[<html><body><a href=\"http://example.com/\">click</a>]<u style=\"font-size:.0px\">x</u>]<u style=\"font-size:.0px\">y</u>></body></html>",
			 {"http://example.com/"},
			 "click]]>",
			 true},
			/* The first `>` ends it, even inside a tag */
			{"<![CDATA[<a href=\"http://example.com/\">click</a>", {}, "click", true},
			{"<![x[><a href=\"http://example.com/\">click</a>", {"http://example.com/"}, "click", false},
			{"<![CDATA[x]]><a href=\"http://example.com/\">click</a>", {"http://example.com/"}, "click", true},
			/* Outlook downlevel-revealed conditional comments */
			{"<html><body><![if !mso]><p>Hello</p><![endif]><a href=\"http://example.com/\">click</a></body></html>",
			 {"http://example.com/"},
			 "Hello\nclick",
			 false},
			/* CDATA in SVG/MathML is legit text up to `]]>`, markup included */
			{"<svg><![CDATA[a]]></svg><a href=\"http://example.com/\">click</a>", {"http://example.com/"}, "aclick", false},
			{"<math><![CDATA[a]]></math><a href=\"http://example.com/\">click</a>", {"http://example.com/"}, "aclick", false},
			{"<svg><![CDATA[x><p><style>]]></svg><a href=\"http://example.com/\">click</a>",
			 {"http://example.com/"},
			 "x><p><style>click",
			 false},
			{"<svg><text><![CDATA[a]]]>b</text></svg>", {}, "a]b", false},
			/* Character references are text in CDATA and raw text, title and textarea decode them */
			{"<svg><![CDATA[a&amp;b]]>&amp;c</svg>", {}, "a&amp;b&c", false},
			{"<svg><![CDATA[a&amp;b", {}, "a&amp;b", false},
			{"<xmp>a&amp;b</xmp>&amp;c", {}, "a&amp;b\n&c", false},
			{"<plaintext>a&amp;b", {}, "a&amp;b\n", false},
			{"<textarea>a&amp;b</textarea>", {}, "a&b", false},
			{"<svg><![CDATA[<a href=\"http://example.com/\">x", {}, "<a href=\"http://example.com/\">x", false},
			{"<svg></svg><![CDATA[a]]><a href=\"http://example.com/\">click</a>", {"http://example.com/"}, "click", true},
			/* Comments */
			{"<!-- x --!><a href=\"http://example.com/\">click</a>", {"http://example.com/"}, "click", false},
			{"<!-- x --><a href=\"http://example.com/\">click</a>", {"http://example.com/"}, "click", false},
			{"<!-- x -- y --><a href=\"http://example.com/\">click</a>", {"http://example.com/"}, "click", false},
			{"<!-->click", {}, "click", false},
			{"<!--->click", {}, "click", false},
			{"<!-x>click", {}, "click", false},
			{"<?>click", {}, "click", false},
			/* Input ending inside markup keeps the text before it */
			{"click<!--", {}, "click", false},
			{"click<!-", {}, "click", false},
			{"click<!-- x", {}, "click", false},
			{"<p>a</p>b<!-- c", {}, "a\nb", false},
			{"<div>a<span>b</span>c</b", {}, "abc\n", false},
			{"<div>a<span>b</span>c</", {}, "abc\n", false},
			{"click<!DOCTYPE", {}, "click", false},
			{"click<?xml", {}, "click", false},
			{"click<a href=\"http://example.com/", {}, "click", false},
			/* End tags without a name */
			{"</ x><a href=\"http://example.com/\">click</a>", {"http://example.com/"}, "click", false},
			{"</>click", {}, "click", false},
			{"<p>a</ <b>b</p>", {}, "ab\n", false},
			/* Raw text ends at its own end tag, whatever follows the name */
			{"<style>a{}</style\t><a href=\"http://example.com/\">click</a>", {"http://example.com/"}, "click", false},
			{"<style>a{}</STYLE data-x=\"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\"><a href=\"http://example.com/\">click</a>",
			 {"http://example.com/"},
			 "click",
			 false},
			{"<style></b><a href=\"http://example.com/\">x</a></style>click", {}, "click", false},
			{"<style>a{}</stylex></style>click", {}, "click", false},
			/* Comments inside RCDATA/RAWTEXT are text */
			{"<textarea><!--</textarea><a href=\"http://example.com/\">click</a>-->",
			 {"http://example.com/"},
			 "<!--click-->",
			 false},
			{"<title><!--</title><a href=\"http://example.com/\">click</a>", {"http://example.com/"}, "click", false},
			{"<xmp><!--</xmp><a href=\"http://example.com/\">click</a>", {"http://example.com/"}, "<!--\nclick", false},
			{"<iframe><![CDATA[</iframe><a href=\"http://example.com/\">click</a>",
			 {"http://example.com/"},
			 "<![CDATA[click",
			 false},
			{"<plaintext><a href=\"http://example.com/\">click</a>", {}, "<a href=\"http://example.com/\">click</a>\n", false},
			/* Mail clients run no scripts, so noscript content is markup */
			{"<noscript><a href=\"http://example.com/\">click</a></noscript>", {"http://example.com/"}, "click\n", false},
			/* `/>` is ignored on HTML elements other than the void ones */
			{"<span style=\"display:none\"/>poison</span>visible", {}, "visible", false},
			{"<div style=\"display:none\" />poison", {}, "", false},
			{"<a href=\"http://example.com/\"/>click", {"http://example.com/"}, "click", false},
			{"a<br/>b<img alt=\"c\"/>", {}, "a\nb c", false},
			/* ...and stays in an unquoted value */
			{"<img alt=c/>", {}, "c/", false},
			{"<object data=\"x\"/>fallback", {}, "fallback", false},
			/* ...but not on SVG/MathML elements */
			{"<svg/><textarea><!--</textarea><a href=\"http://example.com/\">click</a>-->",
			 {"http://example.com/"},
			 "<!--click-->",
			 false},
			{"<svg><rect style=\"display:none\"/>text</svg>", {}, "text", false},
			/* Only `/` right before `>` closes */
			{"<svg/x><style></svg><a href=\"http://example.com/\">click</a>", {"http://example.com/"}, "click", false},
			{"<svg/ ><style></svg><a href=\"http://example.com/\">click</a>", {"http://example.com/"}, "click", false},
			{"<svg width=10/><style></svg><a href=\"http://example.com/\">click</a>", {"http://example.com/"}, "click", false},
			{"<a href=http://example.com/>click</a>", {"http://example.com/"}, "click", false},
			{"<a href=\"http://example.com/\"/title=x>click</a>", {"http://example.com/"}, "click", false},
			/* SVG elements named like raw text ones hold markup */
			{"<svg><title></svg><a href=\"http://example.com/\">click</a>", {"http://example.com/"}, "click", false},
			{"<svg><style/></svg><a href=\"http://example.com/\">click</a>", {"http://example.com/"}, "click", false},
			{"<svg><textarea><!--</textarea>--></svg><a href=\"http://example.com/\">click</a>",
			 {"http://example.com/"},
			 "click",
			 false},
			/* HTML-only tags and `</p>` leave SVG, raw text is back after them */
			{"<svg><p><textarea><!--</textarea><a href=\"http://example.com/\">click</a>-->",
			 {"http://example.com/"},
			 "<!--click-->\n",
			 false},
			{"<svg></p><textarea><!--</textarea><a href=\"http://example.com/\">click</a>-->",
			 {"http://example.com/"},
			 "<!--click-->",
			 false},
			{"<svg><font color=\"red\"><textarea><!--</textarea><a href=\"http://example.com/\">click</a>-->",
			 {"http://example.com/"},
			 "<!--click-->",
			 false},
			{"<svg><font><textarea><!--</textarea><a href=\"http://example.com/\">click</a>--></svg>", {}, "", false},
			/* Integration points hold HTML again */
			{"<svg><foreignObject><textarea><!--</textarea><a href=\"http://example.com/\">click</a>-->",
			 {"http://example.com/"},
			 "<!--click-->",
			 false},
			{"<math><mi><textarea><!--</textarea><a href=\"http://example.com/\">click</a>-->",
			 {"http://example.com/"},
			 "<!--click-->",
			 false},
			/* desc is one in SVG only */
			{"<math><desc><textarea><!--</textarea><a href=\"http://example.com/\">click</a>--></math>", {}, "", false},
			/* CDATA is legit in SVG/MathML elements, integration points included */
			{"<svg><foreignObject><![CDATA[a]]></svg>", {}, "a", false},
			{"<svg><p><![CDATA[a]]>", {}, "", true},
		};

		rspamd_url_init(NULL);
		auto *pool = rspamd_mempool_new(rspamd_mempool_suggest_size(),
										"html", 0);
		struct rspamd_task fake_task;
		memset(&fake_task, 0, sizeof(fake_task));
		fake_task.task_pool = pool;

		for (const auto &c: cases) {
			SUBCASE(c.input.c_str())
			{
				GPtrArray *purls = g_ptr_array_new();
				GByteArray *tmp = g_byte_array_sized_new(c.input.size());
				g_byte_array_append(tmp, (const uint8_t *) c.input.data(), c.input.size());
				auto *hc = html_process_input(&fake_task, tmp, nullptr, nullptr, purls, true, nullptr);
				CHECK(hc != nullptr);
				CHECK(hc->parsed == c.text);
				std::string expected_urls, actual_urls;
				for (const auto &u: c.urls) {
					expected_urls += u + " ";
				}
				for (auto j = 0u; j < purls->len; ++j) {
					auto *url = (rspamd_url *) g_ptr_array_index(purls, j);
					actual_urls += std::string{url->string, url->urllen} + " ";
				}
				CHECK(expected_urls == actual_urls);
				CHECK(((hc->flags & RSPAMD_HTML_FLAG_CDATA_IN_HTML) != 0) == c.cdata_in_html);
				g_byte_array_free(tmp, TRUE);
				g_ptr_array_free(purls, TRUE);
			}
		}

		rspamd_mempool_delete(pool);
	}

	TEST_CASE("html tree building as in browsers")
	{
		/* The structure: elements that browsers end implicitly */
		const std::vector<std::pair<std::string, std::string>> tree_cases{
			{"<p>a<p>b", "+p;+p;"},
			{"<p>a<div>b</div>", "+p;+div;"},
			{"<p>a<span>b<ul><li>c", "+p;++span;+ul;++li;"},
			{"<div><p>a</div><p>b", "+div;++p;+p;"},
			/* A boundary stops the search for the open p */
			{"<p>a<button><div>b", "+p;++button;+++div;"},
			{"<p>a<marquee><p>b", "+p;++unknown;+++p;"},
			{"<p>a<object><div>b", "+p;++object;+++div;"},
			{"<table><tr><td><p>a<td><p>b",
			 "+table;++tr;+++td;++++p;+++td;++++p;"},
			{"<div><p>a<table><tr><td><div>b", "+div;++p;++table;+++tr;++++td;+++++div;"},
			{"<h1>a<h2>b", "+h1;+h2;"},
			{"<h1>a<b><h2>b", "+h1;++b;+++h2;"},
			{"<p>a<h3>b", "+p;+h3;"},
			{"<ul><li>a<li>b", "+ul;++li;++li;"},
			{"<li><ul><li>a", "+li;++ul;+++li;"},
			{"<li>a<span>b<li>c", "+li;++span;+li;"},
			{"<li>a<div>b<li>c", "+li;++div;+li;"},
			{"<li>a<section>b<li>c", "+li;++section;+++li;"},
			{"<li><p>a<li>b", "+li;++p;+li;"},
			{"<dl><dt>a<dd>b<dt>c", "+dl;++dt;++dd;++dt;"},
			{"<dl><dd>a<span>b<dd>c", "+dl;++dd;+++span;++dd;"},
			{"<select><option>a<option>b", "+select;++option;++option;"},
			{"<select><optgroup><option>a<optgroup><option>b",
			 "+select;++optgroup;+++option;++optgroup;+++option;"},
			{"<table><tr><td>a<td>b<tr><td>c",
			 "+table;++tr;+++td;+++td;++tr;+++td;"},
			{"<table><tr><th>a<td>b", "+table;++tr;+++th;+++td;"},
			{"<table><tbody><tr><td>a<tbody><tr><td>b",
			 "+table;++tbody;+++tr;++++td;++tbody;+++tr;++++td;"},
			{"<table><caption>a<tr><td>b", "+table;++caption;++tr;+++td;"},
			{"<table><tr><td><table><tr><td>a<td>b",
			 "+table;++tr;+++td;++++table;+++++tr;++++++td;++++++td;"},
			{"<a href=x>a<a href=y>b", "+a;+a;"},
			{"<a href=x>a<b>b<a href=y>c", "+a;++b;+a;"},
			{"<a href=x>a<object><a href=y>b", "+a;++object;+++a;"},
			/* Names are not decoded: this is an unknown element */
			{"<scr&#105;pt><p>a", "+unknown;++p;"},
		};

		rspamd_url_init(NULL);
		auto *pool = rspamd_mempool_new(rspamd_mempool_suggest_size(),
										"html", 0);
		struct rspamd_task fake_task;
		memset(&fake_task, 0, sizeof(fake_task));
		fake_task.task_pool = pool;

		for (const auto &c: tree_cases) {
			SUBCASE((std::string("tree of: ") + c.first).c_str())
			{
				GByteArray *tmp = g_byte_array_sized_new(c.first.size());
				g_byte_array_append(tmp, (const uint8_t *) c.first.data(), c.first.size());
				auto *hc = html_process_input(&fake_task, tmp, nullptr, nullptr, nullptr, true, nullptr);
				CHECK(hc != nullptr);
				CHECK(html_debug_structure(*hc) == c.second);
				g_byte_array_free(tmp, TRUE);
			}
		}

		/* The text that is shown, as a browser renders it */
		const std::vector<std::pair<std::string, std::string>> text_cases{
			/* Text after the last tag goes to the body */
			{"<html><body><p>one</p></body></html>TAIL", "one\nTAIL"},
			{"<html><body><p>one</p></body>TAIL</html>", "one\nTAIL"},
			{"<html><body><p>one</p></body></html>\nTAIL\n", "one\nTAIL"},
			{"<style></style><p>one</p>TAIL", "one\nTAIL"},
			{"<meta charset=\"utf-8\"><div>one</div>TAIL", "one\nTAIL"},
			{"<html><meta charset=\"utf-8\"><div>one</div>TAIL", "one\nTAIL"},
			{"<html><head><style></style></head><body><div>one</div></body></html>TAIL", "one\nTAIL"},
			{"<body style=\"display:none\">HID</body>TAIL", ""},
			{"<div>one</div></html>TAIL<p>two</p>", "one\nTAIL\ntwo\n"},
			/* An open element is not ended by the end tag of the body */
			{"<body><div style=\"display:none\">HID</body>TAIL", ""},
			/* Text in the head */
			{"<html><head>HEADTXT</head><body>body</body></html>", "HEADTXTbody"},
			{"<html><head>  <title>T</title> HEADTXT</head>", "HEADTXT"},
			{"<html><head><!-- c -->HEADTXT", "HEADTXT"},
			{"<html><head><title>T</title></head><body>body</body></html>", "body"},
			{"<html><head> \n <title>T</title>\n</head>\n<body>body</body></html>", "body"},
			{"<html><head><script>SCR</script><style>STY</style></head><body>body</body></html>", "body"},
			/* Implied end tags */
			{"<p style=\"display:none\">HID<p>SHOWN", "SHOWN\n"},
			{"<p style=\"display:none\">HID<div>SHOWN</div>", "SHOWN\n"},
			{"<p style=\"display:none\"><span>HID</span><h2>SHOWN</h2>", "SHOWN\n"},
			{"<p style=\"display:none\">HID<ul><li>SHOWN</ul>", "SHOWN\n"},
			{"<p style=\"display:none\">HID<table><tr><td>SHOWN", "SHOWN\n"},
			{"<ul><li style=\"display:none\">HID<li>SHOWN", "SHOWN\n"},
			{"<dl><dt style=\"display:none\">HID<dd>SHOWN", "SHOWN\n"},
			{"<h1 style=\"display:none\">HID<h2>SHOWN", "SHOWN\n"},
			{"<select><option style=\"display:none\">HID<option>SHOWN</select>", "SHOWN"},
			{"<table><tr><td style=\"display:none\">HID<td>SHOWN", "SHOWN\n"},
			{"<table><tr style=\"display:none\"><td>HID<tr><td>SHOWN", "SHOWN\n"},
			{"<table><tbody style=\"display:none\"><tr><td>HID<tbody><tr><td>SHOWN", "SHOWN\n"},
			/* And what stays nested keeps its style */
			{"<div style=\"display:none\">HID<p>STILL HIDDEN</p></div>", ""},
			{"<p style=\"display:none\"><span>HID</span><b>HID2</b></p>", ""},
			{"<p style=\"display:none\">HID<button><div>HID2</div></button>", ""},
			{"<p style=\"display:none\">HID<marquee><p>HID2</marquee>", ""},
			{"<p style=\"display:none\">HID<span><a>HID2</a></span>", ""},
			{"<p style=\"display:none\">HID<table><tr><td><div>SHOWN?</div></td></tr></table>", "SHOWN?\n"},
			{"<table style=\"display:none\"><tr><td>HID<td>HID2<tr><td>HID3</table>", ""},
			{"<ul style=\"display:none\"><li>HID<ul><li>HID2<li>HID3</ul><li>HID4</ul>", ""},
			{"<li style=\"display:none\">HID<ul><li>HID2</ul>", ""},
			{"<span style=\"display:none\">HID<li>HID2</span>", ""},
			{"<select style=\"display:none\"><option>HID<option>HID2</select>", ""},
			/* An end tag of a p that was ended implicitly makes an empty one */
			{"<p>a<p>b</p></p>c", "a\nb\nc"},
			{"<span>a<p>b<p>c</span>d", "a\nb\nc\nd"},
			/* Links are not nested */
			{"<a href=\"http://a.example/\">one<a href=\"http://b.example/\">two</a></a>three", "onetwothree"},
			/* Tag names are not decoded */
			{"x<scr&#105;pt>INSIDE</scr&#105;pt>y", "xINSIDEy"},
			{"x<scr&#105;pt>INSIDE</script>y", "xINSIDEy"},
			{"x<script>INSIDE</script>y", "xy"},
			{"x<style>INSIDE</style>y", "xy"},
			{"x<sty&#108;e>INSIDE</sty&#108;e>y", "xINSIDEy"},
			{"<div style=\"display:none\">x<d&#105;v>HID</d&#105;v></div>y", "y"},
			{"x<title>T</title>y", "xy"},
		};

		for (const auto &c: text_cases) {
			SUBCASE((std::string("text of: ") + c.first).c_str())
			{
				GByteArray *tmp = g_byte_array_sized_new(c.first.size());
				g_byte_array_append(tmp, (const uint8_t *) c.first.data(), c.first.size());
				auto *hc = html_process_input(&fake_task, tmp, nullptr, nullptr, nullptr, true, nullptr);
				CHECK(hc != nullptr);
				CHECK(hc->parsed == c.second);
				g_byte_array_free(tmp, TRUE);
			}
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

	TEST_CASE("html tags limit and its relief")
	{
		rspamd_url_init(NULL);
		auto *pool = rspamd_mempool_new(rspamd_mempool_suggest_size(),
										"html", 0);
		struct rspamd_task fake_task;
		memset(&fake_task, 0, sizeof(fake_task));
		fake_task.task_pool = pool;

		auto repeat = [](const std::string &what, unsigned int n) -> std::string {
			std::string ret;
			ret.reserve(what.size() * n);
			for (unsigned int i = 0; i < n; i++) {
				ret += what;
			}
			return ret;
		};
		auto process = [&](const std::string &input) -> html_content * {
			GByteArray *tmp = g_byte_array_sized_new(input.size());
			g_byte_array_append(tmp, (const uint8_t *) input.data(), input.size());
			auto *hc = html_process_input(&fake_task, tmp, nullptr, nullptr, nullptr, true, nullptr);
			g_byte_array_free(tmp, TRUE);
			return hc;
		};
		auto count_tags = [](html_content *hc, tag_id_t id) -> unsigned int {
			unsigned int n = 0;
			hc->traverse_all_tags([&](const html_tag *t) -> bool {
				n += t->id == id;
				return true;
			});
			return n;
		};

		SUBCASE("comments are kept up to their budget and do not use up the elements")
		{
			auto *hc = process("<html><body>" + repeat("<!-- c -->", 8192) + repeat("<b>x</b> ", 8000) +
							   "<p>SHOWN</p></body></html>");

			CHECK(hc != nullptr);
			CHECK(hc->special_tags == 8192);
			CHECK((hc->flags & RSPAMD_HTML_FLAG_TOO_MANY_TAGS) == 0);
			CHECK(count_tags(hc, Tag_P) == 1);
			CHECK(hc->parsed.find("SHOWN") != std::string::npos);
			CHECK(hc->parsed.find("<!--") == std::string::npos);
		}

		SUBCASE("a comment over the budget joins the one before it")
		{
			const std::string input = "<html><body>" + repeat("<!--a-->", 8192) + "<!--b--> \n<?pi?>\n<!DOCTYPE x>" +
									  "t<!--c--><p>SHOWN</p></body></html>";
			auto *hc = process(input);

			CHECK(hc != nullptr);
			/* The text ends the run: the last comment is read without tags */
			CHECK(hc->special_tags == 8192);
			CHECK((hc->flags & RSPAMD_HTML_FLAG_TOO_MANY_TAGS) != 0);
			CHECK(hc->parsed.find("SHOWN") != std::string::npos);
			CHECK(hc->parsed.find("<") == std::string::npos);
			CHECK(hc->parsed.find("a--") == std::string::npos);

			hc = process("<html><body>" + repeat("<!--a-->", 8192) + repeat("<!--b--> \n", 5000) +
						 "<p>SHOWN</p></body></html>");
			CHECK(hc != nullptr);
			CHECK(hc->special_tags == 8192);
			CHECK((hc->flags & RSPAMD_HTML_FLAG_TOO_MANY_TAGS) == 0);
			CHECK(count_tags(hc, Tag_P) == 1);
			CHECK(hc->parsed == "SHOWN\n");

			/* Not closed, as without the budget */
			hc = process("<html><body>" + repeat("<!--a-->", 8192) + "t<!--b-->u<!--unclosed <p>x");
			CHECK(hc != nullptr);
			CHECK(hc->parsed.find("unclosed") == std::string::npos);
			CHECK(hc->parsed.find("<") == std::string::npos);
		}

		SUBCASE("a run of empty elements is one element")
		{
			auto *hc = process("<html><body>a" + repeat("<b></b>", 9000) + "c<i></i><i></i><i>x</i><i></i>" +
							   "<p>SHOWN</p></body></html>");

			CHECK(hc != nullptr);
			CHECK((hc->flags & RSPAMD_HTML_FLAG_TOO_MANY_TAGS) == 0);
			CHECK(count_tags(hc, Tag_B) == 1);
			CHECK(count_tags(hc, Tag_I) == 3);
			CHECK(hc->all_tags.size() < 20);
			CHECK(hc->parsed == "acx\nSHOWN\n");

			/* The balance index and the tree hold no removed element */
			hc = process("<html><body><b></b><b></b><b></b>text</b></i><b></b><b></b></body></html>");
			CHECK(hc != nullptr);
			CHECK(hc->parsed == "text");
		}

		SUBCASE("elements that are not alike are not folded")
		{
			auto *hc = process("<html><body>" + repeat("<b></b> ", 20) + repeat("<b x=1></b>", 20) +
							   repeat("<b></b><i></i>", 20) + repeat("<div></div>", 20) +
							   repeat("<b><i></i></b>", 20) + "</body></html>");

			CHECK(hc != nullptr);
			CHECK(count_tags(hc, Tag_B) == 20 + 20 + 20 + 20);
			CHECK(count_tags(hc, Tag_DIV) == 20);
		}

		SUBCASE("text hidden by a style is hidden past the limit")
		{
			auto *hc = process("<html><body>" + repeat("<i>", 8200) +
							   "<div style=\"display:none\">HIDONE</div><span hidden>HIDTWO</span>"
							   "<div style=\"visibility:hidden\">HIDTHREE<b style=\"visibility:visible\">SHOWNTWO</b></div>"
							   "<p>SHOWN</p>");

			CHECK(hc != nullptr);
			CHECK((hc->flags & RSPAMD_HTML_FLAG_TOO_MANY_TAGS) != 0);
			CHECK(hc->parsed.find("HID") == std::string::npos);
			CHECK(hc->parsed.find("SHOWNTWO") != std::string::npos);
			CHECK(hc->parsed.find("SHOWN") != std::string::npos);
			CHECK(hc->invisible.find("HIDONE") != std::string::npos);
			CHECK(hc->invisible.find("HIDTWO") != std::string::npos);
			CHECK(hc->invisible.find("HIDTHREE") != std::string::npos);
			CHECK(hc->features.text_hidden > 0);
		}

		rspamd_mempool_delete(pool);
	}

	TEST_CASE("html entities decoding in place")
	{
		const std::vector<std::pair<std::string, std::string>> cases{
			{"a &amp; b", "a & b"},
			{"&#x41;&#65;&#o101;", "AAA"},
			/* Values past the last code point must not overflow */
			{"&#99999999999999999999;x", "\uFFFD"
										 "x"},
			{"&#xFFFFFFFFFFFFFFFF;x", "\uFFFD"
									  "x"},
			{"&#2147483648;x", "\uFFFD"
							   "x"},
			/*
			 * `&nGt;` expands to 6 bytes, more than the entity itself: it is
			 * left as is unless there is room from the earlier entities,
			 * and never overwrites the text that follows
			 */
			{"&nGt;tail", "&nGt;tail"},
			{"a &nGt; tail", "a &nGt; tail"},
			{"&amp;&amp;&nGt;tail", "&&\u226B\u20D2tail"},
			{"&acE;tail", "\u223E\u0333tail"},
			/* An unfinished entity at the end, once, after others made room */
			{"?a=&amp;x&#zz", "?a=&x&#zz"},
			{"?a=&amp;x&#", "?a=&x&#"},
			{"&amp;&amp;&amp;&\"c", "&&&&\"c"},
		};

		for (const auto &c: cases) {
			std::string s{c.first};
			decode_html_entitles_inplace(s);
			CHECK_MESSAGE(s == c.second, c.first);
		}
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
			/* The budget is for attributes rspamd does not interpret */
			CHECK(atag->components.size() == max_attrs_per_tag + 1);
			CHECK(atag->find_component_by_name("href").has_value());
		}

		SUBCASE("junk attributes do not push out the ones rspamd uses")
		{
			/* Browsers keep a link whatever comes before it */
			std::string input = "<a";
			for (unsigned int i = 0; i < max_attrs_per_tag * 2; i++) {
				input += fmt::format(" data-x{}=\"{}\"", i, i);
			}
			input += " href=\"http://evil.example.com/\" style=\"color:red\" face=\"x\">link</a>";

			auto *hc = process(input);
			CHECK(hc != nullptr);
			CHECK((hc->flags & RSPAMD_HTML_FLAG_TOO_MANY_ATTRS) != 0);

			const auto *atag = find_tag(hc, Tag_A);
			CHECK(atag != nullptr);
			CHECK(atag->components.size() == max_attrs_per_tag + 3);
			REQUIRE(atag->find_href().has_value());
			CHECK(atag->find_href().value() == "http://evil.example.com/");
			CHECK(atag->find_style().has_value());
			/* Read by name to leave foreign content, so kept as well */
			CHECK(atag->find_component_by_name("face").has_value());
		}

		SUBCASE("junk attributes do not push out an SVG link or a submit type")
		{
			std::string junk;
			for (unsigned int i = 0; i < max_attrs_per_tag * 2; i++) {
				junk += fmt::format(" data-x{}=\"{}\"", i, i);
			}
			std::string input = "<svg><a" + junk + " xlink:href=\"http://evil.example.com/a\">x</a></svg>";
			input += "<input formaction=\"http://evil.example.com/i\"" + junk + " type=submit>";
			auto *hc = process(input);
			CHECK(hc != nullptr);

			const auto *atag = find_tag(hc, Tag_A);
			REQUIRE(atag != nullptr);
			CHECK(atag->find_href().value_or("") == "http://evil.example.com/a");

			const auto *itag = find_tag(hc, Tag_INPUT);
			REQUIRE(itag != nullptr);
			CHECK((itag->flags & FL_HREF) != 0);
		}

		SUBCASE("a repeated attribute is ignored, the first one wins")
		{
			/* As in browsers; repeating one must not use up any budget either */
			std::string input = "<a href=\"http://first.example.com/\"";
			for (unsigned int i = 0; i < max_attrs_per_tag * 2; i++) {
				input += " href=\"http://other.example.com/\" style=\"x\"";
			}
			input += " title=\"t\">link</a>";

			auto *hc = process(input);
			CHECK(hc != nullptr);
			CHECK((hc->flags & RSPAMD_HTML_FLAG_TOO_MANY_ATTRS) == 0);

			const auto *atag = find_tag(hc, Tag_A);
			CHECK(atag != nullptr);
			CHECK(atag->components.size() == 3);
			REQUIRE(atag->find_href().has_value());
			CHECK(atag->find_href().value() == "http://first.example.com/");
			CHECK(atag->find_component_by_name("title").has_value());
		}

		SUBCASE("a tag goes where browsers go: href of a link, action of a form")
		{
			/* The attribute that is not the destination of the tag must not mask it */
			auto *hc = process("<a action=\"https://good.example.org/\" "
							   "href=\"https://evil.example.net/\">click</a>"
							   "<form href=\"https://good.example.org/\" "
							   "action=\"https://evil.example.net/form\"></form>");
			CHECK(hc != nullptr);

			const auto *atag = find_tag(hc, Tag_A);
			REQUIRE(atag != nullptr);
			REQUIRE(atag->find_href().has_value());
			CHECK(atag->find_href().value() == "https://evil.example.net/");

			const auto *ftag = find_tag(hc, Tag_FORM);
			REQUIRE(ftag != nullptr);
			REQUIRE(ftag->find_href().has_value());
			CHECK(ftag->find_href().value() == "https://evil.example.net/form");
		}

		SUBCASE("a character reference in an attribute name is not decoded")
		{
			/* As in browsers: hr&#101;f is another attribute, not a first href */
			auto *hc = process("<a hr&#101;f=\"https://good.example.org/g\" "
							   "href=\"https://evil.example.net/g\">x</a>"
							   "<form &#97;ction=\"https://good.example.org/k\" "
							   "action=\"https://evil.example.net/k\"></form>");
			CHECK(hc != nullptr);

			const auto *atag = find_tag(hc, Tag_A);
			REQUIRE(atag != nullptr);
			REQUIRE(atag->find_href().has_value());
			CHECK(atag->find_href().value() == "https://evil.example.net/g");

			const auto *ftag = find_tag(hc, Tag_FORM);
			REQUIRE(ftag != nullptr);
			REQUIRE(ftag->find_href().has_value());
			CHECK(ftag->find_href().value() == "https://evil.example.net/k");
		}

		SUBCASE("the destination of buttons")
		{
			/* href of a button is no destination */
			auto *hc = process("<button href=\"https://good.example.org/b\" "
							   "formaction=\"https://evil.example.net/b\">Go</button>");
			CHECK(hc != nullptr);

			const auto *btag = find_tag(hc, Tag_BUTTON);
			REQUIRE(btag != nullptr);
			REQUIRE(btag->find_href().has_value());
			CHECK(btag->find_href().value() == "https://evil.example.net/b");
			CHECK(btag->find_component_by_name("formaction").value_or("") == "https://evil.example.net/b");
			CHECK(btag->find_component_by_name("href").value_or("") == "https://good.example.org/b");
		}

		SUBCASE("href of an SVG link wins over xlink:href")
		{
			auto *hc = process("<svg><a xlink:href=\"https://good.example.org/a\" "
							   "href=\"https://evil.example.net/a\">x</a></svg>");
			CHECK(hc != nullptr);

			const auto *atag = find_tag(hc, Tag_A);
			REQUIRE(atag != nullptr);
			REQUIRE(atag->find_href().has_value());
			CHECK(atag->find_href().value() == "https://evil.example.net/a");
		}

		SUBCASE("xlink:href is no href attribute")
		{
			auto *hc = process("<svg><a xlink:href=\"https://evil.example.net/a\">x</a></svg>");
			CHECK(hc != nullptr);

			const auto *atag = find_tag(hc, Tag_A);
			REQUIRE(atag != nullptr);
			CHECK(atag->find_href().value_or("") == "https://evil.example.net/a");
			CHECK(!atag->find_component_by_name("href").has_value());
			CHECK(atag->find_component_by_name("xlink:href").value_or("") == "https://evil.example.net/a");
		}

		SUBCASE("attributes are read under their own names")
		{
			auto *hc = process("<a action=\"https://a.example.org/\" href=\"https://h.example.org/\">x</a>"
							   "<form href=\"https://h.example.net/\" action=\"https://a.example.net/\"></form>");
			CHECK(hc != nullptr);

			const auto *atag = find_tag(hc, Tag_A);
			REQUIRE(atag != nullptr);
			CHECK(atag->find_component_by_name("href").value_or("") == "https://h.example.org/");
			CHECK(atag->find_component_by_name("action").value_or("") == "https://a.example.org/");

			const auto *ftag = find_tag(hc, Tag_FORM);
			REQUIRE(ftag != nullptr);
			CHECK(ftag->find_component_by_name("href").value_or("") == "https://h.example.net/");
			CHECK(ftag->find_component_by_name("action").value_or("") == "https://a.example.net/");
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

			/*
			 * The second part of the same task gets no more attributes rspamd
			 * does not interpret, but still its link
			 */
			auto *hc2 = process("<a href=\"http://example.com\" data-x=\"1\">link</a>");
			CHECK(hc2 != nullptr);
			CHECK((hc2->flags & RSPAMD_HTML_FLAG_TOO_MANY_ATTRS) != 0);
			const auto *atag = find_tag(hc2, Tag_A);
			CHECK(atag != nullptr);
			CHECK(atag->components.size() == 1);
			CHECK(atag->find_href().has_value());
		}

		rspamd_mempool_delete(pool);
	}

	TEST_CASE("html empty numeric attributes")
	{
		rspamd_url_init(NULL);
		auto *pool = rspamd_mempool_new(rspamd_mempool_suggest_size(),
										"html", 0);
		struct rspamd_task fake_task;
		memset(&fake_task, 0, sizeof(fake_task));
		fake_task.task_pool = pool;

		auto find_tag = [&](const std::string &input, tag_id_t id) -> const html_tag * {
			GByteArray *tmp = g_byte_array_sized_new(input.size());
			g_byte_array_append(tmp, (const uint8_t *) input.data(), input.size());
			auto *hc = html_process_input(&fake_task, tmp, nullptr, nullptr, nullptr, true, nullptr);
			g_byte_array_free(tmp, TRUE);
			REQUIRE(hc != nullptr);
			const html_tag *found = nullptr;
			hc->traverse_all_tags([&](const html_tag *t) -> bool {
				if (t->id == id) {
					found = t;
					return false;
				}
				return true;
			});
			REQUIRE(found != nullptr);
			return found;
		};

		/*
		 * A valueless or empty attribute has an empty value with no data:
		 * it must give no number (and no arithmetic on a null pointer, UBSan)
		 */
		for (const auto *input: {"<img width height>", "<img width=\"\" height=\"\">"}) {
			CAPTURE(input);
			const auto *img = find_tag(input, Tag_IMG);
			auto width = img->find_component<html_component_width>();
			REQUIRE(width.has_value());
			CHECK(width.value()->get_string_value().empty());
			CHECK_FALSE(width.value()->get_numeric_value().has_value());
			auto height = img->find_component<html_component_height>();
			REQUIRE(height.has_value());
			CHECK_FALSE(height.value()->get_numeric_value().has_value());
		}

		const auto *font = find_tag("<font size>x</font>", Tag_FONT);
		REQUIRE(font->find_component<html_component_size>().has_value());
		CHECK_FALSE(font->find_component<html_component_size>().value()->get_numeric_value().has_value());

		const auto *table = find_tag("<table cellpadding cellspacing>", Tag_TABLE);
		REQUIRE(table->find_component<html_component_cellpadding>().has_value());
		CHECK_FALSE(table->find_component<html_component_cellpadding>().value()->get_numeric_value().has_value());
		REQUIRE(table->find_component<html_component_cellspacing>().has_value());
		CHECK_FALSE(table->find_component<html_component_cellspacing>().value()->get_numeric_value().has_value());

		const auto *span = find_tag("<span tabindex max-height>x</span>", Tag_SPAN);
		REQUIRE(span->find_component<html_component_tabindex>().has_value());
		CHECK_FALSE(span->find_component<html_component_tabindex>().value()->get_numeric_value().has_value());
		REQUIRE(span->find_component<html_component_max_height>().has_value());
		CHECK_FALSE(span->find_component<html_component_max_height>().value()->get_numeric_value().has_value());

		/* Opacity with no number in it is no opacity, not opacity 0 */
		for (const auto *input: {"<div opacity>x</div>", "<div opacity=\"abc\">x</div>"}) {
			CAPTURE(input);
			const auto *div = find_tag(input, Tag_DIV);
			auto opacity = div->find_component<html_component_opacity>();
			REQUIRE(opacity.has_value());
			CHECK_FALSE(opacity.value()->get_numeric_value().has_value());
		}

		/* Values still parse */
		const auto *img = find_tag("<img width=\"12\">", Tag_IMG);
		CHECK(img->find_component<html_component_width>().value()->get_numeric_value() == 12u);
		const auto *div = find_tag("<div opacity=\"0.5\" tabindex=\"-3\">x</div>", Tag_DIV);
		CHECK(div->find_component<html_component_opacity>().value()->get_numeric_value() == doctest::Approx(0.5));
		CHECK(div->find_component<html_component_tabindex>().value()->get_numeric_value() == -3);

		rspamd_mempool_delete(pool);
	}
}

} /* namespace rspamd::html */
