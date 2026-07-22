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

#ifndef RSPAMD_RSPAMD_CXX_UNIT_IMAGES_HXX
#define RSPAMD_RSPAMD_CXX_UNIT_IMAGES_HXX

#define DOCTEST_CONFIG_IMPLEMENTATION_IN_DLL
#include "doctest/doctest.h"

#include "libmime/images.h"
#include "libserver/html/html.h"
#include "libserver/html/html.hxx"
#include "libutil/mem_pool.h"

#include <string>

TEST_SUITE("image_processing")
{
	TEST_CASE("bulk Content-ID linking covers repeated HTML images")
	{
		auto *pool = rspamd_mempool_new(rspamd_mempool_suggest_size(), nullptr, 0);
		std::string html;
		html.reserve(1024 * 32);

		for (unsigned int i = 0; i < 1024; i++) {
			html += "<img src=\"cid:shared-image\">";
		}

		auto *input = g_byte_array_sized_new(html.size());
		g_byte_array_append(input,
							reinterpret_cast<const guint8 *>(html.data()), html.size());
		auto *parsed = rspamd_html_process_part(pool, input);
		g_byte_array_free(input, TRUE);

		struct rspamd_image mime_image = {};
		mime_image.width = 320;
		mime_image.height = 240;
		auto *cid_images = g_hash_table_new(g_str_hash, g_str_equal);
		g_hash_table_insert(cid_images,
							const_cast<char *>("shared-image"), &mime_image);

		rspamd_html_link_embedded_images(parsed, cid_images);

		auto *hc = rspamd::html::html_content::from_ptr(parsed);
		REQUIRE(hc->images.size() == 1024);
		for (const auto *html_image: hc->images) {
			CHECK(html_image->embedded_image == &mime_image);
			CHECK(html_image->width == mime_image.width);
			CHECK(html_image->height == mime_image.height);
		}

		g_hash_table_destroy(cid_images);
		rspamd_mempool_delete(pool);
	}
}

#endif
