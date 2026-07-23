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

#ifndef RSPAMD_RSPAMD_CXX_UNIT_COMPRESSION_HXX
#define RSPAMD_RSPAMD_CXX_UNIT_COMPRESSION_HXX

#define DOCTEST_CONFIG_IMPLEMENTATION_IN_DLL
#include "doctest/doctest.h"

#include "libutil/compression.h"

#include <string>
#include <vector>

/*
 * Tests for the bounded zstd decompression helper shared by the HTTP,
 * proxy and map code paths. The limit must hold both when the frame header
 * advertises the decompressed size (single-shot compression) and when it
 * does not (streaming compression), and the returned length must never
 * exceed it.
 */

static std::vector<char>
unit_zstd_compress_oneshot(const std::string &in)
{
	std::vector<char> out(ZSTD_compressBound(in.size()));
	auto r = ZSTD_compress(out.data(), out.size(), in.data(), in.size(), 1);
	REQUIRE(!ZSTD_isError(r));
	out.resize(r);

	return out;
}

/* Streaming compression produces frames without a content-size header */
static std::vector<char>
unit_zstd_compress_stream(const std::string &in)
{
	auto *cs = ZSTD_createCStream();
	REQUIRE(cs != nullptr);
	ZSTD_initCStream(cs, 1);

	std::vector<char> out(ZSTD_compressBound(in.size()) + 128);
	ZSTD_outBuffer zout = {out.data(), out.size(), 0};
	ZSTD_inBuffer zin = {in.data(), in.size(), 0};

	while (zin.pos < zin.size) {
		auto r = ZSTD_compressStream(cs, &zout, &zin);
		REQUIRE(!ZSTD_isError(r));
	}

	auto r = ZSTD_endStream(cs, &zout);
	REQUIRE(r == 0);
	ZSTD_freeCStream(cs);
	out.resize(zout.pos);

	return out;
}

TEST_SUITE("bounded zstd decompression")
{
	TEST_CASE("roundtrip without limit")
	{
		std::string plain;
		for (int i = 0; i < 1000; i++) {
			plain += "some compressible payload ";
		}

		auto compressed = unit_zstd_compress_oneshot(plain);
		GError *err = nullptr;
		auto *body = rspamd_zstd_decompress_bounded(nullptr, compressed.data(),
													compressed.size(), 0, &err);
		REQUIRE(body != nullptr);
		REQUIRE(err == nullptr);
		CHECK(std::string{body->str, body->len} == plain);
		rspamd_fstring_free(body);
	}

	TEST_CASE("limit exactly equal to decompressed size is allowed")
	{
		std::string plain(65536, 'x');
		auto compressed = unit_zstd_compress_oneshot(plain);

		GError *err = nullptr;
		auto *body = rspamd_zstd_decompress_bounded(nullptr, compressed.data(),
													compressed.size(),
													plain.size(), &err);
		REQUIRE(body != nullptr);
		REQUIRE(err == nullptr);
		CHECK(body->len == plain.size());
		rspamd_fstring_free(body);
	}

	TEST_CASE("advertised size over the limit is rejected upfront")
	{
		std::string plain(4 * 1024 * 1024, '\0');
		auto compressed = unit_zstd_compress_oneshot(plain);

		GError *err = nullptr;
		auto *body = rspamd_zstd_decompress_bounded(nullptr, compressed.data(),
													compressed.size(),
													1024 * 1024, &err);
		CHECK(body == nullptr);
		REQUIRE(err != nullptr);
		CHECK(err->code == RSPAMD_DECOMPRESS_ERROR_TOO_LARGE);
		g_error_free(err);
	}

	TEST_CASE("unknown-size frame over the limit is rejected while streaming")
	{
		std::string plain(4 * 1024 * 1024, '\0');
		auto compressed = unit_zstd_compress_stream(plain);
		/* The frame must not advertise its decompressed size */
		REQUIRE(ZSTD_getDecompressedSize(compressed.data(), compressed.size()) == 0);

		GError *err = nullptr;
		auto *body = rspamd_zstd_decompress_bounded(nullptr, compressed.data(),
													compressed.size(),
													64 * 1024, &err);
		CHECK(body == nullptr);
		REQUIRE(err != nullptr);
		CHECK(err->code == RSPAMD_DECOMPRESS_ERROR_TOO_LARGE);
		g_error_free(err);
	}

	TEST_CASE("unknown-size frame within the limit roundtrips via buffer growth")
	{
		std::string plain;
		for (int i = 0; i < 100000; i++) {
			plain += "0123456789";
		}
		auto compressed = unit_zstd_compress_stream(plain);
		REQUIRE(ZSTD_getDecompressedSize(compressed.data(), compressed.size()) == 0);

		GError *err = nullptr;
		auto *body = rspamd_zstd_decompress_bounded(nullptr, compressed.data(),
													compressed.size(),
													2 * plain.size(), &err);
		REQUIRE(body != nullptr);
		REQUIRE(err == nullptr);
		CHECK(std::string{body->str, body->len} == plain);
		rspamd_fstring_free(body);
	}

	TEST_CASE("corrupt input is an error")
	{
		std::string garbage = "definitely not a zstd frame at all";

		GError *err = nullptr;
		auto *body = rspamd_zstd_decompress_bounded(nullptr, garbage.data(),
													garbage.size(), 0, &err);
		CHECK(body == nullptr);
		REQUIRE(err != nullptr);
		CHECK(err->code == RSPAMD_DECOMPRESS_ERROR_DATA);
		g_error_free(err);
	}

	TEST_CASE("caller-provided stream is used and not freed")
	{
		std::string plain(1024, 'y');
		auto compressed = unit_zstd_compress_oneshot(plain);

		auto *ds = ZSTD_createDStream();
		REQUIRE(ds != nullptr);
		ZSTD_initDStream(ds);

		GError *err = nullptr;
		auto *body = rspamd_zstd_decompress_bounded(ds, compressed.data(),
													compressed.size(), 0, &err);
		REQUIRE(body != nullptr);
		CHECK(std::string{body->str, body->len} == plain);
		rspamd_fstring_free(body);

		/* Stream must still be usable for another frame */
		ZSTD_DCtx_reset(ds, ZSTD_reset_session_only);
		body = rspamd_zstd_decompress_bounded(ds, compressed.data(),
											  compressed.size(), 0, &err);
		REQUIRE(body != nullptr);
		CHECK(body->len == plain.size());
		rspamd_fstring_free(body);
		ZSTD_freeDStream(ds);
	}
}

#endif
