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

#include "multipart_response.hxx"
#include "ottery.h"
#include "printf.h"
#include <cstdlib>
#include <cstring>

#ifdef SYS_ZSTD
#include "zstd.h"
#else
#include "contrib/zstd/zstd.h"
#endif

namespace rspamd::http {

multipart_response::multipart_response()
{
	/* Generate a random boundary using ottery CSPRNG */
	char buf[64];
	uint64_t rnd = ottery_rand_uint64();
	static unsigned int counter = 0;
	rspamd_snprintf(buf, sizeof(buf), "rspamd-v3-%016xL-%ud",
					rnd, counter++);
	boundary_ = buf;
}

void multipart_response::add_part(std::string name, std::string content_type,
								  std::string_view data, bool compress)
{
	parts_.push_back({std::move(name), std::move(content_type), data, compress});
}

auto multipart_response::serialize(void *zstream) const -> std::string
{
	std::string out;
	out.reserve(4096);

	for (const auto &part: parts_) {
		out.append("--");
		out.append(boundary_);
		out.append("\r\n");

		/* Content-Disposition */
		out.append("Content-Disposition: form-data; name=\"");
		out.append(part.name);
		out.append("\"\r\n");

		/* Content-Type */
		if (!part.content_type.empty()) {
			out.append("Content-Type: ");
			out.append(part.content_type);
			out.append("\r\n");
		}

		/* Compress if requested and zstream is available */
		if (part.compress && zstream && !part.data.empty()) {
			auto *cstream = static_cast<ZSTD_CStream *>(zstream);
			size_t bound = ZSTD_compressBound(part.data.size());
			std::string compressed(bound, '\0');

			ZSTD_inBuffer zin{};
			zin.src = part.data.data();
			zin.size = part.data.size();
			zin.pos = 0;

			ZSTD_outBuffer zout{};
			zout.dst = compressed.data();
			zout.size = compressed.size();
			zout.pos = 0;

			ZSTD_CCtx_reset(cstream, ZSTD_reset_session_only);

			bool ok = true;
			while (zin.pos < zin.size) {
				size_t r = ZSTD_compressStream2(cstream, &zout, &zin, ZSTD_e_continue);
				if (ZSTD_isError(r)) {
					ok = false;
					break;
				}
			}

			if (ok) {
				size_t r = ZSTD_compressStream2(cstream, &zout, &zin, ZSTD_e_end);
				if (ZSTD_isError(r)) {
					ok = false;
				}
			}

			if (ok) {
				compressed.resize(zout.pos);
				out.append("Content-Encoding: zstd\r\n");
				out.append("\r\n");
				out.append(compressed);
			}
			else {
				/* Fallback: write uncompressed */
				out.append("\r\n");
				out.append(part.data);
			}
		}
		else {
			out.append("\r\n");
			out.append(part.data);
		}

		out.append("\r\n");
	}

	/* Closing boundary */
	out.append("--");
	out.append(boundary_);
	out.append("--\r\n");

	return out;
}

auto multipart_response::content_type() const -> std::string
{
	return "multipart/mixed; boundary=\"" + boundary_ + "\"";
}

}// namespace rspamd::http


/*
 * C bridge implementation
 */

struct rspamd_multipart_response_c {
	rspamd::http::multipart_response resp;
	std::string cached_content_type;
};

extern "C" {

struct rspamd_multipart_response_c *
rspamd_multipart_response_new(void)
{
	return new rspamd_multipart_response_c();
}

void rspamd_multipart_response_add_part(
	struct rspamd_multipart_response_c *resp,
	const char *name,
	const char *content_type,
	const char *data, gsize len,
	gboolean compress)
{
	if (!resp) {
		return;
	}
	resp->resp.add_part(
		name ? name : "",
		content_type ? content_type : "",
		{data, len},
		compress != FALSE);
}

rspamd_fstring_t *
rspamd_multipart_response_serialize(
	struct rspamd_multipart_response_c *resp,
	void *zstream)
{
	if (!resp) {
		return nullptr;
	}
	auto serialized = resp->resp.serialize(zstream);
	return rspamd_fstring_new_init(serialized.data(), serialized.size());
}

const char *
rspamd_multipart_response_content_type(
	struct rspamd_multipart_response_c *resp)
{
	if (!resp) {
		return "multipart/mixed";
	}
	resp->cached_content_type = resp->resp.content_type();
	return resp->cached_content_type.c_str();
}

void rspamd_multipart_response_free(
	struct rspamd_multipart_response_c *resp)
{
	delete resp;
}

} /* extern "C" */
