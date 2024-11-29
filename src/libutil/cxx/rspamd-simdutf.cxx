/*
 * Copyright 2024 Vsevolod Stakhov
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
 * A simple interface for simdutf library to allow old functions to work properly
 */

#include "config.h"
#include "simdutf.h"

extern "C" {

const simdutf::implementation *impl{nullptr};
const simdutf::implementation *ref_impl{nullptr};

void rspamd_fast_utf8_library_init(unsigned flags)
{
	impl = simdutf::get_active_implementation();
	auto all_impls = simdutf::get_available_implementations();

	for (auto &i: all_impls) {
		if (i->name() == "fallback") {
			ref_impl = i;
			break;
		}
	}
}

off_t rspamd_fast_utf8_validate(const unsigned char *data, size_t len)
{
	auto res = impl->validate_utf8_with_errors((const char *) data, len);

	if (res.error == simdutf::error_code::SUCCESS) {
		return 0;
	}

	return res.count + 1;// We need to return offset for the first invalid character
}

off_t rspamd_fast_utf8_validate_ref(const unsigned char *data, size_t len)
{
	auto res = ref_impl->validate_utf8_with_errors((const char *) data, len);

	if (res.error == simdutf::error_code::SUCCESS) {
		return 0;
	}

	return res.count + 1;// We need to return offset for the first invalid character
}

const char *rspamd_fast_utf8_library_impl_name(void)
{
	static auto impl_name = std::string{};

	if (impl_name.empty()) {
		impl_name = impl->name() + "(" + impl->description() + ")";
	}

	return impl_name.c_str();
}
}