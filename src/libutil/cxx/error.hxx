/*-
 * Copyright 2022 Vsevolod Stakhov
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef RSPAMD_ERROR_HXX
#define RSPAMD_ERROR_HXX
#pragma once

#include "config.h"
#include <string>
#include <string_view>
#include <cstdint>
#include <optional>

/***
 * This unit is used to represent Rspamd C++ errors in a way to interoperate
 * with C code if needed and avoid allocations for static strings
 */
namespace rspamd::util {

enum class error_category : std::uint8_t {
	INFORMAL,
	IMPORTANT,
	CRITICAL
};

struct error {
public:
	/**
	 * Construct from a static string, this string must live long enough to outlive this object
	 * @param msg
	 * @param code
	 * @param category
	 */
	error(const char *msg, int code, error_category category = error_category::INFORMAL) :
		error_message(msg), error_code(code), category(category) {}
	/**
	 * Construct error from a temporary string taking membership
	 * @param msg
	 * @param code
	 * @param category
	 */
	error(std::string &&msg, int code, error_category category = error_category::INFORMAL)
		: error_code(code), category(category) {
		static_storage = std::move(msg);
		error_message = static_storage.value();
	}
	/**
	 * Construct error from another string copying it into own storage
	 * @param msg
	 * @param code
	 * @param category
	 */
	error(const std::string &msg, int code, error_category category = error_category::INFORMAL)
		: error_code(code), category(category) {
		static_storage = msg;
		error_message = static_storage.value();
	}

	error(const error &other) : error_code(other.error_code), category(other.category) {
		if (other.static_storage) {
			static_storage = other.static_storage;
			error_message = static_storage.value();
		}
		else {
			error_message = other.error_message;
		}
	}

	error(error &&other) noexcept {
		*this = std::move(other);
	}

	error& operator = (error &&other) noexcept {
		if (other.static_storage.has_value()) {
			std::swap(static_storage, other.static_storage);
			error_message = static_storage.value();
		}
		else {
			std::swap(error_message, other.error_message);
		}
		std::swap(other.error_code, error_code);
		std::swap(other.category, category);

		return *this;
	}

	/**
	 * Convert into GError
	 * @return
	 */
	auto into_g_error() const -> GError * {
		return g_error_new(g_quark_from_static_string("rspamd"), error_code, "%s",
			error_message.data());
	}

	/**
	 * Convenience alias for the `into_g_error`
	 * @param err
	 */
	auto into_g_error_set(GError **err) const -> void {
		if (err && *err == nullptr) {
			*err = into_g_error();
		}
	}
public:
	std::string_view error_message;
	int error_code;
	error_category category;
private:
	std::optional<std::string> static_storage;
};

} // namespace rspamd::util

#endif //RSPAMD_ERROR_HXX
