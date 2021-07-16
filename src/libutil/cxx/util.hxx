/*-
 * Copyright 2021 Vsevolod Stakhov
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
#ifndef RSPAMD_UTIL_HXX
#define RSPAMD_UTIL_HXX

#pragma once

#include <memory>
#include <array>
#include <string_view>
#include <optional>

/*
 * Common C++ utilities
 */

namespace rspamd {
/*
 * Transparent smart pointers hashing
 */
template<typename T>
struct smart_ptr_equal {
	using is_transparent = void; /* We want to find values in a set of shared_ptr by reference */
	auto operator()(const std::shared_ptr<T> &a, const std::shared_ptr<T> &b) const {
		return (*a) == (*b);
	}
	auto operator()(const std::shared_ptr<T> &a, const T &b) const {
		return (*a) == b;
	}
	auto operator()(const T &a, const std::shared_ptr<T> &b) const {
		return a == (*b);
	}
	auto operator()(const std::unique_ptr<T> &a, const std::unique_ptr<T> &b) const {
		return (*a) == (*b);
	}
	auto operator()(const std::unique_ptr<T> &a, const T &b) const {
		return (*a) == b;
	}
	auto operator()(const T &a, const std::unique_ptr<T> &b) const {
		return a == (*b);
	}
};

template<typename T>
struct smart_ptr_hash {
	using is_transparent = void; /* We want to find values in a set of shared_ptr by reference */
	auto operator()(const std::shared_ptr<T> &a) const {
		return std::hash<T>()(*a);
	}
	auto operator()(const std::unique_ptr<T> &a) const {
		return std::hash<T>()(*a);
	}
	auto operator()(const T &a) const {
		return std::hash<T>()(a);
	}
};

/*
 * Creates std::array from a standard C style array with automatic size calculation
 */
template <typename V, typename... T>
constexpr auto array_of(T&&... t) -> std::array<V, sizeof...(T)>
{
	return {{ std::forward<T>(t)... }};
}

template<class C, class K, class V = typename C::mapped_type, typename std::enable_if_t<
		std::is_constructible_v<typename C::key_type, K>
		&& std::is_constructible_v<typename C::mapped_type, V>, bool> = false>
constexpr auto find_map(const C &c, const K &k) -> std::optional<std::reference_wrapper<const V>>
{
	auto f = c.find(k);

	if (f != c.end()) {
		return std::cref<V>(f->second);
	}

	return std::nullopt;
}


template <typename _It>
inline constexpr auto make_string_view_from_it(_It begin, _It end)
{
	using result_type = std::string_view;

	return result_type{((begin != end) ? &*begin : nullptr),
					   (typename result_type::size_type)std::max(std::distance(begin, end),
							   (typename result_type::difference_type)0)
	};
}

}

#endif //RSPAMD_UTIL_HXX
