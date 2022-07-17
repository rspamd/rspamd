///////////////////////// ankerl::unordered_dense::{map, set} /////////////////////////

// A fast & densely stored hashmap and hashset based on robin-hood backward shift deletion.
// Version 1.0.2
// https://github.com/martinus/unordered_dense
//
// Licensed under the MIT License <http://opensource.org/licenses/MIT>.
// SPDX-License-Identifier: MIT
// Copyright (c) 2022 Martin Leitner-Ankerl <martin.ankerl@gmail.com>
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

#ifndef ANKERL_UNORDERED_DENSE_H
#define ANKERL_UNORDERED_DENSE_H

// see https://semver.org/spec/v2.0.0.html
#define ANKERL_UNORDERED_DENSE_VERSION_MAJOR 1 // incompatible API changes
#define ANKERL_UNORDERED_DENSE_VERSION_MINOR 0 // add functionality in a backwards compatible manner
#define ANKERL_UNORDERED_DENSE_VERSION_PATCH 2 // backwards compatible bug fixes

#if __cplusplus < 201703L
#    error ankerl::unordered_dense requires C++17 or higher
#else

#    include <array>            // for array
#    include <cstdint>          // for uint64_t, uint32_t, uint8_t, UINT64_C
#    include <cstring>          // for size_t, memcpy, memset
#    include <functional>       // for equal_to, hash
#    include <initializer_list> // for initializer_list
#    include <iterator>         // for pair, distance
#    include <limits>           // for numeric_limits
#    include <memory>           // for allocator, allocator_traits, shared_ptr
#    include <stdexcept>        // for out_of_range
#    include <string>           // for basic_string
#    include <string_view>      // for basic_string_view, hash
#    include <tuple>            // for forward_as_tuple
#    include <type_traits>      // for enable_if_t, declval, conditional_t, ena...
#    include <utility>          // for forward, exchange, pair, as_const, piece...
#    include <vector>           // for vector

#    define ANKERL_UNORDERED_DENSE_PMR 0
#    if defined(__has_include)
#        if __has_include(<memory_resource>)
#            undef ANKERL_UNORDERED_DENSE_PMR
#            define ANKERL_UNORDERED_DENSE_PMR 1
#            include <memory_resource> // for polymorphic_allocator
#        endif
#    endif

#    if defined(_MSC_VER) && defined(_M_X64)
#        include <intrin.h>
#        pragma intrinsic(_umul128)
#    endif

#    if defined(__GNUC__) || defined(__INTEL_COMPILER) || defined(__clang__)
#        define ANKERL_UNORDERED_DENSE_LIKELY(x) __builtin_expect(x, 1)
#        define ANKERL_UNORDERED_DENSE_UNLIKELY(x) __builtin_expect(x, 0)
#    else
#        define ANKERL_UNORDERED_DENSE_LIKELY(x) (x)
#        define ANKERL_UNORDERED_DENSE_UNLIKELY(x) (x)
#    endif

namespace ankerl::unordered_dense {

// hash ///////////////////////////////////////////////////////////////////////

// This is a stripped-down implementation of wyhash: https://github.com/wangyi-fudan/wyhash
// No big-endian support (because different values on different machines don't matter),
// hardcodes seed and the secret, reformattes the code, and clang-tidy fixes.
namespace detail::wyhash {

static inline void mum(uint64_t* a, uint64_t* b) {
#    if defined(__SIZEOF_INT128__)
    __uint128_t r = *a;
    r *= *b;
    *a = static_cast<uint64_t>(r);
    *b = static_cast<uint64_t>(r >> 64U);
#    elif defined(_MSC_VER) && defined(_M_X64)
    *a = _umul128(*a, *b, b);
#    else
    uint64_t ha = *a >> 32U;
    uint64_t hb = *b >> 32U;
    uint64_t la = static_cast<uint32_t>(*a);
    uint64_t lb = static_cast<uint32_t>(*b);
    uint64_t hi{};
    uint64_t lo{};
    uint64_t rh = ha * hb;
    uint64_t rm0 = ha * lb;
    uint64_t rm1 = hb * la;
    uint64_t rl = la * lb;
    uint64_t t = rl + (rm0 << 32U);
    auto c = static_cast<uint64_t>(t < rl);
    lo = t + (rm1 << 32U);
    c += static_cast<uint64_t>(lo < t);
    hi = rh + (rm0 >> 32U) + (rm1 >> 32U) + c;
    *a = lo;
    *b = hi;
#    endif
}

// multiply and xor mix function, aka MUM
[[nodiscard]] static inline auto mix(uint64_t a, uint64_t b) -> uint64_t {
    mum(&a, &b);
    return a ^ b;
}

// read functions. WARNING: we don't care about endianness, so results are different on big endian!
[[nodiscard]] static inline auto r8(const uint8_t* p) -> uint64_t {
    uint64_t v{};
    std::memcpy(&v, p, 8);
    return v;
}

[[nodiscard]] static inline auto r4(const uint8_t* p) -> uint64_t {
    uint32_t v{};
    std::memcpy(&v, p, 4);
    return v;
}

// reads 1, 2, or 3 bytes
[[nodiscard]] static inline auto r3(const uint8_t* p, size_t k) -> uint64_t {
    return (static_cast<uint64_t>(p[0]) << 16U) | (static_cast<uint64_t>(p[k >> 1U]) << 8U) | p[k - 1];
}

[[nodiscard]] static inline auto hash(void const* key, size_t len) -> uint64_t {
    static constexpr auto secret = std::array{UINT64_C(0xa0761d6478bd642f),
                                              UINT64_C(0xe7037ed1a0b428db),
                                              UINT64_C(0x8ebc6af09c88c6e3),
                                              UINT64_C(0x589965cc75374cc3)};

    auto const* p = static_cast<uint8_t const*>(key);
    uint64_t seed = secret[0];
    uint64_t a{};
    uint64_t b{};
    if (ANKERL_UNORDERED_DENSE_LIKELY(len <= 16)) {
        if (ANKERL_UNORDERED_DENSE_LIKELY(len >= 4)) {
            a = (r4(p) << 32U) | r4(p + ((len >> 3U) << 2U));
            b = (r4(p + len - 4) << 32U) | r4(p + len - 4 - ((len >> 3U) << 2U));
        } else if (ANKERL_UNORDERED_DENSE_LIKELY(len > 0)) {
            a = r3(p, len);
            b = 0;
        } else {
            a = 0;
            b = 0;
        }
    } else {
        size_t i = len;
        if (ANKERL_UNORDERED_DENSE_UNLIKELY(i > 48)) {
            uint64_t see1 = seed;
            uint64_t see2 = seed;
            do {
                seed = mix(r8(p) ^ secret[1], r8(p + 8) ^ seed);
                see1 = mix(r8(p + 16) ^ secret[2], r8(p + 24) ^ see1);
                see2 = mix(r8(p + 32) ^ secret[3], r8(p + 40) ^ see2);
                p += 48;
                i -= 48;
            } while (ANKERL_UNORDERED_DENSE_LIKELY(i > 48));
            seed ^= see1 ^ see2;
        }
        while (ANKERL_UNORDERED_DENSE_UNLIKELY(i > 16)) {
            seed = mix(r8(p) ^ secret[1], r8(p + 8) ^ seed);
            i -= 16;
            p += 16;
        }
        a = r8(p + i - 16);
        b = r8(p + i - 8);
    }

    return mix(secret[1] ^ len, mix(a ^ secret[1], b ^ seed));
}

[[nodiscard]] static inline auto hash(uint64_t x) -> uint64_t {
    return detail::wyhash::mix(x, UINT64_C(0x9E3779B97F4A7C15));
}

} // namespace detail::wyhash

template <typename T, typename Enable = void>
struct hash : public std::hash<T> {
    using is_avalanching = void;
    auto operator()(T const& obj) const noexcept(noexcept(std::declval<std::hash<T>>().operator()(std::declval<T const&>())))
        -> size_t {
        return static_cast<size_t>(detail::wyhash::hash(std::hash<T>::operator()(obj)));
    }
};

template <typename CharT>
struct hash<std::basic_string<CharT>> {
    using is_avalanching = void;
    auto operator()(std::basic_string<CharT> const& str) const noexcept -> size_t {
        return static_cast<size_t>(detail::wyhash::hash(str.data(), sizeof(CharT) * str.size()));
    }
};

template <typename CharT>
struct hash<std::basic_string_view<CharT>> {
    using is_avalanching = void;
    auto operator()(std::basic_string_view<CharT> const& sv) const noexcept -> size_t {
        return static_cast<size_t>(detail::wyhash::hash(sv.data(), sizeof(CharT) * sv.size()));
    }
};

template <class T>
struct hash<T*> {
    using is_avalanching = void;
    auto operator()(T* ptr) const noexcept -> size_t {
        return static_cast<size_t>(detail::wyhash::hash(reinterpret_cast<uintptr_t>(ptr)));
    }
};

template <class T>
struct hash<std::unique_ptr<T>> {
    using is_avalanching = void;
    auto operator()(std::unique_ptr<T> const& ptr) const noexcept -> size_t {
        return static_cast<size_t>(detail::wyhash::hash(reinterpret_cast<uintptr_t>(ptr.get())));
    }
};

template <class T>
struct hash<std::shared_ptr<T>> {
    using is_avalanching = void;
    auto operator()(std::shared_ptr<T> const& ptr) const noexcept -> size_t {
        return static_cast<size_t>(detail::wyhash::hash(reinterpret_cast<uintptr_t>(ptr.get())));
    }
};

template <typename Enum>
struct hash<Enum, typename std::enable_if<std::is_enum<Enum>::value>::type> {
    using is_avalanching = void;
    auto operator()(Enum e) const noexcept -> size_t {
        using Underlying = typename std::underlying_type_t<Enum>;
        return static_cast<size_t>(detail::wyhash::hash(static_cast<Underlying>(e)));
    }
};

#    define ANKERL_UNORDERED_DENSE_HASH_STATICCAST(T)                                         \
        template <>                                                                           \
        struct hash<T> {                                                                      \
            using is_avalanching = void;                                                      \
            auto operator()(T const& obj) const noexcept -> size_t {                          \
                return static_cast<size_t>(detail::wyhash::hash(static_cast<uint64_t>(obj))); \
            }                                                                                 \
        }

#    if defined(__GNUC__) && !defined(__clang__)
#        pragma GCC diagnostic push
#        pragma GCC diagnostic ignored "-Wuseless-cast"
#    endif
// see https://en.cppreference.com/w/cpp/utility/hash
ANKERL_UNORDERED_DENSE_HASH_STATICCAST(bool);
ANKERL_UNORDERED_DENSE_HASH_STATICCAST(char);
ANKERL_UNORDERED_DENSE_HASH_STATICCAST(signed char);
ANKERL_UNORDERED_DENSE_HASH_STATICCAST(unsigned char);
#    if __cplusplus >= 202002L
ANKERL_UNORDERED_DENSE_HASH_STATICCAST(char8_t);
#    endif
ANKERL_UNORDERED_DENSE_HASH_STATICCAST(char16_t);
ANKERL_UNORDERED_DENSE_HASH_STATICCAST(char32_t);
ANKERL_UNORDERED_DENSE_HASH_STATICCAST(wchar_t);
ANKERL_UNORDERED_DENSE_HASH_STATICCAST(short);
ANKERL_UNORDERED_DENSE_HASH_STATICCAST(unsigned short);
ANKERL_UNORDERED_DENSE_HASH_STATICCAST(int);
ANKERL_UNORDERED_DENSE_HASH_STATICCAST(unsigned int);
ANKERL_UNORDERED_DENSE_HASH_STATICCAST(long);
ANKERL_UNORDERED_DENSE_HASH_STATICCAST(long long);
ANKERL_UNORDERED_DENSE_HASH_STATICCAST(unsigned long);
ANKERL_UNORDERED_DENSE_HASH_STATICCAST(unsigned long long);

#    if defined(__GNUC__) && !defined(__clang__)
#        pragma GCC diagnostic pop
#    endif

namespace detail {

struct nonesuch {};

template <class Default, class AlwaysVoid, template <class...> class Op, class... Args>
struct detector {
    using value_t = std::false_type;
    using type = Default;
};

template <class Default, template <class...> class Op, class... Args>
struct detector<Default, std::void_t<Op<Args...>>, Op, Args...> {
    using value_t = std::true_type;
    using type = Op<Args...>;
};

template <template <class...> class Op, class... Args>
using is_detected = typename detail::detector<detail::nonesuch, void, Op, Args...>::value_t;

template <template <class...> class Op, class... Args>
constexpr bool is_detected_v = is_detected<Op, Args...>::value;

template <typename T>
using detect_avalanching = typename T::is_avalanching;

template <typename T>
using detect_is_transparent = typename T::is_transparent;

template <typename H, typename KE>
using is_transparent =
    std::enable_if_t<is_detected_v<detect_is_transparent, H> && is_detected_v<detect_is_transparent, KE>, bool>;

// This is it, the table. Doubles as map and set, and uses `void` for T when its used as a set.
template <class Key,
          class T, // when void, treat it as a set.
          class Hash,
          class KeyEqual,
          class Allocator>
class table {
    struct Bucket;
    using ValueContainer =
        typename std::vector<typename std::conditional_t<std::is_void_v<T>, Key, std::pair<Key, T>>, Allocator>;
    using BucketAlloc = typename std::allocator_traits<Allocator>::template rebind_alloc<Bucket>;
    using BucketAllocTraits = std::allocator_traits<BucketAlloc>;

    static constexpr uint32_t BUCKET_DIST_INC = 1U << 8U;                    // skip 1 byte fingerprint
    static constexpr uint32_t BUCKET_FINGERPRINT_MASK = BUCKET_DIST_INC - 1; // mask for 1 byte of fingerprint
    static constexpr uint8_t INITIAL_SHIFTS = 64 - 3;                        // 2^(64-m_shift) number of buckets
    static constexpr float DEFAULT_MAX_LOAD_FACTOR = 0.8F;

public:
    using key_type = Key;
    using mapped_type = T;
    using value_type = typename ValueContainer::value_type;
    using size_type = typename ValueContainer::size_type;
    using difference_type = typename ValueContainer::difference_type;
    using hasher = Hash;
    using key_equal = KeyEqual;
    using allocator_type = typename ValueContainer::allocator_type;
    using reference = typename ValueContainer::reference;
    using const_reference = typename ValueContainer::const_reference;
    using pointer = typename ValueContainer::pointer;
    using const_pointer = typename ValueContainer::const_pointer;
    using iterator = typename ValueContainer::iterator;
    using const_iterator = typename ValueContainer::const_iterator;

private:
    struct Bucket {
        uint32_t dist_and_fingerprint; // upper 3 byte: distance to original bucket. lower byte: fingerprint from hash
        uint32_t value_idx;            // index into the m_values vector.
    };
    static_assert(std::is_trivially_destructible_v<Bucket>, "assert there's no need to call destructor / std::destroy");
    static_assert(std::is_trivially_copyable_v<Bucket>, "assert we can just memset / memcpy");

    ValueContainer m_values{}; // Contains all the key-value pairs in one densely stored container. No holes.
    Bucket* m_buckets_start = nullptr;
    Bucket* m_buckets_end = nullptr;
    uint32_t m_max_bucket_capacity = 0;
    float m_max_load_factor = DEFAULT_MAX_LOAD_FACTOR;
    Hash m_hash{};
    KeyEqual m_equal{};
    uint8_t m_shifts = INITIAL_SHIFTS;

    [[nodiscard]] auto next(Bucket const* bucket) const -> Bucket const* {
        return ANKERL_UNORDERED_DENSE_UNLIKELY(bucket + 1 == m_buckets_end) ? m_buckets_start : bucket + 1;
    }

    [[nodiscard]] auto next(Bucket* bucket) -> Bucket* {
        return ANKERL_UNORDERED_DENSE_UNLIKELY(bucket + 1 == m_buckets_end) ? m_buckets_start : bucket + 1;
    }

    template <typename K>
    [[nodiscard]] constexpr auto mixed_hash(K const& key) const -> uint64_t {
        if constexpr (is_detected_v<detect_avalanching, Hash>) {
            return m_hash(key);
        } else {
            return wyhash::hash(m_hash(key));
        }
    }

    [[nodiscard]] constexpr auto dist_and_fingerprint_from_hash(uint64_t hash) const -> uint32_t {
        return BUCKET_DIST_INC | (hash & BUCKET_FINGERPRINT_MASK);
    }

    [[nodiscard]] constexpr auto bucket_from_hash(uint64_t hash) const -> Bucket const* {
        return m_buckets_start + (hash >> m_shifts);
    }

    [[nodiscard]] constexpr auto bucket_from_hash(uint64_t hash) -> Bucket* {
        return m_buckets_start + (hash >> m_shifts);
    }

    [[nodiscard]] static constexpr auto get_key(value_type const& vt) -> key_type const& {
        if constexpr (std::is_void_v<T>) {
            return vt;
        } else {
            return vt.first;
        }
    }

    template <typename K>
    [[nodiscard]] auto next_while_less(K const& key) -> std::pair<uint32_t, Bucket*> {
        auto const& pair = std::as_const(*this).next_while_less(key);
        return {pair.first, const_cast<Bucket*>(pair.second)}; // NOLINT(cppcoreguidelines-pro-type-const-cast)
    }

    template <typename K>
    [[nodiscard]] auto next_while_less(K const& key) const -> std::pair<uint32_t, Bucket const*> {
        auto hash = mixed_hash(key);
        auto dist_and_fingerprint = dist_and_fingerprint_from_hash(hash);
        auto const* bucket = bucket_from_hash(hash);

        while (dist_and_fingerprint < bucket->dist_and_fingerprint) {
            dist_and_fingerprint += BUCKET_DIST_INC;
            bucket = next(bucket);
        }
        return {dist_and_fingerprint, bucket};
    }

    void place_and_shift_up(Bucket bucket, Bucket* place) {
        while (0 != place->dist_and_fingerprint) {
            bucket = std::exchange(*place, bucket);
            bucket.dist_and_fingerprint += BUCKET_DIST_INC;
            place = next(place);
        }
        *place = bucket;
    }

    [[nodiscard]] static constexpr auto calc_num_buckets(uint8_t shifts) -> uint64_t {
        return UINT64_C(1) << (64U - shifts);
    }

    [[nodiscard]] constexpr auto calc_shifts_for_size(size_t s) const -> uint8_t {
        auto shifts = INITIAL_SHIFTS;
        while (shifts > 0 && static_cast<uint64_t>(calc_num_buckets(shifts) * max_load_factor()) < s) {
            --shifts;
        }
        return shifts;
    }

    // assumes m_values has data, m_buckets_start=m_buckets_end=nullptr, m_shifts is INITIAL_SHIFTS
    void copy_buckets(table const& other) {
        if (!empty()) {
            m_shifts = other.m_shifts;
            allocate_buckets_from_shift();
            std::memcpy(m_buckets_start, other.m_buckets_start, sizeof(Bucket) * bucket_count());
        }
    }

    /**
     * True when no element can be added any more without increasing the size
     */
    [[nodiscard]] auto is_full() const -> bool {
        return size() >= m_max_bucket_capacity;
    }

    void deallocate_buckets() {
        auto bucket_alloc = BucketAlloc(m_values.get_allocator());
        BucketAllocTraits::deallocate(bucket_alloc, m_buckets_start, bucket_count());
        m_buckets_start = nullptr;
        m_buckets_end = nullptr;
        m_max_bucket_capacity = 0;
    }

    void allocate_buckets_from_shift() {
        auto bucket_alloc = BucketAlloc(m_values.get_allocator());
        auto num_buckets = calc_num_buckets(m_shifts);
        m_buckets_start = BucketAllocTraits::allocate(bucket_alloc, num_buckets);
        m_buckets_end = m_buckets_start + num_buckets;
        m_max_bucket_capacity = static_cast<uint64_t>(num_buckets * max_load_factor());
    }

    void clear_buckets() {
        if (m_buckets_start != nullptr) {
            std::memset(m_buckets_start, 0, sizeof(Bucket) * bucket_count());
        }
    }

    void clear_and_fill_buckets_from_values() {
        clear_buckets();
        for (uint32_t value_idx = 0, end_idx = static_cast<uint32_t>(m_values.size()); value_idx < end_idx; ++value_idx) {
            auto const& key = get_key(m_values[value_idx]);
            auto [dist_and_fingerprint, bucket] = next_while_less(key);

            // we know for certain that key has not yet been inserted, so no need to check it.
            place_and_shift_up({dist_and_fingerprint, value_idx}, bucket);
        }
    }

    void increase_size() {
        --m_shifts;
        deallocate_buckets();
        allocate_buckets_from_shift();
        clear_and_fill_buckets_from_values();
    }

    void do_erase(Bucket* bucket) {
        auto const value_idx_to_remove = bucket->value_idx;

        // shift down until either empty or an element with correct spot is found
        auto* next_bucket = next(bucket);
        while (next_bucket->dist_and_fingerprint >= BUCKET_DIST_INC * 2) {
            *bucket = {next_bucket->dist_and_fingerprint - BUCKET_DIST_INC, next_bucket->value_idx};
            bucket = std::exchange(next_bucket, next(next_bucket));
        }
        *bucket = {};

        // update m_values
        if (value_idx_to_remove != m_values.size() - 1) {
            // no luck, we'll have to replace the value with the last one and update the index accordingly
            auto& val = m_values[value_idx_to_remove];
            val = std::move(m_values.back());

            // update the values_idx of the moved entry. No need to play the info game, just look until we find the values_idx
            auto mh = mixed_hash(get_key(val));
            bucket = bucket_from_hash(mh);

            auto const values_idx_back = static_cast<uint32_t>(m_values.size() - 1);
            while (values_idx_back != bucket->value_idx) {
                bucket = next(bucket);
            }
            bucket->value_idx = value_idx_to_remove;
        }
        m_values.pop_back();
    }

    template <typename K>
    auto do_erase_key(K&& key) -> size_t {
        if (empty()) {
            return 0;
        }

        auto [dist_and_fingerprint, bucket] = next_while_less(key);

        while (dist_and_fingerprint == bucket->dist_and_fingerprint && !m_equal(key, get_key(m_values[bucket->value_idx]))) {
            dist_and_fingerprint += BUCKET_DIST_INC;
            bucket = next(bucket);
        }

        if (dist_and_fingerprint != bucket->dist_and_fingerprint) {
            return 0;
        }
        do_erase(bucket);
        return 1;
    }

    template <class K, class M>
    auto do_insert_or_assign(K&& key, M&& mapped) -> std::pair<iterator, bool> {
        auto it_isinserted = try_emplace(std::forward<K>(key), std::forward<M>(mapped));
        if (!it_isinserted.second) {
            it_isinserted.first->second = std::forward<M>(mapped);
        }
        return it_isinserted;
    }

    template <typename K, typename... Args>
    auto do_try_emplace(K&& key, Args&&... args) -> std::pair<iterator, bool> {
        if (is_full()) {
            increase_size();
        }

        auto hash = mixed_hash(key);
        auto dist_and_fingerprint = dist_and_fingerprint_from_hash(hash);
        auto* bucket = bucket_from_hash(hash);

        while (dist_and_fingerprint <= bucket->dist_and_fingerprint) {
            if (dist_and_fingerprint == bucket->dist_and_fingerprint && m_equal(key, m_values[bucket->value_idx].first)) {
                return {begin() + bucket->value_idx, false};
            }
            dist_and_fingerprint += BUCKET_DIST_INC;
            bucket = next(bucket);
        }

        // emplace the new value. If that throws an exception, no harm done; index is still in a valid state
        m_values.emplace_back(std::piecewise_construct,
                              std::forward_as_tuple(std::forward<K>(key)),
                              std::forward_as_tuple(std::forward<Args>(args)...));

        // place element and shift up until we find an empty spot
        uint32_t value_idx = static_cast<uint32_t>(m_values.size()) - 1;
        place_and_shift_up({dist_and_fingerprint, value_idx}, bucket);
        return {begin() + value_idx, true};
    }

    template <typename K>
    auto do_find(K const& key) -> iterator {
        if (empty()) {
            return end();
        }

        auto mh = mixed_hash(key);
        auto dist_and_fingerprint = dist_and_fingerprint_from_hash(mh);
        auto const* bucket = bucket_from_hash(mh);

        // unrolled loop. *Always* check a few directly, then enter the loop. This is faster.
        if (dist_and_fingerprint == bucket->dist_and_fingerprint && m_equal(key, get_key(m_values[bucket->value_idx]))) {
            return begin() + bucket->value_idx;
        }
        dist_and_fingerprint += BUCKET_DIST_INC;
        bucket = next(bucket);

        if (dist_and_fingerprint == bucket->dist_and_fingerprint && m_equal(key, get_key(m_values[bucket->value_idx]))) {
            return begin() + bucket->value_idx;
        }
        dist_and_fingerprint += BUCKET_DIST_INC;
        bucket = next(bucket);

        do {
            if (dist_and_fingerprint == bucket->dist_and_fingerprint && m_equal(key, get_key(m_values[bucket->value_idx]))) {
                return begin() + bucket->value_idx;
            }
            dist_and_fingerprint += BUCKET_DIST_INC;
            bucket = next(bucket);
        } while (dist_and_fingerprint <= bucket->dist_and_fingerprint);
        return end();
    }

    template <typename K>
    auto do_find(K const& key) const -> const_iterator {
        return const_cast<table*>(this)->do_find(key); // NOLINT(cppcoreguidelines-pro-type-const-cast)
    }

public:
    table()
        : table(0) {}

    explicit table(size_t /*bucket_count*/,
                   Hash const& hash = Hash(),
                   KeyEqual const& equal = KeyEqual(),
                   Allocator const& alloc = Allocator())
        : m_values(alloc)
        , m_hash(hash)
        , m_equal(equal) {}

    table(size_t bucket_count, Allocator const& alloc)
        : table(bucket_count, Hash(), KeyEqual(), alloc) {}

    table(size_t bucket_count, Hash const& hash, Allocator const& alloc)
        : table(bucket_count, hash, KeyEqual(), alloc) {}

    explicit table(Allocator const& alloc)
        : table(0, Hash(), KeyEqual(), alloc) {}

    template <class InputIt>
    table(InputIt first,
          InputIt last,
          size_type bucket_count = 0,
          Hash const& hash = Hash(),
          KeyEqual const& equal = KeyEqual(),
          Allocator const& alloc = Allocator())
        : table(bucket_count, hash, equal, alloc) {
        insert(first, last);
    }

    template <class InputIt>
    table(InputIt first, InputIt last, size_type bucket_count, Allocator const& alloc)
        : table(first, last, bucket_count, Hash(), KeyEqual(), alloc) {}

    template <class InputIt>
    table(InputIt first, InputIt last, size_type bucket_count, Hash const& hash, Allocator const& alloc)
        : table(first, last, bucket_count, hash, KeyEqual(), alloc) {}

    table(table const& other)
        : table(other, other.m_values.get_allocator()) {}

    table(table const& other, Allocator const& alloc)
        : m_values(other.m_values, alloc)
        , m_max_load_factor(other.m_max_load_factor)
        , m_hash(other.m_hash)
        , m_equal(other.m_equal) {
        copy_buckets(other);
    }

    table(table&& other) noexcept
        : table(std::move(other), other.m_values.get_allocator()) {}

    table(table&& other, Allocator const& alloc) noexcept
        : m_values(std::move(other.m_values), alloc)
        , m_buckets_start(std::exchange(other.m_buckets_start, nullptr))
        , m_buckets_end(std::exchange(other.m_buckets_end, nullptr))
        , m_max_bucket_capacity(std::exchange(other.m_max_bucket_capacity, 0))
        , m_max_load_factor(std::exchange(other.m_max_load_factor, DEFAULT_MAX_LOAD_FACTOR))
        , m_hash(std::exchange(other.m_hash, {}))
        , m_equal(std::exchange(other.m_equal, {}))
        , m_shifts(std::exchange(other.m_shifts, INITIAL_SHIFTS)) {
        other.m_values.clear();
    }

    table(std::initializer_list<value_type> ilist,
          size_t bucket_count = 0,
          Hash const& hash = Hash(),
          KeyEqual const& equal = KeyEqual(),
          Allocator const& alloc = Allocator())
        : table(bucket_count, hash, equal, alloc) {
        insert(ilist);
    }

    table(std::initializer_list<value_type> ilist, size_type bucket_count, const Allocator& alloc)
        : table(ilist, bucket_count, Hash(), KeyEqual(), alloc) {}

    table(std::initializer_list<value_type> init, size_type bucket_count, Hash const& hash, Allocator const& alloc)
        : table(init, bucket_count, hash, KeyEqual(), alloc) {}

    ~table() {
        auto bucket_alloc = BucketAlloc(m_values.get_allocator());
        BucketAllocTraits::deallocate(bucket_alloc, m_buckets_start, bucket_count());
    }

    auto operator=(table const& other) -> table& {
        if (&other != this) {
            deallocate_buckets(); // deallocate before m_values is set (might have another allocator)
            m_values = other.m_values;
            m_max_load_factor = other.m_max_load_factor;
            m_hash = other.m_hash;
            m_equal = other.m_equal;
            m_shifts = INITIAL_SHIFTS;
            copy_buckets(other);
        }
        return *this;
    }

    auto operator=(table&& other) noexcept(
        noexcept(std::is_nothrow_move_assignable_v<ValueContainer>&& std::is_nothrow_move_assignable_v<Hash>&&
                     std::is_nothrow_move_assignable_v<KeyEqual>)) -> table& {
        if (&other != this) {
            deallocate_buckets(); // deallocate before m_values is set (might have another allocator)
            m_values = std::move(other.m_values);
            m_buckets_start = std::exchange(other.m_buckets_start, nullptr);
            m_buckets_end = std::exchange(other.m_buckets_end, nullptr);
            m_max_bucket_capacity = std::exchange(other.m_max_bucket_capacity, 0);
            m_max_load_factor = std::exchange(other.m_max_load_factor, DEFAULT_MAX_LOAD_FACTOR);
            m_hash = std::exchange(other.m_hash, {});
            m_equal = std::exchange(other.m_equal, {});
            m_shifts = std::exchange(other.m_shifts, INITIAL_SHIFTS);
            other.m_values.clear();
        }
        return *this;
    }

    auto operator=(std::initializer_list<value_type> ilist) -> table& {
        clear();
        insert(ilist);
        return *this;
    }

    auto get_allocator() const noexcept -> allocator_type {
        return m_values.get_allocator();
    }

    // iterators //////////////////////////////////////////////////////////////

    auto begin() noexcept -> iterator {
        return m_values.begin();
    }

    auto begin() const noexcept -> const_iterator {
        return m_values.begin();
    }

    auto cbegin() const noexcept -> const_iterator {
        return m_values.cbegin();
    }

    auto end() noexcept -> iterator {
        return m_values.end();
    }

    auto cend() const noexcept -> const_iterator {
        return m_values.cend();
    }

    auto end() const noexcept -> const_iterator {
        return m_values.end();
    }

    // capacity ///////////////////////////////////////////////////////////////

    [[nodiscard]] auto empty() const noexcept -> bool {
        return m_values.empty();
    }

    [[nodiscard]] auto size() const noexcept -> size_t {
        return m_values.size();
    }

    [[nodiscard]] auto max_size() const noexcept -> size_t {
        return std::numeric_limits<uint32_t>::max();
    }

    // modifiers //////////////////////////////////////////////////////////////

    void clear() {
        m_values.clear();
        clear_buckets();
    }

    auto insert(value_type const& value) -> std::pair<iterator, bool> {
        return emplace(value);
    }

    auto insert(value_type&& value) -> std::pair<iterator, bool> {
        return emplace(std::move(value));
    }

    template <class P, std::enable_if_t<std::is_constructible_v<value_type, P&&>, bool> = true>
    auto insert(P&& value) -> std::pair<iterator, bool> {
        return emplace(std::forward<P>(value));
    }

    auto insert(const_iterator /*hint*/, value_type const& value) -> iterator {
        return insert(value).first;
    }

    auto insert(const_iterator /*hint*/, value_type&& value) -> iterator {
        return insert(std::move(value)).first;
    }

    template <class P, std::enable_if_t<std::is_constructible_v<value_type, P&&>, bool> = true>
    auto insert(const_iterator /*hint*/, P&& value) -> iterator {
        return insert(std::forward<P>(value)).first;
    }

    template <class InputIt>
    void insert(InputIt first, InputIt last) {
        while (first != last) {
            insert(*first);
            ++first;
        }
    }

    void insert(std::initializer_list<value_type> ilist) {
        insert(ilist.begin(), ilist.end());
    }

    template <class M, typename Q = T, std::enable_if_t<!std::is_void_v<Q>, bool> = true>
    auto insert_or_assign(Key const& key, M&& mapped) -> std::pair<iterator, bool> {
        return do_insert_or_assign(key, std::forward<M>(mapped));
    }

    template <class M, typename Q = T, std::enable_if_t<!std::is_void_v<Q>, bool> = true>
    auto insert_or_assign(Key&& key, M&& mapped) -> std::pair<iterator, bool> {
        return do_insert_or_assign(std::move(key), std::forward<M>(mapped));
    }

    template <class M, typename Q = T, std::enable_if_t<!std::is_void_v<Q>, bool> = true>
    auto insert_or_assign(const_iterator /*hint*/, Key const& key, M&& mapped) -> iterator {
        return do_insert_or_assign(key, std::forward<M>(mapped)).first;
    }

    template <class M, typename Q = T, std::enable_if_t<!std::is_void_v<Q>, bool> = true>
    auto insert_or_assign(const_iterator /*hint*/, Key&& key, M&& mapped) -> iterator {
        return do_insert_or_assign(std::move(key), std::forward<M>(mapped)).first;
    }

    template <class... Args>
    auto emplace(Args&&... args) -> std::pair<iterator, bool> {
        if (is_full()) {
            increase_size();
        }

        // first emplace_back the object so it is constructed. If the key is already there, pop it.
        auto& val = m_values.emplace_back(std::forward<Args>(args)...);
        auto hash = mixed_hash(get_key(val));
        auto dist_and_fingerprint = dist_and_fingerprint_from_hash(hash);
        auto* bucket = bucket_from_hash(hash);

        while (dist_and_fingerprint <= bucket->dist_and_fingerprint) {
            if (dist_and_fingerprint == bucket->dist_and_fingerprint &&
                m_equal(get_key(val), get_key(m_values[bucket->value_idx]))) {
                m_values.pop_back(); // value was already there, so get rid of it
                return {begin() + bucket->value_idx, false};
            }
            dist_and_fingerprint += BUCKET_DIST_INC;
            bucket = next(bucket);
        }

        // value is new, place the bucket and shift up until we find an empty spot
        uint32_t value_idx = static_cast<uint32_t>(m_values.size()) - 1;
        place_and_shift_up({dist_and_fingerprint, value_idx}, bucket);

        return {begin() + value_idx, true};
    }

    template <class... Args>
    auto emplace_hint(const_iterator /*hint*/, Args&&... args) -> iterator {
        return emplace(std::forward<Args>(args)...).first;
    }

    template <class... Args, typename Q = T, std::enable_if_t<!std::is_void_v<Q>, bool> = true>
    auto try_emplace(Key const& key, Args&&... args) -> std::pair<iterator, bool> {
        return do_try_emplace(key, std::forward<Args>(args)...);
    }

    template <class... Args, typename Q = T, std::enable_if_t<!std::is_void_v<Q>, bool> = true>
    auto try_emplace(Key&& key, Args&&... args) -> std::pair<iterator, bool> {
        return do_try_emplace(std::move(key), std::forward<Args>(args)...);
    }

    template <class... Args, typename Q = T, std::enable_if_t<!std::is_void_v<Q>, bool> = true>
    auto try_emplace(const_iterator /*hint*/, Key const& key, Args&&... args) -> iterator {
        return do_try_emplace(key, std::forward<Args>(args)...).first;
    }

    template <class... Args, typename Q = T, std::enable_if_t<!std::is_void_v<Q>, bool> = true>
    auto try_emplace(const_iterator /*hint*/, Key&& key, Args&&... args) -> iterator {
        return do_try_emplace(std::move(key), std::forward<Args>(args)...).first;
    }

    auto erase(iterator it) -> iterator {
        auto hash = mixed_hash(get_key(*it));
        auto* bucket = bucket_from_hash(hash);

        auto const value_idx_to_remove = static_cast<uint32_t>(it - cbegin());
        while (bucket->value_idx != value_idx_to_remove) {
            bucket = next(bucket);
        }

        do_erase(bucket);
        return begin() + value_idx_to_remove;
    }

    auto erase(const_iterator it) -> iterator {
        return erase(begin() + (it - cbegin()));
    }

    auto erase(const_iterator first, const_iterator last) -> iterator {
        auto const idx_first = first - cbegin();
        auto const idx_last = last - cbegin();
        auto const first_to_last = std::distance(first, last);
        auto const last_to_end = std::distance(last, cend());

        // remove elements from left to right which moves elements from the end back
        auto const mid = idx_first + std::min(first_to_last, last_to_end);
        auto idx = idx_first;
        while (idx != mid) {
            erase(begin() + idx);
            ++idx;
        }

        // all elements from the right are moved, now remove the last element until all done
        idx = idx_last;
        while (idx != mid) {
            --idx;
            erase(begin() + idx);
        }

        return begin() + idx_first;
    }

    auto erase(Key const& key) -> size_t {
        return do_erase_key(key);
    }

    template <class K, class H = Hash, class KE = KeyEqual, is_transparent<H, KE> = true>
    auto erase(K&& key) -> size_t {
        return do_erase_key(std::forward<K>(key));
    }

    void swap(table& other) noexcept(noexcept(std::is_nothrow_swappable_v<ValueContainer>&& std::is_nothrow_swappable_v<Hash>&&
                                                  std::is_nothrow_swappable_v<KeyEqual>)) {
        using std::swap;
        swap(other, *this);
    }

    // lookup /////////////////////////////////////////////////////////////////

    template <typename Q = T, std::enable_if_t<!std::is_void_v<Q>, bool> = true>
    auto at(key_type const& key) -> Q& {
        if (auto it = find(key); end() != it) {
            return it->second;
        }
        throw std::out_of_range("ankerl::unordered_dense::map::at(): key not found");
    } // LCOV_EXCL_LINE is this a gcov/lcov bug? this method is fully tested.

    template <typename Q = T, std::enable_if_t<!std::is_void_v<Q>, bool> = true>
    auto at(key_type const& key) const -> Q const& {
        return const_cast<table*>(this)->at(key); // NOLINT(cppcoreguidelines-pro-type-const-cast)
    }

    template <typename Q = T, std::enable_if_t<!std::is_void_v<Q>, bool> = true>
    auto operator[](Key const& key) -> Q& {
        return try_emplace(key).first->second;
    }

    template <typename Q = T, std::enable_if_t<!std::is_void_v<Q>, bool> = true>
    auto operator[](Key&& key) -> Q& {
        return try_emplace(std::move(key)).first->second;
    }

    auto count(Key const& key) const -> size_t {
        return find(key) == end() ? 0 : 1;
    }

    template <class K, class H = Hash, class KE = KeyEqual, is_transparent<H, KE> = true>
    auto count(K const& key) const -> size_t {
        return find(key) == end() ? 0 : 1;
    }

    auto find(Key const& key) -> iterator {
        return do_find(key);
    }

    auto find(Key const& key) const -> const_iterator {
        return do_find(key);
    }

    template <class K, class H = Hash, class KE = KeyEqual, is_transparent<H, KE> = true>
    auto find(K const& key) -> iterator {
        return do_find(key);
    }

    template <class K, class H = Hash, class KE = KeyEqual, is_transparent<H, KE> = true>
    auto find(K const& key) const -> const_iterator {
        return do_find(key);
    }

    auto contains(Key const& key) const -> size_t {
        return find(key) != end();
    }

    template <class K, class H = Hash, class KE = KeyEqual, is_transparent<H, KE> = true>
    auto contains(K const& key) const -> size_t {
        return find(key) != end();
    }

    auto equal_range(Key const& key) -> std::pair<iterator, iterator> {
        auto it = do_find(key);
        return {it, it == end() ? end() : it + 1};
    }

    auto equal_range(const Key& key) const -> std::pair<const_iterator, const_iterator> {
        auto it = do_find(key);
        return {it, it == end() ? end() : it + 1};
    }

    template <class K, class H = Hash, class KE = KeyEqual, is_transparent<H, KE> = true>
    auto equal_range(K const& key) -> std::pair<iterator, iterator> {
        auto it = do_find(key);
        return {it, it == end() ? end() : it + 1};
    }

    template <class K, class H = Hash, class KE = KeyEqual, is_transparent<H, KE> = true>
    auto equal_range(K const& key) const -> std::pair<const_iterator, const_iterator> {
        auto it = do_find(key);
        return {it, it == end() ? end() : it + 1};
    }

    // bucket interface ///////////////////////////////////////////////////////

    auto bucket_count() const noexcept -> size_t { // NOLINT(modernize-use-nodiscard)
        return m_buckets_end - m_buckets_start;
    }

    auto max_bucket_count() const noexcept -> size_t { // NOLINT(modernize-use-nodiscard)
        return std::numeric_limits<uint32_t>::max();
    }

    // hash policy ////////////////////////////////////////////////////////////

    [[nodiscard]] auto load_factor() const -> float {
        return bucket_count() ? static_cast<float>(size()) / bucket_count() : 0.0F;
    }

    [[nodiscard]] auto max_load_factor() const -> float {
        return m_max_load_factor;
    }

    void max_load_factor(float ml) {
        m_max_load_factor = ml;
        m_max_bucket_capacity = static_cast<uint32_t>(bucket_count() * max_load_factor());
    }

    void rehash(size_t count) {
        auto shifts = calc_shifts_for_size(std::max(count, size()));
        if (shifts != m_shifts) {
            m_shifts = shifts;
            deallocate_buckets();
            m_values.shrink_to_fit();
            allocate_buckets_from_shift();
            clear_and_fill_buckets_from_values();
        }
    }

    void reserve(size_t capa) {
        auto shifts = calc_shifts_for_size(std::max(capa, size()));
        if (shifts < m_shifts) {
            m_shifts = shifts;
            deallocate_buckets();
            allocate_buckets_from_shift();
            clear_and_fill_buckets_from_values();
        }
    }

    // observers //////////////////////////////////////////////////////////////

    auto hash_function() const -> hasher {
        return m_hash;
    }

    auto key_eq() const -> key_equal {
        return m_equal;
    }

    // non-member functions ///////////////////////////////////////////////////

    friend auto operator==(table const& a, table const& b) -> bool {
        if (&a == &b) {
            return true;
        }
        if (a.size() != b.size()) {
            return false;
        }
        for (auto const& b_entry : b) {
            auto it = a.find(get_key(b_entry));
            if constexpr (std::is_void_v<T>) {
                // set: only check that the key is here
                if (a.end() == it) {
                    return false;
                }
            } else {
                // map: check that key is here, then also check that value is the same
                if (a.end() == it || !(b_entry.second == it->second)) {
                    return false;
                }
            }
        }
        return true;
    }

    friend auto operator!=(table const& a, table const& b) -> bool {
        return !(a == b);
    }
};

} // namespace detail

template <class Key,
          class T,
          class Hash = hash<Key>,
          class KeyEqual = std::equal_to<Key>,
          class Allocator = std::allocator<std::pair<Key, T>>>
using map = detail::table<Key, T, Hash, KeyEqual, Allocator>;

template <class Key, class Hash = hash<Key>, class KeyEqual = std::equal_to<Key>, class Allocator = std::allocator<Key>>
using set = detail::table<Key, void, Hash, KeyEqual, Allocator>;

#    if ANKERL_UNORDERED_DENSE_PMR

namespace pmr {

template <class Key, class T, class Hash = hash<Key>, class KeyEqual = std::equal_to<Key>>
using map = detail::table<Key, T, Hash, KeyEqual, std::pmr::polymorphic_allocator<std::pair<Key, T>>>;

template <class Key, class Hash = hash<Key>, class KeyEqual = std::equal_to<Key>>
using set = detail::table<Key, void, Hash, KeyEqual, std::pmr::polymorphic_allocator<Key>>;

} // namespace pmr

#    endif

// deduction guides ///////////////////////////////////////////////////////////

// deduction guides for alias templates are only possible since C++20
// see https://en.cppreference.com/w/cpp/language/class_template_argument_deduction

} // namespace ankerl::unordered_dense

// std extensions /////////////////////////////////////////////////////////////

namespace std { // NOLINT(cert-dcl58-cpp)

template <class Key, class T, class Hash, class KeyEqual, class Allocator, class Pred>
auto erase_if(ankerl::unordered_dense::detail::table<Key, T, Hash, KeyEqual, Allocator>& map, Pred pred) -> size_t {
    // going back to front because erase() invalidates the end iterator
    auto const old_size = map.size();
    auto idx = old_size;
    while (idx) {
        --idx;
        auto it = map.begin() + idx;
        if (pred(*it)) {
            map.erase(it);
        }
    }

    return map.size() - old_size;
}

} // namespace std

#endif
#endif
