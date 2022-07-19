// ┌─┐┬  ┬┌─┐┌─┐┌┬┐┌─┐┬─┐   Compact SVO optimized vector C++17 or higher
// └─┐└┐┌┘├┤ │   │ │ │├┬┘   Version 1.0.1
// └─┘ └┘ └─┘└─┘ ┴ └─┘┴└─   https://github.com/martinus/svector
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

#ifndef ANKERL_SVECTOR_H
#define ANKERL_SVECTOR_H

// see https://semver.org/spec/v2.0.0.html
#define ANKERL_SVECTOR_VERSION_MAJOR 1 // incompatible API changes
#define ANKERL_SVECTOR_VERSION_MINOR 0 // add functionality in a backwards compatible manner
#define ANKERL_SVECTOR_VERSION_PATCH 1 // backwards compatible bug fixes

// API versioning with inline namespace, see https://www.foonathan.net/2018/11/inline-namespaces/
#define ANKERL_SVECTOR_VERSION_CONCAT1(major, minor, patch) v##major##_##minor##_##patch
#define ANKERL_SVECTOR_VERSION_CONCAT(major, minor, patch) ANKERL_SVECTOR_VERSION_CONCAT1(major, minor, patch)
#define ANKERL_SVECTOR_NAMESPACE \
    ANKERL_SVECTOR_VERSION_CONCAT(ANKERL_SVECTOR_VERSION_MAJOR, ANKERL_SVECTOR_VERSION_MINOR, ANKERL_SVECTOR_VERSION_PATCH)

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <initializer_list>
#include <iterator>
#include <limits>
#include <memory>
#include <new>
#include <stdexcept>
#include <type_traits>
#include <utility>

namespace ankerl {
inline namespace ANKERL_SVECTOR_NAMESPACE {
namespace detail {

template <typename Condition, typename T = void>
using enable_if_t = typename std::enable_if<Condition::value, T>::type;

template <typename It>
using is_input_iterator = std::is_base_of<std::input_iterator_tag, typename std::iterator_traits<It>::iterator_category>;

constexpr auto round_up(size_t n, size_t multiple) -> size_t {
    return ((n + (multiple - 1)) / multiple) * multiple;
}

template <typename T>
constexpr auto cx_min(T a, T b) -> T {
    return a < b ? a : b;
}

template <typename T>
constexpr auto cx_max(T a, T b) -> T {
    return a > b ? a : b;
}

template <typename T>
constexpr auto alignment_of_svector() -> size_t {
    return cx_max(sizeof(void*), std::alignment_of_v<T>);
}

/**
 * @brief Calculates sizeof(svector<T, N>) for a given type and inline capacity
 */
template <typename T>
constexpr auto size_of_svector(size_t min_inline_capacity) -> size_t {
    // + 1 for one byte size in direct mode
    return round_up(sizeof(T) * min_inline_capacity + 1, alignment_of_svector<T>());
}

/**
 * @brief Calculates how many T we can actually store inside of an svector without increasing its sizeof().
 *
 * E.g. svector<char, 1> could store 7 bytes even though 1 is specified. This makes sure we don't waste any
 * of the padding.
 */
template <typename T>
constexpr auto automatic_capacity(size_t min_inline_capacity) -> size_t {
    return cx_min((size_of_svector<T>(min_inline_capacity) - 1U) / sizeof(T), size_t(127));
}

/**
 * Holds size & capacity, a glorified struct.
 */
class header {
    size_t m_size{};
    size_t const m_capacity;

public:
    inline explicit header(size_t capacity)
        : m_capacity{capacity} {}

    [[nodiscard]] inline auto size() const -> size_t {
        return m_size;
    }

    [[nodiscard]] inline auto capacity() const -> size_t {
        return m_capacity;
    }

    inline void size(size_t s) {
        m_size = s;
    }
};

/**
 * @brief Holds header (size+capacity) plus an arbitrary number of T.
 *
 * To make storage compact, we don't actually store a pointer to T. We don't have to
 * because we know exactly at which location it begins.
 */
template <typename T>
struct storage : public header {
    static constexpr auto alignment_of_t = std::alignment_of_v<T>;
    static constexpr auto max_alignment = std::max(std::alignment_of_v<header>, std::alignment_of_v<T>);
    static constexpr auto offset_to_data = detail::round_up(sizeof(header), alignment_of_t);
    static_assert(max_alignment <= __STDCPP_DEFAULT_NEW_ALIGNMENT__);

    explicit storage(size_t capacity)
        : header(capacity) {}

    auto data() -> T* {
        auto ptr_to_data = reinterpret_cast<std::byte*>(this) + offset_to_data;
        return std::launder(reinterpret_cast<T*>(ptr_to_data));
    }

    /**
     * @brief Allocates space for storage plus capacity*T objects.
     *
     * Checks to make sure that allocation won't overflow.
     *
     * @param capacity Number of T to allocate.
     * @return storage<T>*
     */
    static auto alloc(size_t capacity) -> storage<T>* {
        // make sure we don't overflow!
        auto mem = sizeof(T) * capacity;
        if (mem < capacity) {
            throw std::bad_alloc();
        }
        if (offset_to_data + mem < mem) {
            throw std::bad_alloc();
        }
        mem += offset_to_data;
        if (static_cast<uint64_t>(mem) > static_cast<uint64_t>(std::numeric_limits<std::ptrdiff_t>::max())) {
            throw std::bad_alloc();
        }

        void* ptr = ::operator new(offset_to_data + sizeof(T) * capacity);
        if (nullptr == ptr) {
            throw std::bad_alloc();
        }
        // use void* to ensure we don't use an overload for T*
        return new (ptr) storage<T>(capacity);
    }
};

} // namespace detail

template <typename T, size_t MinInlineCapacity>
class svector {
    static_assert(MinInlineCapacity <= 127, "sorry, can't have more than 127 direct elements");
    static constexpr auto N = detail::automatic_capacity<T>(MinInlineCapacity);

    enum class direction { direct, indirect };

    /**
     * A buffer to hold the data of the svector Depending on direct/indirect mode, the content it holds is like so:
     *
     * direct:
     *    m_data[0] & 1: lowest bit is 1 for direct mode.
     *    m_data[0] >> 1: size for direct mode
     *    Then 0-X bytes unused (padding), and then the actual inline T data.
     * indirect:
     *    m_data[0] & 1: lowest bit is 0 for indirect mode
     *    m_data[0..7]: stores an uintptr_t, which points to the indirect data.
     */
    alignas(detail::alignment_of_svector<T>()) std::array<uint8_t, detail::size_of_svector<T>(MinInlineCapacity)> m_data;

    // direct mode ///////////////////////////////////////////////////////////

    [[nodiscard]] auto is_direct() const -> bool {
        return (m_data[0] & 1U) != 0U;
    }

    [[nodiscard]] auto direct_size() const -> size_t {
        return m_data[0] >> 1U;
    }

    // sets size of direct mode and mode to direct too.
    constexpr void set_direct_and_size(size_t s) {
        m_data[0] = (s << 1U) | 1U;
    }

    [[nodiscard]] auto direct_data() -> T* {
        return std::launder(reinterpret_cast<T*>(m_data.data() + std::alignment_of_v<T>));
    }

    // indirect mode /////////////////////////////////////////////////////////

    [[nodiscard]] auto indirect() -> detail::storage<T>* {
        detail::storage<T>* ptr; // NOLINT(cppcoreguidelines-init-variables)
        std::memcpy(&ptr, m_data.data(), sizeof(ptr));
        return ptr;
    }

    [[nodiscard]] auto indirect() const -> detail::storage<T> const* {
        return const_cast<svector*>(this)->indirect(); // NOLINT(cppcoreguidelines-pro-type-const-cast)
    }

    void set_indirect(detail::storage<T>* ptr) {
        std::memcpy(m_data.data(), &ptr, sizeof(ptr));

        // safety check to guarantee the lowest bit is 0
        if (is_direct()) {
            throw std::bad_alloc(); // LCOV_EXCL_LINE
        }
    }

    // helpers ///////////////////////////////////////////////////////////////

    /**
     * @brief Moves size objects from source_ptr to target_ptr, and destroys what remains in source_ptr.
     *
     * Assumes data is not overlapping
     */
    static void uninitialized_move_and_destroy(T* source_ptr, T* target_ptr, size_t size) {
        if constexpr (std::is_trivially_copyable_v<T>) {
            std::memcpy(target_ptr, source_ptr, size * sizeof(T));
        } else {
            std::uninitialized_move_n(source_ptr, size, target_ptr);
            std::destroy_n(source_ptr, size);
        }
    }

    /**
     * @brief Reallocates all data when capacity changes.
     *
     * if new_capacity <= N chooses direct memory, otherwise indirect.
     */
    void realloc(size_t new_capacity) {
        if (new_capacity <= N) {
            // put everything into direct storage
            if (is_direct()) {
                // direct -> direct: nothing to do!
                return;
            }

            // indirect -> direct
            auto* storage = indirect();
            uninitialized_move_and_destroy(storage->data(), direct_data(), storage->size());
            set_direct_and_size(storage->size());
            std::destroy_at(storage);
            ::operator delete(storage);
        } else {
            // put everything into indirect storage
            auto* storage = detail::storage<T>::alloc(new_capacity);
            if (is_direct()) {
                // direct -> indirect
                uninitialized_move_and_destroy(data<direction::direct>(), storage->data(), size<direction::direct>());
                storage->size(size<direction::direct>());
            } else {
                // indirect -> indirect
                uninitialized_move_and_destroy(data<direction::indirect>(), storage->data(), size<direction::indirect>());
                storage->size(size<direction::indirect>());
                auto* storage = indirect();
                std::destroy_at(storage);
                ::operator delete(storage);
            }
            set_indirect(storage);
        }
    }

    /**
     * @brief Doubles starting_capacity until it is >= size_to_fit.
     */
    [[nodiscard]] static auto calculate_new_capacity(size_t size_to_fit, size_t starting_capacity) -> size_t {
        if (size_to_fit > max_size()) {
            // not enough space
            throw std::bad_alloc();
        }

        if (size_to_fit == 0) {
            // special handling for 0 so N==0 works
            return starting_capacity;
        }
        // start with at least 1, so N==0 works
        auto new_capacity = std::max<size_t>(1, starting_capacity);

        // double capacity until its large enough, but make sure we don't overflow
        while (new_capacity < size_to_fit && new_capacity * 2 > new_capacity) {
            new_capacity *= 2;
        }
        if (new_capacity < size_to_fit) {
            // got an overflow, set capacity to max
            new_capacity = max_size();
        }
        return std::min(new_capacity, max_size());
    }

    template <direction D>
    [[nodiscard]] auto capacity() const -> size_t {
        if constexpr (D == direction::direct) {
            return N;
        } else {
            return indirect()->capacity();
        }
    }

    template <direction D>
    [[nodiscard]] auto size() const -> size_t {
        if constexpr (D == direction::direct) {
            return direct_size();
        } else {
            return indirect()->size();
        }
    }

    template <direction D>
    void set_size(size_t s) {
        if constexpr (D == direction::direct) {
            set_direct_and_size(s);
        } else {
            indirect()->size(s);
        }
    }

    void set_size(size_t s) {
        if (is_direct()) {
            set_size<direction::direct>(s);
        } else {
            set_size<direction::indirect>(s);
        }
    }

    template <direction D>
    [[nodiscard]] auto data() -> T* {
        if constexpr (D == direction::direct) {
            return direct_data();
        } else {
            return indirect()->data();
        }
    }

    template <direction D>
    [[nodiscard]] auto data() const -> T const* {
        return const_cast<svector*>(this)->data<D>(); // NOLINT(cppcoreguidelines-pro-type-const-cast)
    }

    template <direction D>
    void pop_back() {
        if constexpr (std::is_trivially_destructible_v<T>) {
            set_size<D>(size<D>() - 1);
        } else {
            auto s = size<D>() - 1;
            (data<D>() + s)->~T();
            set_size<D>(s);
        }
    }

    /**
     * @brief We need variadic arguments so we can either use copy ctor or default ctor
     */
    template <direction D, class... Args>
    void resize_after_reserve(size_t count, Args&&... args) {
        auto current_size = size<D>();
        if (current_size > count) {
            if constexpr (!std::is_trivially_destructible_v<T>) {
                auto* d = data<D>();
                std::destroy(d + count, d + current_size);
            }
        } else {
            auto* d = data<D>();
            for (auto ptr = d + current_size, end = d + count; ptr != end; ++ptr) {
                new (static_cast<void*>(ptr)) T(std::forward<Args>(args)...);
            }
        }
        set_size<D>(count);
    }

    // Makes sure that to is not past the end iterator
    template <direction D>
    auto erase_checked_end(T const* cfrom, T const* to) -> T* {
        auto* const erase_begin = const_cast<T*>(cfrom); // NOLINT(cppcoreguidelines-pro-type-const-cast)
        auto* const container_end = data<D>() + size<D>();
        auto* const erase_end = std::min(const_cast<T*>(to), container_end); // NOLINT(cppcoreguidelines-pro-type-const-cast)

        std::move(erase_end, container_end, erase_begin);
        auto const num_erased = std::distance(erase_begin, erase_end);
        std::destroy(container_end - num_erased, container_end);
        set_size<D>(size<D>() - num_erased);
        return erase_begin;
    }

    template <typename It>
    void assign(It first, It last, std::input_iterator_tag /*unused*/) {
        clear();

        // TODO this can be made faster, e.g. by setting size only when finished.
        while (first != last) {
            push_back(*first);
            ++first;
        }
    }

    template <typename It>
    void assign(It first, It last, std::forward_iterator_tag /*unused*/) {
        clear();

        auto s = std::distance(first, last);
        reserve(s);
        std::uninitialized_copy(first, last, data());
        set_size(s);
    }

    // precondition: all uninitialized
    void do_move_assign(svector&& other) {
        if (!other.is_direct()) {
            // take other's memory, even when empty
            set_indirect(other.indirect());
        } else {
            auto* other_ptr = other.data<direction::direct>();
            auto s = other.size<direction::direct>();
            auto* other_end = other_ptr + s;

            std::uninitialized_move(other_ptr, other_end, data<direction::direct>());
            std::destroy(other_ptr, other_end);
            set_size(s);
        }
        other.set_direct_and_size(0);
    }

    /**
     * @brief Shifts data [source_begin, source_end( to the right, starting on target_begin.
     *
     * Preconditions:
     * * contiguous memory
     * * source_begin <= target_begin
     * * source_end onwards is uninitialized memory
     *
     * Destroys then empty elements in [source_begin, source_end(
     */
    static auto shift_right(T* source_begin, T* source_end, T* target_begin) {
        // 1. uninitialized moves
        auto const num_moves = std::distance(source_begin, source_end);
        auto const target_end = target_begin + num_moves;
        auto const num_uninitialized_move = std::min(num_moves, std::distance(source_end, target_end));
        std::uninitialized_move(source_end - num_uninitialized_move, source_end, target_end - num_uninitialized_move);
        std::move_backward(source_begin, source_end - num_uninitialized_move, target_end - num_uninitialized_move);
        std::destroy(source_begin, std::min(source_end, target_begin));
    }

    template <direction D>
    [[nodiscard]] auto make_uninitialized_space_new(size_t s, T* p, size_t count) -> T* {
        auto target = svector();
        // we know target is indirect because we're increasing capacity
        target.reserve(s + count);

        // move everything [begin, pos[
        auto* target_pos = std::uninitialized_move(data<D>(), p, target.template data<direction::indirect>());

        // move everything [pos, end]
        std::uninitialized_move(p, data<D>() + s, target_pos + count);

        target.template set_size<direction::indirect>(s + count);
        *this = std::move(target);
        return target_pos;
    }

    template <direction D>
    [[nodiscard]] auto make_uninitialized_space(T const* pos, size_t count) -> T* {
        auto* const p = const_cast<T*>(pos); // NOLINT(cppcoreguidelines-pro-type-const-cast)
        auto s = size<D>();
        if (s + count > capacity<D>()) {
            return make_uninitialized_space_new<D>(s, p, count);
        }

        shift_right(p, data<D>() + s, p + count);
        set_size<D>(s + count);
        return p;
    }

    // makes space for uninitialized data of cout elements. Also updates size.
    [[nodiscard]] auto make_uninitialized_space(T const* pos, size_t count) -> T* {
        if (is_direct()) {
            return make_uninitialized_space<direction::direct>(pos, count);
        }
        return make_uninitialized_space<direction::indirect>(pos, count);
    }

    void destroy() {
        auto const is_dir = is_direct();
        if constexpr (!std::is_trivially_destructible_v<T>) {
            T* ptr = nullptr;
            size_t s = 0;
            if (is_dir) {
                ptr = data<direction::direct>();
                s = size<direction::direct>();
            } else {
                ptr = data<direction::indirect>();
                s = size<direction::indirect>();
            }
            std::destroy_n(ptr, s);
        }
        if (!is_dir) {
            auto* storage = indirect();
            std::destroy_at(storage);
            ::operator delete(storage);
        }
    }

    // performs a const_cast so we don't need this implementation twice
    template <direction D>
    auto at(size_t idx) -> T& {
        if (idx >= size<D>()) {
            throw std::out_of_range{"svector: idx out of range"};
        }
        auto* ptr = const_cast<T*>(data<D>() + idx); // NOLINT(cppcoreguidelines-pro-type-const-cast)
        return *ptr;
    } // LCOV_EXCL_LINE why is this single } marked as not covered? gcov bug?

public:
    using value_type = T;
    using size_type = size_t;
    using difference_type = std::ptrdiff_t;
    using reference = value_type&;
    using const_reference = value_type const&;
    using pointer = T*;
    using const_pointer = T const*;
    using iterator = T*;
    using const_iterator = T const*;
    using reverse_iterator = std::reverse_iterator<iterator>;
    using const_reverse_iterator = std::reverse_iterator<const_iterator>;

    svector() {
        set_direct_and_size(0);
    }

    svector(size_t count, T const& value)
        : svector() {
        resize(count, value);
    }

    explicit svector(size_t count)
        : svector() {
        reserve(count);
        if (is_direct()) {
            resize_after_reserve<direction::direct>(count);
        } else {
            resize_after_reserve<direction::indirect>(count);
        }
    }

    template <typename InputIt, typename = detail::enable_if_t<detail::is_input_iterator<InputIt>>>
    svector(InputIt first, InputIt last)
        : svector() {
        assign(first, last);
    }

    svector(svector const& other)
        : svector() {
        auto s = other.size();
        reserve(s);
        std::uninitialized_copy(other.begin(), other.end(), begin());
        set_size(s);
    }

    svector(svector&& other) noexcept
        : svector() {
        do_move_assign(std::move(other));
    }

    svector(std::initializer_list<T> init)
        : svector(init.begin(), init.end()) {}

    ~svector() {
        destroy();
    }

    void assign(size_t count, T const& value) {
        clear();
        resize(count, value);
    }

    template <typename InputIt, typename = detail::enable_if_t<detail::is_input_iterator<InputIt>>>
    void assign(InputIt first, InputIt last) {
        assign(first, last, typename std::iterator_traits<InputIt>::iterator_category());
    }

    void assign(std::initializer_list<T> l) {
        assign(l.begin(), l.end());
    }

    auto operator=(svector const& other) -> svector& {
        if (&other == this) {
            return *this;
        }

        assign(other.begin(), other.end());
        return *this;
    }

    auto operator=(svector&& other) noexcept -> svector& {
        if (&other == this) {
            // It doesn't seem to be required to do self-check, but let's do it anyways to be safe
            return *this;
        }
        destroy();
        do_move_assign(std::move(other));
        return *this;
    }

    auto operator=(std::initializer_list<T> l) -> svector& {
        assign(l.begin(), l.end());
        return *this;
    }

    void resize(size_t count) {
        if (count > capacity()) {
            reserve(count);
        }
        if (is_direct()) {
            resize_after_reserve<direction::direct>(count);
        } else {
            resize_after_reserve<direction::indirect>(count);
        }
    }

    void resize(size_t count, T const& value) {
        if (count > capacity()) {
            reserve(count);
        }
        if (is_direct()) {
            resize_after_reserve<direction::direct>(count, value);
        } else {
            resize_after_reserve<direction::indirect>(count, value);
        }
    }

    auto reserve(size_t s) {
        auto old_capacity = capacity();
        auto new_capacity = calculate_new_capacity(s, old_capacity);
        if (new_capacity > old_capacity) {
            realloc(new_capacity);
        }
    }

    [[nodiscard]] auto capacity() const -> size_t {
        if (is_direct()) {
            return capacity<direction::direct>();
        }
        return capacity<direction::indirect>();
    }

    [[nodiscard]] auto size() const -> size_t {
        if (is_direct()) {
            return size<direction::direct>();
        }
        return size<direction::indirect>();
    }

    [[nodiscard]] auto data() -> T* {
        if (is_direct()) {
            return direct_data();
        }
        return indirect()->data();
    }

    [[nodiscard]] auto data() const -> T const* {
        return const_cast<svector*>(this)->data(); // NOLINT(cppcoreguidelines-pro-type-const-cast)
    }

    template <class... Args>
    auto emplace_back(Args&&... args) -> T& {
        size_t c; // NOLINT(cppcoreguidelines-init-variables)
        size_t s; // NOLINT(cppcoreguidelines-init-variables)
        bool is_dir = is_direct();
        if (is_dir) {
            c = capacity<direction::direct>();
            s = size<direction::direct>();
        } else {
            c = capacity<direction::indirect>();
            s = size<direction::indirect>();
        }

        if (s == c) {
            auto new_capacity = calculate_new_capacity(s + 1, c);
            realloc(new_capacity);
            // reallocation happened, so we definitely are now in indirect mode
            is_dir = false;
        }

        T* ptr; // NOLINT(cppcoreguidelines-init-variables)
        if (is_dir) {
            ptr = data<direction::direct>() + s;
            set_size<direction::direct>(s + 1);
        } else {
            ptr = data<direction::indirect>() + s;
            set_size<direction::indirect>(s + 1);
        }
        return *new (static_cast<void*>(ptr)) T(std::forward<Args>(args)...);
    }

    void push_back(T const& value) {
        emplace_back(value);
    }

    void push_back(T&& value) {
        emplace_back(std::move(value));
    }

    [[nodiscard]] auto operator[](size_t idx) const -> T const& {
        return *(data() + idx);
    }

    [[nodiscard]] auto operator[](size_t idx) -> T& {
        return *(data() + idx);
    }

    auto at(size_t idx) -> T& {
        if (is_direct()) {
            return at<direction::direct>(idx);
        }
        return at<direction::indirect>(idx);
    }

    auto at(size_t idx) const -> T const& {
        return const_cast<svector*>(this)->at(idx); // NOLINT(cppcoreguidelines-pro-type-const-cast)
    }

    [[nodiscard]] auto begin() const -> T const* {
        return data();
    }

    [[nodiscard]] auto cbegin() const -> T const* {
        return begin();
    }

    [[nodiscard]] auto begin() -> T* {
        return data();
    }

    [[nodiscard]] auto end() -> T* {
        if (is_direct()) {
            return data<direction::direct>() + size<direction::direct>();
        }
        return data<direction::indirect>() + size<direction::indirect>();
    }

    [[nodiscard]] auto end() const -> T const* {
        return const_cast<svector*>(this)->end(); // NOLINT(cppcoreguidelines-pro-type-const-cast)
    }

    [[nodiscard]] auto cend() const -> T const* {
        return end();
    }

    [[nodiscard]] auto rbegin() -> reverse_iterator {
        return reverse_iterator{end()};
    }

    [[nodiscard]] auto rbegin() const -> const_reverse_iterator {
        return crbegin();
    }

    [[nodiscard]] auto crbegin() const -> const_reverse_iterator {
        return const_reverse_iterator{end()};
    }

    [[nodiscard]] auto rend() -> reverse_iterator {
        return reverse_iterator{begin()};
    }

    [[nodiscard]] auto rend() const -> const_reverse_iterator {
        return crend();
    }

    [[nodiscard]] auto crend() const -> const_reverse_iterator {
        return const_reverse_iterator{begin()};
    }

    [[nodiscard]] auto front() const -> T const& {
        return *data();
    }

    [[nodiscard]] auto front() -> T& {
        return *data();
    }

    [[nodiscard]] auto back() -> T& {
        if (is_direct()) {
            return *(data<direction::direct>() + size<direction::direct>() - 1);
        }
        return *(data<direction::indirect>() + size<direction::indirect>() - 1);
    }

    [[nodiscard]] auto back() const -> T const& {
        return const_cast<svector*>(this)->back(); // NOLINT(cppcoreguidelines-pro-type-const-cast)
    }

    void clear() {
        if constexpr (!std::is_trivially_destructible_v<T>) {
            std::destroy(begin(), end());
        }

        if (is_direct()) {
            set_size<direction::direct>(0);
        } else {
            set_size<direction::indirect>(0);
        }
    }

    [[nodiscard]] auto empty() const -> bool {
        return 0U == size();
    }

    void pop_back() {
        if (is_direct()) {
            pop_back<direction::direct>();
        } else {
            pop_back<direction::indirect>();
        }
    }

    [[nodiscard]] static auto max_size() -> size_t {
        return std::numeric_limits<std::ptrdiff_t>::max();
    }

    void swap(svector& other) {
        // TODO we could try to do the minimum number of moves
        std::swap(*this, other);
    }

    void shrink_to_fit() {
        // per the standard we wouldn't need to do anything here. But since we are so nice,
        // let's do the shrink.
        auto const c = capacity();
        auto const s = size();
        if (s >= c) {
            return;
        }

        auto new_capacity = calculate_new_capacity(s, N);
        if (new_capacity == c) {
            // nothing change!
            return;
        }

        realloc(new_capacity);
    }

    template <class... Args>
    auto emplace(const_iterator pos, Args&&... args) -> iterator {
        auto* p = make_uninitialized_space(pos, 1);
        return new (static_cast<void*>(p)) T(std::forward<Args>(args)...);
    }

    auto insert(const_iterator pos, T const& value) -> iterator {
        return emplace(pos, value);
    }

    auto insert(const_iterator pos, T&& value) -> iterator {
        return emplace(pos, std::move(value));
    }

    auto insert(const_iterator pos, size_t count, T const& value) -> iterator {
        auto* p = make_uninitialized_space(pos, count);
        std::uninitialized_fill_n(p, count, value);
        return p;
    }

    template <typename It>
    auto insert(const_iterator pos, It first, It last, std::input_iterator_tag /*unused*/) {
        if (!(first != last)) {
            return const_cast<T*>(pos); // NOLINT(cppcoreguidelines-pro-type-const-cast)
        }

        // just input_iterator_tag makes this very slow. Let's do the same as the STL.
        if (pos == end()) {
            auto s = size();
            while (first != last) {
                emplace_back(*first);
                ++first;
            }
            return begin() + s;
        }

        auto tmp = svector(first, last);
        return insert(pos, std::make_move_iterator(tmp.begin()), std::make_move_iterator(tmp.end()));
    }

    template <typename It>
    auto insert(const_iterator pos, It first, It last, std::forward_iterator_tag /*unused*/) {
        auto* p = make_uninitialized_space(pos, std::distance(first, last));
        std::uninitialized_copy(first, last, p);
        return p;
    }

    template <typename InputIt, typename = detail::enable_if_t<detail::is_input_iterator<InputIt>>>
    auto insert(const_iterator pos, InputIt first, InputIt last) -> iterator {
        return insert(pos, first, last, typename std::iterator_traits<InputIt>::iterator_category());
    }

    auto insert(const_iterator pos, std::initializer_list<T> l) -> iterator {
        return insert(pos, l.begin(), l.end());
    }

    auto erase(const_iterator pos) -> iterator {
        return erase(pos, pos + 1);
    }

    auto erase(const_iterator first, const_iterator last) -> iterator {
        if (is_direct()) {
            return erase_checked_end<direction::direct>(first, last);
        }
        return erase_checked_end<direction::indirect>(first, last);
    }
};

template <typename T, size_t NA, size_t NB>
[[nodiscard]] auto operator==(svector<T, NA> const& a, svector<T, NB> const& b) -> bool {
    return std::equal(a.begin(), a.end(), b.begin(), b.end());
}

template <typename T, size_t NA, size_t NB>
[[nodiscard]] auto operator!=(svector<T, NA> const& a, svector<T, NB> const& b) -> bool {
    return !(a == b);
}

template <typename T, size_t NA, size_t NB>
[[nodiscard]] auto operator<(svector<T, NA> const& a, svector<T, NB> const& b) -> bool {
    return std::lexicographical_compare(a.begin(), a.end(), b.begin(), b.end());
}

template <typename T, size_t NA, size_t NB>
[[nodiscard]] auto operator>=(svector<T, NA> const& a, svector<T, NB> const& b) -> bool {
    return !(a < b);
}

template <typename T, size_t NA, size_t NB>
[[nodiscard]] auto operator>(svector<T, NA> const& a, svector<T, NB> const& b) -> bool {
    return std::lexicographical_compare(b.begin(), b.end(), a.begin(), a.end());
}

template <typename T, size_t NA, size_t NB>
[[nodiscard]] auto operator<=(svector<T, NA> const& a, svector<T, NB> const& b) -> bool {
    return !(a > b);
}

} // namespace ANKERL_SVECTOR_NAMESPACE
} // namespace ankerl

// NOLINTNEXTLINE(cert-dcl58-cpp)
namespace std {
inline namespace ANKERL_SVECTOR_NAMESPACE {

template <class T, size_t N, class U>
constexpr auto erase(ankerl::svector<T, N>& sv, U const& value) -> typename ankerl::svector<T, N>::size_type {
    auto* removed_begin = std::remove(sv.begin(), sv.end(), value);
    auto num_removed = std::distance(removed_begin, sv.end());
    sv.erase(removed_begin, sv.end());
    return num_removed;
}

template <class T, size_t N, class Pred>
constexpr auto erase_if(ankerl::svector<T, N>& sv, Pred pred) -> typename ankerl::svector<T, N>::size_type {
    auto* removed_begin = std::remove_if(sv.begin(), sv.end(), pred);
    auto num_removed = std::distance(removed_begin, sv.end());
    sv.erase(removed_begin, sv.end());
    return num_removed;
}

} // namespace ANKERL_SVECTOR_NAMESPACE
} // namespace std

#endif
