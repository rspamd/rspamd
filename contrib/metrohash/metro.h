/*-
The MIT License (MIT)

Copyright (c) 2015 J. Andrew Rogers

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
 */
#ifndef CONTRIB_METROHASH_METRO_H_
#define CONTRIB_METROHASH_METRO_H_

#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>
#ifdef _MSC_VER
typedef unsigned __int32 uint32_t;
typedef unsigned __int64 uint64_t;
#else
#include <stdint.h>
#endif

/* rotate right idiom recognized by compiler*/
inline static uint64_t rotate_right(uint64_t v, unsigned k)
{
    return (v >> k) | (v << (64 - k));
}

inline static uint64_t read_u64(const void * const ptr)
{
    return * (uint64_t *) ptr;
}

inline static uint64_t read_u32(const void * const ptr)
{
    return * (uint32_t *) ptr;
}

inline static uint64_t read_u16(const void * const ptr)
{
    return * (uint16_t *) ptr;
}

inline static uint64_t read_u8 (const void * const ptr)
{
    return * (uint8_t *) ptr;
}

static inline uint64_t metrohash64_1(const uint8_t * key, uint64_t len, uint64_t seed)
{
    static const uint64_t k0 = 0xC83A91E1;
    static const uint64_t k1 = 0x8648DBDB;
    static const uint64_t k2 = 0x7BDEC03B;
    static const uint64_t k3 = 0x2F5870A5;

    const uint8_t * ptr = key;
    const uint8_t * const end = ptr + len;

    uint64_t hash = ((((uint64_t) seed) + k2) * k0) + len;

    if (len >= 32)
    {
        uint64_t v[4];
        v[0] = hash;
        v[1] = hash;
        v[2] = hash;
        v[3] = hash;

        do
        {
            v[0] += read_u64(ptr) * k0; ptr += 8; v[0] = rotate_right(v[0],29) + v[2];
            v[1] += read_u64(ptr) * k1; ptr += 8; v[1] = rotate_right(v[1],29) + v[3];
            v[2] += read_u64(ptr) * k2; ptr += 8; v[2] = rotate_right(v[2],29) + v[0];
            v[3] += read_u64(ptr) * k3; ptr += 8; v[3] = rotate_right(v[3],29) + v[1];
        }
        while (ptr <= (end - 32));

        v[2] ^= rotate_right(((v[0] + v[3]) * k0) + v[1], 33) * k1;
        v[3] ^= rotate_right(((v[1] + v[2]) * k1) + v[0], 33) * k0;
        v[0] ^= rotate_right(((v[0] + v[2]) * k0) + v[3], 33) * k1;
        v[1] ^= rotate_right(((v[1] + v[3]) * k1) + v[2], 33) * k0;
        hash += v[0] ^ v[1];
    }

    if ((end - ptr) >= 16)
    {
        uint64_t v0 = hash + (read_u64(ptr) * k0); ptr += 8; v0 = rotate_right(v0,33) * k1;
        uint64_t v1 = hash + (read_u64(ptr) * k1); ptr += 8; v1 = rotate_right(v1,33) * k2;
        v0 ^= rotate_right(v0 * k0, 35) + v1;
        v1 ^= rotate_right(v1 * k3, 35) + v0;
        hash += v1;
    }

    if ((end - ptr) >= 8)
    {
        hash += read_u64(ptr) * k3; ptr += 8;
        hash ^= rotate_right(hash, 33) * k1;

    }

    if ((end - ptr) >= 4)
    {
        hash += read_u32(ptr) * k3; ptr += 4;
        hash ^= rotate_right(hash, 15) * k1;
    }

    if ((end - ptr) >= 2)
    {
        hash += read_u16(ptr) * k3; ptr += 2;
        hash ^= rotate_right(hash, 13) * k1;
    }

    if ((end - ptr) >= 1)
    {
        hash += read_u8 (ptr) * k3;
        hash ^= rotate_right(hash, 25) * k1;
    }

    hash ^= rotate_right(hash, 33);
    hash *= k0;
    hash ^= rotate_right(hash, 33);

    return hash;
}

#endif /* CONTRIB_METROHASH_METRO_H_ */
