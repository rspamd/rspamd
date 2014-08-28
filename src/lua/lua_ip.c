/* Copyright (c) 2013, Vsevolod Stakhov
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *       * Redistributions of source code must retain the above copyright
 *         notice, this list of conditions and the following disclaimer.
 *       * Redistributions in binary form must reproduce the above copyright
 *         notice, this list of conditions and the following disclaimer in the
 *         documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED ''AS IS'' AND ANY
 * EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL AUTHOR BE LIABLE FOR ANY
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include "lua_common.h"

/***
 * `rspamd_ip` is a helper module to simplify IP addresses manipulations.
 * @module rspamd_ip
 * @example
local print_octets = function(ip)
        print('Normal order octets:')
        for _,o in ipairs(ip:str_octets()) do
                print(o)
        end
        print('Reversed order octets:')
        for _,o in ipairs(ip:inversed_str_octets()) do
                print(o)
        end
        print('Numeric octets:')
        for _,o in ipairs(ip:to_table()) do
                print(o)
        end
end

local rspamd_ip = require "rspamd_ip"
-- Create ipv4
local ip4 = rspamd_ip.from_string('127.0.0.1')
-- Implicit conversion to string
print(ip4)
-- Numeric version
print(ip4:get_version())
print_octets(ip4)

-- Create a sample ipv6 address
local ip6 = rspamd_ip.from_string('2001:41d0:8:dd9a::100')
print(ip6)
print(ip6:get_version())
print_octets(ip6)
 */

/***
 * @method ip:to_string()
 * Converts valid IP address to string
 * @return {string or nil} string representation of IP or `nil` if IP is invalid
 */
LUA_FUNCTION_DEF (ip, to_string);
/***
 * @method ip:to_number()
 * Converts valid IP address to number or list of numbers in case of IPv6
 * @return {integer(s) or nil} numeric representation of IP in *host* byte order or `nil` if IP is invalid
 */
LUA_FUNCTION_DEF (ip, to_number);
/***
 * @function rspamd_ip.from_number(num[, num, num, num])
 * @param {integer} num one or four numbers that represents IPv4 and IPv6 accordingly (in *host* byte order)
 * @return {ip} new ip object
 */
LUA_FUNCTION_DEF (ip, from_number);
/***
 * @method ip:to_table()
 * Converts valid IP address to the table of numeric octets
 * @return {table or nil} numeric octets of IP address or `nil` if IP is invalid
 * @example
local ip = rspamd_ip.from_string('127.0.0.1')
for _,o in ipairs(ip:to_table()) do
    print(o)
end
-- Output:
-- 127
-- 0
-- 0
-- 1
 */
LUA_FUNCTION_DEF (ip, to_table);
/***
 * @method ip:str_octets()
 * Converts valid IP address to the table of string octets. The difference from
 * @see ip:to_table() is that this method returns just hex strings for ipv6
 * addresses.
 * @return {table or nil} string octets of IP address or `nil` if IP is invalid
 */
LUA_FUNCTION_DEF (ip, str_octets);
/***
 * @method ip:str_octets()
 * Converts valid IP address to the table of string octets in reversed order. The difference from
 * @see ip:to_table() is that this method returns just hex strings for ipv6
 * addresses.
 * @return {table or nil} string octets of IP address or `nil` if IP is invalid
 * @example
local ip = rspamd_ip.from_string('127.0.0.1')
for _,o in ipairs(ip:to_table()) do
    print(o)
end
-- Output:
-- 1
-- 0
-- 0
-- 127
 */
LUA_FUNCTION_DEF (ip, inversed_str_octets);
/***
 * @function rspamd_ip.from_string(line)
 * Create IP address from its string representation.
 * @param {string} line valid IP address string (either ipv4 or ipv6)
 * @return {ip} new ip object or `nil` if input is invalid
 */
LUA_FUNCTION_DEF (ip, from_string);
/***
 * @method ip:__gc()
 * Automatically destroys IP object.
 */
LUA_FUNCTION_DEF (ip, destroy);
/***
 * @method ip:get_version()
 * Gets numeric version of ip address
 * @return {number} `4` for IPv4 and `6` for IPv6
 */
LUA_FUNCTION_DEF (ip, get_version);
/***
 * @method ip:is_valid()
 * Checks if an IP object is a valid IP address.
 * @return {boolean} `true` if IP is valid and `false` otherwise
 */
LUA_FUNCTION_DEF (ip, is_valid);
/***
 * @method ip:apply_mask(mask)
 * Applies mask to IP address, reseting up to `mask` least significant bits to zero.
 * @param {integer} mask how many bits to reset
 * @return {ip} new IP object with `mask` bits reset
 */
LUA_FUNCTION_DEF (ip, apply_mask);
/***
 * @method ip:__eq(other)
 * Compares two IP addresses
 * @param {ip} other IP to compare
 * @return {boolean} `true` if two objects are the same
 */
LUA_FUNCTION_DEF (ip, equal);
/***
 * @method ip:copy()
 * Performs deep copy of IP address.
 * @return {ip} a fresh copy of IP address
 */
LUA_FUNCTION_DEF (ip, copy);

static const struct luaL_reg iplib_m[] = {
	LUA_INTERFACE_DEF (ip, to_string),
	LUA_INTERFACE_DEF (ip, to_table),
	LUA_INTERFACE_DEF (ip, to_number),
	LUA_INTERFACE_DEF (ip, str_octets),
	LUA_INTERFACE_DEF (ip, inversed_str_octets),
	LUA_INTERFACE_DEF (ip, get_version),
	LUA_INTERFACE_DEF (ip, is_valid),
	LUA_INTERFACE_DEF (ip, apply_mask),
	LUA_INTERFACE_DEF (ip, copy),
	{"__tostring", lua_ip_to_string},
	{"__eq", lua_ip_equal},
	{"__gc", lua_ip_destroy},
	{NULL, NULL}
};

static const struct luaL_reg iplib_f[] = {
	LUA_INTERFACE_DEF (ip, from_string),
	LUA_INTERFACE_DEF (ip, from_number),
	{"from_ip", lua_ip_copy},
	{NULL, NULL}
};

static struct rspamd_lua_ip *
lua_ip_new (lua_State *L, struct rspamd_lua_ip *old)
{
	struct rspamd_lua_ip *ip, **pip;

	ip = g_slice_alloc (sizeof (*ip));

	if (old != NULL) {
		memcpy (ip, old, sizeof (*ip));
	}
	pip = lua_newuserdata (L, sizeof (struct rspamd_lua_ip *));
	rspamd_lua_setclass (L, "rspamd{ip}", -1);
	*pip = ip;


	return ip;
}

static struct rspamd_lua_ip *
lua_check_ip (lua_State * L, gint pos)
{
	void *ud = luaL_checkudata (L, pos, "rspamd{ip}");

	luaL_argcheck (L, ud != NULL, pos, "'ip' expected");
	return ud ? *((struct rspamd_lua_ip **)ud) : NULL;
}

static gint
lua_ip_to_table (lua_State *L)
{
	struct rspamd_lua_ip *ip = lua_check_ip (L, 1);
	int max, i;
	guint8 *ptr;

	if (ip != NULL && ip->is_valid) {
		lua_newtable (L);
		if (ip->addr.af == AF_INET) {
			max = 32 / 8;
			ptr = (guint8 *)&ip->addr.addr.s4.sin_addr;
		}
		else {
			max = 128 / 8;
			ptr = (guint8 *)&ip->addr.addr.s6.sin6_addr;
		}

		for (i = 1; i <= max; i++, ptr++) {
			lua_pushnumber (L, *ptr);
			lua_rawseti (L, -2, i);
		}
	}
	else {
		lua_pushnil (L);
	}

	return 1;
}

static gint
lua_ip_str_octets (lua_State *L)
{
	struct rspamd_lua_ip *ip = lua_check_ip (L, 1);
	int max, i;
	guint8 *ptr;
	char numbuf[8];

	if (ip != NULL && ip->is_valid) {
		lua_newtable (L);
		if (ip->addr.af == AF_INET) {
			ptr = (guint8 *)&ip->addr.addr.s4.sin_addr;
			max = 32 / 8;
		}
		else {
			max = 128 / 8;
			ptr = (guint8 *)&ip->addr.addr.s6.sin6_addr;
		}

		for (i = 1; i <= max; i++, ptr++) {
			if (ip->addr.af == AF_INET) {
				rspamd_snprintf (numbuf, sizeof (numbuf), "%d", *ptr);
				lua_pushstring (L, numbuf);
				lua_rawseti (L, -2, i);
			}
			else {
				rspamd_snprintf (numbuf,
					sizeof (numbuf),
					"%xd",
					(*ptr & 0xf0) >> 4);
				lua_pushstring (L, numbuf);
				lua_rawseti (L, -2, i * 2 - 1);
				rspamd_snprintf (numbuf, sizeof (numbuf), "%xd", *ptr & 0x0f);
				lua_pushstring (L, numbuf);
				lua_rawseti (L, -2, i * 2);
			}
		}
	}
	else {
		lua_pushnil (L);
	}

	return 1;
}

static gint
lua_ip_inversed_str_octets (lua_State *L)
{
	struct rspamd_lua_ip *ip = lua_check_ip (L, 1);
	int max, i;
	guint8 *ptr;
	char numbuf[4];

	if (ip != NULL && ip->is_valid) {
		lua_newtable (L);
		if (ip->addr.af == AF_INET) {
			max = 32 / 8;
			ptr = (guint8 *)&ip->addr.addr.s4.sin_addr;
		}
		else {
			max = 128 / 8;
			ptr = (guint8 *)&ip->addr.addr.s6.sin6_addr;
		}

		ptr += max - 1;
		for (i = 1; i <= max; i++, ptr--) {
			if (ip->addr.af == AF_INET) {
				rspamd_snprintf (numbuf, sizeof (numbuf), "%d", *ptr);
				lua_pushstring (L, numbuf);
				lua_rawseti (L, -2, i);
			}
			else {
				rspamd_snprintf (numbuf, sizeof (numbuf), "%xd", *ptr & 0x0f);
				lua_pushstring (L, numbuf);
				lua_rawseti (L, -2, i * 2 - 1);
				rspamd_snprintf (numbuf,
					sizeof (numbuf),
					"%xd",
					(*ptr & 0xf0) >> 4);
				lua_pushstring (L, numbuf);
				lua_rawseti (L, -2, i * 2);
			}
		}
	}
	else {
		lua_pushnil (L);
	}

	return 1;
}

static gint
lua_ip_to_string (lua_State *L)
{
	struct rspamd_lua_ip *ip = lua_check_ip (L, 1);

	if (ip != NULL && ip->is_valid) {
		lua_pushstring (L, rspamd_inet_address_to_string (&ip->addr));
	}
	else {
		lua_pushnil (L);
	}

	return 1;
}

static gint
lua_ip_from_string (lua_State *L)
{
	struct rspamd_lua_ip *ip;
	const gchar *ip_str;

	ip_str = luaL_checkstring (L, 1);
	if (ip_str) {
		ip = lua_ip_new (L, NULL);
		ip->is_valid = rspamd_parse_inet_address (&ip->addr, ip_str);
	}
	else {
		lua_pushnil (L);
	}

	return 1;
}

static gint
lua_ip_to_number (lua_State *L)
{
	struct rspamd_lua_ip *ip = lua_check_ip (L, 1);
	guint32 dst[4], i;

	if (ip != NULL && ip->is_valid) {
		if (ip->addr.af == AF_INET) {
			/* One integer in host byte order */
			lua_pushinteger (L, ntohl (ip->addr.addr.s4.sin_addr.s_addr));
		}
		else {
			/* 4 integers in host byte order */
			G_STATIC_ASSERT (sizeof (ip->addr.addr.s6.sin6_addr) >=
				sizeof (dst));
			memcpy (dst, &ip->addr.addr.s6.sin6_addr, sizeof (dst));
			for (i = 0; i < G_N_ELEMENTS (dst); i++) {
				lua_pushinteger (L, ntohl (dst[i]));
			}
			return 4;
		}
	}
	else {
		lua_pushnil (L);
	}

	return 1;
}

static gint
lua_ip_from_number (lua_State *L)
{
	guint32 src[4], i;
	struct rspamd_lua_ip *ip;

	if (lua_gettop (L) == 1 && lua_isnumber (L, 1)) {
		/* Ipv4 version */
		ip = lua_ip_new (L, NULL);
		src[0] = lua_tointeger (L, 1);
		ip->addr.af = AF_INET;
		ip->is_valid = TRUE;
		ip->addr.addr.s4.sin_addr.s_addr = htonl (src[0]);
	}
	else if (lua_gettop (L) == 4 && lua_isnumber (L, 1)) {
		/* Ipv6 version */
		for (i = 0; i < 4; i++) {
			src[i] = htonl (lua_tonumber (L, i + 1));
		}
		G_STATIC_ASSERT (sizeof (ip->addr.addr.s6.sin6_addr) >= sizeof (src));
		ip = lua_ip_new (L, NULL);
		ip->addr.af = AF_INET6;
		ip->is_valid = TRUE;
		memcpy (&ip->addr.addr.s6.sin6_addr, src, sizeof (src));
	}
	else {
		lua_pushnil (L);
	}

	return 1;
}

static gint
lua_ip_destroy (lua_State *L)
{
	struct rspamd_lua_ip *ip = lua_check_ip (L, 1);

	if (ip) {
		g_slice_free1 (sizeof (struct rspamd_lua_ip), ip);
	}

	return 0;
}

static gint
lua_ip_get_version (lua_State *L)
{
	struct rspamd_lua_ip *ip = lua_check_ip (L, 1);

	if (ip && ip->is_valid) {
		lua_pushnumber (L, ip->addr.af == AF_INET6 ? 6 : 4);
	}
	else {
		lua_pushnil (L);
	}

	return 1;
}

static gint
lua_ip_is_valid (lua_State *L)
{
	struct rspamd_lua_ip *ip = lua_check_ip (L, 1);

	if (ip) {
		lua_pushboolean (L, ip->is_valid);
	}
	else {
		lua_pushnil (L);
	}

	return 1;
}

static gint
lua_ip_apply_mask (lua_State *L)
{
	struct rspamd_lua_ip *ip = lua_check_ip (L, 1), *nip;
	gint mask;
	guint32 umsk, *p;

	mask = lua_tonumber (L, 2);
	if (mask > 0 && ip->is_valid) {
		if (ip->addr.af == AF_INET && mask <= 32) {
			nip = lua_ip_new (L, ip);
			umsk = htonl (G_MAXUINT32 << (32 - mask));
			nip->addr.addr.s4.sin_addr.s_addr &= umsk;
		}
		else if (ip->addr.af == AF_INET && mask <= 128) {
			nip = lua_ip_new (L, ip);
			p = (uint32_t *)&nip->addr.addr.s6.sin6_addr;
			p += 3;
			while (mask > 0) {
				umsk = htonl (G_MAXUINT32 << (32 - (mask > 32 ? 32 : mask)));
				*p &= umsk;
				p --;
				mask -= 32;
			}
		}
		else {
			lua_pushnil (L);
		}
	}
	else {
		lua_pushnil (L);
	}

	return 1;
}

static gint
lua_ip_equal (lua_State *L)
{
	struct rspamd_lua_ip *ip1 = lua_check_ip (L, 1),
		*ip2 = lua_check_ip (L, 2);
	gboolean res = FALSE;

	if (ip1->is_valid && ip2->is_valid) {
		if (ip1->addr.af == ip2->addr.af) {
			if (ip1->addr.af == AF_INET) {
				if (memcmp(&ip1->addr.addr.s4.sin_addr,
					&ip2->addr.addr.s4.sin_addr, sizeof (struct in_addr)) == 0) {
					res = TRUE;
				}
			}
			else if (ip1->addr.af == AF_INET6) {
				if (memcmp(&ip1->addr.addr.s6.sin6_addr,
					&ip2->addr.addr.s6.sin6_addr, sizeof (struct in6_addr)) == 0) {
					res = TRUE;
				}
			}
		}
	}
	lua_pushboolean (L, res);

	return 1;
}

static gint
lua_ip_copy (lua_State *L)
{
	struct rspamd_lua_ip *ip = lua_check_ip (L, 1);

	if (ip) {
		lua_ip_new (L, ip);
	}
	else {
		lua_pushnil (L);
	}

	return 1;
}

void
rspamd_lua_ip_push (lua_State *L, rspamd_inet_addr_t *addr)
{
	struct rspamd_lua_ip *ip, **pip;

	ip = g_slice_alloc (sizeof (struct rspamd_lua_ip));

	if (!rspamd_ip_is_valid (addr)) {
		ip->is_valid = FALSE;
	}
	else {
		ip->is_valid = TRUE;
		memcpy (&ip->addr, addr, sizeof (ip->addr));
	}
	pip = lua_newuserdata (L, sizeof (struct rspamd_lua_ip *));
	rspamd_lua_setclass (L, "rspamd{ip}", -1);
	*pip = ip;
}

void
rspamd_lua_ip_push_fromstring (lua_State *L, const gchar *ip_str)
{
	struct rspamd_lua_ip *ip, **pip;

	if (ip_str == NULL) {
		lua_pushnil (L);
	}
	else {
		ip = g_slice_alloc (sizeof (struct rspamd_lua_ip));
		ip->is_valid = rspamd_parse_inet_address (&ip->addr, ip_str);

		pip = lua_newuserdata (L, sizeof (struct rspamd_lua_ip *));
		rspamd_lua_setclass (L, "rspamd{ip}", -1);
		*pip = ip;
	}
}

static gint
lua_load_ip (lua_State * L)
{
	lua_newtable (L);
	luaL_register (L, NULL, iplib_f);

	return 1;
}

void
luaopen_ip (lua_State * L)
{
	luaL_newmetatable (L, "rspamd{ip}");
	lua_pushstring (L, "__index");
	lua_pushvalue (L, -2);
	lua_settable (L, -3);

	lua_pushstring (L, "class");
	lua_pushstring (L, "rspamd{ip}");
	lua_rawset (L, -3);

	luaL_register (L, NULL,		   iplib_m);
	rspamd_lua_add_preload (L, "rspamd_ip", lua_load_ip);

	lua_pop (L, 1);                      /* remove metatable from stack */
}
