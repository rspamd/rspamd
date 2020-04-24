/*-
 * Copyright 2016 Vsevolod Stakhov
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
#include "lua_common.h"
#include "libserver/maps/map_helpers.h"

/***
 * @module rspamd_ip
 * `rspamd_ip` is a helper module to simplify IP addresses manipulations.
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
 * @method ip:to_string([pretty=false])
 * Converts valid IP address to string
 * @param {bool} pretty print IP address with port and braces (for IPv6)
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
 * Applies mask to IP address, resetting up to `mask` least significant bits to zero.
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

/**
 * @method ip:get_port()
 * Returns associated port for this IP address
 * @return {number} port number or nil
 */
LUA_FUNCTION_DEF (ip, get_port);
/***
 * @method ip:is_local()
 * Returns true if address is local one
 * @return {boolean} `true` if address is local
 */
LUA_FUNCTION_DEF (ip, is_local);

/***
 * @method ip:less_than(other)
 * Returns true if address is less than other
 * @return {boolean}
 */
LUA_FUNCTION_DEF (ip, less_than);

static const struct luaL_reg iplib_m[] = {
	LUA_INTERFACE_DEF (ip, to_string),
	LUA_INTERFACE_DEF (ip, to_table),
	LUA_INTERFACE_DEF (ip, to_number),
	LUA_INTERFACE_DEF (ip, str_octets),
	LUA_INTERFACE_DEF (ip, inversed_str_octets),
	LUA_INTERFACE_DEF (ip, get_version),
	LUA_INTERFACE_DEF (ip, get_port),
	LUA_INTERFACE_DEF (ip, is_valid),
	LUA_INTERFACE_DEF (ip, apply_mask),
	LUA_INTERFACE_DEF (ip, copy),
	LUA_INTERFACE_DEF (ip, is_local),
	{"tostring", lua_ip_to_string},
	{"totable", lua_ip_to_table},
	{"tonumber", lua_ip_to_number},
	{"__tostring", lua_ip_to_string},
	{"__eq", lua_ip_equal},
	{"__gc", lua_ip_destroy},
	{"__lt", lua_ip_less_than},
	{NULL, NULL}
};

static const struct luaL_reg iplib_f[] = {
	LUA_INTERFACE_DEF (ip, from_string),
	{"fromstring", lua_ip_from_string},
	{"fromip", lua_ip_copy},
	{"from_ip", lua_ip_copy},
	{NULL, NULL}
};

static struct rspamd_lua_ip *
lua_ip_new (lua_State *L, struct rspamd_lua_ip *old)
{
	struct rspamd_lua_ip *ip, **pip;

	ip = g_malloc0 (sizeof (*ip));

	if (old != NULL && old->addr != NULL) {
		ip->addr = rspamd_inet_address_copy (old->addr);
	}

	pip = lua_newuserdata (L, sizeof (struct rspamd_lua_ip *));
	rspamd_lua_setclass (L, "rspamd{ip}", -1);
	*pip = ip;


	return ip;
}

struct rspamd_lua_ip *
lua_check_ip (lua_State * L, gint pos)
{
	void *ud = rspamd_lua_check_udata (L, pos, "rspamd{ip}");

	luaL_argcheck (L, ud != NULL, pos, "'ip' expected");
	return ud ? *((struct rspamd_lua_ip **)ud) : NULL;
}

static gint
lua_ip_to_table (lua_State *L)
{
	LUA_TRACE_POINT;
	struct rspamd_lua_ip *ip = lua_check_ip (L, 1);
	guint max, i;
	guint8 *ptr;

	if (ip != NULL && ip->addr) {
		ptr = rspamd_inet_address_get_hash_key (ip->addr, &max);
		lua_createtable (L, max, 0);

		for (i = 1; i <= max; i++, ptr++) {
			lua_pushinteger (L, *ptr);
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
	LUA_TRACE_POINT;
	struct rspamd_lua_ip *ip = lua_check_ip (L, 1);
	guint max, i;
	guint8 *ptr;
	gint af;
	char numbuf[8];

	if (ip != NULL && ip->addr) {
		af = rspamd_inet_address_get_af (ip->addr);
		ptr = rspamd_inet_address_get_hash_key (ip->addr, &max);
		lua_createtable (L, max * 2, 0);

		for (i = 1; i <= max; i++, ptr++) {
			if (af == AF_INET) {
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
	LUA_TRACE_POINT;
	struct rspamd_lua_ip *ip = lua_check_ip (L, 1);
	guint max, i;
	guint8 *ptr;
	char numbuf[4];
	gint af;

	if (ip != NULL && ip->addr) {
		ptr = rspamd_inet_address_get_hash_key (ip->addr, &max);
		af = rspamd_inet_address_get_af (ip->addr);
		lua_createtable (L, max * 2, 0);

		ptr += max - 1;
		for (i = 1; i <= max; i++, ptr--) {
			if (af == AF_INET) {
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
	LUA_TRACE_POINT;
	struct rspamd_lua_ip *ip = lua_check_ip (L, 1);

	if (ip != NULL && ip->addr) {
		if (lua_isboolean (L, 2) && lua_toboolean (L, 2) == true) {
			lua_pushstring (L, rspamd_inet_address_to_string_pretty (ip->addr));
		}
		else {
			lua_pushstring (L, rspamd_inet_address_to_string (ip->addr));
		}
	}
	else {
		luaL_error (L, "invalid arguments");
	}

	return 1;
}

static gint
lua_ip_get_port (lua_State *L)
{
	LUA_TRACE_POINT;
	struct rspamd_lua_ip *ip = lua_check_ip (L, 1);

	if (ip != NULL && ip->addr) {
		lua_pushinteger (L, rspamd_inet_address_get_port (ip->addr));
	}
	else {
		lua_pushnil (L);
	}

	return 1;
}

static gint
lua_ip_from_string (lua_State *L)
{
	LUA_TRACE_POINT;
	struct rspamd_lua_ip *ip;
	const gchar *ip_str;
	gsize len;

	ip_str = luaL_checklstring (L, 1, &len);
	if (ip_str) {
		ip = lua_ip_new (L, NULL);

		if (!rspamd_parse_inet_address (&ip->addr,
				ip_str, len, RSPAMD_INET_ADDRESS_PARSE_DEFAULT)) {
			msg_warn ("cannot parse ip: %*s", (gint) len, ip_str);
			ip->addr = NULL;
		}
	}
	else {
		lua_pushnil (L);
	}

	return 1;
}

static gint
lua_ip_to_number (lua_State *L)
{
	LUA_TRACE_POINT;
	struct rspamd_lua_ip *ip = lua_check_ip (L, 1);
	guint32 c;
	guint max, i;
	guchar *ptr;

	if (ip != NULL && ip->addr) {
		ptr = rspamd_inet_address_get_hash_key (ip->addr, &max);

		for (i = 0; i < max / sizeof (c); i ++) {
			memcpy (&c, ptr + i * sizeof (c), sizeof (c));
			lua_pushinteger (L, ntohl (c));
		}

		return max / sizeof (c);
	}
	else {
		lua_pushnil (L);
	}

	return 1;
}


static gint
lua_ip_destroy (lua_State *L)
{
	LUA_TRACE_POINT;
	struct rspamd_lua_ip *ip = lua_check_ip (L, 1);

	if (ip) {
		if (ip->addr) {
			rspamd_inet_address_free (ip->addr);
		}
		g_free (ip);
	}

	return 0;
}

static gint
lua_ip_get_version (lua_State *L)
{
	LUA_TRACE_POINT;
	struct rspamd_lua_ip *ip = lua_check_ip (L, 1);

	if (ip && ip->addr) {
		lua_pushinteger (L, rspamd_inet_address_get_af (ip->addr) == AF_INET6 ?
				6 : 4);
	}
	else {
		lua_pushnil (L);
	}

	return 1;
}

static gint
lua_ip_is_valid (lua_State *L)
{
	LUA_TRACE_POINT;
	struct rspamd_lua_ip *ip = lua_check_ip (L, 1);

	if (ip) {
		lua_pushboolean (L, ip->addr != NULL);
	}
	else {
		lua_pushnil (L);
	}

	return 1;
}

static gint
lua_ip_apply_mask (lua_State *L)
{
	LUA_TRACE_POINT;
	struct rspamd_lua_ip *ip = lua_check_ip (L, 1), *nip;
	gint mask;

	mask = lua_tonumber (L, 2);
	if (mask > 0 && ip != NULL && ip->addr) {
		nip = lua_ip_new (L, ip);
		rspamd_inet_address_apply_mask (nip->addr, mask);
	}
	else {
		lua_pushnil (L);
	}

	return 1;
}

static gint
lua_ip_equal (lua_State *L)
{
	LUA_TRACE_POINT;
	struct rspamd_lua_ip *ip1 = lua_check_ip (L, 1),
		*ip2 = lua_check_ip (L, 2);
	gboolean res = FALSE;

	if (ip1 && ip2 && ip1->addr && ip2->addr) {
		res = rspamd_inet_address_compare (ip1->addr, ip2->addr, TRUE) == 0;
	}

	lua_pushboolean (L, res);

	return 1;
}

static gint
lua_ip_copy (lua_State *L)
{
	LUA_TRACE_POINT;
	struct rspamd_lua_ip *ip = lua_check_ip (L, 1);

	if (ip) {
		lua_ip_new (L, ip);
	}
	else {
		lua_pushnil (L);
	}

	return 1;
}

static gint
lua_ip_is_local (lua_State *L)
{
	struct rspamd_lua_ip *ip = lua_check_ip (L, 1);
	gboolean check_laddrs = TRUE;

	if (ip && ip->addr) {

		if (lua_type (L, 2) == LUA_TBOOLEAN) {
			check_laddrs = lua_toboolean (L, 2);
		}

		if ( rspamd_inet_address_is_local (ip->addr)) {
			lua_pushboolean (L, true);

			return 1;
		}
		else if (check_laddrs) {
			struct rspamd_radix_map_helper *local_addrs =
					rspamd_inet_library_get_lib_ctx ();
			if (local_addrs) {
				if (rspamd_match_radix_map_addr (local_addrs, ip->addr) != NULL) {
					lua_pushboolean (L, true);

					return 1;
				}
			}
		}

		lua_pushboolean (L, false);
	}
	else {
		lua_pushnil (L);
	}

	return 1;
}

static gint
lua_ip_less_than (lua_State *L)
{
	LUA_TRACE_POINT;
	struct rspamd_lua_ip *ip = lua_check_ip (L, 1),
			*other = lua_check_ip (L, 2);

	if (ip && other) {
		lua_pushboolean (L,
				rspamd_inet_address_compare (ip->addr, other->addr, true) < 0);
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

	ip = g_malloc0 (sizeof (struct rspamd_lua_ip));
	ip->addr = rspamd_inet_address_copy (addr);
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
		ip = g_malloc0 (sizeof (struct rspamd_lua_ip));

		if (rspamd_parse_inet_address (&ip->addr,
				ip_str, strlen (ip_str), RSPAMD_INET_ADDRESS_PARSE_DEFAULT)) {

			pip = lua_newuserdata (L, sizeof (struct rspamd_lua_ip *));
			rspamd_lua_setclass (L, "rspamd{ip}", -1);
			*pip = ip;
		}
		else {
			g_free (ip);
			lua_pushnil (L);
		}
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
	rspamd_lua_new_class (L, "rspamd{ip}", iplib_m);
	lua_pop (L, 1);
	rspamd_lua_add_preload (L, "rspamd_ip", lua_load_ip);
}
