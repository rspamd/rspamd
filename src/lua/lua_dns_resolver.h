#ifndef RSPAMD_LUA_DNS_H
#define RSPAMD_LUA_DNS_H

struct lua_State;
struct rdns_reply;

/**
 * Pushes dns reply onto Lua stack
 *
 * @param L
 * @param reply
 */
void
lua_push_dns_reply (struct lua_State *L, const struct rdns_reply *reply);

#endif
