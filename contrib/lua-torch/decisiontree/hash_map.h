#include "luaT.h"
#include "TH.h"

typedef void* hash_map_t;

hash_map_t hash_map_init(void);
void hash_map_destroy(hash_map_t);
void hash_map_clear(hash_map_t);
int hash_map_put(hash_map_t, long key, long val);
int hash_map_put_tensor(hash_map_t, THLongTensor *keys_, THLongTensor *vals_);
int hash_map_fill(hash_map_t, long key, long *counter);
int hash_map_fill_tensor(hash_map_t, THLongTensor *keys_, long *counter);
int hash_map_get(hash_map_t, long key, long *val);
void hash_map_get_tensor(hash_map_t, THLongTensor *keys_, THLongTensor *vals_, THByteTensor *mask_);
void hash_map_del(hash_map_t, long key);
void hash_map_del_tensor(hash_map_t, THLongTensor *keys_);
size_t hash_map_size(hash_map_t);
void hash_map_to_tensor(hash_map_t, THLongTensor *keys_, THLongTensor *vals_);

int hash_map_autolock_on_lua(lua_State *L);
int hash_map_autolock_off_lua(lua_State *L);
int hash_map_init_lua(lua_State *L);
int hash_map_gc_lua(lua_State *L);
int hash_map_retain_lua(lua_State *L);
int hash_map_metatablename_lua(lua_State *L);
int hash_map_clear_lua(lua_State *L);
int hash_map_put_lua(lua_State *L);
int hash_map_fill_lua(lua_State *L);
int hash_map_adjust_counter_lua(lua_State *L);
int hash_map_set_counter_lua(lua_State *L);
int hash_map_get_counter_lua(lua_State *L);
int hash_map_get_lua(lua_State *L);
int hash_map_get_inplace_lua(lua_State *L);
int hash_map_del_lua(lua_State *L);
int hash_map_size_lua(lua_State *L);
int hash_map_to_tensor_lua(lua_State *L);
