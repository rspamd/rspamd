#include "utils.h"
#include "hash_map.h"
#include "internal_hash_map.h"
#include <pthread.h>

hash_map_t hash_map_init(void) {
   return kh_init(long);
}

void hash_map_destroy(hash_map_t h_) {
   internal_hash_map_t h = (internal_hash_map_t) h_;
   kh_destroy(long, h);
}

void hash_map_clear(hash_map_t h_) {
   internal_hash_map_t h = (internal_hash_map_t) h_;
   kh_clear(long, h);
}

int hash_map_put(hash_map_t h_, long key, long val) {
   internal_hash_map_t h = (internal_hash_map_t) h_;
   int ret;
   khiter_t k = kh_put(long, h, key, &ret);
   ret = (ret >= 0);
   if (ret)
      kh_value(h, k) = val;
   return ret;
}

int hash_map_put_tensor(hash_map_t h_, THLongTensor *keys_, THLongTensor *vals_) {
   long *keys = THLongTensor_data(keys_);
   long *vals = THLongTensor_data(vals_);
   long size = get_tensor_size(keys_, Long);
   for (long i = 0; i < size; i++)
      if (!hash_map_put(h_, keys[i], vals[i]))
         return 0;
   return 1;
}

int hash_map_fill(hash_map_t h_, long key, long *counter) {
   internal_hash_map_t h = (internal_hash_map_t) h_;
   khiter_t k = kh_get(long, h, key);
   if (k == kh_end(h))
      return hash_map_put(h_, key, ++(*counter));
   return 1;
}

int hash_map_fill_tensor(hash_map_t h_, THLongTensor *keys_, long *counter) {
   long *keys = THLongTensor_data(keys_);
   long size = get_tensor_size(keys_, Long);
   for (long i = 0; i < size; i++)
      if (!hash_map_fill(h_, keys[i], counter))
         return 0;
   return 1;
}

int hash_map_get(hash_map_t h_, long key, long* val) {
   internal_hash_map_t h = (internal_hash_map_t) h_;
   khiter_t k = kh_get(long, h, key);
   if (k == kh_end(h))
      return 0;
   *val = kh_value(h, k);
   return 1;
}

void hash_map_get_tensor(hash_map_t h_, THLongTensor *keys_, THLongTensor *vals_, THByteTensor *mask_) {
   long *keys = THLongTensor_data(keys_);
   long *vals = THLongTensor_data(vals_);;
   unsigned char *mask = THByteTensor_data(mask_);
   long size = get_tensor_size(keys_, Long);
   for (long i = 0; i < size; i++)
      mask[i] = hash_map_get(h_, keys[i], &vals[i]);
}

void hash_map_del(hash_map_t h_, long key) {
   internal_hash_map_t h = (internal_hash_map_t) h_;
   khiter_t k = kh_get(long, h, key);
   if (k != kh_end(h))
      kh_del(long, h, k);
}

void hash_map_del_tensor(hash_map_t h_, THLongTensor *keys_) {
   long *keys = THLongTensor_data(keys_);
   long size = get_tensor_size(keys_, Long);
   for (long i = 0; i < size; i++)
      hash_map_del(h_, keys[i]);
}

size_t hash_map_size(hash_map_t h_) {
   internal_hash_map_t h = (internal_hash_map_t) h_;
   return kh_size(h);
}

void hash_map_to_tensor(hash_map_t h_, THLongTensor *keys_, THLongTensor *vals_) {
   internal_hash_map_t h = (internal_hash_map_t) h_;
   long *keys = THLongTensor_data(keys_);
   long *vals = THLongTensor_data(vals_);
   long key, val, i = 0;
   kh_foreach(h, key, val, {
      keys[i] = key;
      vals[i] = val;
      i++;
   });
}

static void autolock(hash_map_lua_t *h) {
   if (h->autolock) {
      pthread_mutex_lock(&h->mutex);
   }
}

static void autounlock(hash_map_lua_t *h) {
   if (h->autolock) {
      pthread_mutex_unlock(&h->mutex);
   }
}

int hash_map_autolock_on_lua(lua_State *L) {
   hash_map_lua_t *h = *(hash_map_lua_t**)lua_touserdata(L, 1);
   h->autolock = 1;
   return 0;
}

int hash_map_autolock_off_lua(lua_State *L) {
   hash_map_lua_t *h = *(hash_map_lua_t**)lua_touserdata(L, 1);
   h->autolock = 0;
   return 0;
}

int hash_map_init_lua(lua_State *L) {
   hash_map_lua_t **hp = (hash_map_lua_t**)lua_newuserdata(L, sizeof(hash_map_lua_t*));
   *hp = (hash_map_lua_t*)malloc(sizeof(hash_map_lua_t));
   hash_map_lua_t *h = *hp;
   h->refcount = 1;
   h->counter = 0;
   h->autolock = 0;
   h->h = hash_map_init();

   pthread_mutexattr_t mutex_attr;
   pthread_mutexattr_init(&mutex_attr);
   pthread_mutexattr_settype(&mutex_attr, PTHREAD_MUTEX_RECURSIVE);
   pthread_mutex_init(&h->mutex, &mutex_attr);

   luaL_getmetatable(L, "dt.HashMap");
   lua_setmetatable(L, -2);
   return 1;
}

int hash_map_gc_lua(lua_State *L) {
   hash_map_lua_t *h = *(hash_map_lua_t**)lua_touserdata(L, 1);
   if (THAtomicDecrementRef(&h->refcount)) {
      pthread_mutex_destroy(&h->mutex);
      hash_map_destroy(h->h);
      free(h);
   }
   return 0;
}

int hash_map_retain_lua(lua_State *L) {
   hash_map_lua_t *h = *(hash_map_lua_t**)lua_touserdata(L, 1);
   THAtomicIncrementRef(&h->refcount);
   return 0;
}

int hash_map_metatablename_lua(lua_State *L) {
   lua_pushstring(L, "dt.HashMap");
   return 1;
}

int hash_map_clear_lua(lua_State *L) {
   hash_map_lua_t *h = *(hash_map_lua_t**)lua_touserdata(L, 1);
   autolock(h);
   hash_map_clear(h->h);
   autounlock(h);
   return 0;
}

int hash_map_put_lua(lua_State *L) {
   hash_map_lua_t *h = *(hash_map_lua_t**)lua_touserdata(L, 1);
   int ret;
#if LUA_VERSION_NUM <= 501
#define lua_isinteger lua_isnumber
#endif
   if (lua_isinteger(L, 2)) {
      if (!lua_isinteger(L, 3))
         return LUA_HANDLE_ERROR_STR(L, "second parameter is not a number");
      long key = lua_tointeger(L, 2);
      long val = lua_tointeger(L, 3);
      autolock(h);
      ret = hash_map_put(h->h, key, val);
      autounlock(h);
   }
   else {
      THLongTensor *keys = (THLongTensor *)luaT_checkudata(L, 2, "torch.LongTensor");
      THLongTensor *vals = (THLongTensor *)luaT_checkudata(L, 3, "torch.LongTensor");
      check_tensor(L, keys, THLongTensor);
      check_tensor(L, vals, THLongTensor);
      check_tensors(L, keys, vals);
      autolock(h);
      ret = hash_map_put_tensor(h->h, keys, vals);
      autounlock(h);
   }
   if (!ret)
      return LUA_HANDLE_ERROR_STR(L, "failed to put into hash map");
   return 0;
}

int hash_map_fill_lua(lua_State *L) {
   hash_map_lua_t *h = *(hash_map_lua_t**)lua_touserdata(L, 1);
   int ret;
   if (lua_isinteger(L, 2)) {
      long key = lua_tointeger(L, 2);
      autolock(h);
      ret = hash_map_fill(h->h, key, &h->counter);
      autounlock(h);
   }
   else {
      THLongTensor *keys = (THLongTensor *)luaT_checkudata(L, 2, "torch.LongTensor");
      check_tensor(L, keys, THLongTensor);
      autolock(h);
      ret = hash_map_fill_tensor(h->h, keys, &h->counter);
      autounlock(h);
   }
   if (!ret)
      return LUA_HANDLE_ERROR_STR(L, "failed to fill into hash map");
   return 0;
}

int hash_map_adjust_counter_lua(lua_State *L) {
   hash_map_lua_t *h_ = *(hash_map_lua_t**)lua_touserdata(L, 1);
   internal_hash_map_t h = (internal_hash_map_t) h_->h;

   long val;
   kh_foreach_value(h, val, {
      if (val >= h_->counter)
         h_->counter = val;
   });
   return 0;
}

int hash_map_set_counter_lua(lua_State *L) {
   hash_map_lua_t *h_ = *(hash_map_lua_t**)lua_touserdata(L, 1);
   h_->counter = lua_tointeger(L, 2);
   return 0;
}

int hash_map_get_counter_lua(lua_State *L) {
   hash_map_lua_t *h_ = *(hash_map_lua_t**)lua_touserdata(L, 1);
   lua_pushinteger(L, h_->counter);
   return 1;
}

static int hash_map_get_tensor_lua(lua_State *L, hash_map_lua_t *h, int inplace) {
    THLongTensor *keys = (THLongTensor *)luaT_checkudata(L, 2, "torch.LongTensor");
    check_tensor(L, keys, THLongTensor);
    THLongTensor *vals = inplace ? keys : NULL;
    THByteTensor *mask = NULL;

    int maskIdx = inplace ? 3 : 4;

    if (!inplace) {
       if (lua_gettop(L) < 3) {
          vals = THLongTensor_new();
       } else {
          vals = (THLongTensor *)luaT_checkudata(L, 3, "torch.LongTensor");
          check_tensor(L, vals, THLongTensor);
       }
    }

    if (lua_gettop(L) < maskIdx) {
        mask = THByteTensor_new();
    } else {
        mask = (THByteTensor *)luaT_checkudata(L, maskIdx, "torch.ByteTensor");
        check_tensor(L, mask, THByteTensor);
    }

    int n_dim = THLongTensor_nDimension(keys);
    THLongStorage *st = THLongStorage_newWithSize1(n_dim);
    for (int i = 0; i < n_dim; i++) {
        THLongStorage_set(st, i, THLongTensor_size(keys, i));
    }
    THByteTensor_resize(mask, st, NULL);
    if (!inplace) THLongTensor_resize(vals, st, NULL);
    THLongStorage_free(st);

    autolock(h);
    hash_map_get_tensor(h->h, keys, vals, mask);
    autounlock(h);

    if (!inplace && lua_gettop(L) < 3)
        luaT_pushudata(L, vals, "torch.LongTensor");
    if (lua_gettop(L) < maskIdx)
        luaT_pushudata(L, mask, "torch.ByteTensor");

    return 2;
}

static int hash_map_get_table_lua(lua_State *L, hash_map_lua_t *h, int inplace) {
    const int kidx = 2;
    const int vidx = inplace ? 2 : 3;
    const int midx = inplace ? 3 : 4;
    const int narg = lua_gettop(L);

    if (inplace) {
        if (narg < 3) {
            LUA_HANDLE_ERROR_STR(L, "HashMap.getInplace requires two arguments.");
        }
    } else {
        if (narg < 4) {
            LUA_HANDLE_ERROR_STR(L, "HashMap.get requires three arguments.");
        }
    }

    int count = push_table_contents(L, kidx);
    verify_push_table_contents(L, vidx, count);
    verify_push_table_contents(L, midx, count);

    THLongTensor *keys;
    THLongTensor *vals;
    THByteTensor *mask;
    for (int i = count - 1; i >= 0; i--) {
        int maskIdx = i - count;
        int valIdx = maskIdx -  count;
        int keyIdx = inplace ? valIdx : (valIdx - count);

        keys = (THLongTensor *)luaT_checkudata(L, keyIdx, "torch.LongTensor");
        check_tensor(L, keys, THLongTensor);
        if (inplace) {
            vals = keys;
        } else {
            vals = (THLongTensor *)luaT_checkudata(L, valIdx, "torch.LongTensor");
        }
        mask = (THByteTensor *)luaT_checkudata(L, maskIdx, "torch.ByteTensor");

        int n_dim = THLongTensor_nDimension(keys);
        THLongStorage *st = THLongStorage_newWithSize1(n_dim);
        for (int i = 0; i < n_dim; i++) {
            THLongStorage_set(st, i, THLongTensor_size(keys, i));
        }
        THByteTensor_resize(mask, st, NULL);
        THLongTensor_resize(vals, st, NULL);
        THLongStorage_free(st);

        autolock(h);
        hash_map_get_tensor(h->h, keys, vals, mask);
        autounlock(h);
    }
    lua_pop(L, (narg - 1) * count);
    return 2;
}

int hash_map_get_lua(lua_State *L) {
   hash_map_lua_t *h = *(hash_map_lua_t**)lua_touserdata(L, 1);
   if (lua_isinteger(L, 2)) {
      long key = lua_tointeger(L, 2);
      long val;
      autolock(h);
      int ret = hash_map_get(h->h, key, &val);
      autounlock(h);
      if (ret) {
         lua_pushinteger(L, val);
         lua_pushinteger(L, 1);
      }
      else {
         lua_pushinteger(L, 0);
         lua_pushinteger(L, 0);
      }
   } else if (lua_istable(L, 2)) {
      return hash_map_get_table_lua(L, h, 0);
   } else {
      return hash_map_get_tensor_lua(L, h, 0);
   }
   return 2;
}

int hash_map_get_inplace_lua(lua_State *L) {
   hash_map_lua_t *h = *(hash_map_lua_t**)lua_touserdata(L, 1);
   if (lua_isinteger(L, 2)) {
      LUA_HANDLE_ERROR_STR(L, "HashMap.getInplace does not support integer arguments.");
   } else if (lua_istable(L, 2)) {
      return hash_map_get_table_lua(L, h, 1);
   } else {
      return hash_map_get_tensor_lua(L, h, 1);
   }
   return 2;
}

int hash_map_del_lua(lua_State *L) {
   hash_map_lua_t *h = *(hash_map_lua_t**)lua_touserdata(L, 1);
   if (lua_isinteger(L, 2)) {
      long key = lua_tointeger(L, 2);
      autolock(h);
      hash_map_del(h->h, key);
      autounlock(h);
   }
   else {
      THLongTensor *keys = (THLongTensor *)luaT_checkudata(L, 2, "torch.LongTensor");
      autolock(h);
      hash_map_del_tensor(h->h, keys);
      autounlock(h);
   }
   return 0;
}

int hash_map_size_lua(lua_State *L) {
   hash_map_lua_t *h = *(hash_map_lua_t**)lua_touserdata(L, 1);
   long size = hash_map_size(h->h);
   lua_pushinteger(L, size);
   return 1;
}

int hash_map_to_tensor_lua(lua_State *L) {
   hash_map_lua_t *h = *(hash_map_lua_t**)lua_touserdata(L, 1);
   THLongTensor *keys, *vals;

   if (lua_gettop(L) < 2) {
      keys = THLongTensor_new();
   }
   else {
      keys = (THLongTensor *)luaT_checkudata(L, 2, "torch.LongTensor");
      check_tensor(L, keys, THLongTensor);
   }

   if (lua_gettop(L) < 3) {
      vals = THLongTensor_new();
   }
   else {
      vals = (THLongTensor *)luaT_checkudata(L, 3, "torch.LongTensor");
      check_tensor(L, vals, THLongTensor);
   }

   size_t size = hash_map_size(h->h);
   THLongTensor_resize1d(keys, size);
   THLongTensor_resize1d(vals, size);

   autolock(h);
   hash_map_to_tensor(h->h, keys, vals);
   autounlock(h);

   if (lua_gettop(L) < 2)
      luaT_pushudata(L, keys, "torch.LongTensor");
   if (lua_gettop(L) < 3)
      luaT_pushudata(L, vals, "torch.LongTensor");
   return 2;
}
