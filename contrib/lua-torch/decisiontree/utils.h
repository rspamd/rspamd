#include "error.h"

#define check_tensors(L, a, b) \
   do { \
      if ((a)->nDimension != (b)->nDimension) \
         return LUA_HANDLE_ERROR_STR((L), "different tensor dimensions"); \
      for (int __local__var = 0; __local__var < (a)->nDimension; __local__var++) \
         if ((a)->size[__local__var] != (b)->size[__local__var]) \
            return LUA_HANDLE_ERROR_STR((L), "different tensor sizes"); \
   } while (0)

#define check_tensor(L, t, type) \
   do { \
      if (!type##_isContiguous(t)) \
         return LUA_HANDLE_ERROR_STR((L), "tensor should be contiguous"); \
   } while (0)

#define get_tensor_size(t, type)                \
    (TH##type##Tensor_nElement(t))

#define get_tensor(L, idx, type)                                        \
    (TH##type##Tensor *)luaT_checkudata(L, idx, "torch." #type "Tensor")

static int push_table_contents(lua_State *L, int arg)
{
    int size = 0;
    while(1) {
        lua_checkstack(L, 1);
        lua_rawgeti(L, arg, size + 1);
        if (lua_isnil(L, -1)) {
            lua_pop(L, 1);
            break;
        }
        size++;
    }
    return size;
}

#define verify_push_table_contents(L, idx, count)  do {             \
        int __tmp_count = push_table_contents(L, idx);              \
        if (__tmp_count != count) {                                 \
            lua_pop(L, __tmp_count);                                \
            LUA_HANDLE_ERROR_STR(L, "Table sizes do not match");    \
        }                                                           \
    } while(0)
