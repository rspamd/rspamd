#include "luaT.h"
#include "TH.h"

extern void torch_Generator_init(lua_State *L);
extern void torch_Generator_new(lua_State *L);

#ifndef _CWRAP_STR_ARG_TYPES_4821726c1947cdf3eebacade98173939
#define _CWRAP_STR_ARG_TYPES_4821726c1947cdf3eebacade98173939
#include "string.h"
static void str_arg_types(lua_State *L, char *buf, int n) {
    int i;
  int nargs = lua_gettop(L);
  if (nargs == 0) {
    snprintf(buf, n, "no arguments provided");
    return;
  }
  for (i = 1; i <= nargs; i++) {
    int l;
    const char *torch_type = luaT_typename(L, i);
    if(torch_type && !strncmp(torch_type, "torch.", 6)) torch_type += 6;
    if (torch_type) l = snprintf(buf, n, "%s ", torch_type);
    else if(lua_isnil(L, i)) l = snprintf(buf, n, "%s ", "nil");
    else if(lua_isboolean(L, i)) l = snprintf(buf, n, "%s ", "boolean");
    else if(lua_isnumber(L, i)) l = snprintf(buf, n, "%s ", "number");
    else if(lua_isstring(L, i)) l = snprintf(buf, n, "%s ", "string");
    else if(lua_istable(L, i)) l = snprintf(buf, n, "%s ", "table");
    else if(lua_isuserdata(L, i)) l = snprintf(buf, n, "%s ", "userdata");
    else l = snprintf(buf, n, "%s ", "???");
    if (l >= n) return;
    buf += l;
    n   -= l;
  }
}
#endif
static int wrapper_seed(lua_State *L)
{
int narg = lua_gettop(L);
THGenerator *arg1 = NULL;
long arg2 = 0;
if(narg == 0
)
{
lua_getglobal(L,"torch");
arg1 = luaT_getfieldcheckudata(L, -1, "_gen", torch_Generator);
lua_pop(L, 2);
}
else if(narg == 1
&& (arg1 = luaT_toudata(L, 1, torch_Generator))
)
{
}
else
{
char type_buf[512];
str_arg_types(L, type_buf, 512);
luaL_error(L, "invalid arguments: %s\nexpected arguments: [Generator]", type_buf);
}
arg2 = THRandom_seed(arg1);
lua_pushnumber(L, (lua_Number)arg2);
return 1;
}

static int wrapper_initialSeed(lua_State *L)
{
int narg = lua_gettop(L);
THGenerator *arg1 = NULL;
long arg2 = 0;
if(narg == 0
)
{
lua_getglobal(L,"torch");
arg1 = luaT_getfieldcheckudata(L, -1, "_gen", torch_Generator);
lua_pop(L, 2);
}
else if(narg == 1
&& (arg1 = luaT_toudata(L, 1, torch_Generator))
)
{
}
else
{
char type_buf[512];
str_arg_types(L, type_buf, 512);
luaL_error(L, "invalid arguments: %s\nexpected arguments: [Generator]", type_buf);
}
arg2 = THRandom_initialSeed(arg1);
lua_pushnumber(L, (lua_Number)arg2);
return 1;
}

static int wrapper_manualSeed(lua_State *L)
{
int narg = lua_gettop(L);
THGenerator *arg1 = NULL;
long arg2 = 0;
if(narg == 1
&& lua_isnumber(L, 1)
)
{
arg2 = (long)lua_tonumber(L, 1);
lua_getglobal(L,"torch");
arg1 = luaT_getfieldcheckudata(L, -1, "_gen", torch_Generator);
lua_pop(L, 2);
}
else if(narg == 2
&& (arg1 = luaT_toudata(L, 1, torch_Generator))
&& lua_isnumber(L, 2)
)
{
arg2 = (long)lua_tonumber(L, 2);
}
else
{
char type_buf[512];
str_arg_types(L, type_buf, 512);
luaL_error(L, "invalid arguments: %s\nexpected arguments: [Generator] long", type_buf);
}
THRandom_manualSeed(arg1,arg2);
return 0;
}

static int wrapper_getRNGState(lua_State *L)
{
int narg = lua_gettop(L);
THGenerator *arg1 = NULL;
THByteTensor *arg2 = NULL;
int arg2_idx = 0;
if(narg == 0
)
{
lua_getglobal(L,"torch");
arg1 = luaT_getfieldcheckudata(L, -1, "_gen", torch_Generator);
lua_pop(L, 2);
arg2 = THByteTensor_new();
}
else if(narg == 1
&& (arg1 = luaT_toudata(L, 1, torch_Generator))
)
{
arg2 = THByteTensor_new();
}
else if(narg == 1
&& (arg2 = luaT_toudata(L, 1, "torch.ByteTensor"))
)
{
arg2_idx = 1;
lua_getglobal(L,"torch");
arg1 = luaT_getfieldcheckudata(L, -1, "_gen", torch_Generator);
lua_pop(L, 2);
}
else if(narg == 2
&& (arg1 = luaT_toudata(L, 1, torch_Generator))
&& (arg2 = luaT_toudata(L, 2, "torch.ByteTensor"))
)
{
arg2_idx = 2;
}
else
{
char type_buf[512];
str_arg_types(L, type_buf, 512);
luaL_error(L, "invalid arguments: %s\nexpected arguments: [Generator] [*ByteTensor*]", type_buf);
}
if(arg2_idx)
lua_pushvalue(L, arg2_idx);
else
luaT_pushudata(L, arg2, "torch.ByteTensor");
THByteTensor_getRNGState(arg1,arg2);
return 1;
}

static int wrapper_setRNGState(lua_State *L)
{
int narg = lua_gettop(L);
THGenerator *arg1 = NULL;
THByteTensor *arg2 = NULL;
int arg2_idx = 0;
if(narg == 0
)
{
lua_getglobal(L,"torch");
arg1 = luaT_getfieldcheckudata(L, -1, "_gen", torch_Generator);
lua_pop(L, 2);
arg2 = THByteTensor_new();
}
else if(narg == 1
&& (arg1 = luaT_toudata(L, 1, torch_Generator))
)
{
arg2 = THByteTensor_new();
}
else if(narg == 1
&& (arg2 = luaT_toudata(L, 1, "torch.ByteTensor"))
)
{
arg2_idx = 1;
lua_getglobal(L,"torch");
arg1 = luaT_getfieldcheckudata(L, -1, "_gen", torch_Generator);
lua_pop(L, 2);
}
else if(narg == 2
&& (arg1 = luaT_toudata(L, 1, torch_Generator))
&& (arg2 = luaT_toudata(L, 2, "torch.ByteTensor"))
)
{
arg2_idx = 2;
}
else
{
char type_buf[512];
str_arg_types(L, type_buf, 512);
luaL_error(L, "invalid arguments: %s\nexpected arguments: [Generator] [*ByteTensor*]", type_buf);
}
if(arg2_idx)
lua_pushvalue(L, arg2_idx);
else
luaT_pushudata(L, arg2, "torch.ByteTensor");
THByteTensor_setRNGState(arg1,arg2);
return 1;
}

static const struct luaL_Reg random__ [] = {
{"seed", wrapper_seed},
{"initialSeed", wrapper_initialSeed},
{"manualSeed", wrapper_manualSeed},
{"getRNGState", wrapper_getRNGState},
{"setRNGState", wrapper_setRNGState},
{NULL, NULL}
};

void torch_random_init(lua_State *L)
{
  torch_Generator_init(L);
  torch_Generator_new(L);
  lua_setfield(L, -2, "_gen");
  luaT_setfuncs(L, random__, 0);
}
