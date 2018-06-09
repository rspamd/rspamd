#include "TH.h"
#include "luaT.h"

#ifdef _OPENMP
#include "omp.h"
#endif

#include "error.h"
#include "hash_map.h"

#define torch_(NAME) TH_CONCAT_3(torch_, Real, NAME)
#define torch_Tensor TH_CONCAT_STRING_3(torch., Real, Tensor)
#define nn_(NAME) TH_CONCAT_3(nn_, Real, NAME)

#include "generic/LogitBoostCriterion.c"
#include "THGenerateFloatTypes.h"

#include "generic/DFD.c"
#include "THGenerateFloatTypes.h"

#include "generic/S2D.c"
#include "THGenerateFloatTypes.h"

#include "generic/CartTree.c"
#include "THGenerateFloatTypes.h"

#include "GBDT_common.h"
#include "generic/GBDT.c"
#include "THGenerateFloatTypes.h"

static const struct luaL_Reg decisiontree_hash_map_routines[] = {
   {"__gc", hash_map_gc_lua},
   {"retain", hash_map_retain_lua},
   {"metatablename", hash_map_metatablename_lua},
   {"clear", hash_map_clear_lua},
   {"put", hash_map_put_lua},
   {"fill", hash_map_fill_lua},
   {"adjustCounter", hash_map_adjust_counter_lua},
   {"getCounter", hash_map_get_counter_lua},
   {"setCounter", hash_map_set_counter_lua},
   {"get", hash_map_get_lua},
   {"getInplace", hash_map_get_inplace_lua},
   {"del", hash_map_del_lua},
   {"size", hash_map_size_lua},
   {"safe", hash_map_autolock_on_lua},
   {"unsafe", hash_map_autolock_off_lua},
   {"toTensors", hash_map_to_tensor_lua},
   {"new", hash_map_init_lua},
   {NULL, NULL}
};

DLL_EXPORT int luaopen_libdecisiontree(lua_State *L)
{
  // HashMap
  luaL_newmetatable(L, "dt.HashMap");
  lua_pushstring(L, "__index");
  lua_pushvalue(L, -2);
  lua_settable(L, -3);
  luaT_setfuncs(L, decisiontree_hash_map_routines, 0);

  nn_FloatLogitBoostCriterion_init(L);
  nn_DoubleLogitBoostCriterion_init(L);

  nn_FloatDFD_init(L);
  nn_DoubleDFD_init(L);

  nn_FloatS2D_init(L);
  nn_DoubleS2D_init(L);

  nn_FloatCT_init(L);
  nn_DoubleCT_init(L);

  nn_FloatGBDT_init(L);
  nn_DoubleGBDT_init(L);

  return 1;
}
