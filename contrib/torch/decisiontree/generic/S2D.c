#ifndef TH_GENERIC_FILE
#define TH_GENERIC_FILE "generic/S2D.c"
#else

static int nn_(S2D_computeOutput)(lua_State *L) {
  THTensor *output = luaT_checkudata(L, 1, torch_Tensor);
  const int keys_index = 2;
  const int values_index = 3;
  const int masks_index = 4;

  if (!lua_istable(L, keys_index))
    return LUA_HANDLE_ERROR_STR(L, "expeced position 2 to be a table");
  if (!lua_istable(L, values_index))
    return LUA_HANDLE_ERROR_STR(L, "expeced position 3 to be a table");
  if (!lua_istable(L, masks_index))
    return LUA_HANDLE_ERROR_STR(L, "expeced position 4 to be a table");


  THLongTensor *features = luaT_checkudata(L, 5, "torch.LongTensor");

  const int original_top = lua_gettop(L);

  long outputsize = THLongTensor_size(features, 0);
  long batch_size = lua_objlen(L, keys_index);

  // initializes output
  THTensor_(resize2d)(output, batch_size, outputsize);
  THTensor_(zero)(output);
  real *output_data = THTensor_(data)(output);

  // iterates over samples
  lua_pushnil(L);
  const int local_top = lua_gettop(L);
  while (lua_next(L, keys_index) != 0) {
    // gets data corresponding to the current sample
    long i = lua_tointeger(L, -2)-1;
    real *current_output_data = &output_data[i * outputsize];
    THLongTensor *keys = luaT_checkudata(L, -1, "torch.LongTensor");
    lua_rawgeti(L, values_index, i+1);
    THTensor *values = luaT_checkudata(L, -1, torch_Tensor);
    lua_rawgeti(L, masks_index, i+1);
    THByteTensor *mask = luaT_checkudata(L, -1, "torch.ByteTensor");

    long n_keys = THLongTensor_size(keys, 0);
    long n_values = THTensor_(size)(values, 0);

    // quick safety check
    if (n_keys != n_values)
      return LUA_HANDLE_ERROR_STR(L, "keys and values have to have the same size");

    // gets the direct memory pointers
    long *keys_data = THLongTensor_data(keys);
    real *values_data = THTensor_(data)(values);
    unsigned char *mask_data = THByteTensor_data(mask);

    // for each value in the sparse input...
    for (long j = 0; j < n_keys; j++) {
      // loads the value and key
      real current_value = values_data[j];
      long current_key = keys_data[j];
      unsigned char current_mask = mask_data[j];

      // if the feature is present in the map
      if (current_mask)
        // saves in the given position
        current_output_data[current_key-1] = current_value;
    }
    // cleans up the trash we create by iterating over keys to avoid it from overflowing
    lua_pop(L, lua_gettop(L) - local_top);
  }

  // cleans up the trash we added to the stack
  lua_pop(L, lua_gettop(L) - original_top);

  return 0;
}

static const struct luaL_Reg nn_(S2D__) [] = {
  {"S2D_computeOutput", nn_(S2D_computeOutput)},
  {NULL, NULL}
};

static void nn_(S2D_init)(lua_State *L)
{
  luaT_pushmetatable(L, torch_Tensor);
  luaT_registeratname(L, nn_(S2D__), "nn");
  lua_pop(L,1);
}

#endif
