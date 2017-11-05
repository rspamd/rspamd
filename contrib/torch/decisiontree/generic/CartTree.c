#ifndef TH_GENERIC_FILE
#define TH_GENERIC_FILE "generic/CartTree.c"
#else

static int nn_(tree_fast_score)(lua_State *L) {
  THTensor *input = luaT_checkudata(L, 1, torch_Tensor);
  THTensor *score = luaT_checkudata(L, 3, torch_Tensor);
  long n_samples = THTensor_(size)(input, 0);
  long n_features = THTensor_(size)(input, 1);
  THTensor_(resize1d)(score, n_samples);
  real *input_data = THTensor_(data)(input);
  real *score_data = THTensor_(data)(score);

  lua_pushstring(L, "leftChild");
  const int left_child_string = 4;
  lua_pushstring(L, "rightChild");
  const int right_child_string = 5;
  lua_pushstring(L, "score");
  const int score_string = 6;
  lua_pushstring(L, "splitFeatureId");
  const int id_string = 7;
  lua_pushstring(L, "splitFeatureValue");
  const int value_string = 8;

  const int original_top = lua_gettop(L);
  for (long i = 0; i < n_samples; i++) {
    int node = 2;
    while (1) {
      int current_top = lua_gettop(L);
      lua_pushvalue(L, left_child_string);
      lua_rawget(L, node);
      lua_pushvalue(L, right_child_string);
      lua_rawget(L, node);
      if (lua_isnil(L, -2) && lua_isnil(L, -1)) {
        lua_pushvalue(L, score_string);
        lua_rawget(L, node);
        score_data[i] = lua_tonumber(L, -1);
        break;
      }
      if (lua_isnil(L, -2)) {
        // go to right
        node = current_top + 2;
        continue;
      }
      if (lua_isnil(L, -1)) {
        // go to left
        node = current_top + 1;
        continue;
      }
      lua_pushvalue(L, id_string);
      lua_rawget(L, node);
      lua_pushvalue(L, value_string);
      lua_rawget(L, node);
      long feature_id = lua_tointeger(L, -2);
      real feature_value = lua_tonumber(L, -1);

      real current_value = input_data[i * n_features + (feature_id-1)];
      if (current_value < feature_value) {
        // go to left
        node = current_top + 1;
      }
      else {
        // go to right
        node = current_top + 2;
      }
    }
    lua_pop(L, lua_gettop(L) - original_top);
  }

  lua_pop(L, 5);

  lua_pushvalue(L, 3);
  return 1;
}

static const struct luaL_Reg nn_(CT__) [] = {
  {"CartTreeFastScore", nn_(tree_fast_score)},
  {NULL, NULL}
};

static void nn_(CT_init)(lua_State *L)
{
  luaT_pushmetatable(L, torch_Tensor);
  luaT_registeratname(L, nn_(CT__), "nn");
  lua_pop(L,1);
}

#endif
