#ifndef TH_GENERIC_FILE
#define TH_GENERIC_FILE "generic/LogitBoostCriterion.c"
#else

#define EPS 1e-12

static int nn_(LogitBoostCriterion_updateOutput)(lua_State *L)
{
  THTensor *input = luaT_checkudata(L, 1, torch_Tensor);
  THTensor *target = luaT_checkudata(L, 2, torch_Tensor);
  THTensor *output = luaT_checkudata(L, 3, torch_Tensor);
  int sizeAverage = lua_toboolean(L, 4);

  if (THTensor_(nElement)(input) != THTensor_(nElement)(target)) {
    luaL_error(L, "inconsistent input and target size");
  }
  THTensor_(resize1d)(output, 1);

  real sum = 0;

  TH_TENSOR_APPLY2(real, input, real, target,
    real x = *input_data;
    real y = *target_data;
    // math.log(1 + math.exp(target[i] <= 0 and input[i] or -input[i]))
    sum += log(1 + exp(y <= 0 ? x : -x));
  );

  if (sizeAverage)
    sum /= THTensor_(nElement)(input);

  THTensor_(set1d)(output, 0, sum);
  return 0;
}

static int nn_(LogitBoostCriterion_updateGradInput)(lua_State *L)
{
  THTensor *input = luaT_checkudata(L, 1, torch_Tensor);
  THTensor *target = luaT_checkudata(L, 2, torch_Tensor);
  THTensor *gradInput = luaT_checkudata(L, 3, torch_Tensor);

  if (THTensor_(nElement)(input) != THTensor_(nElement)(target)) {
    luaL_error(L, "inconsistent input and target size");
  }
  THTensor_(resizeAs)(gradInput, input);

  TH_TENSOR_APPLY3(real, gradInput, real, input, real, target,
    real x = *input_data;
    real y = *target_data;
    real p = (x >= 0) ? (1 / (1 + exp(-x))) : (1 - 1 / (1 + exp(x)));
    *gradInput_data = (y <= 0) ? p : (p - 1);
  );

  return 0;
}

static int nn_(LogitBoostCriterion_updateHessInput)(lua_State *L)
{
  THTensor *input = luaT_checkudata(L, 1, torch_Tensor);
  THTensor *target = luaT_checkudata(L, 2, torch_Tensor);
  THTensor *hessInput = luaT_checkudata(L, 3, torch_Tensor);

  if (THTensor_(nElement)(input) != THTensor_(nElement)(target)) {
    luaL_error(L, "inconsistent input and target size");
  }
  THTensor_(resizeAs)(hessInput, input);

  TH_TENSOR_APPLY3(real, hessInput, real, input, real, target,
    real x = *input_data;
    real p = (x >= 0) ? (1 / (1 + exp(-x))) : (1 - 1 / (1 + exp(x)));
    *hessInput_data = p * (1.0 - p);
  );

  return 0;
}

static const struct luaL_Reg nn_(LogitBoostCriterion__) [] = {
  {"LogitBoostCriterion_updateOutput", nn_(LogitBoostCriterion_updateOutput)},
  {"LogitBoostCriterion_updateGradInput", nn_(LogitBoostCriterion_updateGradInput)},
  {"LogitBoostCriterion_updateHessInput", nn_(LogitBoostCriterion_updateHessInput)},
  {NULL, NULL}
};

static void nn_(LogitBoostCriterion_init)(lua_State *L)
{
  luaT_pushmetatable(L, torch_Tensor);
  luaT_registeratname(L, nn_(LogitBoostCriterion__), "nn");
  lua_pop(L,1);
}

#endif
