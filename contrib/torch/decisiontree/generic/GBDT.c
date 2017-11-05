#ifndef TH_GENERIC_FILE
#define TH_GENERIC_FILE "generic/GBDT.c"
#else

#include "GBDT_internal.h"
#include "GBDT_internal.c"

// note that each one of the functions to find the best split is a subset of the next.
// first we have one that can only evaluate a single feature, using the logic in lua to control the
// features
// then we have one that can go over a shard of faetures, following the feature parallelism
// introduced by the lua logic
// and finally we have one that performans the feature parallelism itself in the special case of
// dense tensors
// these functions are provided for completeness and to test in case the logic is to be changed

// finds the best split for a given node and feature
static int nn_(gb_findBestFeatureSplit)(lua_State *L) {
  THLongTensor *exampleIds = luaT_checkudata(L, 1, "torch.LongTensor");
  const int dataset_index = 2;
  if (!lua_isnumber(L, 3))
    return LUA_HANDLE_ERROR_STR(L, "third argument should be an integer");
  long feature_id = lua_tointeger(L, 3);
  if (!lua_isnumber(L, 4))
    return LUA_HANDLE_ERROR_STR(L, "fourth argument should be an integer");
  long minLeafSize = lua_tointeger(L, 4);
  // Since minLeafSize == 1 corresponds to each sample in its own leaf, any value below it doesn't
  // make sense
  if (minLeafSize < 1)
    minLeafSize = 1;
  THTensor *grad = luaT_checkudata(L, 5, torch_Tensor);
  THTensor *hess = luaT_checkudata(L, 6, torch_Tensor);

  if (!THLongTensor_isContiguous(exampleIds))
    return LUA_HANDLE_ERROR_STR(L, "exampleIds has to be contiguous");
  if (!THTensor_(isContiguous)(grad))
    return LUA_HANDLE_ERROR_STR(L, "grad has to be contiguous");
  if (!THTensor_(isContiguous)(hess))
    return LUA_HANDLE_ERROR_STR(L, "hessian has to be contiguous");

  // initializes the static data
  nn_(GBInitialization) initialization_data;
  nn_(gb_initialize)(L, &initialization_data, exampleIds, grad, hess, dataset_index);

  // initializes the dynamic data
  GBRunData run_data;
  gb_create_run_data(&run_data, minLeafSize);

  // finds the best state possible for the split
  nn_(GBBestState) bs;
  nn_(gb_find_best_feature_split)(L, &initialization_data, &bs, feature_id, &run_data);

  lua_pop(L, lua_gettop(L) - initialization_data.splitInfo_index);

  // fills the table we the best split found and the lua logic above will do everything else
  // if no state was found, returns nil
  if (bs.valid_state == 0) {
    lua_pop(L, 1);
    lua_pushnil(L);
  }
  else {
    nn_(gb_internal_split_info)(L, &bs, initialization_data.splitInfo_index);
  }

  gb_destroy_run_data(&run_data);

  return 1;
}

// finds the best split for a given node and shard of features
// this is more efficient than calling the previous one multiple times
static int nn_(gb_findBestSplit)(lua_State *L) {
  THLongTensor *exampleIds = luaT_checkudata(L, 1, "torch.LongTensor");
  const int dataset_index = 2;
  THLongTensor *feature_ids = luaT_checkudata(L, 3, "torch.LongTensor");
  if (!lua_isnumber(L, 4))
    return LUA_HANDLE_ERROR_STR(L, "fourth argument should be an integer");
  long minLeafSize = lua_tointeger(L, 4);
  // Since minLeafSize == 1 corresponds to each sample in its own leaf, any value below it doesn't
  // make sense
  if (minLeafSize < 1)
    minLeafSize = 1;
  if (!lua_isnumber(L, 5))
    return LUA_HANDLE_ERROR_STR(L, "fifth argument should be an integer");
  long shardId = lua_tointeger(L, 5);
  if (!lua_isnumber(L, 6))
    return LUA_HANDLE_ERROR_STR(L, "sixth argument should be an integer");
  long nShard = lua_tointeger(L, 6);
  THTensor *grad = luaT_checkudata(L, 7, torch_Tensor);
  THTensor *hess = luaT_checkudata(L, 8, torch_Tensor);

  if (!THLongTensor_isContiguous(exampleIds))
    return LUA_HANDLE_ERROR_STR(L, "exampleIds has to be contiguous");
  if (!THTensor_(isContiguous)(grad))
    return LUA_HANDLE_ERROR_STR(L, "grad has to be contiguous");
  if (!THTensor_(isContiguous)(hess))
    return LUA_HANDLE_ERROR_STR(L, "hessian has to be contiguous");

  // initializes the static data
  nn_(GBInitialization) initialization_data;
  nn_(gb_initialize)(L, &initialization_data, exampleIds, grad, hess, dataset_index);

  // initializes the dynamic data
  GBRunData run_data;
  gb_create_run_data(&run_data, minLeafSize);

  // initializes to evaluate all the features in this shard
  nn_(GBBestState) global_bs;
  global_bs.valid_state = 0;
  long n_features = THLongTensor_size(feature_ids, 0);
  if (!THLongTensor_isContiguous(feature_ids))
    return LUA_HANDLE_ERROR_STR(L, "feature_ids must be contiguous");
  long *feature_ids_data = THLongTensor_data(feature_ids);

  // for every feature
  for (long i = 0; i < n_features; i++) {
    long feature_id = feature_ids_data[i];
    // if we are responsible for it
    if (nShard <= 1 || (feature_id % nShard) + 1 == shardId) {
      // finds the best state possible for the split
      nn_(GBBestState) bs;
      nn_(gb_find_best_feature_split)(L, &initialization_data, &bs, feature_id, &run_data);

      // if it's valid and better than one we found before, saves it
      if (bs.valid_state) {
        if (global_bs.valid_state == 0 || bs.gain < global_bs.gain) {
          global_bs = bs;
        }
      }
    }
  }

  lua_pop(L, lua_gettop(L) - initialization_data.splitInfo_index);

  // fills the table we the best split found and the lua logic above will do everything else
  // if no state was found, returns nil
  if (global_bs.valid_state == 0) {
    lua_pop(L, 1);
    lua_pushnil(L);
  }
  else {
    nn_(gb_internal_split_info)(L, &global_bs, initialization_data.splitInfo_index);
  }

  gb_destroy_run_data(&run_data);

  return 1;
}

// all the info we have to apss to the slave threads so that they can do their jobs
// note that we do not pass the lua state since it isn't required. we perform direct C parallelism
// instead of using lua's parallelism like with the previous version
typedef struct {
  nn_(GBInitialization) *initialization_data;
  GBRunData *run_data;
  long *index;
  nn_(GBBestState) *global_bs;
  long n_features;
  long *feature_ids_data;
  pthread_mutex_t *mutex;
  THLongTensor *exampleIds;
  THTensor *input;
  THLongTensor **sorted_ids_per_feature;
} nn_(ThreadInfo);

// loops over all the features in parallel and finds the best global split
static void* nn_(thread_worker)(void *arg) {
  nn_(ThreadInfo) *info = (nn_(ThreadInfo) *)arg;

  while (1) {
    pthread_mutex_lock(info->mutex);
    long index = (*info->index);
    (*info->index)++;
    pthread_mutex_unlock(info->mutex);

    if (index >= info->n_features)
      break;

    // performs part of steps (1) and (2) of gb_find_best_feature_split without having to access the
    // lua state using pre-loaded data
    long feature_id = info->feature_ids_data[index];
    THLongTensor *exampleIdsWithFeature_ret = info->exampleIds;
    THLongTensor *featureExampleIds = info->sorted_ids_per_feature[index];
    nn_(GBInitialization) *initialization_data = info->initialization_data;
    GBRunData *run_data = info->run_data;

    // performs steps (3) and (4) of gb_find_best_feature_split since (1) and (2) were already
    // performed before
    nn_(GBBestState) bs;
    nn_(gb_internal_create)(initialization_data->grad, initialization_data->hess,
        exampleIdsWithFeature_ret, &bs.state);
    nn_(gb_internal_get_best_split_special)(&bs, featureExampleIds, run_data->exampleMap,
        info->input, run_data->minLeafSize, feature_id);

    // saves to the global state if it's better
    if (bs.valid_state) {
      pthread_mutex_lock(info->mutex);
      if (info->global_bs->valid_state == 0 || bs.gain < info->global_bs->gain) {
        (*info->global_bs) = bs;
      }
      pthread_mutex_unlock(info->mutex);
    }
  }

  return NULL;
}

// finds the global best split by doing feature parallelism directly in C
static int nn_(gb_findBestSplitFP)(lua_State *L) {
  THLongTensor *exampleIds = luaT_checkudata(L, 1, "torch.LongTensor");
  const int dataset_index = 2;
  THLongTensor *feature_ids = luaT_checkudata(L, 3, "torch.LongTensor");
  if (!lua_isnumber(L, 4))
    return LUA_HANDLE_ERROR_STR(L, "fourth argument should be an integer");
  long minLeafSize = lua_tointeger(L, 4);
  THTensor *grad = luaT_checkudata(L, 5, torch_Tensor);
  THTensor *hess = luaT_checkudata(L, 6, torch_Tensor);
  if (!lua_isnumber(L, 7))
    return LUA_HANDLE_ERROR_STR(L, "seventh argument should be an integer");
  long nThread = lua_tointeger(L, 7);

  if (!THLongTensor_isContiguous(exampleIds))
    return LUA_HANDLE_ERROR_STR(L, "exampleIds has to be contiguous");
  if (!THTensor_(isContiguous)(grad))
    return LUA_HANDLE_ERROR_STR(L, "grad has to be contiguous");
  if (!THTensor_(isContiguous)(hess))
    return LUA_HANDLE_ERROR_STR(L, "hessian has to be contiguous");

  pthread_mutex_t mutex;
  pthread_mutex_init(&mutex, NULL);

  // initializes the static data
  nn_(GBInitialization) initialization_data;
  nn_(gb_initialize)(L, &initialization_data, exampleIds, grad, hess, dataset_index);

  // initializes the dynamic data
  GBRunData run_data;
  gb_create_run_data(&run_data, minLeafSize);

  // initializes to evaluate all the features
  nn_(GBBestState) global_bs;
  global_bs.valid_state = 0;
  long n_features = THLongTensor_size(feature_ids, 0);
  if (!THLongTensor_isContiguous(feature_ids))
    return LUA_HANDLE_ERROR_STR(L, "feature_ids must be contiguous");
  long *feature_ids_data = THLongTensor_data(feature_ids);

  THTensor *input = luaT_checkudata(L, initialization_data.input_index, torch_Tensor);

  // performs step (1) of gb_find_best_feature_split so that we don't have to pass the lua state
  THLongTensor *sorted_ids_per_feature[n_features];
  for (long i = 0; i < n_features; i++) {
    long feature_id = feature_ids_data[i];
    lua_pushvalue(L, initialization_data.getSortedFeature_index);
    lua_pushvalue(L, initialization_data.dataset_index);
    lua_pushinteger(L, feature_id);
    lua_call(L, 2, 1);

    THLongTensor *featureExampleIds = luaT_checkudata(L, -1, "torch.LongTensor");
    sorted_ids_per_feature[i] = featureExampleIds;
  }

  // performas step (2) of gb_find_best_feature_split since it's the same for all features when the
  // data is dense
  long exampleIds_size = THLongTensor_size(initialization_data.exampleIds, 0);
  long *exampleIds_data = THLongTensor_data(initialization_data.exampleIds);

  int ret;
  kh_resize(long, run_data.exampleMap, exampleIds_size*8);
  for (long i = 0; i < exampleIds_size; i++)
    kh_put(long, run_data.exampleMap, exampleIds_data[i], &ret);

  // saves the info for the threads
  long index = 0;
  nn_(ThreadInfo) info;
  info.initialization_data = &initialization_data;
  info.run_data = &run_data;
  info.index = &index;
  info.global_bs = &global_bs;
  info.n_features = n_features;
  info.feature_ids_data = feature_ids_data;
  info.mutex = &mutex;
  info.exampleIds = exampleIds;
  info.input = input;
  info.sorted_ids_per_feature = sorted_ids_per_feature;

  pthread_t threads[nThread];

  // let the threads run like crazy over the features to find the minimum
  for (long i = 0; i < nThread; i++) {
    int ret = pthread_create(&threads[i], NULL, nn_(thread_worker), &info);
    if (ret)
      return LUA_HANDLE_ERROR_STR(L, "falied to create thread");
  }

  for (long i = 0; i < nThread; i++) {
    int ret = pthread_join(threads[i], NULL);
    if (ret)
      return LUA_HANDLE_ERROR_STR(L, "failed to join thread");
  }

  lua_pop(L, lua_gettop(L) - initialization_data.splitInfo_index);

  // fills the table we the best split found and the lua logic above will do everything else
  // if no state was found, returns nil
  if (global_bs.valid_state == 0) {
    lua_pop(L, 1);
    lua_pushnil(L);
  }
  else {
    nn_(gb_internal_split_info)(L, &global_bs, initialization_data.splitInfo_index);
  }

  gb_destroy_run_data(&run_data);
  pthread_mutex_destroy(&mutex);

  return 1;
}

// performs an efficient branch of the current examples based on a split info provided
static int nn_(gb_branch)(lua_State *L) {
  if (!lua_istable(L, 1))
    return LUA_HANDLE_ERROR_STR(L, "first argument must be a table");
  THTensor *input = luaT_checkudata(L, 2, torch_Tensor);
  THLongTensor *exampleIds = luaT_checkudata(L, 3, "torch.LongTensor");

  // gets direct access to the dataset
  long n_exampleIds = THLongTensor_size(exampleIds, 0);
  long *exampleIds_data = THLongTensor_data(exampleIds);
  long n_features = THTensor_(size)(input, 1);
  real *input_data = THTensor_(data)(input);

  // creates the tensors to be returned
  luaT_pushudata(L, THLongTensor_new(), "torch.LongTensor");
  luaT_pushudata(L, THLongTensor_new(), "torch.LongTensor");
  THLongTensor *leftExampleIds = luaT_checkudata(L, 4, "torch.LongTensor");
  THLongTensor *rightExampleIds = luaT_checkudata(L, 5, "torch.LongTensor");
  THLongTensor_resize1d(leftExampleIds, n_exampleIds);

  // gets direct access to the examples
  THLongTensor *splitExampleIds = leftExampleIds;
  long *splitExampleIds_data = THLongTensor_data(splitExampleIds);

  // gets the split info
  lua_pushstring(L, "splitId");
  lua_rawget(L, 1);
  const long splitId = lua_tointeger(L, -1);
  lua_pushstring(L, "splitValue");
  lua_rawget(L, 1);
  const real splitValue = lua_tonumber(L, -1);
  lua_pop(L, 2);

  long leftIdx = 0, rightIdx = 0;

  // goes over all the samples dividing them into the two sides
  for (long i = 0; i < n_exampleIds; i++) {
    long exampleId = exampleIds_data[i];
    real val = input_data[(exampleId-1) * n_features + (splitId - 1)];
    if (val <= splitValue) {
      leftIdx++;
      splitExampleIds_data[leftIdx-1] = exampleId;
    }
    else {
      rightIdx++;
      splitExampleIds_data[n_exampleIds - rightIdx + 1 - 1] = exampleId;
    }
  }

  // once done, the resulting tensors are just splits of the sample base. this is more efficient
  // than having 2 tensors since we didn't know where the split would happen (how much to each
  // side), but we knew that the sum would be constant
  THLongTensor_narrow(rightExampleIds, splitExampleIds, 0, n_exampleIds-rightIdx+1-1, rightIdx);
  THLongTensor_narrow(leftExampleIds, splitExampleIds, 0, 0, leftIdx);
  return 2;
}

static const struct luaL_Reg nn_(GBDT__) [] = {
  {"GBDT_findBestFeatureSplit", nn_(gb_findBestFeatureSplit)},
  {"GBDT_findBestSplit", nn_(gb_findBestSplit)},
  {"GBDT_findBestSplitFP", nn_(gb_findBestSplitFP)},
  {"GBDT_branch", nn_(gb_branch)},
  {NULL, NULL}
};

static void nn_(GBDT_init)(lua_State *L)
{
  luaT_pushmetatable(L, torch_Tensor);
  luaT_registeratname(L, nn_(GBDT__), "nn");
  lua_pop(L,1);
}

#endif
