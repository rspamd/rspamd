#include "khash.h"
#include <pthread.h>

#define computeGradientBoostLoss(g, h) (-(g)*(g)/(h))

// we use khash to make iteration faster than lua tables
KHASH_SET_INIT_INT64(long)

// defines the data we need for running an instance of thet and its constructor/destructor
typedef struct {
  khash_t(long)* exampleMap;
  THLongTensor *exampleIdsWithFeature_cache;
  long minLeafSize;
} GBRunData;


// allocates data that cannot be shared between threads
static void gb_local_create_run_data(GBRunData *run_data) {
  run_data->exampleMap = kh_init(long);
  run_data->exampleIdsWithFeature_cache = THLongTensor_new();
}

static void gb_create_run_data(GBRunData *run_data, int minLeafSize) {
  gb_local_create_run_data(run_data);
  run_data->minLeafSize = minLeafSize;
}

static void gb_destroy_run_data(GBRunData *run_data) {
  THLongTensor_free(run_data->exampleIdsWithFeature_cache);
  kh_destroy(long, run_data->exampleMap);
}

// initializes the data required by the optimizer for the given feature.
static THLongTensor *gb_internal_prepare(lua_State *L, THLongTensor *exampleIds,
    THLongTensor *exampleIdsWithFeature_cache, int input_index, long feature_id,
    khash_t(long)* exampleMap) {
  long *exampleIds_data = THLongTensor_data(exampleIds);
  long exampleIds_size = THLongTensor_size(exampleIds, 0);

  int ret = 0;

  // if the the input is a table, then we have a sparse dataset
  if (lua_istable(L, input_index)) {
    if (exampleIds_size == 0) {
      return NULL;
    }
    else {
      // loops over the examples' ids that this node has to evaluate and, if they have the feature
      // we're looking for, marks them as present and stores them in the order provided by the
      // dataset
      THLongTensor_resize1d(exampleIdsWithFeature_cache, exampleIds_size);
      kh_clear(long, exampleMap);
      kh_resize(long, exampleMap, exampleIds_size*8);
      long *exampleIdsWithFeature_data = THLongTensor_data(exampleIdsWithFeature_cache);
      long j = 0;
      // for each sample to be evaluated
      for (long i = 0; i < exampleIds_size; i++) {
        // gets the representation for the example
        lua_pushinteger(L, exampleIds_data[i]);
        lua_gettable(L, input_index);

        // builds the index, which happens only once per thread for efficiency
        lua_pushstring(L, "buildIndex");
        lua_gettable(L, -2);
        lua_pushvalue(L, -2);
        lua_call(L, 1, 0);

        // tries to get the feature for this sample
        lua_pushinteger(L, feature_id);
        lua_gettable(L, -2);
        // if present, then...
        if (!lua_isnil(L, -1)) {
          // saves the example
          exampleIdsWithFeature_data[j] = exampleIds_data[i];
          j++;

          // marks it as present in the hash table
          kh_put(long, exampleMap, exampleIds_data[i], &ret);
        }

        lua_pop(L, 2);
      }

      // resizes to fit only the samples that have the feature
      THLongTensor_resize1d(exampleIdsWithFeature_cache, j);
      kh_resize(long, exampleMap, j*8);
      return exampleIdsWithFeature_cache;
    }
  }
  else {
    // if the input isn't a table, then it's dense and we cannot have exampleIds missing, so it
    // depends on feature_id
    // since exampleIds is fixed between calls and this is going to store the same values to the
    // same position, we can cache it between calls
    if (kh_size(exampleMap) == 0) {
      kh_resize(long, exampleMap, exampleIds_size*8);
      for (long i = 0; i < exampleIds_size; i++) {
        kh_put(long, exampleMap, exampleIds_data[i], &ret);
      }
    }
    // notice that we just return the given tensor of ids instead of copying it. the rest of the
    // code handles this transparently
    return exampleIds;
  }
}

