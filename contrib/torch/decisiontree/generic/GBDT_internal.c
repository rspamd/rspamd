// initializes the optimization structure based on the arguments provided, either filling directly
// or making calls to lua to load some kind of data
static void nn_(gb_initialize)(lua_State *L, nn_(GBInitialization) *initialization_data,
    THLongTensor *exampleIds, THTensor *grad, THTensor *hess, int dataset_index) {
  initialization_data->dataset_index = dataset_index;
  initialization_data->exampleIds = exampleIds;
  initialization_data->grad = grad;
  initialization_data->hess = hess;

  lua_newtable(L);
  initialization_data->splitInfo_index = lua_gettop(L);

  lua_pushstring(L, "input");
  lua_gettable(L, dataset_index);
  initialization_data->input_index = lua_gettop(L);

  lua_pushstring(L, "getSortedFeature");
  lua_gettable(L, dataset_index);
  initialization_data->getSortedFeature_index = lua_gettop(L);
}

// initializes a state that will be passed to the optimizer
static void nn_(gb_internal_create)(THTensor *grad, THTensor *hessian,
    THLongTensor *exampleIds, nn_(GBState)* s) {
  long *exampleIds_data = THLongTensor_data(exampleIds);
  long n_examples = THLongTensor_size(exampleIds, 0);
  accreal leftGradientSum = 0;
  accreal leftHessianSum = 0;

  real *grad_data = THTensor_(data)(grad);
  real *hessian_data = THTensor_(data)(hessian);

  // only sums the relevant gradients and hessians
  for (long i = 0; i < n_examples; i++) {
    long exampleId = exampleIds_data[i]-1;
    leftGradientSum += grad_data[exampleId];
    leftHessianSum += hessian_data[exampleId];
  }

  // we move data from the left branch to the right branch
  s->rightGradientSum = 0;
  s->rightHessianSum = 1;
  s->nExampleInRightBranch = 0;
  s->leftGradientSum = leftGradientSum;
  s->leftHessianSum = leftHessianSum + 1;
  s->nExampleInLeftBranch = n_examples;

  // stores the loss in parent for efficiency
  real lossInParent = computeGradientBoostLoss(s->leftGradientSum + s->rightGradientSum,
      s->leftHessianSum + s->rightHessianSum);
  s->lossInParent = lossInParent;

  // caches the direct pointers to the data for efficiency
  s->grad_data = grad_data;
  s->hessian_data = hessian_data;
}

// computes the gain obtained by performing the split
static real nn_(computeSplitGain)(nn_(GBState) *s) {
  real lossInLeftBranch = computeGradientBoostLoss(s->leftGradientSum, s->leftHessianSum);
  real lossInRightBranch = computeGradientBoostLoss(s->rightGradientSum, s->rightHessianSum);
  return lossInLeftBranch + lossInRightBranch - s->lossInParent;
}

// uses the state information to build the table required by the lua library about the best split
static void nn_(gb_internal_split_info)(lua_State *L, nn_(GBBestState) *bs, int res) {
  long feature_id = bs->feature_id;
  real feature_value = bs->feature_value;
  real gain  = bs->gain;
  nn_(GBState) *s = &bs->state;
  lua_pushstring(L, "splitGain");
  lua_pushnumber(L, gain);
  lua_rawset(L, res);
  lua_pushstring(L, "splitId");
  lua_pushinteger(L, feature_id);
  lua_rawset(L, res);
  lua_pushstring(L, "splitValue");
  lua_pushnumber(L, feature_value);
  lua_rawset(L, res);
  lua_pushstring(L, "leftChildSize");
  lua_pushinteger(L, s->nExampleInLeftBranch);
  lua_rawset(L, res);
  lua_pushstring(L, "rightChildSize");
  lua_pushinteger(L, s->nExampleInRightBranch);
  lua_rawset(L, res);
  lua_pushstring(L, "leftGradient");
  lua_pushnumber(L, s->leftGradientSum);
  lua_rawset(L, res);
  lua_pushstring(L, "rightGradient");
  lua_pushnumber(L, s->rightGradientSum);
  lua_rawset(L, res);
  lua_pushstring(L, "leftHessian");
  lua_pushnumber(L, s->leftHessianSum);
  lua_rawset(L, res);
  lua_pushstring(L, "rightHessian");
  lua_pushnumber(L, s->rightHessianSum);
  lua_rawset(L, res);
}

// core of the computation, where we loop over all the relevant samples looking for the best split
// we can find
static void nn_(gb_internal_get_best_split)(lua_State *L, nn_(GBBestState) *bs,
    THLongTensor *featureExampleIds, khash_t(long)* exampleMap, int input_table_index,
    long minLeafSize, long feature_id) {
  nn_(GBState) current_state;
  nn_(GBState) best_state;
  current_state = bs->state;

  real best_gain = INFINITY;
  real best_value = 0;

  // if the data is dense, pre-loads direct access to it
  THTensor *input = NULL;
  real *input_data = NULL;
  long n_features = 0;
  if (lua_istable(L, input_table_index)) {
  }
  else {
    input = luaT_checkudata(L, input_table_index, torch_Tensor);
    input_data = THTensor_(data)(input);
    n_features = THTensor_(size)(input, 1);
  }

  long stride = featureExampleIds->stride[0];
  long *featureExampleIds_data = THLongTensor_data(featureExampleIds);

  khiter_t k;

  real previousSplitValue = 0;
  // for each example with the given feature and from large to small value...
  for (long i = THLongTensor_size(featureExampleIds, 0)-1; i >= 0; i--) {
    long exampleId = featureExampleIds_data[i * stride];

    // checks if the sample is in the list of ones that have to be evaluated by this node
    k = kh_get(long, exampleMap, exampleId);
    if (k != kh_end(exampleMap)) {
      long exampleIdx = exampleId;

      // gets the split value, depending on whether the input is sparse or dense
      real splitValue;
      if (input_data) {
        splitValue = input_data[(exampleId-1) * n_features + feature_id-1];
      }
      else {
        lua_pushinteger(L, exampleId);
        lua_gettable(L, input_table_index);
        lua_pushinteger(L, feature_id);
        lua_gettable(L, -2);
        splitValue = lua_tonumber(L, -1);
        lua_pop(L, 2);
      }

      // performs one update of the state, moving a sample from the left branch to the right
      real gradient = current_state.grad_data[exampleIdx-1];
      real hessian = current_state.hessian_data[exampleIdx-1];
      current_state.leftGradientSum -= gradient;
      current_state.rightGradientSum += gradient;
      current_state.leftHessianSum -= hessian;
      current_state.rightHessianSum += hessian;
      current_state.nExampleInLeftBranch--;
      current_state.nExampleInRightBranch++;

      // since we remove from the left, once this becomes true, it stays true forever
      // hence we stop the loop
      if (current_state.nExampleInLeftBranch < minLeafSize)
        break;

      if (current_state.nExampleInRightBranch >= minLeafSize) {
        // if the values are equal between the steps, it doesn't make sense to evaluate the score
        // since we won't be able to separate the two
        if (previousSplitValue != splitValue) {
          // computes the gain **without including the parent** since it doesn't change as we move
          // examples between branches
          real lossInLeftBranch = computeGradientBoostLoss(current_state.leftGradientSum, current_state.leftHessianSum);
          real lossInRightBranch = computeGradientBoostLoss(current_state.rightGradientSum, current_state.rightHessianSum);
          real current_gain = lossInLeftBranch + lossInRightBranch;
          if (current_gain < best_gain) {
            best_gain = current_gain;
            best_value = splitValue;
            best_state = current_state;
          }
        }
      }
      previousSplitValue = splitValue;
    }
  }

  // if there is a valid gain, then marks the state as valid and fills the meta-info
  if (!isfinite(best_gain)) {
    bs->valid_state = 0;
  }
  else {
    bs->valid_state = 1;
    bs->state = best_state;
    bs->feature_id = feature_id;
    bs->gain = nn_(computeSplitGain)(&bs->state);
    bs->feature_value = best_value;
  }
}

// exactly like the previous version, but direct access to the data for efficiency. it also doesn't
// rely on the lua state in the particular case of dense data, so we can evaluate this without using
// the lua state
static void nn_(gb_internal_get_best_split_special)(nn_(GBBestState) *bs,
    THLongTensor *featureExampleIds, khash_t(long)* exampleMap, THTensor *input, long minLeafSize,
    long feature_id) {
  nn_(GBState) current_state;
  nn_(GBState) best_state;
  current_state = bs->state;

  real best_gain = INFINITY;
  real best_value = 0;

  real *input_data = NULL;
  long n_features = 0;
  input_data = THTensor_(data)(input);
  n_features = THTensor_(size)(input, 1);

  long stride = featureExampleIds->stride[0];
  long *featureExampleIds_data = THLongTensor_data(featureExampleIds);

  khiter_t k;

  real previousSplitValue = 0;
  for (long i = THLongTensor_size(featureExampleIds, 0)-1; i >= 0; i--) {
    long exampleId = featureExampleIds_data[i * stride];

    k = kh_get(long, exampleMap, exampleId);
    if (k != kh_end(exampleMap)) {
      long exampleIdx = exampleId;

      // THIS is the main part that changes. seems crazy to have a special case just for this, but
      // since there are a **lot** of samples to be evaluated, the "if" in the previous case can
      // become expensive
      real splitValue;
      splitValue = input_data[(exampleId-1) * n_features + feature_id-1];

      real gradient = current_state.grad_data[exampleIdx-1];
      real hessian = current_state.hessian_data[exampleIdx-1];
      current_state.leftGradientSum -= gradient;
      current_state.rightGradientSum += gradient;
      current_state.leftHessianSum -= hessian;
      current_state.rightHessianSum += hessian;
      current_state.nExampleInLeftBranch--;
      current_state.nExampleInRightBranch++;

      // since we remove from the left, once this becomes true, it stays true forever
      // hence we stop the loop
      if (current_state.nExampleInLeftBranch < minLeafSize)
        break;

      // This will always fail in the first pass since minLeafSize >= 1 and nExampleInRightBranch
      // starts at 0
      if (current_state.nExampleInRightBranch >= minLeafSize) {
        if (previousSplitValue != splitValue) {
          real lossInLeftBranch = computeGradientBoostLoss(current_state.leftGradientSum, current_state.leftHessianSum);
          real lossInRightBranch = computeGradientBoostLoss(current_state.rightGradientSum, current_state.rightHessianSum);
          real current_gain = lossInLeftBranch + lossInRightBranch;
          if (current_gain < best_gain) {
            best_gain = current_gain;
            best_value = splitValue;
            best_state = current_state;
          }
        }
      }
      previousSplitValue = splitValue;
    }
  }

  if (!isfinite(best_gain)) {
    bs->valid_state = 0;
  }
  else {
    bs->valid_state = 1;
    bs->state = best_state;
    bs->feature_id = feature_id;
    bs->gain = nn_(computeSplitGain)(&bs->state);
    bs->feature_value = best_value;
  }
}

// core of the computation to find the split for a given feature and is divided in 4 steps
static void nn_(gb_find_best_feature_split)(lua_State *L,
    nn_(GBInitialization) *initialization_data, nn_(GBBestState) *bs, long feature_id,
    GBRunData *run_data) {

  // 1) loads the examples in the dataset ordered by their feature value
  lua_pushvalue(L, initialization_data->getSortedFeature_index);
  lua_pushvalue(L, initialization_data->dataset_index);
  lua_pushinteger(L, feature_id);
  lua_call(L, 2, 1);

  THLongTensor *featureExampleIds = luaT_checkudata(L, -1, "torch.LongTensor");

  // 2) processes the data to find the intersection between the examples in the dataset and the
  // examples the current node has to evaluate
  THLongTensor *exampleIdsWithFeature_ret = gb_internal_prepare(L, initialization_data->exampleIds,
      run_data->exampleIdsWithFeature_cache, initialization_data->input_index, feature_id,
      run_data->exampleMap);
  if (!exampleIdsWithFeature_ret) {
    bs->valid_state = 0;
    return;
  }

  // 3) creates a new state to be used by the optimizer
  nn_(gb_internal_create)(initialization_data->grad, initialization_data->hess,
      exampleIdsWithFeature_ret, &bs->state);

  // 4) optimize away!
  nn_(gb_internal_get_best_split)(L, bs, featureExampleIds, run_data->exampleMap,
      initialization_data->input_index, run_data->minLeafSize, feature_id);
}
