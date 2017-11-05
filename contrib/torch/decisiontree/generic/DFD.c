#ifndef TH_GENERIC_FILE
#define TH_GENERIC_FILE "generic/DFD.c"
#else

static int nn_(DFD_computeOutput)(lua_State *L) {
  THLongTensor *outputkeys =       luaT_checkudata(L, 1, "torch.LongTensor");
  THTensor *outputvalues =         luaT_checkudata(L, 2, torch_Tensor);
  THLongTensor *root_ids =         luaT_checkudata(L, 3, "torch.LongTensor");
  THLongTensor *left_child =       luaT_checkudata(L, 4, "torch.LongTensor");
  THLongTensor *right_child =      luaT_checkudata(L, 5, "torch.LongTensor");
  THLongTensor *split_feature_id = luaT_checkudata(L, 6, "torch.LongTensor");
  THTensor *split_feature_value =  luaT_checkudata(L, 7, torch_Tensor);
  THTensor *input =                luaT_checkudata(L, 8, torch_Tensor);
  char only_last_node =            lua_toboolean(L, 9);

  // gets some important sizes from the input
  long batch_size = THTensor_(size)(input, 0);
  long input_size = THTensor_(size)(input, 1);
  long roots_size = THLongTensor_size(root_ids, 0);
  long depth = THLongTensor_size(outputkeys, 1);

  // keeps track of the number of nodes traversed in the trees by each sample.
  // each traversed node maps to an output feature having a value of 1
  long outputsize[batch_size];
  for (long i = 0; i < batch_size; i++)
    outputsize[i] = 0;

  // gets direct pointers to the memory of each tensor for efficiency
  long *root_ids_data = THLongTensor_data(root_ids);
  long *left_child_data = THLongTensor_data(left_child);
  long *right_child_data = THLongTensor_data(right_child);
  real *split_feature_value_data = THTensor_(data)(split_feature_value);
  long *split_feature_id_data = THLongTensor_data(split_feature_id);
  long *outputkeys_data = THLongTensor_data(outputkeys);
  real *input_data = THTensor_(data)(input);

  // for each sample in the batch
  for (long sample_index = 0; sample_index < batch_size; sample_index++) {
    // gets pointers to the direct memory associated with each sample for efficiency
    const long outputkeys_offset = sample_index * depth;
    const long input_offset = sample_index * input_size;
    long *local_outputkeys_data = &outputkeys_data[outputkeys_offset];
    real *local_input_data = &input_data[input_offset];

    // for each tree in the forest
    for (long i = 0; i < roots_size; i++) {
      int root = 1;
      long node_id = root_ids_data[i];

      // traverses the whole tree keeping track of which nodes were seen
      while (1) {
        if (root) {
          // root nodes aren't added to output because they are always traversed
          root = 0;
        }
        else if (!only_last_node) {
          // updates the outputsize for all samples traversing this node; and
          // set the traversed node as a feature in output for exampleIds
          long output_index = outputsize[sample_index];
          // updates the outputsize for all samples traversing this node
          outputsize[sample_index]++;
          // sets the traversed node as a feature in output for exampleIds
          local_outputkeys_data[output_index] = node_id;
        }

        // gets the left and right nodes. values of -1 represent missing node
        long left_id = left_child_data[node_id-1];
        long right_id = right_child_data[node_id-1];

        if (left_id <= 0 && right_id <= 0) {
          if (only_last_node) {
            long output_index = outputsize[sample_index];
            outputsize[sample_index]++;
            local_outputkeys_data[output_index] = node_id;
          }
          // if no children, stops
          break;
        }
        else if (left_id <= 0) {
          // if no left child, traverses right node
          node_id = right_id;
        }
        else if (right_id <= 0) {
          // if no right child, traverses left node
          node_id = left_id;
        }
        else {
          // if both left and right children, finds the direction for this sample
          // first get the reference from the node
          real split_value = split_feature_value_data[node_id-1];
          long split_id = split_feature_id_data[node_id-1]-1;

          // then gets the value of the sample
          real node_value = local_input_data[split_id];
          // and branchs
          if (node_value < split_value)
            node_id = left_id;
          else
            node_id = right_id;
        }
      }
    }
  }

  // now that we know which nodes were traverse for each sample, we can create the sparse output
  // with 1 entry pair for each sample
  THTensor *input_feature = THTensor_(new)();
  THLongTensor *indices = THLongTensor_new();

  // pushes the return table with 2 children tables
  lua_newtable(L);
  lua_pushinteger(L, 1);
  lua_newtable(L);
  lua_pushinteger(L, 2);
  lua_newtable(L);

  // for each sample...
  for (long i = 0; i < batch_size; i++) {
    long j = outputsize[i];
    // selects the tensor lines from the dense output
    THLongTensor_select(indices, outputkeys, 0, i);
    THTensor_(select)(input_feature, outputvalues, 0, i);

    // narrows the keys to actual number of nodes traversed and saves to the output
    lua_pushinteger(L, i+1);
    luaT_pushudata(L, THLongTensor_newNarrow(indices, 0, 0, j), "torch.LongTensor");
    lua_settable(L, -5);

    // and narrows the values
    lua_pushinteger(L, i+1);
    luaT_pushudata(L, THTensor_(newNarrow)(input_feature, 0, 0, j), torch_Tensor);
    lua_settable(L, -3);
  }

  // pushes the two parts of the output into the output table
  lua_settable(L, -5);
  lua_settable(L, -3);

  THLongTensor_free(indices);
  THTensor_(free)(input_feature);

  return 1;
}

static const struct luaL_Reg nn_(DFD__) [] = {
  {"DFD_computeOutput", nn_(DFD_computeOutput)},
  {NULL, NULL}
};

static void nn_(DFD_init)(lua_State *L)
{
  luaT_pushmetatable(L, torch_Tensor);
  luaT_registeratname(L, nn_(DFD__), "nn");
  lua_pop(L,1);
}

#endif
