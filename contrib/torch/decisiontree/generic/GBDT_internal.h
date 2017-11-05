// representation of a state used while searching for the best split
typedef struct {
  real leftGradientSum, rightGradientSum;
  real leftHessianSum, rightHessianSum;
  real lossInParent;
  long nExampleInLeftBranch, nExampleInRightBranch;
  real *grad_data, *hessian_data;
} nn_(GBState);

// representation for the best state found for a given feature
typedef struct {
  nn_(GBState) state;
  real gain;
  long feature_id;
  real feature_value;
  int valid_state;
} nn_(GBBestState);

// full data that must be initialized before calling the optimizer
typedef struct {
  // *_index represent positions on the lua stack
  int dataset_index;
  int splitInfo_index;
  int input_index;
  // position of the dataset's function to return the samples ordered for a given feature
  int getSortedFeature_index;

  // samples that this node has to evaluate
  THLongTensor *exampleIds;

  // cached gradient and hessian for all data
  THTensor *grad;
  THTensor *hess;
} nn_(GBInitialization);
