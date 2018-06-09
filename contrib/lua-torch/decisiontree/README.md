# Torch decision tree library

```lua
local dt = require 'decisiontree'
```

This project implements random forests and gradient boosted decision trees (GBDT).
The latter uses gradient tree boosting.
Both use ensemble learning to produce ensembles of decision trees (that is, forests).

## `nn.DFD`

One practical application for decision forests is to *discretize* an input feature space into a richer output feature space.
The  `nn.DFD` Module can be used as a decision forest discretizer (DFD):

```lua
local dfd = nn.DFD(df, onlyLastNode)
```

where `df` is a `dt.DecisionForest` instance or the table returned by the method `getReconstructionInfo()` on another `nn.DFD` module, and `onlyLastNode` is a boolean that indicates that module should return only the id of the last node visited on each tree (by default it outputs all traversed nodes except for the roots).
The `nn.DFD` module requires dense `input` tensors.
Sparse `input` tensors (tables of tensors) are not supported.
The `output` returned by a call to `updateOutput` is a batch of sparse tensors.
This `output` where `output[1]` and `output[2]` are a respectively a list of key and value tensors:

```lua
{
  { [torch.LongTensor], ... , [torch.LongTensor] },
  { [torch.Tensor], ... , [torch.Tensor] }
}
```

This module doesn't support CUDA.

### Example
As a concrete example, let us first train a Random Forest on a dummy dense dataset:

```lua
local nExample = 100
local batchsize = 2
local inputsize = 10

-- train Random Forest
local trainSet = dt.getDenseDummyData(nExample, nil, inputsize)
local opt = {
   activeRatio=0.5,
   featureBaggingSize=5,
   nTree=4,
   maxLeafNodes=nExample/2,
   minLeafSize=nExample/10,
}
local trainer = dt.RandomForestTrainer(opt)
local df = trainer:train(trainSet, trainSet.featureIds)
mytester:assert(#df.trees == opt.nTree)
```

Now that we have `df`, a `dt.DecisionForest` instance, we can use it to initialize `nn.DFD`:

```lua
local dfd = nn.DFD(df)
```

The `dfd` instance holds no reference to `df`, instead it extracts the relevant attributes from `df`.
These attributes are stored in tensors for batching and efficiency.

We can discretize a hypothetical `input` by calling `forward`:
```lua
local input = trainSet.input:sub(1,batchsize)
local output = dfd:forward(input)
```

The resulting output is a table consisting of two tables: keys and values.
The keys and values tables each contains `batchsize` tensors:

```lua
print(output)
{
  1 :
    {
      1 : LongTensor - size: 14
      2 : LongTensor - size: 16
      3 : LongTensor - size: 15
      4 : LongTensor - size: 13
    }
  2 :
    {
      1 : DoubleTensor - size: 14
      2 : DoubleTensor - size: 16
      3 : DoubleTensor - size: 15
      4 : DoubleTensor - size: 13
    }
}
```

An example's feature keys (`LongTensor`) and commensurate values (`DoubleTensor`) have the same number of elements.
The examples have variable number of key-value pairs representing the nodes traversed in the tree.
The output feature space has as many dimensions (that is, possible feature keys) for each node in the forest.

## `torch.SparseTensor`

Suppose you have a set of `keys` mapped to `values`:
```lua
local keys = torch.LongTensor{1,3,4,7,2}
local values = torch.Tensor{0.1,0.3,0.4,0.7,0.2}
```

You can use a `SparseTensor` to encapsulate these into a read-only tensor:

```lua
local st = torch.SparseTensor(input, target)
```

The _decisiontree_ library uses `SparseTensors` to simulate the `__index` method of the `torch.Tensor`.
For example, one can obtain the value associated to key 3 of the above `st` instance:

```lua
local value = st[3]
assert(value == 0.3)
```

When the key,value pair are missing, `nil` is returned instead:

```lua
local value = st[2]
assert(value == nil)
```

The best implementation for this kind of indexing is slow (it uses a sequential scan of the `keys).
To speedup indexing, one can call the `buildIndex()` method before hand:

```lua
st:buildIndex()
```

The `buildIndex()` creates a hash map (a Lua table) of keys to their commensurate indices in the `values` table.

## `dt.DataSet`

The `CartTrainer`, `RandomForestTrainer` and `GradientBoostTrainer` require that data sets be encapsulated into a `DataSet`.
Suppose you have a dataset of dense inputs and targets:

```lua
local nExample = 10
local nFeature = 5
local input = torch.randn(nExample, nFeature)
local target = torch.Tensor(nExample):random(0,1)
```

these can be encapsulated into a `DataSet` object:

```lua
local dataset = dt.DataSet(input, target)
```

Now suppose you have a dataset where the `input` is a table of `SparseTensor` instances:

```lua
local input = {}
for i=1,nExample do
   local nKeyVal = math.random(2,nFeature)
   local keys = torch.LongTensor(nKeyVal):random(1,nFeature)
   local values = torch.randn(nKeyVal)
   input[i] = torch.SparseTensor(keys, values)
end
```

You can still use a `DataSet` to encapsulate the sparse dataset:

```lua
local dataset = dt.DataSet(input, target)
```

The main purpose of the `DataSet` class is to sort each feature by value.
This is captured by the `sortFeatureValues(input)` method, which is called in the constructor:

```lua
local sortedFeatureValues, featureIds = self:sortFeatureValues(input)
```

The `featureIds` is a `torch.LongTensor` of all available feature IDs.
For a dense `input` tensor, this is just `torch.LongTensor():range(1,input:size(2))`.
But for a sparse `input` tensor, the `featureIds` tensor only contains the feature IDs present in the dataset.

The resulting `sortedFeatureValues` is a table mapping `featureIds` to `exampleIds` sorted by `featureValues`.
For each `featureId`, examples are sorted by `featureValue` in ascending order.
For example, the table might look like: `{featureId=exampleIds}` where `examplesIds={1,3,2}`.

The `CartTrainer` accesses the `sortedFeatureValues` tensor by calling `getSortedFeature(featureId)`:

```lua
local exampleIdsWithFeature = dataset:getSortedFeature(featureId)
```

The ability to access examples IDs sorted by feature value, given a feature ID, is the main purpose of the `DataSet`.
The `CartTrainer` relies on these sorted lists to find the best way to split a set of examples between two tree nodes.

## `dt.CartTrainer`

```lua
local trainer = dt.CartTrainer(dataset, minLeafSize, maxLeafNodes)
```

The `CartTrainer` is used by the `RandomForestTrainer` and `GradientBoostTrainer` to train individual trees.
CART stands for classification and regression trees.
However, only binary classifiers are unit tested.

The constructor takes the following arguments:

 * `dataset` is a `dt.DataSet` instance representing the training set.
 * `minLeafSize` is the minimum examples per leaf node in a tree. The larger the value, the more regularization.
 * `maxLeafNodes` is the maximum nodes in the tree. The lower the value, the more regularization.

Training is initiated by calling the `train()` method:

```lua
local trainSet = dt.DataSet(input, target)
local rootTreeState = dt.GiniState(trainSet:getExampleIds())
local activeFeatures = trainSet.featureIds
local tree = trainer:train(rootTreeState, activeFeatures)
```

The resulting `tree` is a `CartTree` instance.
The `rootTreeState` is a `TreeState` instance like `GiniState` (used by `RandomForestTrainer`) or `GradientBoostState` (used by `GradientBoostTrainer`).
The `activeFeatures` is a `LongTensor` of feature IDs that used to build the tree.
Every other feature ID is ignored during training. This is useful for feature bagging.

By default the `CartTrainer` runs in a single-thread.
The `featureParallel(nThread)` method can be called before calling `train()` to parallelize training using `nThread` workers:

```lua
local nThread = 3
trainer:featureParallel(nThread)
trainer:train(rootTreeState, activeFeatures)
```

Feature parallelization assigns a set of features IDs to each thread.

The `CartTrainer` can be used as a stand-alone tree trainer.
But it is recommended to use it within the context of a `RandomForestTrainer` or `GradientBoostTrainer` instead.
The latter typically generalize better.

## RandomForestTrainer

The `RandomForestTrainer` is used to train a random forest:

```lua
local nExample = trainSet:size()
local opt = {
   activeRatio=0.5,
   featureBaggingSize=5,
   nTree=14,
   maxLeafNodes=nExample/2,
   minLeafSize=nExample/10,
}
local trainer = dt.RandomForestTrainer(opt)
local forest = trainer:train(trainSet, trainSet.featureIds)
```

The returned `forest` is a `DecisionForest` instance.
A `DecisionForest` has a similar interface to the `CartTree`.
Indeed, they both sub-class the `DecisionTree` abstract class.

The constructor takes a single `opt` table argument, which contains the actual arguments:

 * `activeRatio` is the ratio of active examples per tree. This is used for boostrap sampling.
 * `featureBaggingSize` is the number of features per tree. This is also used fpr feature bagging.
 * `nTree` is the number of trees to be trained.
 * `maxLeafNodes` and `minLeafSize` are passed to the underlying `CartTrainer` constructor (controls regularization).

Internally, the `RandomForestTrainer` passes a `GiniBoostState` to the `CartTrainer:train()` method.

Training can be parallelized by calling `treeParallel(nThread)`:

```lua
local nThread = 3
trainer:treeParallel(nThread)
local forest = trainer:train(trainSet, trainSet.featureIds)
```

Training then parallelizes by training each tree in its own thread worker.

## GradientBoostTrainer

References:
 * A. [Boosted Tree presentation](https://homes.cs.washington.edu/~tqchen/pdf/BoostedTree.pdf)

Graient boosted decision trees (GBDT) can be trained as follows:
```lua
local nExample = trainSet:size()
local maxLeafNode, minLeafSize = nExample/2, nExample/10
local cartTrainer = dt.CartTrainer(trainSet, minLeafSize, maxLeafNode)

local opt = {
  lossFunction=nn.LogitBoostCriterion(false),
  treeTrainer=cartTrainer,
  shrinkage=0.1,
  downsampleRatio=0.8,
  featureBaggingSize=-1,
  nTree=14,
  evalFreq=8,
  earlyStop=0
}

local trainer = dt.GradientBoostTrainer(opt)
local forest = trainer:train(trainSet, trainSet.featureIds, validSet)
```

The above code snippet uses the `LogitBoostCriterion` outlined in reference A.
It is used for training binary classification trees.

The returned `forest` is a `DecisionForest` instance.
A `DecisionForest` has a similar interface to the `CartTree`.
Indeed, they both sub-class the `DecisionTree` abstract class.

The constructor takes a single `opt` table argument, which contains the actual arguments:

 * `lossFunction` is a `nn.Criterion` instance extended to include the `updateHessInput(input, target)` and `backward2(input, target)`. These return the hessian of the `input`.
 * `treeTrainer` is a `CartTrainer` instance. Its `featureParallel()` method can be called to implement feature parallelization.
 * `shrinkage` is the weight of each additional tree.
 * `downsampleRatio` is the ratio of examples to be sampled for each tree. Used for bootstrap sampling.
 * `featureBaggingSize` is the number of features to sample per tree. Used for feature bagging. `-1` defaults to `torch.round(math.sqrt(featureIds:size(1)))`
 * `nTree` is the maximum number of trees.
 * `evalFreq` is the number of epochs between calls to `validate()` for cross-validation and early-stopping.
 * `earlyStop` is the maximum number of epochs to wait for early-stopping.

Internally, the `GradientBoostTrainer` passes a `GradientBoostState` to the `CartTrainer:train()` method.

## TreeState

An abstract class that holds the state of a subtree during decision tree training.
It also manages the state of candidate splits.

```lua
local treeState = dt.TreeState(exampleIds)
```

The `exampleIds` argument is a `LongTensor` containing the example IDs that make up the sub-tree.

## GiniState

A `TreeState` subclass used internally by the `RandomForestTrainer`.
Uses Gini impurity to determine how to split trees.

```lua
local treeState = dt.GiniState(exampleIds)
```

The `exampleIds` argument is a `LongTensor` containing the example IDs that make up the sub-tree.

## GradientBoostState

A `TreeState` subclass used internally by the `GradientBoostTrainer`.
It implements the GBDT spliting algorithm, which uses a loss function.

```lua
local treeState = dt.GradientBoostState(exampleIds, lossFunction)
```

The `exampleIds` argument is a `LongTensor` containing the example IDs that make up the sub-tree.
The `lossFunction` is an `nn.Criterion` instance (see `GradientBoostTrainer`).


## WorkPool

Utility class that simplifies construction of a pool of daemon threads with which to execute tasks in parallel.

```lua
local workpool = dt.WorkPool(nThread)
```

## CartTree

Implements a trained CART decision tree:

```lua
local tree = nn.CartTree(rootNode)
```

The `rootNode` is a `CartNode` instance.
Each `CartNode` contains pointers to left and right branches, which are themselves `CartNode` instances.

For inference, use the `score(input)` method:

```lua
local score = tree:score(input)
```
