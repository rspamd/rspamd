# Benchmarks

This file outlines the roadmap (and commensurate benchmarks) of optimizations and refactorings over time.

## Baseline

The baseline implementation is very slow.
We converted the Twitter decision tree library (used internally) from Java to Lua.
The objective was to replicate the GBDT and Random Forest implementations as is (more or less).
The Java library is very good and reasonably fast. The same code in Lua is slow.
The point of this Lua baseline was not to obtain the same computational performance as the Java library.
Instead, we wanted the training and inferences algorithms of the Lua lib to match thoses of the Java lib.
As such, the training/validation error of the baseline Lua lib should match that of the Java lib.
The unit tests seem to validate this claim as both training/validation set performance is unit tested.
We also used the conversion exercise as a way to learn about decision tree implementation (our background is deep learning).
That being said, the baseline performance is terrible:

```
th -e "dt = require 'decisiontree'; dt.benchmark()"
CartTrainer: sparse dataset create: 2963.192386 samples/sec; 0.337479 sec
CartTrainer: train single-thread : 14.165438 samples/sec; 70.594361 sec
CartTrainer: setup feature-parallel : 5.129034 samples/sec; 194.968478 sec
CartTrainer: train feature-parallel : 9.736592 samples/sec; 102.705344 sec
```

The original Java lib had approximately 43 classes.
The baseline has about 24.
This reduction is due to obvious merging of classes. But also to conversions of classes to functions.
The next patches continue this process of reducing the number of classes.

## Patch 1 (complete):

This patch further reduces the number of classes, but adds the DataSet class.
The code is much simple to read. Examples are batched.

 * [x] examples are batched in dt.DataSet: {input, target, score}
 * [x] deprecate dt.LabeledExample
 * [x] list of examples are replaced with torch.LongTensors of exampleIds
 * [x] merge TreeBrancher into TreeState
 * [x] merge BestSplitFinder and SplitStateUpdater into TreeState
 * [x] TreeState subclasses: GradientBoostState and GiniState

```
th -e "dt = require 'decisiontree'; dt.benchmark()"
CartTrainer: sparse dataset create: 3597.392294 samples/sec; 0.277984 sec
CartTrainer: train single-thread : 35.763255 samples/sec; 27.961663 sec
CartTrainer: setup feature-parallel : 36759.250495 samples/sec; 0.027220 sec
CartTrainer: train feature-parallel : 72.523658 samples/sec; 13.788606 sec
```

 The setup time for feature-parallelization is most improved.
 The run-time for feature-parallel also about half that of single-thread.
 Since its using 2 threads, that means the parallelization is working quite well.

 We also added benchmarks for the `RandomForestTrainer` and `GradientBoostTrainer`:

```
GradientBoostTrainer: train single-thread : 599.895105 samples/sec; 0.083348 sec/tree, 1.666958 sec
GradientBoostTrainer: train feature-parallel : 974.235273 samples/sec; 0.051322 sec/tree, 1.026446 sec
RandomForestTrainer: train single-thread : 134.781044 samples/sec; 0.370972 sec/tree, 7.419441 sec
RandomForestTrainer: setup tree-parallel : 73341.097064 samples/sec; 0.013649 sec
RandomForestTrainer: train tree-parallel : 262.975891 samples/sec; 0.190131 sec/tree, 3.802630 sec
```

Looks good.

## Patch 2 (complete):

 * [x] dt.LossFunction -> nn.Criterion (LogitBoost is done, missing MSE)
 * [x] use SparseTensor:buildIndex() to accelerate TreeState:findBestSplit()
 * [x] benchmarks use 10000 instead of 1000 examples

The benchmarks indicate good improvements. Most improvements were made possible by the use of `buildIndex`:

```
th -e "dt = require 'decisiontree'; dt.benchmark()"
GradientBoostState: findBestSplit (first) : 11.415645 sec
GradientBoostState: findBestSplit (second) : 11.246336 sec
CartTrainer: sparse dataset create: 3284.803629 samples/sec; 3.044327 sec
CartTrainer: train single-thread : 239.544758 samples/sec; 41.745858 sec
CartTrainer: setup feature-parallel : 10996.443063 samples/sec; 0.909390 sec
CartTrainer: train feature-parallel : 473.888592 samples/sec; 21.102011 sec
RandomForestTrainer: train single-thread : 892.985186 samples/sec; 0.559920 sec/tree, 11.198394 sec
RandomForestTrainer: setup tree-parallel : 176806.252266 samples/sec; 0.056569 sec
RandomForestTrainer: train tree-parallel : 1377.849291 samples/sec; 0.362884 sec/tree, 7.257688 sec
GradientBoostTrainer: train single-thread : 2685.485128 samples/sec; 0.186186 sec/tree, 3.723722 sec
GradientBoostTrainer: train feature-parallel : 3712.313215 samples/sec; 0.134687 sec/tree, 2.693738 sec
```

The main bottleneck now is in serializing the SparseTensor hash maps. We temporarly overcame this bottleneck by
deleting indexes when calling `CartTrainer:featureParallel()` and `RandomForestTrainer:treeParallel()`.
In this way, the indexes are recreated for each thread. Ideally, we would use a C hash map such that a pointer
could be serialized instead. But `tds.Hash` does not serialize well. For now instead, we use lua tables.

This is the benchmark for `GradientBoostTrainer` on a large dataset of dense inputs:

```
th -e "dt = require 'decisiontree'; dt.benchmark({'GradientBoostTrainer'}, {nExample=100000, sparse=false, nFeature=836, nTree=5, downsampleRatio=1, minLeafSize=1000, maxLeafNodes=8})"
GradientBoostTrainer: train single-thread : 152.463989 samples/sec; 131.178517 sec/tree, 655.892584 sec
GradientBoostTrainer: train feature-parallel : 224.288488 samples/sec; 89.170872 sec/tree, 445.854358 sec
[tw-mbp-nleonard decisiontree]$ th -e "dt = require 'decisiontree'; dt.benchmark({'GradientBoostTrainer'}, {nExample=100000, sparse=false, nFeature=836, nTree=5, downsampleRatio=1, minLeafSize=1000, maxLeafNodes=8,nThread=4})"
GradientBoostTrainer: train single-thread : 163.836896 samples/sec; 122.072625 sec/tree, 610.363126 sec
GradientBoostTrainer: train feature-parallel : 407.981442 samples/sec; 49.021838 sec/tree, 245.109188 sec
```

## Patch 3 :

Optimize GBDT for large datasets consisting of dense inputs. The benchmarks:

```
th -e "dt = require 'decisiontree'; dt.benchmark({'GradientBoostTrainer'}, {nExample=100000, sparse=false, nFeature=836, nTree=5, downsampleRatio=1, minLeafSize=1000, maxLeafNodes=8})"
GradientBoostTrainer: train single-thread : 547.553407 samples/sec; 36.526117 sec/tree, 182.630587 sec
GradientBoostTrainer: train feature-parallel : 792.964678 samples/sec; 25.221804 sec/tree, 126.109022 sec
[tw-mbp-nleonard decisiontree]$ th -e "dt = require 'decisiontree'; dt.benchmark({'GradientBoostTrainer'}, {nExample=100000, sparse=false, nFeature=836, nTree=5, downsampleRatio=1, minLeafSize=1000, maxLeafNodes=8,nThread=4})"
GradientBoostTrainer: train single-thread : 555.793759 samples/sec; 35.984571 sec/tree, 179.922855 sec
GradientBoostTrainer: train feature-parallel : 1289.977846 samples/sec; 15.504142 sec/tree, 77.520711 sec
```

For 1, 2 and 4 threads, the speedups of patch 3 over patch 2 are respectively: 3.39, 3.53, and 3.18.
For this patch, the multi-threading speedup of 2 and 4 threads over a single thread are respectively: 1.42 and 2.33.
Improvements over the previous patch were obtained by optimizing two aspects:

  1. Optimizing `TreeState.findBestFeatureSplit` for dense datasets (for example: `if dense, then ...`);
  2. Removing `assert` clauses in `GradientBoostState.update`. The `update` method is called for every (example, feature), making it a major bottleneck.

Converting the `update` to C could lead to further optimizations.

This patch also improves the benchmark on sparse datasets:
```
$ th -e "dt = require 'decisiontree'; dt.benchmark()"
RandomForestTrainer: train single-thread : 1121.311196 samples/sec; 0.445907 sec/tree, 8.918131 sec
RandomForestTrainer: setup tree-parallel : 168773.323354 samples/sec; 0.059256 sec
RandomForestTrainer: train tree-parallel : 1701.280938 samples/sec; 0.293896 sec/tree, 5.877924 sec
GradientBoostState: findBestSplit (first) : 8.250646 sec
GradientBoostState: findBestSplit (second) : 7.952077 sec
GradientBoostTrainer: train single-thread : 3355.248596 samples/sec; 0.149020 sec/tree, 2.980405 sec
GradientBoostTrainer: train feature-parallel : 4399.133369 samples/sec; 0.113659 sec/tree, 2.273175 sec
CartTrainer: sparse dataset create: 3428.105601 samples/sec; 2.917069 sec
CartTrainer: train single-thread : 282.172416 samples/sec; 35.439331 sec
CartTrainer: setup feature-parallel : 9455.440801 samples/sec; 1.057598 sec
CartTrainer: train feature-parallel : 594.054049 samples/sec; 16.833491 sec
DFD: train random forest in parallel : 346.831378 samples/sec; 0.288325 sec/tree, 5.766491 sec
DFD: updateOutput : 831.105546 samples/sec; 0.038509 sec
```

## Patch 4 :

This patch improves `nn.DFD` from

```
th -e "dt = require 'decisiontree'; dt.benchmark({'DFD'}, {nTree=500,maxLeafNodes=8,minLeafSize=1})"
DFD: train random forest in parallel : 10.527251 samples/sec; 0.037997 sec/tree, 18.998313 sec
DFD: updateOutput : 32.442950 samples/sec; 9.863472 sec
```

to

```
th -e "dt = require 'decisiontree'; dt.benchmark({'DFD'}, {nTree=500,maxLeafNodes=8,minLeafSize=1})"
DFD: train random forest in parallel : 10.839547 samples/sec; 0.036902 sec/tree, 18.450956 sec
DFD: updateOutput : 359.158353 samples/sec; 0.890975 sec
Sparse2Dense: updateOutput : 15395.648952 samples/sec; 0.020791 sec
```

That is a 10x speedup for `nn.DFD`.

The patch also adds a benchmark for `nn.Sparse2Dense`:

```
th -e "dt = require 'decisiontree'; dt.benchmark({'Sparse2Dense'}, {nTree=500,maxLeafNodes=8,minLeafSize=1})"
Sparse2Dense: updateOutput : 17158.126406 samples/sec; 0.018653 sec
```

Indeed, `nn.Sparse2Dense` is not the bottleneck; `nn.DFD` is.

## Patch 5 :

This patch improves `nn.DFD` inference from

```
for i in `seq 3`; do th -e "dt = require 'decisiontree'; dt.benchmark({'DFD'}, {nTree=500,maxLeafNodes=8,minLeafSize=1,batchsize=16,nActive=1200,nFeature=1300,nloop=100})"; done
DFD: train random forest in parallel : 8.452295 samples/sec; 0.047324 sec/tree, 23.662212 sec
DFD: updateOutput : 176.617872 samples/sec; 9.059109 sec
DFD: train random forest in parallel : 8.350019 samples/sec; 0.047904 sec/tree, 23.952042 sec
DFD: updateOutput : 183.508204 samples/sec; 8.718962 sec
DFD: train random forest in parallel : 8.525779 samples/sec; 0.046917 sec/tree, 23.458266 sec
DFD: updateOutput : 178.877077 samples/sec; 8.944692 sec
```

to

```
for i in `seq 3`; do th -e "dt = require 'decisiontree'; dt.benchmark({'DFD'}, {nTree=500,maxLeafNodes=8,minLeafSize=1,batchsize=16,nActive=1200,nFeature=1300,nloop=100})"; done
DFD: train random forest in parallel : 8.434502 samples/sec; 0.047424 sec/tree, 23.712129 sec
DFD: updateOutput : 6479.597179 samples/sec; 0.246933 sec
DFD: train random forest in parallel : 8.334543 samples/sec; 0.047993 sec/tree, 23.996518 sec
DFD: updateOutput : 6663.641184 samples/sec; 0.240114 sec
DFD: train random forest in parallel : 8.353265 samples/sec; 0.047885 sec/tree, 23.942735 sec
DFD: updateOutput : 6882.607456 samples/sec; 0.232475 sec
```

That is a 37x speedup for `nn.DFD`.

## Patch 6:

This patch improves `nn.DFD` from the previous result to

```
for i in `seq 5`; do th -e "dt = require 'decisiontree'; dt.benchmark({'DFD'}, {nTree=500,maxLeafNodes=8,minLeafSize=1,batchsize=16,nActive=1200,nFeature=1300,nloop=10000})"; done
DFD: train random forest in parallel : 8.353504 samples/sec; 0.047884 sec/tree, 23.942050 sec
DFD: updateOutput : 91967.342339 samples/sec; 1.739753 sec
DFD: train random forest in parallel : 8.528141 samples/sec; 0.046904 sec/tree, 23.451770 sec
DFD: updateOutput : 91405.321702 samples/sec; 1.750451 sec
DFD: train random forest in parallel : 8.184562 samples/sec; 0.048872 sec/tree, 24.436250 sec
DFD: updateOutput : 91623.388867 samples/sec; 1.746284 sec
DFD: train random forest in parallel : 8.779561 samples/sec; 0.045560 sec/tree, 22.780182 sec
DFD: updateOutput : 93914.242852 samples/sec; 1.703686 sec
DFD: train random forest in parallel : 8.636201 samples/sec; 0.046317 sec/tree, 23.158330 sec
DFD: updateOutput : 94092.241963 samples/sec; 1.700465 sec
```

That is another 13.8x speedup.

## Patch 7:

This patch improves `nn.Sparse2Dense` computation from

```
for i in `seq 3`; do th -e "dt = require 'decisiontree'; torch.setdefaulttensortype('torch.FloatTensor'); dt.benchmark({'Sparse2Dense'}, {nTree=500,maxLeafNodes=8,minLeafSize=1,nFeature=1500,nActive=1300,nloop=1000})"; done
Sparse2Dense: updateOutput : 1103.570777 samples/sec; 28.996786 sec
Sparse2Dense: updateOutput : 1092.064331 samples/sec; 29.302309 sec
Sparse2Dense: updateOutput : 1036.963572 samples/sec; 30.859334 sec
```

to

```
for i in `seq 3`; do th -e "dt = require 'decisiontree'; torch.setdefaulttensortype('torch.FloatTensor'); dt.benchmark({'Sparse2Dense'}, {nTree=500,maxLeafNodes=8,minLeafSize=1,nFeature=1500,nActive=1300,nloop=1000})"; done
Sparse2Dense: updateOutput : 62995.834470 samples/sec; 0.507978 sec
Sparse2Dense: updateOutput : 62471.568253 samples/sec; 0.512242 sec
Sparse2Dense: updateOutput : 62965.099331 samples/sec; 0.508226 sec
```

This represents a speedup of about 57x.

## Patch 8:

This patch improves `nn.Sparse2Dense` from the previous result to

```for i in `seq 3`; do th -e "dt = require 'decisiontree'; torch.setdefaulttensortype('torch.FloatTensor'); dt.benchmark({'Sparse2Dense'}, {nTree=500,maxLeafNodes=8,minLeafSize=1,nFeature=1500,nActive=1300,nloop=1000})"; done
Sparse2Dense: updateOutput : 124268.079914 samples/sec; 0.257515 sec
Sparse2Dense: updateOutput : 114750.039542 samples/sec; 0.278873 sec
Sparse2Dense: updateOutput : 122863.314766 samples/sec; 0.260458 sec
```

which corresponds to another 1.95x speedup.

## Patch 9:

This patches moves the core of training GBDTs, which used to be a big bottleneck, to C. It also
performs small optimizations across the board (faster scoring, faster branching, ...) that provide a
little more performance.

The original commit had this performance:

```
th -e "dt = require 'decisiontree'; torch.setdefaulttensortype('torch.FloatTensor'); dt.benchmark({'GradientBoostTrainer'}, {nExample=100000, sparse=false, nFeature=836, nTree=5, downsampleRatio=1, minLeafSize=1000, maxLeafNodes=8})"
GradientBoostTrainer: train single-thread : 500.414666 samples/sec; 39.966854 sec/tree, 199.834271 sec
GradientBoostTrainer: train feature-parallel : 1227.228044 samples/sec; 16.296890 sec/tree, 81.484448 sec (4 threads)
GradientBoostTrainer: train feature-parallel : 1385.926280 samples/sec; 14.430782 sec/tree, 72.153910 sec (8 threads)
```

and the new version has

```
GradientBoostTrainer: train single-thread : 15285.644631 samples/sec; 1.308417 sec/tree, 6.542086 sec
GradientBoostTrainer: train feature-parallel : 43170.435932 samples/sec; 0.463280 sec/tree, 2.316400 sec (4 threads)
GradientBoostTrainer: train feature-parallel : 50062.681239 samples/sec; 0.399499 sec/tree, 1.997496 sec (8 threads)
```

That represents a speedup of about 30.5x over the baseline for 1 thread and 36.1x for 8 threads.
Note that the performance doesn't increase much as we increase the number of threads since we use
feature parallelism and the number of features evaluated is small (29 in this case) due to bagging.
If we disable bagging, then we have the following result with 8 threads and the new code:

```
GradientBoostTrainer: train single-thread : 590.823965 samples/sec; 33.851030 sec/tree, 169.255152 sec
GradientBoostTrainer: train feature-parallel : 3232.188576 samples/sec; 6.187758 sec/tree, 30.938789 sec
```

So processing 836 features now is much faster than processing 29 before.
