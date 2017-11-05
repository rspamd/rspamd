require 'paths'
require 'xlua'
require 'string'
require 'os'
require 'sys'
require 'image'
require 'lfs'
require 'nn'

-- these actually return local variables but we will re-require them
-- when needed. This is just to make sure they are loaded.
require 'moses'

unpack = unpack or table.unpack

local dt = require 'decisiontree._env'

-- c lib:
require "paths"
paths.require 'libdecisiontree'

dt.HashMap = torch.getmetatable("dt.HashMap").new

dt.EPSILON = 1e-6

-- experimental Tensor-like container
require 'decisiontree.SparseTensor'

-- functions
require 'decisiontree.math'
require 'decisiontree.utils'

-- for multi-threading
require 'decisiontree.WorkPool'

-- abstract classes
require 'decisiontree.DecisionTree'
require 'decisiontree.DecisionForest'
require 'decisiontree.DecisionForestTrainer'
require 'decisiontree.TreeState'

-- for CaRTree inference
require 'decisiontree.CartNode'
require 'decisiontree.CartTree'

-- Criterions (extended with updateHessInput and backward2)
require 'decisiontree.MSECriterion'
require 'decisiontree.LogitBoostCriterion'

-- Used by both RandomForestTrainer and GradientBoostTrainer
require 'decisiontree.CartTrainer'

-- Used by CartTrainer
require 'decisiontree.DataSet'

-- Random Forest Training
require 'decisiontree.RandomForestTrainer'
require 'decisiontree.GiniState' -- TreeState subclass

-- Gradient Boosted Decision Tree Training
require 'decisiontree.GradientBoostTrainer'
require 'decisiontree.GradientBoostState' -- TreeState subclass

-- unit tests and benchmarks
require 'decisiontree.test'
require 'decisiontree.benchmark'

-- nn.Module
require 'decisiontree.DFD'
require 'decisiontree.Sparse2Dense'

return dt
