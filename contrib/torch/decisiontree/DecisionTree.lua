local dt = require "decisiontree._env"

-- An interface for decision trees.
local DecisionTree = torch.class("dt.DecisionTree", dt)

-- Score an input example and return the prediction score.
-- input is a Tensor or SparseTensor
-- return prediction score and nodeId
function DecisionTree:score(input)
   error"Not Implemented"
   return score, nodeId
end
