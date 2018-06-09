local dt = require "decisiontree._env"

-- Interface for all decisionForestTrainers
local DFT = torch.class("dt.DecisionForestTrainer", dt)

-- Train a DecisionForest with examples, a table of valid featureIds and a dataset (i.e. sortedExamplesByFeatureId)
function DFT:train(examples, validFeatureIds, dataset)
   assert(torch.type(examples) == "table")
   assert(torch.isTypeOf(examples[1], "dt.LabeledExample"))

   assert(torch.type(validFeatureIds) == 'table')

   assert(torch.type(dataset) == 'table')
   for k,v in pairs(dataset) do
      assert(torch.type(v) == 'table')
      assert(torch.isTypeOf(v[1], 'dt.LabeledExample'))
      break
   end
   -- dataset is a table mapping featureIds to sorted lists of LabeledExamples
   -- e.g. {featureId={example1,example2,example3}}
   error"Not Implemented"
end
