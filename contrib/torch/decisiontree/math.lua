local dt = require "decisiontree._env"

local PSEUDOCOUNT = 1.0
local MIN_LOGISTIC = 1E-8
local MAX_LOGISTIC = 1.0 - MIN_LOGISTIC

-- Create counts of possible results (last column of each row is the result)
function dt.uniquecounts(counts, inputset, nclass)
   counts = counts or inputset.input.new()
   nclass = nclass or inputset.target:max()
   counts:resize(nclass):zero()

   inputset.target:apply(function(c) counts[c] = counts[c] + 1 end)
   return counts
end

-- Entropy is the sum of -p(x)log(p(x)) across all the different possible results
local counts, logprobs
function dt.entropy(inputset, nclass)
   local dt = require 'decisiontree'
   counts = dt.uniquecounts(counts, inputset, nclass)
   -- convert counts to categorical probabilities
   counts:add(0.0000001) -- prevent NaN
   counts:div(counts:sum())

   logprobs = logprobs or counts.new()
   logprobs:resize(counts:size())
   logprobs:log(counts):div(math.log(2)) -- log2(x)

   counts:cmul(logprobs)

   return -counts:sum()
end

-- Compute and return the probability of positive label.
function dt.probabilityPositive(nPositive, nTotal)
   return (nPositive + PSEUDOCOUNT) / (nTotal + 2.0 * PSEUDOCOUNT);
end

-- Ref. https://en.wikipedia.org/wiki/Logit
-- Calculates logit of the probability.
-- Logit represents the log-odds. Probabilities transformed to logit 'space' can be combined linearly.
function dt.logit(p)
   assert(p >= 0.0 and p <= 1.0, "Expecting probability for arg 1")
   local truncatedP = math.max(MIN_LOGISTIC, math.min(MAX_LOGISTIC, p))
   return math.log(truncatedP / (1.0 - truncatedP))
end

function dt.logistic(x)
   return (x >= 0) and (1 / (1 + math.exp(-x))) or (1 - 1 / (1 + math.exp(x)))
end

function dt.computeGradientBoostLoss(gradient, hessian)
   return -gradient * gradient / hessian
end

function dt.computeNewtonScore(gradient, hessian)
   return -0.5 * gradient / hessian;
end

-- Calculates the logit score for a Node in a Decision Tree based on the probability of a positive label.
-- params: number of positive examples and total number of examples.
function dt.calculateLogitScore(nPositive, nTotal)
   local dt = require 'decisiontree'
   return dt.logit(dt.probabilityPositive(nPositive, nTotal))
end

-- Compute and return the Gini impurity score based on an input contingency table.
function dt.computeGini(leftCount, positiveLeftCount, rightCount, positiveRightCount)
   assert(torch.type(leftCount) == 'number', 'Expecting total number examples falling into leftBranch.')
   assert(torch.type(positiveLeftCount) == 'number', 'Expecting total number of positive examples falling into left branch.')
   assert(torch.type(rightCount) == 'number', 'Expecting total number of examples falling into the right branch.')
   assert(torch.type(positiveRightCount) == 'number', 'Expecting total number of positive examples falling into the right branch.')

   local total = leftCount + rightCount

   local pPositiveLeft = leftCount == 0 and 0 or (positiveLeftCount / leftCount)
   local leftGini = pPositiveLeft * (1.0 - pPositiveLeft)

   local pPositiveRight = rightCount == 0 and 0 or (positiveRightCount / rightCount)
   local rightGini = pPositiveRight * (1.0 - pPositiveRight)

   return (leftCount * leftGini + rightCount * rightGini) / total
end