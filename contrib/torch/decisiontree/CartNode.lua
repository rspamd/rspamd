local dt = require 'decisiontree._env'
local CartNode = torch.class("dt.CartNode", dt)

function CartNode:__init(nodeId, leftChild, rightChild, splitFeatureId, splitFeatureValue, score, splitGain)
   self.nodeId = nodeId or 0
   self.leftChild = leftChild
   self.rightChild = rightChild
   self.splitFeatureId = splitFeatureId or -1
   self.splitFeatureValue = splitFeatureValue or 0
   self.score = score or 0
   self.splitGain = splitGain
end

function CartNode:__tostring__()
   return self:recursivetostring()
end

function CartNode:recursivetostring(indent)
   indent = indent or ' '

   -- Is this a leaf node?
   local res = ''
   if not (self.leftChild or self.rightChild) then
      res = res .. self.score .. '\n'
   else
      -- Print the criteria
      res = res .. 'input[' .. self.splitFeatureId .. '] <' .. self.splitFeatureValue .. '?\n'

      -- Print the branches
      if self.leftChild then
         res = res .. indent .. 'True->' .. self.leftChild:recursivetostring(indent .. '  ')
      end
      if self.rightChild then
         res = res .. indent .. 'False->' .. self.rightChild:recursivetostring(indent .. '  ')
      end
   end
   return res
end

function CartNode:clone()
   return CartNode(self.nodeId, self.leftChild, self.rightChild, self.splitFeatureId, self.splitFeatureValue, self.score, self.splitGain)
end
