local _ = require "moses"
local dt = require 'decisiontree._env'

-- CART (classification-regression decision tree).
-- The example is always branched to the left when the splitting feature is missing.
local CartTree = torch.class("dt.CartTree", "dt.DecisionTree", dt)

function CartTree:__init(root, branchleft)
   assert(torch.isTypeOf(root, 'dt.CartNode'))
   self.root = root
   self.branchleft = branchleft or function() return true end
end

-- TODO optimize this
function CartTree:score(input, stack, optimized)
   if optimized == true and stack == nil and torch.isTensor(input) and input.isContiguous and input:isContiguous() and input:nDimension() == 2 then
      return input.nn.CartTreeFastScore(input, self.root, input.new())
   end
   return self:recursivescore(self.root, input, stack)
end

-- Continuous: if input[node.splitFeatureId] < node.splitFeatureValue then leftNode else rightNode
-- Binary: if input[node.splitFeatureId] == 0 then leftNode else rightNode
-- when stack is provided, it is returned as the third argument containing the stack of nodes from root to leaf
function CartTree:recursivescore(node, input, stack)
   assert(torch.isTypeOf(node, 'dt.CartNode'))

   if stack then
      stack = torch.type(stack) == 'table' and stack or {}
      table.insert(stack, node)
   end

   if not (node.leftChild or node.rightChild) then
      return node.score, node.nodeId, stack
   elseif not node.leftChild then
      return self:recursivescore(node.rightChild, input, stack)
   elseif not node.rightChild then
      return self:recursivescore(node.leftChild, input, stack)
   end

   local splitId = node.splitFeatureId
   local splitVal = node.splitFeatureValue

   if input[splitId] then -- if has key
      local featureVal = input[splitId]
      local nextNode = featureVal < splitVal and node.leftChild or node.rightChild
      return self:recursivescore(nextNode, input, stack)
   end

   -- if feature is missing, branch left
   local nextNode = self.branchleft() and node.leftChild or node.rightChild
   return self:recursivescore(nextNode, input, stack)
end

function CartTree:__tostring__()
   return self.root:recursivetostring()
end

-- expects a stack returned by score
function CartTree:stackToString(stack, input)
   assert(torch.type(stack) == 'table')
   assert(torch.isTypeOf(stack[1], 'dt.CartNode'))

   local res = 'Stack nodes from root to leaf\n'
   for i,node in ipairs(stack) do
      if not (node.leftChild or node.rightChild) then
         res = res .. "score="..node.score .. '\n'
      else
         local istr = ''
         if input then
            istr = '=' .. (input[node.splitFeatureId] or 'nil')
         end
         res = res .. 'input[' .. node.splitFeatureId .. ']' .. istr ..' < ' .. node.splitFeatureValue .. ' ? '
         res = res .. '(' .. ((node.leftChild and node.rightChild) and 'LR' or node.leftChild and 'L' or node.rightChild and 'R' or 'WAT?') .. ') '
         if node.leftChild == stack[i+1] then
            res = res .. 'Left\n'
         elseif node.rightChild == stack[i+1] then
            res = res .. 'Right\n'
         else
            error"stackToString error"
         end
      end
   end
   return res .. #stack .. " nodes"
end

function CartTree:clone()
   return CartTree(self.root:clone(), self.branchleft)
end

