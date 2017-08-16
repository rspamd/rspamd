local SelectTable, parent = torch.class('nn.SelectTable', 'nn.Module')

function SelectTable:__init(index)
   parent.__init(self)
   self.index = index
   self.gradInput = {}
end

function SelectTable:updateOutput(input)

   -- handle negative indices
   local index = self.index
   if type(index) == "number" then
      index = index < 0 and #input + index + 1 or index
   end

   assert(input[index], "index does not exist in the input table")
   self.output = input[index]

   return self.output
end

local function zeroTableCopy(t1, t2)
   for k, v in pairs(t2) do
      if (torch.type(v) == "table") then
         t1[k] = zeroTableCopy(t1[k] or {}, t2[k])
      elseif torch.isTensor(v) then
         if not t1[k] then
            t1[k] = v:clone():zero()
         else
            t1[k]:resizeAs(v)
            t1[k]:zero()
         end
      else
        t1[k] = nil
      end
   end
   for k, v in pairs(t1) do
      if not t2[k] then
         t1[k] = nil
      end
   end
   return t1
end

function SelectTable:updateGradInput(input, gradOutput)
   -- make gradInput a zeroed copy of input
   zeroTableCopy(self.gradInput, input)
   -- handle negative indices
   local index = self.index
   if type(index) == "number" then
      index = index < 0 and #input + index + 1 or index
   end
   -- copy into gradInput[index] (necessary for variable sized inputs)
   assert(self.gradInput[index])
   nn.utils.recursiveCopy(self.gradInput[index], gradOutput)

   return self.gradInput
end

function SelectTable:type(type, tensorCache)
   self.gradInput = {}
   self.output = {}
   return parent.type(self, type, tensorCache)
end

function SelectTable:__tostring__()
  return torch.type(self) .. '(' .. self.index .. ')'
end

SelectTable.clearState = nn.Identity.clearState
