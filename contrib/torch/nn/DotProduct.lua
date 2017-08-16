local DotProduct, parent = torch.class('nn.DotProduct', 'nn.Module')

function DotProduct:__init()
   parent.__init(self)
   self.gradInput = {torch.Tensor(), torch.Tensor()}
end

function DotProduct:updateOutput(input)
   local input1, input2 = input[1], input[2]
   if input1:dim() == 1 then
      -- convert non batch input to batch input
      input1 = input1:view(1,-1)
      input2 = input2:view(1,-1)
   end
   if not self.buffer then
      self.buffer = input1.new()
   end
   self.buffer:cmul(input1, input2)
   self.output:sum(self.buffer, 2)
   self.output:resize(input1:size(1))
   return self.output
end

function DotProduct:updateGradInput(input, gradOutput)
   local v1 = input[1]
   local v2 = input[2]
   local not_batch = false

   if #self.gradInput ~= 2 then
     self.gradInput[1] = self.gradInput[1] or input[1].new()
     self.gradInput[2] = self.gradInput[2] or input[2].new()
   end

   if v1:dim() == 1 then
      v1 = v1:view(1,-1)
      v2 = v2:view(1,-1)
      not_batch = true
   end

   local gw1 = self.gradInput[1]
   local gw2 = self.gradInput[2]
   gw1:resizeAs(v1):copy(v2)
   gw2:resizeAs(v2):copy(v1)

   local go = gradOutput:view(-1,1):expandAs(v1)
   gw1:cmul(go)
   gw2:cmul(go)

   if not_batch then
      -- unbatch gradInput
      self.gradInput[1]:set(gw1:select(1,1))
      self.gradInput[2]:set(gw2:select(1,1))
   end

   return self.gradInput
end

function DotProduct:clearState()
   if self.buffer then self.buffer:set() end
   return parent.clearState(self)
end
