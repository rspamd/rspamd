local TanhShrink, parent = torch.class('nn.TanhShrink','nn.Module')

function TanhShrink:__init()
   parent.__init(self)
   self.tanh = nn.Tanh()
end

function TanhShrink:updateOutput(input)
   local th = self.tanh:updateOutput(input)
   self.output:resizeAs(input):copy(input)
   self.output:add(-1,th)
   return self.output
end

function TanhShrink:updateGradInput(input, gradOutput)
   local dth = self.tanh:updateGradInput(input,gradOutput)
   self.gradInput:resizeAs(input):copy(gradOutput)
   self.gradInput:add(-1,dth)
   return self.gradInput
end
