local Mul, parent = torch.class('nn.Mul', 'nn.Module')

function Mul:__init()
   parent.__init(self)

   self.weight = torch.Tensor(1)
   self.gradWeight = torch.Tensor(1)

   self:reset()
end


function Mul:reset(stdv)
   if stdv then
      stdv = stdv * math.sqrt(3)
   else
      stdv = 1./math.sqrt(self.weight:size(1))
   end

   self.weight:uniform(-stdv, stdv);
end

function Mul:updateOutput(input)
   self.output:resizeAs(input):copy(input);
   self.output:mul(self.weight[1]);
   return self.output
end

function Mul:updateGradInput(input, gradOutput)
   self.gradInput:resizeAs(input):zero()
   self.gradInput:add(self.weight[1], gradOutput)
   return self.gradInput
end

function Mul:accGradParameters(input, gradOutput, scale)
   scale = scale or 1
   self.gradWeight[1] = self.gradWeight[1] + scale*input:dot(gradOutput);
end
