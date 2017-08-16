local SoftPlus, parent = torch.class('nn.SoftPlus', 'nn.Module')

function SoftPlus:__init(beta)
   parent.__init(self)
   self.beta = beta or 1  -- Beta controls sharpness of transfer function
   self.threshold = 20    -- Avoid floating point issues with exp(x), x>20
end

function SoftPlus:updateOutput(input)
   -- f(x) = 1/beta * log(1 + exp(beta * x))
   input.THNN.SoftPlus_updateOutput(
      input:cdata(),
      self.output:cdata(),
      self.beta,
      self.threshold
   )
   return self.output
end

function SoftPlus:updateGradInput(input, gradOutput)
   -- d/dx[log(1+exp(k*x))/k] = exp(kx) / (exp(kx) + 1)
   -- SINCE
   -- y = (1/k)*log(1+exp(k*x)) --> x = (1/k)*log(exp(k*y)-1)
   -- THEREFORE:
   -- d/dx(f(x)) = (exp(k*y) - 1) / exp(k*y)
   input.THNN.SoftPlus_updateGradInput(
      input:cdata(),
      gradOutput:cdata(),
      self.gradInput:cdata(),
      self.output:cdata(),
      self.beta,
      self.threshold
   )
   return self.gradInput
end
