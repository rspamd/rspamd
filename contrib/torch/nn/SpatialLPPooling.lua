local SpatialLPPooling, parent = torch.class('nn.SpatialLPPooling', 'nn.Sequential')

function SpatialLPPooling:__init(nInputPlane, pnorm, kW, kH, dW, dH)
   parent.__init(self)

   dW = dW or kW
   dH = dH or kH

   self.kW = kW
   self.kH = kH
   self.dW = dW
   self.dH = dH

   if pnorm == 2 then
      self:add(nn.Square())
   else
      self:add(nn.Power(pnorm))
   end
   self:add(nn.SpatialAveragePooling(kW, kH, dW, dH))
   self:add(nn.MulConstant(kW*kH))
   if pnorm == 2 then
      self:add(nn.Sqrt())
   else
      self:add(nn.Power(1/pnorm))
   end
end

-- the module is a Sequential: by default, it'll try to learn the parameters
-- of the sub sampler: we avoid that by redefining its methods.
function SpatialLPPooling:reset()
end

function SpatialLPPooling:accGradParameters()
end

function SpatialLPPooling:accUpdateGradParameters()
end

function SpatialLPPooling:zeroGradParameters()
end

function SpatialLPPooling:updateParameters()
end
