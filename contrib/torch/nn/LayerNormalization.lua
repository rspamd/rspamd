-- Reference: https://arxiv.org/pdf/1607.06450.pdf (Section 3)

local LayerNormalization, parent = torch.class('nn.LayerNormalization', 'nn.Sequential')
function LayerNormalization:__init(nOutput, bias, eps, affine)
   parent.__init(self)
   eps = eps or 1e-10
   affine = (affine == nil) and true or affine
   bias = bias or 0

   self:add(nn.ConcatTable()
               :add(nn.Identity())
               :add(nn.Sequential()
                       :add(nn.Mean(1, 1))
                       :add(nn.Replicate(nOutput,1,1))))
      :add(nn.CSubTable())
      :add(nn.Normalize(2, eps))
      :add(nn.MulConstant(torch.sqrt(nOutput)))

   if affine then
      local biasTransform = nn.Add(nOutput, false)
      biasTransform.bias:fill(bias)
      local gainTransform = nn.CMul(nOutput)
      gainTransform.weight:fill(1.)
      self:add(gainTransform)
      self:add(biasTransform)
   end
end
