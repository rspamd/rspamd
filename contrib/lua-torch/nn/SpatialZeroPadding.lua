local SpatialZeroPadding, parent = torch.class('nn.SpatialZeroPadding', 'nn.Module')

function SpatialZeroPadding:__init(pad_l, pad_r, pad_t, pad_b)
   parent.__init(self)
   self.pad_l = pad_l
   self.pad_r = pad_r or self.pad_l
   self.pad_t = pad_t or self.pad_l
   self.pad_b = pad_b or self.pad_l
end

function SpatialZeroPadding:updateOutput(input)
   if input:dim() == 3 then
      -- sizes
      local h = input:size(2) + self.pad_t + self.pad_b
      local w = input:size(3) + self.pad_l + self.pad_r
      if w < 1 or h < 1 then error('input is too small') end
      self.output:resize(input:size(1), h, w)
      self.output:zero()
      -- crop input if necessary
      local c_input = input
      if self.pad_t < 0 then c_input = c_input:narrow(2, 1 - self.pad_t, c_input:size(2) + self.pad_t) end
      if self.pad_b < 0 then c_input = c_input:narrow(2, 1, c_input:size(2) + self.pad_b) end
      if self.pad_l < 0 then c_input = c_input:narrow(3, 1 - self.pad_l, c_input:size(3) + self.pad_l) end
      if self.pad_r < 0 then c_input = c_input:narrow(3, 1, c_input:size(3) + self.pad_r) end
      -- crop outout if necessary
      local c_output = self.output
      if self.pad_t > 0 then c_output = c_output:narrow(2, 1 + self.pad_t, c_output:size(2) - self.pad_t) end
      if self.pad_b > 0 then c_output = c_output:narrow(2, 1, c_output:size(2) - self.pad_b) end
      if self.pad_l > 0 then c_output = c_output:narrow(3, 1 + self.pad_l, c_output:size(3) - self.pad_l) end
      if self.pad_r > 0 then c_output = c_output:narrow(3, 1, c_output:size(3) - self.pad_r) end
      -- copy input to output
      c_output:copy(c_input)
   elseif input:dim() == 4 then
      -- sizes
      local h = input:size(3) + self.pad_t + self.pad_b
      local w = input:size(4) + self.pad_l + self.pad_r
      if w < 1 or h < 1 then error('input is too small') end
      self.output:resize(input:size(1), input:size(2), h, w)
      self.output:zero()
      -- crop input if necessary
      local c_input = input
      if self.pad_t < 0 then c_input = c_input:narrow(3, 1 - self.pad_t, c_input:size(3) + self.pad_t) end
      if self.pad_b < 0 then c_input = c_input:narrow(3, 1, c_input:size(3) + self.pad_b) end
      if self.pad_l < 0 then c_input = c_input:narrow(4, 1 - self.pad_l, c_input:size(4) + self.pad_l) end
      if self.pad_r < 0 then c_input = c_input:narrow(4, 1, c_input:size(4) + self.pad_r) end
      -- crop outout if necessary
      local c_output = self.output
      if self.pad_t > 0 then c_output = c_output:narrow(3, 1 + self.pad_t, c_output:size(3) - self.pad_t) end
      if self.pad_b > 0 then c_output = c_output:narrow(3, 1, c_output:size(3) - self.pad_b) end
      if self.pad_l > 0 then c_output = c_output:narrow(4, 1 + self.pad_l, c_output:size(4) - self.pad_l) end
      if self.pad_r > 0 then c_output = c_output:narrow(4, 1, c_output:size(4) - self.pad_r) end
      -- copy input to output
      c_output:copy(c_input)
   else
      error('input must be 3 or 4-dimensional')
   end
   return self.output
end

function SpatialZeroPadding:updateGradInput(input, gradOutput)
   if input:dim() == 3 then
      self.gradInput:resizeAs(input):zero()
      -- crop gradInput if necessary
      local cg_input = self.gradInput
      if self.pad_t < 0 then cg_input = cg_input:narrow(2, 1 - self.pad_t, cg_input:size(2) + self.pad_t) end
      if self.pad_b < 0 then cg_input = cg_input:narrow(2, 1, cg_input:size(2) + self.pad_b) end
      if self.pad_l < 0 then cg_input = cg_input:narrow(3, 1 - self.pad_l, cg_input:size(3) + self.pad_l) end
      if self.pad_r < 0 then cg_input = cg_input:narrow(3, 1, cg_input:size(3) + self.pad_r) end
      -- crop gradOutout if necessary
      local cg_output = gradOutput
      if self.pad_t > 0 then cg_output = cg_output:narrow(2, 1 + self.pad_t, cg_output:size(2) - self.pad_t) end
      if self.pad_b > 0 then cg_output = cg_output:narrow(2, 1, cg_output:size(2) - self.pad_b) end
      if self.pad_l > 0 then cg_output = cg_output:narrow(3, 1 + self.pad_l, cg_output:size(3) - self.pad_l) end
      if self.pad_r > 0 then cg_output = cg_output:narrow(3, 1, cg_output:size(3) - self.pad_r) end
      -- copy gradOuput to gradInput
      cg_input:copy(cg_output)
   elseif input:dim() == 4 then
      self.gradInput:resizeAs(input):zero()
      -- crop gradInput if necessary
      local cg_input = self.gradInput
      if self.pad_t < 0 then cg_input = cg_input:narrow(3, 1 - self.pad_t, cg_input:size(3) + self.pad_t) end
      if self.pad_b < 0 then cg_input = cg_input:narrow(3, 1, cg_input:size(3) + self.pad_b) end
      if self.pad_l < 0 then cg_input = cg_input:narrow(4, 1 - self.pad_l, cg_input:size(4) + self.pad_l) end
      if self.pad_r < 0 then cg_input = cg_input:narrow(4, 1, cg_input:size(4) + self.pad_r) end
      -- crop gradOutout if necessary
      local cg_output = gradOutput
      if self.pad_t > 0 then cg_output = cg_output:narrow(3, 1 + self.pad_t, cg_output:size(3) - self.pad_t) end
      if self.pad_b > 0 then cg_output = cg_output:narrow(3, 1, cg_output:size(3) - self.pad_b) end
      if self.pad_l > 0 then cg_output = cg_output:narrow(4, 1 + self.pad_l, cg_output:size(4) - self.pad_l) end
      if self.pad_r > 0 then cg_output = cg_output:narrow(4, 1, cg_output:size(4) - self.pad_r) end
      -- copy gradOuput to gradInput
      cg_input:copy(cg_output)
   else
      error('input must be 3 or 4-dimensional')
   end
   return self.gradInput
end


function SpatialZeroPadding:__tostring__()
   return torch.type(self) ..
   string.format('(l=%d, r=%d, t=%d, b=%d)', self.pad_l, self.pad_r,
   self.pad_t, self.pad_b)
end
