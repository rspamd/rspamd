local SpatialReplicationPadding, parent =
   torch.class('nn.SpatialReplicationPadding', 'nn.Module')

function SpatialReplicationPadding:__init(pad_l, pad_r, pad_t, pad_b)
   parent.__init(self)
   self.pad_l = pad_l
   self.pad_r = pad_r or self.pad_l
   self.pad_t = pad_t or self.pad_l
   self.pad_b = pad_b or self.pad_l
end

function SpatialReplicationPadding:updateOutput(input)
   if input:dim() == 3 or input:dim() == 4 then
      input.THNN.SpatialReplicationPadding_updateOutput(
         input:cdata(), self.output:cdata(),
         self.pad_l, self.pad_r, self.pad_t, self.pad_b)
   else
      error('input must be 3 or 4-dimensional')
   end
   return self.output
end

function SpatialReplicationPadding:updateGradInput(input, gradOutput)
   if input:dim() == 3 and gradOutput:dim() == 3 then
      assert(input:size(1) == gradOutput:size(1)
             and input:size(2) + self.pad_t + self.pad_b == gradOutput:size(2)
             and input:size(3) + self.pad_l + self.pad_r == gradOutput:size(3),
             'input and gradOutput must be compatible in size')
   elseif input:dim() == 4 and gradOutput:dim() == 4 then
      assert(input:size(1) == gradOutput:size(1)
             and input:size(2) == gradOutput:size(2)
             and input:size(3) + self.pad_t + self.pad_b == gradOutput:size(3)
             and input:size(4) + self.pad_l + self.pad_r == gradOutput:size(4),
             'input and gradOutput must be compatible in size')
   else
      error(
         [[input and gradOutput must be 3 or 4-dimensional
         and have equal number of dimensions]]
         )
   end
   input.THNN.SpatialReplicationPadding_updateGradInput(
      input:cdata(), gradOutput:cdata(), self.gradInput:cdata(),
      self.pad_l, self.pad_r, self.pad_t, self.pad_b)
   return self.gradInput
end

function SpatialReplicationPadding:__tostring__()
   return torch.type(self) ..
   string.format('(l=%d, r=%d, t=%d, b=%d)', self.pad_l, self.pad_r,
   self.pad_t, self.pad_b)
end
