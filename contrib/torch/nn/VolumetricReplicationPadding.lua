local VolumetricReplicationPadding, parent =
   torch.class('nn.VolumetricReplicationPadding', 'nn.Module')

function VolumetricReplicationPadding:__init(pleft, pright, ptop, pbottom,
                                             pfront, pback)
   parent.__init(self)
   self.pleft = pleft
   self.pright = pright or self.pleft
   self.ptop = ptop or self.pleft
   self.pbottom = pbottom or self.pleft
   self.pfront = pfront or self.pleft
   self.pback = pback or self.pleft
end

function VolumetricReplicationPadding:updateOutput(input)
   if input:dim() == 4 or input:dim() == 5 then
      input.THNN.VolumetricReplicationPadding_updateOutput(
         input:cdata(), self.output:cdata(),
         self.pleft, self.pright, self.ptop, self.pbottom, self.pfront,
         self.pback)
   else
      error('input must be 4 or 5-dimensional')
   end
   return self.output
end

function VolumetricReplicationPadding:updateGradInput(input, gradOutput)
   if input:dim() == 4 and gradOutput:dim() == 4 then
      assert(input:size(1) == gradOutput:size(1)
             and input:size(2) + self.pfront + self.pback == gradOutput:size(2)
             and input:size(3) + self.ptop + self.pbottom == gradOutput:size(3)
             and input:size(4) + self.pleft + self.pright == gradOutput:size(4),
             'input and gradOutput must be compatible in size')
   elseif input:dim() == 5 and gradOutput:dim() == 5 then
      assert(input:size(1) == gradOutput:size(1)
             and input:size(2) == gradOutput:size(2)
             and input:size(3) + self.pfront + self.pback == gradOutput:size(3)
             and input:size(4) + self.ptop + self.pbottom == gradOutput:size(4)
             and input:size(5) + self.pleft + self.pright == gradOutput:size(5),
             'input and gradOutput must be compatible in size')
   else
      error(
         [[input and gradOutput must be 4 or 5-dimensional
         and have equal number of dimensions]]
         )
   end
   input.THNN.VolumetricReplicationPadding_updateGradInput(
      input:cdata(), gradOutput:cdata(), self.gradInput:cdata(),
      self.pleft, self.pright, self.ptop, self.pbottom, self.pfront, self.pback)
   return self.gradInput
end

function VolumetricReplicationPadding:__tostring__()
   return torch.type(self) ..
   string.format('(left=%d, right=%d, top=%d, bottom=%d, front=%d, back=%d)',
                 self.pleft, self.pright, self.ptop, self.pbottom,
                 self.pfront, self.pback)
end
