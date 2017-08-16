local Threshold, parent = torch.class('nn.Threshold','nn.Module')

function Threshold:__init(th,v,ip)
   parent.__init(self)
   self.threshold = th or 1e-6
   self.val = v or 0
   if (th and type(th) ~= 'number') or (v and type(v) ~= 'number') then
      error('nn.Threshold(threshold, value)')
   end
   -- default for inplace is false
   self.inplace = ip or false
   if (ip and type(ip) ~= 'boolean') then
      error('in-place flag must be boolean')
   end
   self:validateParameters()
end

function Threshold:updateOutput(input)
   self:validateParameters()
   input.THNN.Threshold_updateOutput(
      input:cdata(),
      self.output:cdata(),
      self.threshold,
      self.val,
      self.inplace
   )
   return self.output
end

function Threshold:updateGradInput(input, gradOutput)
   self:validateParameters()
   input.THNN.Threshold_updateGradInput(
      input:cdata(),
      gradOutput:cdata(),
      self.gradInput:cdata(),
      self.threshold,
      self.val,
      self.inplace
   )
   return self.gradInput
end

function Threshold:validateParameters()
   self.inplace = self.inplace or false -- backwards compatibility pre inplace
   if self.inplace then
      if self.val > self.threshold then
         error('in-place processing requires value (' .. self.val ..
                  ') not exceed threshold (' .. self.threshold .. ')')
      end
   end
end
