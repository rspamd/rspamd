local Copy, parent = torch.class('nn.Copy', 'nn.Module')

function Copy:__init(intype, outtype, forceCopy, dontCast)
   intype = intype or torch.Tensor.__typename
   outtype = outtype or torch.Tensor.__typename

   self.dontCast = dontCast

   parent.__init(self)
   self.gradInput = torch.getmetatable(intype).new()
   self.output = torch.getmetatable(outtype).new()

   if (not forceCopy) and intype == outtype then

      self.updateOutput = function(self, input)
                        self.output:set(input)
                        return input
                     end

      self.updateGradInput = function(self, input, gradOutput)
                         self.gradInput:set(gradOutput)
                         return gradOutput
                      end
   end
end

function Copy:updateOutput(input)
   self.output:resize(input:size()):copy(input)
   return self.output
end

function Copy:updateGradInput(input, gradOutput)
   self.gradInput:resize(gradOutput:size()):copy(gradOutput)
   return self.gradInput
end

function Copy:type(type, tensorCache)
   if type and self.dontCast then
      return self
   end
   return parent.type(self, type, tensorCache)
end
