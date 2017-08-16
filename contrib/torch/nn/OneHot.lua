local OneHot, parent = torch.class('nn.OneHot', 'nn.Module')

-- adapted from https://github.com/karpathy/char-rnn
-- and https://github.com/hughperkins/char-lstm

function OneHot:__init(outputSize)
   parent.__init(self)
   self.outputSize = outputSize
end

function OneHot:updateOutput(input)
   local size
   if type(input) == 'number' then
      if self:type() == 'torch.CudaTensor' then
         self._single = self._single or torch.CudaTensor():resize(1);
      else
         self._single = self._single or torch.LongTensor():resize(1);
      end
      self._single[1] = input
      input = self._single;
      size = {}
   else
      size = input:size():totable()
   end
   table.insert(size, self.outputSize)

   self.output:resize(table.unpack(size)):zero()

   size[#size] = 1
   local input_ = input:view(table.unpack(size))

   if torch.type(input) == 'torch.CudaTensor' or torch.type(input) == 'torch.ClTensor' then
      self.output:scatter(self.output:dim(), input_, 1)
   else
      if torch.type(self.output) == 'torch.CudaTensor' then
         -- input is not cuda, module is, cast input to cuda
         self._input = self._input or torch.CudaTensor()
         self._input:resize(input_:size()):copy(input_)
         input_ = self._input
      elseif torch.type(input) ~= 'torch.LongTensor' then
         -- input is not long, module isnot cuda, cast input to long
         self._input = self._input or torch.LongTensor()
         self._input:resize(input_:size()):copy(input_)
         input_ = self._input
      end
      self.output:scatter(self.output:dim(), input_, 1)
   end

   return self.output
end

function OneHot:updateGradInput(input, gradOutput)
   if type(input) == 'number' then
      return 0
   else
      self.gradInput:resize(input:size()):zero()
      return self.gradInput
   end
end

function OneHot:clearState()
   self._single = nil
   self._input = nil
end

function OneHot:type(type, typecache)
   self:clearState()
   return parent.type(self, type, typecache)
end
