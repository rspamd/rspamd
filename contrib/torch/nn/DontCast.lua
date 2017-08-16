local DontCast, parent = torch.class("nn.DontCast", "nn.Decorator")

-- utility functions

local function recursiveTypeCopy(dst, src, type_str)
   if torch.type(src) == 'table' then
      dst = (torch.type(dst) == 'table') and dst or {}
      for k, v in pairs(src) do
         dst[k] = recursiveTypeCopy(dst[k], v, type_str)
      end
   elseif torch.isTensor(src) then
      dst = (torch.type(dst) == type_str) and dst or torch.getmetatable(type_str).new()
      dst:resize(src:size())
      if src:nElement() > 0 then
         dst:copy(src)
      end
   end
   return dst
end

local function tableTensorType(src)
   if type(src) == 'table' then
      local type_str, found
      for k,v in pairs(src) do
         type_str, found = tableTensorType(v)
         if found then
            return type_str, true
         end
      end
      return type_str, found
   else
      return torch.type(src), torch.isTensor(src)
   end
end

-- DontCast methods and constructor

function DontCast:__init(module, castin, castout, moduleType)
   parent.__init(self, module)
   self.castin = castin
   self.castout = (castout == nil) and castin or castout
   self.moduleType = moduleType
   if (self.castin or self.castout) and not self.moduleType then
      local moduleType, found = tableTensorType(module.output)
      if found then
         self.moduleType = moduleType
      else
         moduleType, found = tableTensorType(module:parameters())
         if found then
            self.moduleType = moduleType
         else
            error"Cannot extrapolate moduleType. Provide constructor argument 4"
         end
      end
   end
end

function DontCast:updateOutput(input)
   if self.castin and tableTensorType(input) ~= self.moduleType then
      self._input = recursiveTypeCopy(self._input, input, self.moduleType)
      input = self._input
   end

   local output = self.modules[1]:updateOutput(input)

   if self.castout then
      self.output = recursiveTypeCopy(self.output, output, tableTensorType(self.output))
   else
      self.output = output
   end
   return self.output
end

function DontCast:updateGradInput(input, gradOutput)
   if self.castin and tableTensorType(input) ~= self.moduleType then
      input = self._input
   end
   if self.castout and tableTensorType(gradOutput) ~= self.moduleType then
      self._gradOutput = recursiveTypeCopy(self._gradOutput, gradOutput, self.moduleType)
      gradOutput = self._gradOutput
   end

   local gradInput = self.modules[1]:updateGradInput(input, gradOutput)

   if self.castin then
      self.gradInput = recursiveTypeCopy(self.gradInput, gradInput, tableTensorType(self.gradInput))
   else
      self.gradInput = gradInput
   end
   return self.gradInput
end

function DontCast:accGradParameters(input, gradOutput, scale)
   if self.castin and tableTensorType(input) ~= self.moduleType then
      input = self._input
   end
   if self.castout and tableTensorType(gradOutput) ~= self.moduleType then
      gradOutput = self._gradOutput
   end

   self.modules[1]:accGradParameters(input, gradOutput, scale)
end

function DontCast:accUpdateGradParameters(input, gradOutput, lr)
   if self.castin and tableTensorType(input) ~= self.moduleType then
      input = self._input
   end
   if self.castout and tableTensorType(gradOutput) ~= self.moduleType then
      gradOutput = self._gradOutput
   end

   self.modules[1]:accUpdateGradParameters(input, gradOutput, lr)
end

-- dont cast (the essence thereof)
function DontCast:type(type)
   if self.castout and tableTensorType(self.output) ~= type then
      self.output = recursiveTypeCopy(nil, self.output, type)
   end
   if self.castin and tableTensorType(self.gradInput) ~= type then
      self.gradInput = recursiveTypeCopy(nil, self.gradInput, type)
   end
   return self
end
