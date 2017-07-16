----------------------------------------------------------------------
-- hessian.lua: this file appends extra methods to modules in nn,
-- to estimate diagonal elements of the Hessian. This is useful
-- to condition learning rates individually.
----------------------------------------------------------------------
nn.hessian = {}

----------------------------------------------------------------------
-- Hessian code is still experimental,
-- and deactivated by default
----------------------------------------------------------------------
function nn.hessian.enable()

   local function accDiagHessianParameters(module, input, diagHessianOutput, gw, hw)
      if #gw ~= #hw then
         error('Number of gradients is nto equal to number of hessians')
      end
      module.inputSq = module.inputSq or input.new()
      module.inputSq:resizeAs(input)
      torch.cmul(module.inputSq, input, input)
      -- replace gradients with hessian
      for i=1,#gw do
         local gwname = gw[i]
         local hwname = hw[i]
         local gwval = module[gwname]
         local hwval = module[hwname]
         if hwval == nil then
            module[hwname] = gwval.new():resizeAs(gwval)
            hwval = module[hwname]
         end
         module[gwname] = hwval
         module[hwname] = gwval
      end
      local oldOutput = module.output
      module.output = module.output.new():resizeAs(oldOutput)
      module.forward(module, module.inputSq)
      module.accGradParameters(module, module.inputSq, diagHessianOutput, 1)
      -- put back gradients
      for i=1,#gw do
         local gwname = gw[i]
         local hwname = hw[i]
         local gwval = module[gwname]
         local hwval = module[hwname]
         module[gwname] = hwval
         module[hwname] = gwval
      end
      module.output = oldOutput
   end
   nn.hessian.accDiagHessianParameters = accDiagHessianParameters

   local function updateDiagHessianInput(module, input, diagHessianOutput, w, wsq)
      if #w ~= #wsq then
         error('Number of weights is not equal to number of weights squares')
      end
      module.diagHessianInput = module.diagHessianInput or input.new()
      module.diagHessianInput:resizeAs(input):zero()

      local gi = module.gradInput
      module.gradInput = module.diagHessianInput
      for i=1,#w do
         local wname = w[i]
         local wsqname = wsq[i]
         local wval = module[wname]
         local wsqval = module[wsqname]
         if wsqval == nil then
            module[wsqname] = wval.new()
            wsqval = module[wsqname]
         end
         wsqval:resizeAs(wval)
         torch.cmul(wsqval, wval, wval)
         module[wsqname] = wval
         module[wname] = wsqval
      end
      module.updateGradInput(module,input,diagHessianOutput)
      for i=1,#w do
         local wname = w[i]
         local wsqname = wsq[i]
         local wval = module[wname]
         local wsqval = module[wsqname]
         module[wname] = wsqval
         module[wsqname] = wval
      end
      module.gradInput = gi
   end
   nn.hessian.updateDiagHessianInput = updateDiagHessianInput

   local function updateDiagHessianInputPointWise(module, input, diagHessianOutput)
      local tdh = diagHessianOutput.new():resizeAs(diagHessianOutput):fill(1)
      updateDiagHessianInput(module,input,tdh,{},{})
      module.diagHessianInput:cmul(module.diagHessianInput)
      module.diagHessianInput:cmul(diagHessianOutput)
   end
   nn.hessian.updateDiagHessianInputPointWise = updateDiagHessianInputPointWise

   local function initDiagHessianParameters(module,gw,hw)
      module.diagHessianInput = module.diagHessianInput or module.gradInput.new();
      for i=1,#gw do
         module[hw[i]] = module[hw[i]] or module[gw[i]].new():resizeAs(module[gw[i]])
      end
   end
   nn.hessian.initDiagHessianParameters = initDiagHessianParameters

   ----------------------------------------------------------------------
   -- Module
   ----------------------------------------------------------------------
   function nn.Module.updateDiagHessianInput(self, input, diagHessianOutput)
      error(torch.typename(self) .. ':updateDiagHessianInput() is undefined')
   end

   function nn.Module.accDiagHessianParameters(self, input, diagHessianOutput)
   end

   function nn.Module.initDiagHessianParameters()
   end

   ----------------------------------------------------------------------
   -- Sequential
   ----------------------------------------------------------------------
   function nn.Sequential.initDiagHessianParameters(self)
      for i=1,#self.modules do
         self.modules[i]:initDiagHessianParameters()
      end
   end

   function nn.Sequential.updateDiagHessianInput(self, input, diagHessianOutput)
      local currentDiagHessianOutput = diagHessianOutput
      local currentModule = self.modules[#self.modules]
      for i=#self.modules-1,1,-1 do
         local previousModule = self.modules[i]
         currentDiagHessianOutput = currentModule:updateDiagHessianInput(previousModule.output, currentDiagHessianOutput)
         currentModule = previousModule
      end
      currentDiagHessianOutput = currentModule:updateDiagHessianInput(input, currentDiagHessianOutput)
      self.diagHessianInput = currentDiagHessianOutput
      return currentDiagHessianOutput
   end

   function nn.Sequential.accDiagHessianParameters(self, input, diagHessianOutput)
      local currentDiagHessianOutput = diagHessianOutput
      local currentModule = self.modules[#self.modules]
      for i=#self.modules-1,1,-1 do
         local previousModule = self.modules[i]
         currentModule:accDiagHessianParameters(previousModule.output, currentDiagHessianOutput)
         currentDiagHessianOutput = currentModule.diagHessianInput
         currentModule = previousModule
      end
      currentModule:accDiagHessianParameters(input, currentDiagHessianOutput)
   end

   ----------------------------------------------------------------------
   -- Criterion
   ----------------------------------------------------------------------
   function nn.Criterion.updateDiagHessianInput(self, input, diagHessianOutput)
      error(torch.typename(self) .. ':updateDiagHessianInput() is undefined')
   end

   ----------------------------------------------------------------------
   -- MSECriterion
   ----------------------------------------------------------------------
   function nn.MSECriterion.updateDiagHessianInput(self, input, target)
      self.diagHessianInput = self.diagHessianInput or input.new()
      local val = 2
      if self.sizeAverage then
         val = val / input:nElement()
      end
      self.diagHessianInput:resizeAs(input):fill(val)
      return self.diagHessianInput
   end

   ----------------------------------------------------------------------
   -- WeightedMSECriterion
   ----------------------------------------------------------------------
   function nn.WeightedMSECriterion.updateDiagHessianInput(self,input,target)
      return nn.MSECriterion.updateDiagHessianInput(self,input,target)
   end

   ----------------------------------------------------------------------
   -- L1Cost
   ----------------------------------------------------------------------
   function nn.L1Cost.updateDiagHessianInput(self,input)
      self.diagHessianInput = self.diagHessianInput or input.new()
      self.diagHessianInput:resizeAs(input)
      self.diagHessianInput:fill(1)
      self.diagHessianInput[torch.eq(input,0)] = 0
      return self.diagHessianInput
   end

   ----------------------------------------------------------------------
   -- Linear
   ----------------------------------------------------------------------
   function nn.Linear.updateDiagHessianInput(self, input, diagHessianOutput)
      updateDiagHessianInput(self, input, diagHessianOutput, {'weight'}, {'weightSq'})
      return self.diagHessianInput
   end

   function nn.Linear.accDiagHessianParameters(self, input, diagHessianOutput)
      accDiagHessianParameters(self,input, diagHessianOutput, {'gradWeight','gradBias'}, {'diagHessianWeight','diagHessianBias'})
   end

   function nn.Linear.initDiagHessianParameters(self)
      initDiagHessianParameters(self,{'gradWeight','gradBias'},{'diagHessianWeight','diagHessianBias'})
   end

   ----------------------------------------------------------------------
   -- SpatialConvolution
   ----------------------------------------------------------------------
   function nn.SpatialConvolution.updateDiagHessianInput(self, input, diagHessianOutput)
      updateDiagHessianInput(self, input, diagHessianOutput, {'weight'}, {'weightSq'})
      return self.diagHessianInput
   end

   function nn.SpatialConvolution.accDiagHessianParameters(self, input, diagHessianOutput)
      accDiagHessianParameters(self,input, diagHessianOutput, {'gradWeight','gradBias'}, {'diagHessianWeight','diagHessianBias'})
   end

   function nn.SpatialConvolution.initDiagHessianParameters(self)
      initDiagHessianParameters(self,{'gradWeight','gradBias'},{'diagHessianWeight','diagHessianBias'})
   end

   ----------------------------------------------------------------------
   -- SpatialConvolutionLocal
   ----------------------------------------------------------------------
   function nn.SpatialConvolutionLocal.updateDiagHessianInput(self, input, diagHessianOutput)
      updateDiagHessianInput(self, input, diagHessianOutput, {'weight'}, {'weightSq'})
      return self.diagHessianInput
   end

   function nn.SpatialConvolutionLocal.accDiagHessianParameters(self, input, diagHessianOutput)
      accDiagHessianParameters(self,input, diagHessianOutput, {'gradWeight','gradBias'}, {'diagHessianWeight','diagHessianBias'})
   end

   function nn.SpatialConvolutionLocal.initDiagHessianParameters(self)
      initDiagHessianParameters(self,{'gradWeight','gradBias'},{'diagHessianWeight','diagHessianBias'})
   end

   ----------------------------------------------------------------------
   -- SpatialFullConvolution
   ----------------------------------------------------------------------
   function nn.SpatialFullConvolution.updateDiagHessianInput(self, input, diagHessianOutput)
      updateDiagHessianInput(self, input, diagHessianOutput, {'weight'}, {'weightSq'})
      return self.diagHessianInput
   end

   function nn.SpatialFullConvolution.accDiagHessianParameters(self, input, diagHessianOutput)
      accDiagHessianParameters(self,input, diagHessianOutput, {'gradWeight','gradBias'}, {'diagHessianWeight','diagHessianBias'})
   end

   function nn.SpatialFullConvolution.initDiagHessianParameters(self)
      initDiagHessianParameters(self,{'gradWeight','gradBias'},{'diagHessianWeight','diagHessianBias'})
   end

   ----------------------------------------------------------------------
   -- SpatialConvolutionMap
   ----------------------------------------------------------------------
   function nn.SpatialConvolutionMap.updateDiagHessianInput(self, input, diagHessianOutput)
      updateDiagHessianInput(self, input, diagHessianOutput, {'weight','bias'}, {'weightSq','biasSq'})
      return self.diagHessianInput
   end

   function nn.SpatialConvolutionMap.accDiagHessianParameters(self, input, diagHessianOutput)
      accDiagHessianParameters(self,input, diagHessianOutput, {'gradWeight','gradBias'}, {'diagHessianWeight','diagHessianBias'})
   end

   function nn.SpatialConvolutionMap.initDiagHessianParameters(self)
      initDiagHessianParameters(self,{'gradWeight','gradBias'},{'diagHessianWeight','diagHessianBias'})
   end

   ----------------------------------------------------------------------
   -- SpatialFullConvolutionMap
   ----------------------------------------------------------------------
   function nn.SpatialFullConvolutionMap.updateDiagHessianInput(self, input, diagHessianOutput)
      updateDiagHessianInput(self, input, diagHessianOutput, {'weight'}, {'weightSq'})
      return self.diagHessianInput
   end

   function nn.SpatialFullConvolutionMap.accDiagHessianParameters(self, input, diagHessianOutput)
      accDiagHessianParameters(self,input, diagHessianOutput, {'gradWeight','gradBias'}, {'diagHessianWeight','diagHessianBias'})
   end

   function nn.SpatialFullConvolutionMap.initDiagHessianParameters(self)
      initDiagHessianParameters(self,{'gradWeight','gradBias'},{'diagHessianWeight','diagHessianBias'})
   end

----------------------------------------------------------------------
   -- Tanh
   ----------------------------------------------------------------------
   function nn.Tanh.updateDiagHessianInput(self, input, diagHessianOutput)
      updateDiagHessianInputPointWise(self, input, diagHessianOutput)
      return self.diagHessianInput
   end

   ----------------------------------------------------------------------
   -- TanhShrink
   ----------------------------------------------------------------------
   function nn.TanhShrink.updateDiagHessianInput(self, input, diagHessianOutput)
      updateDiagHessianInputPointWise(self.tanh, input, diagHessianOutput)
      self.diagHessianInput = self.diagHessianInput or input.new():resizeAs(input)
      torch.add(self.diagHessianInput, self.tanh.diagHessianInput, diagHessianOutput)
      return self.diagHessianInput
   end

   ----------------------------------------------------------------------
   -- Square
   ----------------------------------------------------------------------
   function nn.Square.updateDiagHessianInput(self, input, diagHessianOutput)
      updateDiagHessianInputPointWise(self, input, diagHessianOutput)
      return self.diagHessianInput
   end

   ----------------------------------------------------------------------
   -- Sqrt
   ----------------------------------------------------------------------
   function nn.Sqrt.updateDiagHessianInput(self, input, diagHessianOutput)
      updateDiagHessianInputPointWise(self, input, diagHessianOutput)
      return self.diagHessianInput
   end

   ----------------------------------------------------------------------
   -- Reshape
   ----------------------------------------------------------------------
   function nn.Reshape.updateDiagHessianInput(self, input, diagHessianOutput)
      self.diagHessianInput = self.diagHessianInput or input.new()
      diagHessianOutput = diagHessianOutput:contiguous()
      self.diagHessianInput:set(diagHessianOutput):resizeAs(input)
      return self.diagHessianInput
   end

   ----------------------------------------------------------------------
   -- Parameters manipulation:
   -- we modify these functions such that they return hessian coefficients
   ----------------------------------------------------------------------
   function nn.Module.parameters(self)
      if self.weight and self.bias then
         return {self.weight, self.bias}, {self.gradWeight, self.gradBias}, {self.diagHessianWeight, self.diagHessianBias}
      elseif self.weight then
         return {self.weight}, {self.gradWeight}, {self.diagHessianWeight}
      elseif self.bias then
         return {self.bias}, {self.gradBias}, {self.diagHessianBias}
      else
         return
      end
   end

   function nn.Module.getParameters(self)
      -- get parameters
      local parameters,gradParameters,hessianParameters = self:parameters()
      -- flatten parameters and gradients
      local flatParameters = nn.Module.flatten(parameters)
      collectgarbage()
      local flatGradParameters = nn.Module.flatten(gradParameters)
      collectgarbage()
      local flatHessianParameters
      if hessianParameters and hessianParameters[1] then
         flatHessianParameters = nn.Module.flatten(hessianParameters)
         collectgarbage()
      end

      -- return new flat vector that contains all discrete parameters
      return flatParameters, flatGradParameters, flatHessianParameters
   end

   function nn.Sequential.parameters(self)
      local function tinsert(to, from)
         if type(from) == 'table' then
            for i=1,#from do
               tinsert(to,from[i])
            end
         else
            table.insert(to,from)
         end
      end
      local w = {}
      local gw = {}
      local ggw = {}
      for i=1,#self.modules do
         local mw,mgw,mggw = self.modules[i]:parameters()
         if mw then
            tinsert(w,mw)
            tinsert(gw,mgw)
            tinsert(ggw,mggw)
         end
      end
      return w,gw,ggw
   end

   ----------------------------------------------------------------------
   -- Avoid multiple calls to enable()
   ----------------------------------------------------------------------
   function nn.hessian.enable()
   end
end
