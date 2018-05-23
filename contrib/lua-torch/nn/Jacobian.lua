nn.Jacobian = {}

function nn.Jacobian.backward(module, input, param, dparam)
   local doparam = 0
   if param then
      doparam = 1
   end
   param = param or input
   -- output deriv
   module:forward(input)
   local dout = module.output.new():resizeAs(module.output)
   -- 1D view
   local sdout = module.output.new(dout:storage(),1,dout:nElement())
   -- jacobian matrix to calculate
   local jacobian = torch.Tensor(param:nElement(),dout:nElement()):zero()

   for i=1,sdout:nElement() do
      dout:zero()
      sdout[i] = 1
      module:zeroGradParameters()
      local din = module:updateGradInput(input, dout)
      module:accGradParameters(input, dout)
      if doparam == 1 then
         jacobian:select(2,i):copy(dparam)
      else
         jacobian:select(2,i):copy(din)
      end
   end
   return jacobian
end

function nn.Jacobian.backwardUpdate(module, input, param)

   -- output deriv
   module:forward(input)
   local dout = module.output.new():resizeAs(module.output)
   -- 1D view
   local sdout = module.output.new(dout:storage(),1,dout:nElement())
   -- jacobian matrix to calculate
   local jacobian = torch.Tensor(param:nElement(),dout:nElement()):zero()

   -- original param
   local params = module:parameters()
   local origparams = {}
   for j=1,#params do
      table.insert(origparams, params[j]:clone())
   end

   for i=1,sdout:nElement() do
      for j=1,#params do
         params[j]:copy(origparams[j])
      end
      dout:zero()
      sdout[i] = 1
      module:updateGradInput(input, dout)
      module:accUpdateGradParameters(input, dout, 1)
      jacobian:select(2,i):copy(param)
   end

   for j=1,#params do
      params[j]:copy(origparams[j])
   end

   return jacobian
end

function nn.Jacobian.forward(module, input, param, perturbation)
   param = param or input
   -- perturbation amount
   perturbation = perturbation or 1e-6
   -- 1D view of input
   --local tst = param:storage()
   local sin = param.new(param):resize(param:nElement())--param.new(tst,1,tst:size())
   -- jacobian matrix to calculate
   local jacobian = torch.Tensor():resize(param:nElement(),module:forward(input):nElement())

   local outa = torch.Tensor(jacobian:size(2))
   local outb = torch.Tensor(jacobian:size(2))

   for i=1,sin:nElement() do
      local orig = sin[i]
      sin[i] = orig - perturbation
      outa:copy(module:forward(input))
      sin[i] = orig + perturbation
      outb:copy(module:forward(input))
      sin[i] = orig

      outb:add(-1,outa):div(2*perturbation)
      jacobian:select(1,i):copy(outb)
   end

   return jacobian
end

function nn.Jacobian.backwardDiagHessian(module, input, diagHessianParamName)
   -- Compute the second derivatives (diagonal Hessian elements)
   -- by backpropagation (using the code from hessian.lua).
   --
   -- This function computes the diagonal Hessian elements of the following function:
   --
   -- F(x_1, x_2, ..., x_n) = y_1^2/2 + y_2^2/2 + ... + y_m^2/2,
   --
   -- where
   -- x_1, ..., x_n are the input values and parameters of the given module,
   -- y_1, ..., y_m are the output values of the given module.
   --
   -- All x_i and y_i values are scalars here. In other words,
   -- x_1, ..., x_n denote the scalar elements of the module input tensor,
   --             the scalar elements of module.weight,
   --             and the scalar elements of module.bias;
   -- y_1, ..., y_m are the scalar elements of the module output tensor.
   --
   -- The diagonal Hessian elements of F are computed with respect to
   -- the module input values and parameters (x_1, .., x_n).
   --
   -- The function F is chosen for its convenient properties:
   --
   -- dF / dy_i = y_i,
   -- d^2F / dy_i^2 = 1.
   --
   -- In other words, the diagonal Hessian elements of F with respect
   -- to the module OUTPUT values (y_1, ... y_m) are equal to 1.
   --
   -- Because of that, computing the diagonal Hessian elements of F
   -- with respect to the module INPUT values and PARAMETERS (x_1, ..., x_n)
   -- can be done by calling updateDiagHessianInput() and accDiagHessianParameters()
   -- using a tensor of ones as diagHessianOutput.

   module:forward(input)
   local diagHessianOutput = module.output.new():resizeAs(module.output):fill(1)

   module.diagHessianWeight:zero()
   module.diagHessianBias:zero()
   module:updateDiagHessianInput(input, diagHessianOutput)
   module:accDiagHessianParameters(input, diagHessianOutput)

   return module[diagHessianParamName]
end

function nn.Jacobian.linearModuleDiagHessian(module, input, gradParamName)
   -- Compute the second derivatives (diagonal Hessian elements)
   -- from the first derivatives for the given module
   -- (without using the code from hessian.lua).
   --
   -- The given module is assumed to be linear with respect to its inputs and weights
   -- (like nn.Linear, nn.SpatialConvolution, etc.)
   --
   -- This function computes the diagonal Hessian elements of the following function:
   --
   -- F(x_1, x_2, ..., x_n) = y_1^2/2 + y_2^2/2 + ... + y_m^2/2.
   --
   -- (See the the comment for nn.Jacobian.backwardDiagHessian() for explanation.)
   --
   -- The first derivatives of F with respect to
   -- the module inputs and parameters (x_1, ..., x_n) are:
   --
   -- dF / dx_i = \sum_k (dF / dy_k) (dy_k / dx_i).
   --
   -- The second derivatives are:
   --
   -- d^2F / dx_i = \sum_k [(d^2F / dy_k^2) (dy_k / dx_i)^2 + (dF / dy_k) (d^2y_k / dx_i^2)].
   --
   -- The second derivatives of F with respect to the module outputs (y_1, ..., y_m)
   -- are equal to 1, so:
   --
   -- d^2F / dx_i = \sum_k [(dy_k / dx_i)^2 + (dF / dy_k) (d^2y_k / dx_i^2)].
   --
   -- Assuming the linearity of module outputs (y_1, ..., y_m)
   -- with respect to module inputs and parameters (x_1, ..., x_n),
   -- we have (d^2y_k / dx_i^2) = 0,
   -- and the expression finally becomes:
   --
   -- d^2F / dx_i = \sum_k (dy_k / dx_i)^2.
   --
   -- The first derivatives (dy_k / dx_i) are computed by normal backpropagation,
   -- using updateGradInput() and accGradParameters().

   local gradParam = module[gradParamName]

   local diagHessian = gradParam.new():resize(gradParam:nElement()):zero()

   module:forward(input)
   local gradOutput = module.output.new():resizeAs(module.output)
   local gradOutput1D = gradOutput:view(gradOutput:nElement())

   for i=1,gradOutput:nElement() do
      gradOutput1D:zero()
      gradOutput1D[i] = 1
      module.gradWeight:zero()
      if module.bias then
         module.gradBias:zero()
      end
      module:updateGradInput(input, gradOutput)
      module:accGradParameters(input, gradOutput)
      diagHessian:addcmul(gradParam, gradParam)
   end

   return diagHessian
end

function nn.Jacobian.forwardUpdate(module, input, param, perturbation)
   -- perturbation amount
   perturbation = perturbation or 1e-6
   -- 1D view of input
   --local tst = param:storage()
   local sin =  param.new(param):resize(param:nElement())--param.new(tst,1,tst:size())
   -- jacobian matrix to calculate
   local jacobian = torch.Tensor():resize(param:nElement(),module:forward(input):nElement())

   local outa = torch.Tensor(jacobian:size(2))
   local outb = torch.Tensor(jacobian:size(2))

   for i=1,sin:nElement() do
      local orig = sin[i]
      sin[i] = orig - perturbation
      outa:copy(module:forward(input))
      sin[i] = orig + perturbation
      outb:copy(module:forward(input))
      sin[i] = orig

      outb:add(-1,outa):div(2*perturbation)
      jacobian:select(1,i):copy(outb)
      jacobian:select(1,i):mul(-1)
      jacobian:select(1,i):add(sin[i])
   end
   return jacobian
end

function nn.Jacobian.testJacobian(module, input, minval, maxval, perturbation)
   minval = minval or -2
   maxval = maxval or 2
   local inrange = maxval - minval
   input:copy(torch.rand(input:nElement()):mul(inrange):add(minval))
   local jac_fprop = nn.Jacobian.forward(module, input, input, perturbation)
   local jac_bprop = nn.Jacobian.backward(module, input)
   local error = jac_fprop-jac_bprop
   return error:abs():max()
end

function nn.Jacobian.testJacobianParameters(module, input, param, dparam, minval, maxval, perturbation)
   minval = minval or -2
   maxval = maxval or 2
   local inrange = maxval - minval
   input:copy(torch.rand(input:nElement()):mul(inrange):add(minval))
   param:copy(torch.rand(param:nElement()):mul(inrange):add(minval))
   local jac_bprop = nn.Jacobian.backward(module, input, param, dparam)
   local jac_fprop = nn.Jacobian.forward(module, input, param, perturbation)
   local error = jac_fprop - jac_bprop
   return error:abs():max()
end

function nn.Jacobian.testJacobianUpdateParameters(module, input, param, minval, maxval, perturbation)
   minval = minval or -2
   maxval = maxval or 2
   local inrange = maxval - minval
   input:copy(torch.rand(input:nElement()):mul(inrange):add(minval))
   param:copy(torch.rand(param:nElement()):mul(inrange):add(minval))
   local params_bprop = nn.Jacobian.backwardUpdate(module, input, param)
   local params_fprop = nn.Jacobian.forwardUpdate(module, input, param, perturbation)

   local error = params_fprop - params_bprop
   return error:abs():max()
end

function nn.Jacobian.testDiagHessian(module, input, gradParamName, diagHessianParamName, minval, maxval)
   -- Compute the diagonal Hessian elements for the same function in two different ways,
   -- then compare the results and return the difference.

   minval = minval or -2
   maxval = maxval or 2
   local inrange = maxval - minval
   input:copy(torch.rand(input:nElement()):mul(inrange):add(minval))
   module:initDiagHessianParameters()
   local h_bprop = nn.Jacobian.backwardDiagHessian(module, input, diagHessianParamName)
   local h_linearmodule = nn.Jacobian.linearModuleDiagHessian(module, input, gradParamName)
   local error = h_bprop - h_linearmodule
   return error:abs():max()
end

function nn.Jacobian.testDiagHessianInput(module, input, minval, maxval)
   return nn.Jacobian.testDiagHessian(module, input, 'gradInput', 'diagHessianInput', minval, maxval)
end

function nn.Jacobian.testDiagHessianWeight(module, input, minval, maxval)
   return nn.Jacobian.testDiagHessian(module, input, 'gradWeight', 'diagHessianWeight', minval, maxval)
end

function nn.Jacobian.testDiagHessianBias(module, input, minval, maxval)
   return nn.Jacobian.testDiagHessian(module, input, 'gradBias', 'diagHessianBias', minval, maxval)
end

function nn.Jacobian.testIO(module,input, minval, maxval)
   minval = minval or -2
   maxval = maxval or 2
   local inrange = maxval - minval
   local inputclone = input:clone()

   -- run module
   module:forward(input)
   local go = module.output:clone():copy(torch.rand(module.output:nElement()):mul(inrange):add(minval))
   local goclone = go:clone()
   module:zeroGradParameters()
   module:updateGradInput(input,go)
   module:accGradParameters(input,go)

   local fo = module.output:clone()
   local bo = module.gradInput:clone()

   -- write module
   local filename = os.tmpname()
   local f = torch.DiskFile(filename, 'w'):binary()
   -- call clearState and check that it returns itself
   assert(module == module:clearState(),'clearState did not return self')
   f:writeObject(module)
   f:close()
   -- read module
   local m = torch.DiskFile(filename):binary():readObject()
   m:forward(inputclone)
   m:zeroGradParameters()
   m:updateGradInput(inputclone,goclone)
   m:accGradParameters(inputclone,goclone)
   -- cleanup
   os.remove(filename)

   local fo2 = m.output:clone()
   local bo2 = m.gradInput:clone()

   local errf = fo - fo2
   local errb = bo - bo2
   return errf:abs():max(), errb:numel() == 0 and 0 or errb:abs():max()
end

function nn.Jacobian.testAllUpdate(module, input, weight, gradWeight)
   local gradOutput
   local lr = torch.uniform(0.1, 1)
   local errors = {}

   -- accGradParameters
   local maccgp = module:clone()
   local weightc = maccgp[weight]:clone()
   maccgp:forward(input)
   gradOutput = torch.rand(maccgp.output:size())
   maccgp:zeroGradParameters()
   maccgp:updateGradInput(input, gradOutput)
   maccgp:accGradParameters(input, gradOutput)
   maccgp:updateParameters(lr)
   errors["accGradParameters"] = (weightc-maccgp[gradWeight]*lr-maccgp[weight]):norm()

   -- accUpdateGradParameters
   local maccugp = module:clone()
   maccugp:forward(input)
   maccugp:updateGradInput(input, gradOutput)
   maccugp:accUpdateGradParameters(input, gradOutput, lr)
   errors["accUpdateGradParameters"] = (maccugp[weight]-maccgp[weight]):norm()

   -- shared, accGradParameters
   local macsh1 = module:clone()
   local macsh2 = module:clone()
   macsh2:share(macsh1, weight)
   macsh1:forward(input)
   macsh2:forward(input)
   macsh1:zeroGradParameters()
   macsh2:zeroGradParameters()
   macsh1:updateGradInput(input, gradOutput)
   macsh2:updateGradInput(input, gradOutput)
   macsh1:accGradParameters(input, gradOutput)
   macsh2:accGradParameters(input, gradOutput)
   macsh1:updateParameters(lr)
   macsh2:updateParameters(lr)
   local err = (weightc-maccgp[gradWeight]*(lr*2)-macsh1[weight]):norm()
   err = err + (weightc-maccgp[gradWeight]*(lr*2)-macsh2[weight]):norm()
   errors["accGradParameters [shared]"] = err

   -- shared, accUpdateGradParameters
   local macshu1 = module:clone()
   local macshu2 = module:clone()
   macshu2:share(macshu1, weight)
   macshu1:forward(input)
   macshu2:forward(input)
   macshu1:updateGradInput(input, gradOutput)
   macshu2:updateGradInput(input, gradOutput)
   macshu1:accUpdateGradParameters(input, gradOutput, lr)
   macshu2:accUpdateGradParameters(input, gradOutput, lr)
   err = (weightc-maccgp[gradWeight]*(lr*2)-macshu1[weight]):norm()
   err = err + (weightc-maccgp[gradWeight]*(lr*2)-macshu2[weight]):norm()
   errors["accUpdateGradParameters [shared]"] = err

   return errors
end
