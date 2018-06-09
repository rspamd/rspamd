-- you can easily test specific units like this:
-- th -lnn -e "nn.test{'LookupTable'}"
-- th -lnn -e "nn.test{'LookupTable', 'Add'}"

local mytester = torch.Tester()
local jac
local sjac

local precision = 1e-5
local expprecision = 1.1e-4

local nntest = torch.TestSuite()

local function equal(t1, t2, msg)
   if (torch.type(t1) == "table") then
      for k, v in pairs(t2) do
         equal(t1[k], t2[k], msg)
      end
   else
      mytester:eq(t1, t2, 0.00001, msg)
   end
end


--[[ Generate tests to exercise the tostring component of modules. ]]
local tostringTestModules = {
    nnLinear = nn.Linear(1, 2),
    nnReshape = nn.Reshape(10),
    nnSpatialZeroPadding = nn.SpatialZeroPadding(1, 1, 1, 1)}
for test_name, component in pairs(tostringTestModules) do
  nntest['tostring' .. test_name] =
    function ()
      mytester:assert(tostring(component):find(
                         torch.type(component) .. '(', 1, true) ~= nil,
                      'nn components should have a descriptive tostring' ..
                      ' beginning with the classname')
    end
end

function nntest.Add()
   local inj_vals = {math.random(3,5), 1}  -- Also test the inj = 1 spatial case
   local ini = math.random(3,5)
   local ink = math.random(3,5)

   for ind, inj in pairs(inj_vals) do
      local input = torch.Tensor(ini,inj,ink):zero()
      local module = nn.Add(ini,inj,ink)

      -- 1D
      local err = jac.testJacobian(module,input)
      mytester:assertlt(err,precision, 'error on state ')

      local err = jac.testJacobianParameters(module, input, module.bias, module.gradBias)
      mytester:assertlt(err,precision, 'error on bias ')

      local err = jac.testJacobianUpdateParameters(module, input, module.bias)
      mytester:assertlt(err,precision, 'error on bias [direct update] ')

      for t,err in pairs(jac.testAllUpdate(module, input, 'bias', 'gradBias')) do
         mytester:assertlt(err, precision, string.format('error on bias [%s]', t))
      end

      -- 2D
      local nframe = math.random(50,70)
      local input = torch.Tensor(nframe, ini,inj,ink):zero()

      local err = jac.testJacobian(module,input)
      mytester:assertlt(err,precision, 'error on state ')

      local err = jac.testJacobianParameters(module, input, module.bias, module.gradBias)
      mytester:assertlt(err,precision, 'error on bias ')

      local err = jac.testJacobianUpdateParameters(module, input, module.bias)
      mytester:assertlt(err,precision, 'error on bias [direct update] ')

      for t,err in pairs(jac.testAllUpdate(module, input, 'bias', 'gradBias')) do
         mytester:assertlt(err, precision, string.format('error on bias [%s]', t))
      end

      -- IO
      local ferr,berr = jac.testIO(module,input)
      mytester:eq(ferr, 0, torch.typename(module) .. ' - i/o forward err ', precision)
      mytester:eq(berr, 0, torch.typename(module) .. ' - i/o backward err ', precision)
   end
end

function nntest.Bottle()
   local ini = 2
   local inj = 3
   local ink = 4
   local out = 5
   local input = torch.Tensor(ini,inj,ink):normal()
   local linear = nn.Linear(ink, out)
   local module1 = nn.Bottle(linear)
   local module2 = nn.Sequential()
   module2:add(nn.View(ini*inj, ink))
   module2:add(linear)
   module2:add(nn.View(ini, inj, out))
   local output1 = module1:forward(input)
   local output2 = module2:forward(input)
   mytester:eq(output1, output2, 0.0001, 'Bottle output not the same as Module')

   local shape = {4, 5, 6, 7, 8, 1, 3}
   local input = torch.Tensor(table.unpack(shape)):normal()
   local module = nn.Sequential()
   module:add(nn.Squeeze(2))
   module:add(nn.Linear(3, 3))
   local module1 = nn.Bottle(module, 3, 2)
   local outShape = {4, 5, 6, 7, 8, 3}
   local module2 = nn.Sequential()
   module2:add(nn.View(4*5*6*7*8, 1, 3))
   module2:add(module)
   module2:add(nn.View(table.unpack(outShape)))
   local output1 = module1:forward(input)
   local grad = torch.Tensor(output1:size()):normal()
   local gradOutput1 = module1:backward(input, grad):clone()
   local output2 = module2:forward(input)
   local gradOutput2 = module2:backward(input, grad):clone()
   mytester:eq(output1, output2, 0.0001, 'Bottle output not the same as Module')
   mytester:eq(gradOutput1, gradOutput2, 0.0001, 'Bottle gradOutput not the same as Module')
end

function nntest.WeightNorm()
   local input = torch.rand(10, 5)

   -- temporal convolution
   local model = nn.WeightNorm(nn.TemporalConvolution(5, 20, 2, 1))
   local err = nn.Jacobian.testJacobianParameters(model, input,
                                                model.bias, model.gradBias)
   mytester:assert(err < precision, 'Temporal Convolution bias')
   err = nn.Jacobian.testJacobianParameters(model, input,
                                                model.g, model.gradG)
   mytester:assert(err < precision, 'Temporal Convolution g')
   err = nn.Jacobian.testJacobianParameters(model, input,
                                                model.v, model.gradV)
   mytester:assert(err < precision, 'Temporal Convolution v')

    -- linear
   model = nn.WeightNorm(nn.Linear(5, 20))
   err = nn.Jacobian.testJacobianParameters(model, input,
                                                model.bias, model.gradBias)
   mytester:assert(err < precision, 'Linear bias')
   err = nn.Jacobian.testJacobianParameters(model, input, model.g, model.gradG)
   mytester:assert(err < precision, 'Linear g')
   err = nn.Jacobian.testJacobianParameters(model, input,
                                                model.v, model.gradV)
   mytester:assert(err < precision, 'Linear v')

   -- euclidean with weight but no bias
   input = torch.rand(10, 5)
   model = nn.WeightNorm(nn.Euclidean(5, 20))
   err = nn.Jacobian.testJacobianParameters(model, input, model.g, model.gradG)
   mytester:assert(err < precision, 'Euclidean g')
   err = nn.Jacobian.testJacobianParameters(model, input,
                                                    model.v, model.gradV)
   mytester:assert(err < precision, 'Euclidean v')

   -- spatial convolution with 4D weights
   input = torch.rand(5, 10, 10)
   model = nn.WeightNorm(nn.SpatialConvolution(5, 20, 2, 2, 3, 3, 1, 1), 2)
   err = nn.Jacobian.testJacobianParameters(model, input,
                                                model.bias, model.gradBias)
   mytester:assert(err < precision, 'Spatial Convolution bias')
   err = nn.Jacobian.testJacobianParameters(model, input,
                                                model.g, model.gradG)
   mytester:assert(err < precision, 'Spatial Convolution g')
   err = nn.Jacobian.testJacobianParameters(model, input,
                                                model.v, model.gradV)
   mytester:assert(err < precision, 'Spatial Convolution v')

   -- linear save/load
   model = nn.WeightNorm(nn.Linear(5, 20))
   input = torch.rand(10, 5)
   local out = model:forward(input)
   local modelr = torch.deserialize(torch.serialize(model))
   local outr = modelr:forward(input)
   mytester:assertTensorEq(out, outr)
end

function nntest.LinearWeightNorm()
   local input = torch.rand(10, 5)
   local model = nn.LinearWeightNorm(5, 20)

   -- check gradient
   local err = nn.Jacobian.testJacobianParameters(model, input, model.bias, model.gradBias)
   mytester:assert(err < precision, 'bias')
   err = nn.Jacobian.testJacobianParameters(model, input, model.g, model.gradG)
   mytester:assert(err < precision, 'g')
   err = nn.Jacobian.testJacobianParameters(model, input, model.v, model.gradV)
   mytester:assert(err < precision, 'v')

   -- check conversion functions
   local linear = nn.Linear(5,20)
   local wnFromLin = nn.LinearWeightNorm.fromLinear(linear)
   local linFromWn = wnFromLin:toLinear()

   local linOut = linear:forward(input)
   local wnOut = wnFromLin:forward(input)
   local linFromWnOut = linFromWn:forward(input)

   mytester:assertTensorEq(linOut, wnOut, precision, "outputs are not equivalent")
   mytester:assertTensorEq(wnOut, linFromWnOut, precision, "outputs are not equivalent")

   -- check conversion with nobias
   linear = nn.Linear(5,20,false)
   wnFromLin = nn.LinearWeightNorm.fromLinear(linear)
   linFromWn = wnFromLin:toLinear()

   linOut = linear:forward(input)
   wnOut = wnFromLin:forward(input)
   linFromWnOut = linFromWn:forward(input)

   mytester:assertTensorEq(linear.weight, wnFromLin.weight, precision, "weights are not equivalent")
   mytester:assert(not wnFromLin.bias)
   mytester:assert(not linear.bias)
   mytester:assertTensorEq(linOut, wnOut, precision, "outputs are not equivalent")
   mytester:assertTensorEq(wnOut, linFromWnOut, precision, "outputs are not equivalent")

   -- check gradient with nobias
   model = wnFromLin

   err = nn.Jacobian.testJacobianParameters(model, input, model.g, model.gradG)
   mytester:assert(err < precision, 'g')
   err = nn.Jacobian.testJacobianParameters(model, input, model.v, model.gradV)
   mytester:assert(err < precision, 'v')
end

function nntest.CAdd()
   local function testBackwardPass(module, input, params, dparams)
      local err = jac.testJacobian(module,input)
      mytester:assertlt(err,precision, "error computing gradiens w.r.t. inputs")

      err = jac.testJacobianParameters(module, input, params, dparams)
      mytester:assertlt(err,precision, "error computing gradients w.r.t params")

      err = jac.testJacobianUpdateParameters(module, input, module.bias)
      mytester:assertlt(err,precision, "error in update using gradients w.r.t parameters")

      --Test all of the various update methods
      for test, err in pairs(jac.testAllUpdate(module, input, "bias", "gradBias")) do
         mytester:assertlt(err, precision, string.format("error on bias [%s]", test))
      end
   end

   local function testModuleIO(module, input)
      local fwdErr,bkwdErr = jac.testIO(module,input)
      mytester:asserteq(fwdErr, 0, torch.typename(module) .. " - i/o forward err ")
      mytester:asserteq(bkwdErr, 0, torch.typename(module) .. " - i/o backward err ")
   end

   local function testCAddWithNonBatchedInput()
      local channels = math.random(3,5)
      local width = math.random(3,5)
      local height = math.random(3,5)

      local input = torch.Tensor(channels, height, width):zero()

      --Per channel bias
      local module = nn.CAdd(channels, 1, 1)
      local params, gradParams = module:getParameters()

      testBackwardPass(module, input, params, gradParams)

      input:zero()
      local output = module:forward(input)
      mytester:assert(output:isSameSizeAs(input))

      for i = 1, module.bias:view(-1):size(1) do
         local bias = module.bias:view(-1)[i]
         local result = output[i]:view(-1)
         local expectedResult = torch.Tensor({bias}):expandAs(result)
         mytester:assertTensorEq(result, expectedResult, precision)
      end

      --Per row bias
      module = nn.CAdd(1, height, 1)
      params, gradParams = module:getParameters()

      testBackwardPass(module, input, params, gradParams)

      input:zero()
      output = module:forward(input)
      mytester:assert(output:isSameSizeAs(input))

      for i = 1, module.bias:view(-1):size(1) do
         local bias = module.bias:view(-1)[i]
         local result = output[{{}, {i}, {}}]:contiguous():view(-1)
         local expectedResult = torch.Tensor({bias}):expandAs(result)
         mytester:assertTensorEq(result, expectedResult, precision)
      end

      --Per column bias
      module = nn.CAdd(1, 1, width)
      params, gradParams = module:getParameters()

      testBackwardPass(module, input, params, gradParams)

      input:zero()
      output = module:forward(input)
      mytester:assert(output:isSameSizeAs(input))

      for i = 1, module.bias:view(-1):size(1) do
         local bias = module.bias:view(-1)[i]
         local result = output[{{}, {}, {i}}]:contiguous():view(-1)
         local expectedResult = torch.Tensor({bias}):expandAs(result)
         mytester:assertTensorEq(result, expectedResult, precision)
      end

      --Per input component bias
      module = nn.CAdd(channels, height, width)
      params, gradParams = module:getParameters()

      testBackwardPass(module, input, params, gradParams)

      input:zero()
      output = module:forward(input)

      mytester:assert(output:isSameSizeAs(input))
      mytester:assert(module.bias:isSameSizeAs(input))
      mytester:assertTensorEq(module.bias, output, precision)

      testModuleIO(module, input)
   end

   local function testCAddWithBatchedInput()
      local batchSize = math.random(3,5)
      local channels = math.random(3,5)
      local width = math.random(3,5)
      local height = math.random(3,5)

      local input = torch.Tensor(batchSize, channels, height, width):zero()
      local module = nn.CAdd(batchSize, channels, height, width)

      --Per batch bias
      local module = nn.CAdd(batchSize, 1, 1, 1)
      local params, gradParams = module:getParameters()

      testBackwardPass(module, input, params, gradParams)

      input:zero()
      local output = module:forward(input)
      mytester:assert(output:isSameSizeAs(input))

      for i = 1, module.bias:view(-1):size(1) do
         local bias = module.bias:view(-1)[i]
         local result = output[i]:view(-1)
         local expectedResult = torch.Tensor({bias}):expandAs(result)
         mytester:assertTensorEq(result, expectedResult, precision)
      end

      --Per channel bias
      module = nn.CAdd(1, channels, 1, 1)
      params, gradParams = module:getParameters()

      testBackwardPass(module, input, params, gradParams)

      input:zero()
      output = module:forward(input)
      mytester:assert(output:isSameSizeAs(input))

      for i = 1, module.bias:view(-1):size(1) do
         local bias = module.bias:view(-1)[i]
         local result = output[{{}, {i}, {}, {}}]:contiguous():view(-1)
         local expectedResult = torch.Tensor({bias}):expandAs(result)
         mytester:assertTensorEq(result, expectedResult, precision)
      end

      --Per row bias
      module = nn.CAdd(1, 1, height, 1)
      params, gradParams = module:getParameters()

       testBackwardPass(module, input, params, gradParams)

      input:zero()
      output = module:forward(input)
      mytester:assert(output:isSameSizeAs(input))

      for i = 1, module.bias:view(-1):size(1) do
         local bias = module.bias:view(-1)[i]
         local result = output[{{}, {}, {i}, {}}]:contiguous():view(-1)
         local expectedResult = torch.Tensor({bias}):expandAs(result)
         mytester:assertTensorEq(result, expectedResult, precision)
      end

      --Per column bias
      module = nn.CAdd(1, 1, 1, width)
      params, gradParams = module:getParameters()

      testBackwardPass(module, input, params, gradParams)

      input:zero()
      output = module:forward(input)
      mytester:assert(output:isSameSizeAs(input))

      for i = 1, module.bias:view(-1):size(1) do
         local bias = module.bias:view(-1)[i]
         local result = output[{{}, {}, {}, {i}}]:contiguous():view(-1)
         local expectedResult = torch.Tensor({bias}):expandAs(result)
         mytester:assertTensorEq(result, expectedResult, precision)
      end

      --Per input component bias
      module = nn.CAdd(batchSize, channels, height, width)
      params, gradParams = module:getParameters()

      testBackwardPass(module, input, params, gradParams)

      input:zero()
      output = module:forward(input)

      mytester:assert(output:isSameSizeAs(input))
      mytester:assert(module.bias:isSameSizeAs(input))
      mytester:assertTensorEq(module.bias, output, precision)

      testModuleIO(module, input)
   end


   local function testCAddWithLessDimsThanInput()
      local input = torch.rand(4,5)
      local module = nn.CAdd(5)
      local params, gradParams = module:getParameters()
      testBackwardPass(module, input, params, gradParams)

      input:zero()
      local output = module:forward(input)
      local expandedBias = module.bias:view(1,5):expand(4,5):clone()
      mytester:assert(output:isSameSizeAs(input))
      mytester:assertTensorEq(expandedBias, output, precision)

      testModuleIO(module, input)

      input = torch.rand(4,5,6)
      module = nn.CAdd(5,6)
      params, gradParams = module:getParameters()
      testBackwardPass(module, input, params, gradParams)

      input:zero()
      local output = module:forward(input)
      expandedBias = module.bias:view(1,5,6):expand(4,5,6):clone()
      mytester:assert(output:isSameSizeAs(input))
      mytester:assertTensorEq(expandedBias, output, precision)

      testModuleIO(module, input)
   end


   testCAddWithNonBatchedInput()
   testCAddWithBatchedInput()
   testCAddWithLessDimsThanInput()
end

function nntest.CMul()
   local ini = math.random(3,5)
   local inj = math.random(3,5)
   local ink = math.random(3,5)
   local inl = math.random(3,5)
   local input = torch.Tensor(ini,inj,ink):zero()
   local module = nn.CMul(1, ini, inj, ink, 1)

   -- 1D
   local err = jac.testJacobian(module,input)
   mytester:assertlt(err,precision, 'error on state ')

   local err = jac.testJacobianParameters(module, input, module.weight, module.gradWeight)
   mytester:assertlt(err,precision, 'error on weight ')

   local err = jac.testJacobianUpdateParameters(module, input, module.weight)
   mytester:assertlt(err,precision, 'error on weight [direct update] ')

   for t,err in pairs(jac.testAllUpdate(module, input, 'weight', 'gradWeight')) do
      mytester:assertlt(err, precision, string.format(
                         'error on weight [%s]', t))
   end

   -- 2D
   local nframe = math.random(3,14)
   local input = torch.randn(nframe, ini,inj,ink)
   local output = module:forward(input)
   local output2 = torch.cmul(input, module.weight:view(1,ini,inj,ink):expandAs(input))
   mytester:assertTensorEq(output2, output, 0.000001, 'CMul forward 2D err')

   module:zeroGradParameters()
   local gradWeight = module.gradWeight:clone()
   local gradInput = module:backward(input, output)
   local gradInput2 = gradInput:clone():zero()
   local outputView = output:view(input:size(1), -1)
   gradInput2:view(input:size(1), -1):addcmul(1, module.weight:view(1,-1):expandAs(outputView), outputView)
   mytester:assertTensorEq(gradInput2, gradInput, 0.000001, 'CMul updateGradInput 2D err')
   mytester:assert(gradInput:isSameSizeAs(input), 'CMul gradInput 2D size err')

   local inputView = input:view(nframe, -1)
   local gradWeightView = gradWeight:view(1, -1)
   for i=1,nframe do
      gradWeightView:addcmul(1, inputView[i], outputView[i])
   end
   mytester:assertTensorEq(gradWeight, module.gradWeight, 0.000001, 'CMul accGradParameters 2D err')
   mytester:assert(module.weight:isSameSizeAs(module.gradWeight), 'CMul gradWeight size err')

   -- Expansion
   input = torch.randn(nframe, ini,inj,ink,inl)
   output = module:forward(input)
   output2 = torch.cmul(input, module.weight:expandAs(input))
   mytester:assertTensorEq(output2, output, 0.000001, 'CMul forward expand err')

   module:zeroGradParameters()
   gradWeight:zero()
   gradInput = module:backward(input, output)
   gradInput2 = gradInput:clone():zero()
   gradInput2:addcmul(1, module.weight:expandAs(output), output)
   mytester:assertTensorEq(gradInput2, gradInput, 0.000001, 'CMul updateGradInput expansion err')
   mytester:assert(gradInput:isSameSizeAs(input), 'CMul gradInput expand size err')

   for i=1,nframe do
      -- 4 is the [non-batch] singleton dim
      gradWeight:add(torch.cmul(input[i], output[i]):sum(4))
   end
   mytester:assertTensorEq(gradWeight:sum(5), module.gradWeight, 0.000001, 'CMul accGradParameters expand err')
   mytester:assert(module.weight:isSameSizeAs(module.gradWeight), 'CMul accGradParameters expand size err')

   input:zero()

   local err = jac.testJacobian(module,input)
   mytester:assertlt(err,precision, 'error on state ')

   local err = jac.testJacobianParameters(module, input, module.weight, module.gradWeight)
   mytester:assertlt(err,precision, 'error on weight ')

   local err = jac.testJacobianUpdateParameters(module, input, module.weight)
   mytester:assertlt(err,precision, 'error on weight [direct update] ')

   for t,err in pairs(jac.testAllUpdate(module, input, 'weight', 'gradWeight')) do
      mytester:assertlt(err, precision, string.format('error on weight [%s]', t))
   end

   -- Non-contiguous input or gradOutput
   local testModule = nn.CMul(4, 3, 5)
   local testInput = torch.rand(10, 3, 5):resize(10, 1, 3, 5):expand(10, 4, 3, 5)
   local testOutput = testModule:forward(testInput)

   mytester:assert(testOutput:isSameSizeAs(testInput), 'CMul non-contiguous forward err')

   local testGradOutput = torch.rand(10, 3, 5):resize(10, 1, 3, 5):expand(10, 4, 3, 5)
   testOutput = testModule:forward(testInput)
   local testGradInput = testModule:backward(testOutput, testGradOutput)

   mytester:assert(testGradInput:isSameSizeAs(testGradOutput), 'CMul non-contiguous backward err')

   -- IO
   local ferr,berr = jac.testIO(module,input)
   mytester:eq(ferr, 0, torch.typename(module) .. ' - i/o forward err ', precision)
   mytester:eq(berr, 0, torch.typename(module) .. ' - i/o backward err ', precision)
end

function nntest.Contiguous()
   local module = nn.Contiguous()

   -- Contiguous input
   local input = torch.rand(30,20,10)
   local output = module:forward(input)

   mytester:assert(output:ne(input):sum() == 0, 'output not equal to input')

   -- Make input non-contiguous
   local input2 = output:transpose(1,2)
   local output2 = module:forward(input2)

   mytester:assert(output2:ne(output:contiguous()):sum() == 0, 'output not equal to input')
end

function nntest.Dropout()
   local p = 0.2 --prob of droping out a neuron
   local input = torch.Tensor(1000):fill((1-p))
   local module = nn.Dropout(p)
   -- version 2
   local output = module:forward(input)
   mytester:assert(math.abs(output:mean() - (1-p)) < 0.05, 'dropout output')
   local gradInput = module:backward(input, input)
   mytester:assert(math.abs(gradInput:mean() - (1-p)) < 0.05, 'dropout gradInput')
   -- test inplace version
   local module = nn.Dropout(p,nil,true)
   local output = module:forward(input:clone())
   mytester:assert(math.abs(output:mean() - (1-p)) < 0.05, 'dropout output')
   local gradInput = module:backward(input:clone(), input:clone())
   mytester:assert(math.abs(gradInput:mean() - (1-p)) < 0.05, 'dropout gradInput')

   -- version 1 (old nnx version)
   local input = input:fill(1)
   local module = nn.Dropout(p,true)
   local output = module:forward(input)
   mytester:assert(math.abs(output:mean() - (1-p)) < 0.05, 'dropout output')
   local gradInput = module:backward(input, input)
   mytester:assert(math.abs(gradInput:mean() - (1-p)) < 0.05, 'dropout gradInput')
end

function nntest.SpatialDropout()
   local p = 0.2 --prob of dropiing out a neuron
   local w = math.random(1,5)
   local h = math.random(1,5)
   local nfeats = 1000
   local input = torch.Tensor(nfeats, w, h):fill(1)
   local module = nn.SpatialDropout(p)
   module.train = true
   local output = module:forward(input)
   mytester:assert(math.abs(output:mean() - (1-p)) < 0.05, 'dropout output')
   local gradInput = module:backward(input, input)
   mytester:assert(math.abs(gradInput:mean() - (1-p)) < 0.05, 'dropout gradInput')
end

function nntest.SpatialDropoutBatch()
   local p = 0.2 --prob of dropiing out a neuron
   local bsz = math.random(1,5)
   local w = math.random(1,5)
   local h = math.random(1,5)
   local nfeats = 1000
   local input = torch.Tensor(bsz, nfeats, w, h):fill(1)
   local module = nn.SpatialDropout(p)
   module.train = true
   local output = module:forward(input)
   mytester:assert(math.abs(output:mean() - (1-p)) < 0.05, 'dropout output')
   local gradInput = module:backward(input, input)
   mytester:assert(math.abs(gradInput:mean() - (1-p)) < 0.05, 'dropout gradInput')
end

function nntest.VolumetricDropout()
   local p = 0.2 --prob of dropiing out a neuron
   local t = math.random(1,5)
   local w = math.random(1,5)
   local h = math.random(1,5)
   local nfeats = 1000
   local input = torch.Tensor(nfeats, t, w, h):fill(1)
   local module = nn.VolumetricDropout(p)
   module.train = true
   local output = module:forward(input)
   mytester:assert(math.abs(output:mean() - (1-p)) < 0.05, 'dropout output')
   local gradInput = module:backward(input, input)
   mytester:assert(math.abs(gradInput:mean() - (1-p)) < 0.05, 'dropout gradInput')
end

function nntest.VolumetricDropoutBatch()
   local p = 0.2 --prob of dropiing out a neuron
   local bsz = math.random(1,5)
   local t = math.random(1,5)
   local w = math.random(1,5)
   local h = math.random(1,5)
   local nfeats = 1000
   local input = torch.Tensor(bsz, nfeats, t, w, h):fill(1)
   local module = nn.VolumetricDropout(p)
   module.train = true
   local output = module:forward(input)
   mytester:assert(math.abs(output:mean() - (1-p)) < 0.05, 'dropout output')
   local gradInput = module:backward(input, input)
   mytester:assert(math.abs(gradInput:mean() - (1-p)) < 0.05, 'dropout gradInput')
end

function nntest.ReLU()
   local input = torch.randn(3,4)
   local gradOutput = torch.randn(3,4)
   local module = nn.ReLU()
   local output = module:forward(input)
   local output2 = input:clone():gt(input, 0):cmul(input)
   mytester:assertTensorEq(output, output2, 0.000001, 'ReLU output')
   local gradInput = module:backward(input, gradOutput)
   local gradInput2 = input:clone():gt(input, 0):cmul(gradOutput)
   mytester:assertTensorEq(gradInput, gradInput2, 0.000001, 'ReLU gradInput')
end

function nntest.ReLU6()
   for inplace = 0, 1 do
      local input = torch.randn(3, 4):mul(6)
      local gradOutput = torch.randn(3,4)
      local module = nn.ReLU6(inplace == 1)
      local output = module:forward(input:clone())
      local gt = input:clone():gt(input, 0)
      local lt = input:clone():lt(input, 6)
      local output2 = gt:clone():cmul(lt):cmul(input)
      output2:add(6, input:clone():gt(input, 6))
      mytester:assertTensorEq(output, output2, 0.000001, 'ReLU6 output '..(inplace and '(inplace)' or '') )
      local gradInput = module:backward(input, gradOutput:clone())
      local gradInput2 = gt:clone():cmul(lt):cmul(gradOutput)
      mytester:assertTensorEq(gradInput, gradInput2, 0.000001, 'ReLU gradInput '..(inplace and '(inplace)' or '') )
   end
end

function nntest.GatedLinearUnit()
   local model = nn.GatedLinearUnit()
   local t = torch.Tensor({{1, 1}, {2, 2}, {3, 3}})
   local thalf = torch.Tensor():resizeAs(t):copy(t):narrow(2, 1, 1)
   mytester:assertTensorEq(
      thalf:cmul(torch.sigmoid(thalf)),
      model:forward(t):resizeAs(thalf),
      0.000001,
      'Gated Linear output'
   )
   t = torch.Tensor({{1, 1, 1, 1}, {2, 2, 2, 2}, {3, 3, 3, 3}})
   thalf = torch.Tensor():resizeAs(t):copy(t):narrow(2, 1, 2)
   mytester:assertTensorEq(
      thalf:cmul(torch.sigmoid(thalf)),
      model:forward(t),
      0.000001,
      'Gated Linear Unit output'
   )

   local input = torch.rand(1, 10)
   local err = jac.testJacobian(model, input)
   mytester:assert(err < precision, 'Gated Linear gradient')

   input = torch.rand(5, 10, 6)
   model = nn.GatedLinearUnit(2)
   err = jac.testJacobian(model, input)
   mytester:assert(err < precision, 'Gated Linear gradient, non-default dim')

   input = torch.rand(5, 10, 6)
   model = nn.GatedLinearUnit(3)
   err = jac.testJacobian(model, input)
   mytester:assert(err < precision, 'Gated Linear gradient, non-default dim')

   input = torch.rand(5, 10)
   model = nn.Sequential()
   model:add(nn.Linear(10, 10))
   model:add(nn.GatedLinearUnit())
   model:add(nn.ReLU())
   model:add(nn.LogSoftMax())
   err = jac.testJacobian(model, input)
   mytester:assert(err < precision, 'Gated Linear gradient with other layers')
end

function nntest.CReLU()
   local function _verifyCReLU(featureMaps, concatenatedFeatureMaps)
      local rectifiedFeatureMaps = nn.ReLU():forward(featureMaps)
      local rectifiedNegFeatureMaps = nn.ReLU():forward(-featureMaps)

      mytester:asserteq(concatenatedFeatureMaps:size(1), featureMaps:size(1) * 2,
                      "CReLU should double the number of feature maps")

      for i =  1, rectifiedFeatureMaps:size(1) do
         local found = false
         for j = 1, concatenatedFeatureMaps:size(1) do
            found =  found or rectifiedFeatureMaps[i]:equal(concatenatedFeatureMaps[j])
         end
         mytester:assert(found, "Original (rectified) feature maps should be in the output of CReLU")
      end

      for i = 1, rectifiedNegFeatureMaps:size(1) do
         local found = false
         for j = 1, concatenatedFeatureMaps:size(1) do
            found =  found or rectifiedFeatureMaps[i]:equal(concatenatedFeatureMaps[j])
         end
         mytester:assert(found, "The negative of the original (rectified) feature maps should be in the output of CReLU")
      end
   end

   local model = nn.Sequential()
   model:add(nn.SpatialConvolution(1, 3, 3, 3, 1, 1, 1, 1))

   for _, inplace in pairs({true, false}) do
      --batched
      local crelu = nn.CReLU(3, inplace)
      local input = torch.Tensor(2, 1, 20, 20):uniform()
      local featureMaps = model:forward(input)
      local concatenatedFeatureMaps = crelu:forward(featureMaps)
      for i = 1, input:size(1) do
         _verifyCReLU(featureMaps[i], concatenatedFeatureMaps[i])
      end

      --non-batched
      local input = torch.Tensor(1, 20, 20):uniform()
      local featureMaps = model:forward(input)
      local concatenatedFeatureMaps = crelu:forward(featureMaps)
      _verifyCReLU(featureMaps, concatenatedFeatureMaps)
   end

   --test gradients w.r.t input
   local jac = nn.Jacobian

   for _, inplace in pairs({true, false}) do
      local crelu = nn.CReLU(3, inplace)
      --batched
      local input = torch.Tensor(2, 3, 20, 20):uniform()
      local err = jac.testJacobian(crelu, input)
      mytester:assertlt(err, precision, "error computing gradients w.r.t. inputs")

      --I/O
      local fwdErr,bkwdErr = jac.testIO(crelu,input)
      mytester:asserteq(fwdErr, 0, torch.typename(crelu) .. " - i/o forward err ")
      mytester:asserteq(bkwdErr, 0, torch.typename(crelu) .. " - i/o backward err ")

      --non-batched
      input = torch.Tensor(3, 20, 20):uniform()
      err = jac.testJacobian(crelu,input)
      mytester:assertlt(err, precision, "error computing gradients w.r.t. inputs")

      --I/O
      local fwdErr,bkwdErr = jac.testIO(crelu,input)
      mytester:asserteq(fwdErr, 0, torch.typename(crelu) .. " - i/o forward err ")
      mytester:asserteq(bkwdErr, 0, torch.typename(crelu) .. " - i/o backward err ")
   end

end

function nntest.Exp()
   local ini = math.random(3,5)
   local inj = math.random(3,5)
   local ink = math.random(3,5)
   local input = torch.Tensor(ini,inj,ink):zero()
   local module = nn.Exp()

   local err = jac.testJacobian(module,input)
   mytester:assertlt(err,precision, 'error on state ')

   local ferr,berr = jac.testIO(module,input)
   mytester:eq(ferr, 0, torch.typename(module) .. ' - i/o forward err ', precision)
   mytester:eq(berr, 0, torch.typename(module) .. ' - i/o backward err ', precision)
end

function nntest.Log()
   local ini = math.random(3,5)
   local inj = math.random(3,5)
   local ink = math.random(3,5)
   local input = torch.Tensor(ini,inj,ink):zero()
   local module = nn.Log()

   local err = jac.testJacobian(module,input, 0.1, 10)
   mytester:assertlt(err,precision, 'error on state ')

   local ferr,berr = jac.testIO(module,input, 0.1, 10)
   mytester:eq(ferr, 0, torch.typename(module) .. ' - i/o forward err ', precision)
   mytester:eq(berr, 0, torch.typename(module) .. ' - i/o backward err ', precision)
end

function nntest.HardTanh()
   local ini = math.random(3,5)
   local inj = math.random(3,5)
   local ink = math.random(3,5)
   local input = torch.Tensor(ink, inj, ini):zero()

   local module = nn.HardTanh()

   local err = jac.testJacobian(module, input)
   mytester:assertlt(err, precision ,  'error on state ')

   local ferr, berr = jac.testIO(module, input)
   mytester:eq(ferr, 0, torch.typename(module) .. ' - i/o forward err ', precision)
   mytester:eq(berr, 0, torch.typename(module) .. ' - i/o backward err ', precision)

   -- test inclusive bounds -- HardTahn(1,inf) should behave like Threshold(1)
   local input = torch.Tensor({1})
   local gradOutput = torch.Tensor({1})
   local gradOutputClone = gradOutput:clone()
   local module = nn.HardTanh(1, math.huge, true)
   local tanhGradInput = module:backward(input, gradOutput)

   local input = input:clone()
   local gradOutput = gradOutputClone
   local module  = nn.Threshold(1, 0, true)
   local threshGradInput = module:backward(input, gradOutput)
   mytester:assertTensorEq(tanhGradInput, threshGradInput, 0.000001, 'HardTanh gradInput')
end

function nntest.Clamp()
   local ini = math.random(3,5)
   local inj = math.random(3,5)
   local ink = math.random(3,5)
   local max_value =  math.abs(math.random())
   local min_value = -math.abs(math.random())
   local input = torch.Tensor(ink, inj, ini):zero()

   local module = nn.Clamp(min_value, max_value)

   local err = jac.testJacobian(module, input)
   mytester:assertlt(err, precision ,  'error on state ')

   local ferr, berr = jac.testIO(module, input)
   mytester:eq(ferr, 0, torch.typename(module) .. ' - i/o forward err ', precision)
   mytester:eq(berr, 0, torch.typename(module) .. ' - i/o backward err ', precision)
end

function nntest.Abs()
   local ini = math.random(3,5)
   local inj = math.random(3,5)
   local ink = math.random(3,5)
   local input = torch.Tensor(ink, inj, ini):zero()

   local module = nn.Abs()

   local err = jac.testJacobian(module, input)
   mytester:assertlt(err, precision ,  'error on state ')

   local ferr, berr = jac.testIO(module, input)
   mytester:eq(ferr, 0, torch.typename(module) .. ' - i/o forward err ', precision)
   mytester:eq(berr, 0, torch.typename(module) .. ' - i/o backward err ', precision)
end

function nntest.Threshold()
   local ini = math.random(3,5)
   local inj = math.random(3,5)
   local ink = math.random(3,5)
   local input = torch.Tensor(ink, inj, ini):zero()

   local module = nn.Threshold(torch.uniform(-2,2),torch.uniform(-2,2))

   local err = nn.Jacobian.testJacobian(module, input)
   mytester:assertlt(err, precision, 'error on state ')

   local ferr, berr = nn.Jacobian.testIO(module, input)
   mytester:eq(ferr, 0, torch.typename(module) .. ' - i/o forward err ', precision)
   mytester:eq(berr, 0, torch.typename(module) .. ' - i/o backward err ', precision)
end

function nntest.ELU()
   local ini = math.random(3,5)
   local inj = math.random(3,5)
   local ink = math.random(3,5)
   local input = torch.Tensor(ink, inj, ini):zero()

   local module = nn.ELU(0.3)

   local err = jac.testJacobian(module, input)
   mytester:assertlt(err, precision ,  'error on state ')

   local ferr, berr = jac.testIO(module, input)
   mytester:eq(ferr, 0, torch.typename(module) .. ' - i/o forward err ', precision)
   mytester:eq(berr, 0, torch.typename(module) .. ' - i/o backward err ', precision)
end

function nntest.ELUIP()
   local input = torch.randn(3,4)
   local input2 = input:clone()
   local gradOutput = torch.randn(3,4)
   local gradOutput2 = gradOutput:clone()

   -- Compare in-place to not in-place
   local module = nn.ELU(0.3, true)
   local module2 = nn.ELU(0.3, false)

   local output = module:forward(input)
   local output2 = module2:forward(input2)
   mytester:assertTensorEq(output, output2, 0.000001, 'ELU output')
   local gradInput = module:backward(input, gradOutput)
   local gradInput2 = module2:backward(input2, gradOutput2)
   mytester:assertTensorEq(gradInput, gradInput2, 0.000001, 'ELU gradInput')
end

function nntest.PReLU()
   local ini = math.random(3,5)
   local input = torch.Tensor(ini):zero()

   local module = nn.PReLU(ini)

   -- 1D
   local err = jac.testJacobian(module,input)
   mytester:assertlt(err,precision, 'error on state ')

   local err = jac.testJacobianParameters(module, input, module.weight, module.gradWeight)
   mytester:assertlt(err,precision, 'error on weight ')

   local err = jac.testJacobianUpdateParameters(module, input, module.weight)
   mytester:assertlt(err,precision, 'error on weight [direct update] ')

   for t,err in pairs(jac.testAllUpdate(module, input, 'weight', 'gradWeight')) do
      mytester:assertlt(err, precision, string.format(
                        'error on weight [%s]', t))
   end

   -- 2D
   local nframe = math.random(1,7)
   local input = torch.Tensor(nframe, ini):zero()

   local err = jac.testJacobian(module,input)
   mytester:assertlt(err,precision, 'error on state ')

   local err = jac.testJacobianParameters(module, input, module.weight, module.gradWeight)
   mytester:assertlt(err,precision, 'error on weight ')

   local err = jac.testJacobianUpdateParameters(module, input, module.weight)
   mytester:assertlt(err,precision, 'error on weight [direct update] ')

   for t,err in pairs(jac.testAllUpdate(module, input, 'weight', 'gradWeight')) do
      mytester:assertlt(err, precision, string.format(
                        'error on weight [%s]', t))
   end

   -- 4D
   local nframe = math.random(1,7)
   local kW, kH = math.random(1,8), math.random(1,8)
   local input = torch.Tensor(nframe, ini, kW, kH):zero()

   local err = jac.testJacobian(module,input)
   mytester:assertlt(err,precision, 'error on state ')

   local err = jac.testJacobianParameters(module, input, module.weight, module.gradWeight)
   mytester:assertlt(err,precision, 'error on weight ')

   local err = jac.testJacobianUpdateParameters(module, input, module.weight)
   mytester:assertlt(err,precision, 'error on weight [direct update] ')

   for t,err in pairs(jac.testAllUpdate(module, input, 'weight', 'gradWeight')) do
      mytester:assertlt(err, precision, string.format(
                        'error on weight [%s]', t))
   end

   -- IO
   local ferr,berr = jac.testIO(module,input)
   mytester:eq(ferr, 0, torch.typename(module) .. ' - i/o forward err ', precision)
   mytester:eq(berr, 0, torch.typename(module) .. ' - i/o backward err ', precision)
end

function nntest.RReLU()
   local nframe = math.random(1,7)
   local size = math.random(1,7)
   local kW, kH = math.random(1,8), math.random(1,8)
   local input = torch.Tensor(nframe, size, kW, kH):zero()

   local l = 1/math.random(5,8)
   local u = 1/math.random(3,5)

   -- test in evaluation mode (not inplace), RReLU behaves like LeakyReLU
   local module = nn.RReLU(l, u, false)
   mytester:assert(module.train, 'default mode ')
   module:evaluate()

   -- gradient check
   local err = jac.testJacobian(module, input)
   mytester:assertlt(err, precision, 'error on state ')

   -- IO
   local ferr,berr = jac.testIO(module, input)
   mytester:eq(ferr, 0, torch.typename(module) .. ' - i/o forward err ', precision)
   mytester:eq(berr, 0, torch.typename(module) .. ' - i/o backward err ', precision)

   -- test training and evalation mode
   for _,train in ipairs({true,false}) do
      -- test with separate output buffer and inplace
      for _,inplace in ipairs({false,true}) do
         module = nn.RReLU(l, u, inplace)
         if train then
            module:training()
         else
            module:evaluate()
         end
         input = torch.rand(nframe, size, kW, kH) - 0.5
         input:storage()[1] = -1
         local original_input = input:clone()
         local output = module:forward(input)
         mytester:assert(output:sign():eq(original_input:sign()):all(), 'sign flipped forward ')
         local gradOutput = torch.ones(output:size())
         local gradInput = module:backward(input, gradOutput)
         mytester:assert(gradInput:gt(0):eq(input:ne(0)):all(), 'gradient ')
         mytester:assert(gradInput:lt(1):eq(input:le(0)):all(), 'backward negative inputs ')
         mytester:assert(gradInput:eq(1):eq(input:gt(0)):all(), 'backward positive inputs ')
         if not train then
            local err = gradInput[input:le(0)]:mean()-(module.lower+module.upper)/2
            mytester:assertlt(err, precision, 'error on gradient ')
         end

         input = -torch.rand(1000)
         module:forward(input) -- fill internal noise tensor
         local g = module:backward(input, torch.ones(1000))
         local err = math.abs(g[input:le(0)]:mean()-(module.lower+module.upper)/2)
         mytester:assertlt(err, 0.05, 'mean deviation of gradient for negative inputs ')
      end
   end
end

function nntest.LeakyReLU()
   local input = torch.randn(3,4)
   local gradOutput = torch.randn(3,4)
   local negval = math.random()
   local module = nn.LeakyReLU(negval)
   local output = module:forward(input)
   local output2 = input:clone():gt(input, 0):cmul(input) + input:clone():le(input,0):cmul(input) * module.negval
   mytester:assertTensorEq(output, output2, 0.000001, 'LeakyReLU output')
   local gradInput = module:backward(input, gradOutput)
   local gradInput2 = input:clone():gt(input, 0):cmul(gradOutput) + input:clone():le(input,0):cmul(gradOutput) * module.negval
   mytester:assertTensorEq(gradInput, gradInput2, 0.000001, 'LeakyReLU gradInput')
end

function nntest.LeakyReLUIP()
   local input = torch.randn(3,4)
   local gradOutput = torch.randn(3,4)
   local negval = math.random()
   local module = nn.LeakyReLU(negval,true)
   local output = input:clone():gt(input, 0):cmul(input) + input:clone():le(input,0):cmul(input) * module.negval
   local output2 = module:forward(input)
   mytester:assertTensorEq(output2, output, 0.000001, 'LeakyReLU output')
   local gradInput = input:clone():gt(input, 0):cmul(gradOutput) + input:clone():le(input,0):cmul(gradOutput) * module.negval
   local gradInput2 = module:backward(input, gradOutput)
   mytester:assertTensorEq(gradInput2, gradInput, 0.000001, 'LeakyReLU gradInput')
end

function nntest.HardShrink()
   local ini = math.random(3,5)
   local inj = math.random(3,5)
   local ink = math.random(3,5)
   local input = torch.Tensor(ink, inj, ini):zero()

   local module = nn.HardShrink(math.random()/2)

   local err = nn.Jacobian.testJacobian(module, input)
   mytester:assertlt(err, precision, 'error on state ')

   local ferr, berr = nn.Jacobian.testIO(module, input)
   mytester:eq(ferr, 0, torch.typename(module) .. ' - i/o forward err ', precision)
   mytester:eq(berr, 0, torch.typename(module) .. ' - i/o backward err ', precision)
end

function nntest.SoftShrink()
   local ini = math.random(3,5)
   local inj = math.random(3,5)
   local ink = math.random(3,5)
   local input = torch.Tensor(ink, inj, ini):zero()

   local module = nn.SoftShrink(math.random()/2)

   local err = nn.Jacobian.testJacobian(module, input)
   mytester:assertlt(err, precision, 'error on state ')

   local ferr, berr = nn.Jacobian.testIO(module, input)
   mytester:eq(ferr, 0, torch.typename(module) .. ' - i/o forward err ', precision)
   mytester:eq(berr, 0, torch.typename(module) .. ' - i/o backward err ', precision)
end

function nntest.Power()
   local in1 = torch.rand(5,7)
   local module = nn.Power(2)
   local out = module:forward(in1)
   local err = out:dist(in1:cmul(in1))
   mytester:assertlt(err, 1e-15, torch.typename(module) .. ' - forward err ')

   local ini = math.random(3,5)
   local inj = math.random(3,5)
   local ink = math.random(3,5)
   local pw = torch.uniform()*math.random(1,10)
   local input = torch.Tensor(ink, inj, ini):zero()

   local module = nn.Power(pw)

   local err = nn.Jacobian.testJacobian(module, input, 0.1, 2)
   mytester:assertlt(err, precision, 'error on state ')

   local ferr, berr = nn.Jacobian.testIO(module,input, 0.1, 2)
   mytester:eq(ferr, 0, torch.typename(module) .. ' - i/o forward err ', precision)
   mytester:eq(berr, 0, torch.typename(module) .. ' - i/o backward err ', precision)
end

function nntest.Normalize()
   -- compare forward against torch implementation
   -- and check gradient
   for _,p in pairs({1,2,3,4,1.5}) do
      local ini = math.random(3,10)
      local input = torch.randn(ini)
      local module = nn.Normalize(p)
      local out = module:forward(input)
      local expected = torch.div(input,input:norm(p))
      mytester:assertTensorEq(out, expected, 1e-7,
                              torch.typename(module) ..' (' .. p ..') - forward err ')

      local err = jac.testJacobian(module, input, -2, 2)
      mytester:assertlt(err, precision, 'error norm '..p..' on state ')
   end

   -- batch mode
   for _,p in pairs({1,2,3,4,torch.uniform()*math.random(1,10),math.huge}) do
      local ini = math.random(3,5)
      local inj = math.random(3,5)
      local ink = math.random(3,5)
      local input = torch.Tensor(inj, ini):zero()

      local module = nn.Normalize(p)

      local err = jac.testJacobian(module, input, -2, 2)
      mytester:assertlt(err, precision, 'error norm '..p..' on state ')
   end

   -- test IO correctness
   local ini = math.random(3,5)
   local inj = math.random(3,5)
   local ink = math.random(3,5)
   local input = torch.Tensor(inj, ini):zero()

   local module = nn.Normalize(2)

   local ferr, berr = jac.testIO(module,input, 0.1, 2)
   mytester:eq(ferr, 0, torch.typename(module) .. ' - i/o forward err ', precision)
   mytester:eq(berr, 0, torch.typename(module) .. ' - i/o backward err ', precision)

end

function nntest.Square()
   local in1 = torch.rand(5,7)
   local module = nn.Square()
   local out = module:forward(in1)
   local err = out:dist(in1:cmul(in1))
   mytester:assertlt(err, 1e-15, torch.typename(module) .. ' - forward err ')

   local ini = math.random(3,5)
   local inj = math.random(3,5)
   local ink = math.random(3,5)
   local input = torch.Tensor(ink, inj, ini):zero()

   local module = nn.Square()

   local err = nn.Jacobian.testJacobian(module, input)
   mytester:assertlt(err, precision, 'error on state ')

   local ferr, berr = nn.Jacobian.testIO(module, input)
   mytester:eq(ferr, 0, torch.typename(module) .. ' - i/o forward err ', precision)
   mytester:eq(berr, 0, torch.typename(module) .. ' - i/o backward err ', precision)
end

function nntest.Sqrt()
   local in1 = torch.rand(5,7)
   local module = nn.Sqrt()
   local out = module:forward(in1)
   local err = out:dist(in1:sqrt())
   mytester:assertlt(err, 1e-15, torch.typename(module) .. ' - forward err ')

   -- Test zero inputs; we will avoid a div-by-zero by setting to zero
   local zin = torch.DoubleTensor(5, 7):zero()
   module:forward(zin)
   local zgradout = torch.rand(5, 7)
   local zgradin = module:backward(zin, zgradout)
   mytester:assertTensorEq(zgradin, torch.DoubleTensor(5, 7):zero(), 0.000001, "error in sqrt backward singularity")

   local ini = math.random(3,5)
   local inj = math.random(3,5)
   local ink = math.random(3,5)
   local input = torch.Tensor(ink, inj, ini):zero()

   local module = nn.Sqrt()

   local err = nn.Jacobian.testJacobian(module, input, 0.1, 2)
   mytester:assertlt(err, precision, 'error on state ')

   local ferr, berr = nn.Jacobian.testIO(module, input, 0, 2)
   mytester:eq(ferr, 0, torch.typename(module) .. ' - i/o forward err ', precision)
   mytester:eq(berr, 0, torch.typename(module) .. ' - i/o backward err ', precision)
end

function nntest.Linear()
   local ini = math.random(3,5)
   local inj_vals = {math.random(3,5), 1}  -- Also test the inj = 1 spatial case
   local input = torch.Tensor(ini):zero()

   for ind, inj in pairs(inj_vals) do
      local module = nn.Linear(ini,inj)

      local function jacTests(module)
         -- 1D
         local err = jac.testJacobian(module,input)
         mytester:assertlt(err,precision, 'error on state ')

         local err = jac.testJacobianParameters(module, input, module.weight, module.gradWeight)
         mytester:assertlt(err,precision, 'error on weight ')

         if module.bias then
            local err = jac.testJacobianParameters(module, input, module.bias, module.gradBias)
            mytester:assertlt(err,precision, 'error on bias ')
         end

         local err = jac.testJacobianUpdateParameters(module, input, module.weight)
         mytester:assertlt(err,precision, 'error on weight [direct update] ')

         if module.bias then
            local err = jac.testJacobianUpdateParameters(module, input, module.bias)
            mytester:assertlt(err,precision, 'error on bias [direct update] ')
         end

         nn.hessian.enable()

         local err = jac.testDiagHessianInput(module, input)
         mytester:assertlt(err , precision, 'error on diagHessianInput')

         local err = jac.testDiagHessianWeight(module, input)
         mytester:assertlt(err , precision, 'error on diagHessianWeight')

         if module.bias then
            local err = jac.testDiagHessianBias(module, input)
            mytester:assertlt(err , precision, 'error on diagHessianBias')
         end

         for t,err in pairs(jac.testAllUpdate(module, input, 'weight', 'gradWeight')) do
            mytester:assertlt(err, precision, string.format(
                                 'error on weight [%s]', t))
         end

         if module.bias then
            for t,err in pairs(jac.testAllUpdate(module, input, 'bias', 'gradBias')) do
               mytester:assertlt(err, precision, string.format(
                                    'error on bias [%s]', t))
            end
         end

         -- 2D
         local nframe = math.random(50,70)
         local input = torch.Tensor(nframe, ini):zero()

         local err = jac.testJacobian(module,input)
         mytester:assertlt(err,precision, 'error on state ')

         local err = jac.testJacobianParameters(module, input, module.weight, module.gradWeight)
         mytester:assertlt(err,precision, 'error on weight ')

         if module.bias then
            local err = jac.testJacobianParameters(module, input, module.bias, module.gradBias)
            mytester:assertlt(err,precision, 'error on bias ')
         end

         local err = jac.testJacobianUpdateParameters(module, input, module.weight)
         mytester:assertlt(err,precision, 'error on weight [direct update] ')

         if module.bias then
            local err = jac.testJacobianUpdateParameters(module, input, module.bias)
            mytester:assertlt(err,precision, 'error on bias [direct update] ')
         end

         local err = jac.testDiagHessianInput(module, input)
         mytester:assertlt(err , precision, 'error on diagHessianInput')

         local err = jac.testDiagHessianWeight(module, input)
         mytester:assertlt(err , precision, 'error on diagHessianWeight')

         if module.bias then
            local err = jac.testDiagHessianBias(module, input)
            mytester:assertlt(err , precision, 'error on diag HessianBias')
         end

         for t,err in pairs(jac.testAllUpdate(module, input, 'weight', 'gradWeight')) do
            mytester:assertlt(err, precision, string.format(
                                 'error on weight [%s]', t))
         end

         if module.bias then
            for t,err in pairs(jac.testAllUpdate(module, input, 'bias', 'gradBias')) do
               mytester:assertlt(err, precision, string.format(
                                    'error on bias [%s]', t))
            end
         end

         -- IO
         local ferr,berr = jac.testIO(module,input)
         mytester:eq(ferr, 0, torch.typename(module) .. ' - i/o forward err ', precision)
         mytester:eq(berr, 0, torch.typename(module) .. ' - i/o backward err ', precision)
      end

      jacTests(module)
      module:noBias()
      jacTests(module)
      module.bias = torch.Tensor(inj):zero()
      module.gradBias = torch.Tensor(inj):zero()
      module:reset()
      jacTests(module)
   end  -- for ind, inj in pairs(inj_vals) do
end

local function test_sparse_linear(inb, ini, inj, numNonzero)
   local module = nn.SparseLinear(ini,inj, true)
   local linear = nn.Linear(ini, inj)
   linear.weight = module.weight:clone()
   linear.bias = module.bias:clone()
   module:zeroGradParameters()
   linear:zeroGradParameters()

   -- Create a random sparse vector
   local input = {}
   local nonsparse = torch.zeros(inb, ini)
   for i=1,inb do
       local nnz = math.random(1, 3) + numNonzero
       local inds = torch.randperm(ini)[{{1,nnz}}]
       input[i] = torch.Tensor(nnz, 2)
       input[i]:select(2,1):copy(inds)
       input[i]:select(2,2):copy(torch.rand(nnz))
       nonsparse[i]:scatter(1, input[i]:select(2,1):long(), input[i]:select(2,2))
   end
   local gradOutput = torch.rand(inb, inj)

   local cmps = {'weight', 'bias', 'gradWeight', 'gradBias'}

   -- Check output wrt linear, non-batch
   local actual = module:forward(input[1])
   local expected = linear:forward(nonsparse[1])
   local actualgi = module:backward(input[1], gradOutput[1])
   local expectedgi = linear:backward(nonsparse[1], gradOutput[1])
   module:updateParameters(1)
   linear:updateParameters(1)
   local err = (expected - actual):abs():max()
   local gierr = (expectedgi - actualgi[1]:select(2,2)):abs():max()
   mytester:assertle(err, precision, 'error on result')
   mytester:assertle(gierr, precision, 'error on gradInput')

   for _,var in ipairs(cmps) do
        local err = (module[var] - linear[var]):abs():max()
        mytester:assertle(err, precision, 'error on '..var)
   end
   module:zeroGradParameters()
   linear:zeroGradParameters()

   -- Check output wrt linear, batch
   -- doing this n times checks for fast last input param updates
   local test_n_times = function(ntimes)
      local actual, expected, actualgi, expectedgi
      for i=1, ntimes do
         actual = module:forward(input)
         expected = linear:forward(nonsparse)
         actualgi = module:backward(input, gradOutput)
         expectedgi = linear:backward(nonsparse, gradOutput)
      end
      module:updateParameters(1)
      linear:updateParameters(1)
      local err = (expected - actual):abs():max()
      local gicheck = torch.Tensor():resizeAs(expectedgi)
      for i=1,#actualgi do gicheck[i]:copy(actualgi[i]:select(2,2)) end
      local gierr = (expectedgi - gicheck):abs():max()
      mytester:assertle(err, precision, 'error on result with ntimes = '..ntimes)
      mytester:assertle(gierr, precision, 'error on gradInput with ntimes = '..ntimes)

      for _,var in ipairs(cmps) do
          local err = (module[var] - linear[var]):abs():max()
          mytester:assertle(err, precision, 'error on '..var..' with ntimes = '..ntimes)
      end

      module:zeroGradParameters()
      linear:zeroGradParameters()
      mytester:assertle(module.gradWeight:sum(), precision, 'error zeroing gradweight')
      mytester:assertle(module.gradBias:sum(), precision, 'error zeroing gradweight')

   end

   test_n_times(1)
   test_n_times(2)
   test_n_times(3)

   -- legacy batch mode
   local batch = math.random(2,5)

   local input = torch.Tensor(batch, numNonzero, 2):zero()
   for k=1,batch do
      local N = {}
      for i = 1, ini do N[i] = i end
      for i = 1, numNonzero do
         local j = math.random(i,ini)
         N[i], N[j] = N[j], N[i]
      end
      for i = 1, numNonzero do input[{k,i,1}] = N[i] end
   end
   local values = input:select(3,2)
   values:copy(torch.rand(values:nElement())):mul(2):add(-1)

   -- Check output
   local actual = module:forward(input):clone()
   local expected = torch.Tensor(batch, inj)
   for k = 1, batch do
      expected[k]:copy(module:forward(input[k]))
   end
   local err = (expected - actual):abs():max()
   mytester:assertle(err, precision, 'error on batch result forward')
end

function nntest.SparseLinear()
   local inb = math.random(5,10)
   local ini = math.random(50,100)
   local inj = math.random(5,10)
   local numNonzero = math.random(3,5)

   test_sparse_linear(inb, ini, inj, numNonzero)
   -- Tests OMP parallelism
   test_sparse_linear(1, 50000, 10, 20000)
   test_sparse_linear(1000, 1000, 10, 100)
end

local function testIndexLinear(bsize, iSize, oSize, nnz)
   local inb = bsize
   local ini = iSize
   local inj = oSize

   local ilinear  = nn.IndexLinear(ini,inj, true, nil, nil, nil, false)
   local ilinear2 = nn.IndexLinear(ini,inj, true, nil, nil, nil, false)
   local linear = nn.Linear(ini, inj)
   ilinear.weight:zero()
   ilinear.weight:copy(linear.weight:t():clone())
   ilinear.bias = linear.bias:clone()
   ilinear:zeroGradParameters()

   ilinear2.weight:zero()
   ilinear2.weight:copy(linear.weight:t():clone())
   ilinear2.bias = linear.bias:clone()
   ilinear2:zeroGradParameters()

   linear:zeroGradParameters()

   -- Create a random sparse vector
   local input = {{},{}}
   local flatInput = {torch.LongTensor(), torch.Tensor(), torch.LongTensor()}
   local nonsparse = torch.zeros(inb, ini)
   local sizes = flatInput[3]
   sizes:resize(inb)
   for i=1,inb do
      sizes[i] = nnz
      input[1][i] = torch.randperm(ini)[{{1,nnz}}]:long()
      input[2][i] = torch.ones(nnz):uniform()
      nonsparse[i]:scatter(1, input[1][i], input[2][i])
   end
   flatInput[1]:cat(input[1])
   flatInput[2]:cat(input[2])

   local gradOutput = torch.rand(inb, inj)
   local cmps = {'weight', 'bias', 'gradBias'}
   -- Check output wrt linear, non-batch
   local actual = ilinear:forward({input[1][1], input[2][1]})
   local actual2 = ilinear2:forward({input[1][1], input[2][1], flatInput[3][1]})
   local expected = linear:forward(nonsparse[1])

   local actualgi = ilinear:backward({input[1][1], input[2][1]}, gradOutput[1])
   local actualgi2 = ilinear2:backward({input[1][1], input[2][1], flatInput[3][1]}, gradOutput[1])
   local expectedgi = linear:backward(nonsparse[1], gradOutput[1])

   ilinear:updateParameters(1)
   ilinear2:updateParameters(1)
   linear:updateParameters(1)

   local err = (expected - actual):abs():max()
   local err2 = (expected - actual2):abs():max()

   local gierr = (expectedgi - actualgi[2]):abs():max()
   local gierr2 = (expectedgi - actualgi2[2]):abs():max()

   mytester:assertle(err, precision, 'error on result for tensor array')
   mytester:assertle(gierr, precision, 'error on gradInput for tensor array')

   mytester:assertle(err2, precision, 'error on result for batched tensor')
   mytester:assertle(gierr2, precision, 'error on gradInput for batched tensor')

   for _,var in ipairs(cmps) do
      local err, err2
      if var == 'weight' then
         err = (ilinear[var]:t() - linear[var]):abs():max()
         err2 = (ilinear2[var]:t() - linear[var]):abs():max()
      else
         err = (ilinear[var] - linear[var]):abs():max()
         err2 = (ilinear2[var] - linear[var]):abs():max()
      end
      mytester:assertle(err, precision, 'error on '..var..' for tensor array')
      mytester:assertle(err2, precision, 'error on '..var..' for batched tensor')
   end
   ilinear:zeroGradParameters()
   ilinear2:zeroGradParameters()
   linear:zeroGradParameters()

   -- Check output wrt linear, batch
   -- doing this n times checks for fast last input param updates
   local test_n_times = function(ntimes)
      local actual, expected, actualgi, expectedgi
      for i=1, ntimes do
         actual = ilinear:forward(input)
         actual2 = ilinear2:forward(flatInput)
         expected = linear:forward(nonsparse)

         actualgi = ilinear:backward(input, gradOutput)
         actualgi2 = ilinear2:backward(flatInput, gradOutput)
         expectedgi = linear:backward(nonsparse, gradOutput)
      end
      ilinear:updateParameters(1)
      ilinear2:updateParameters(1)
      linear:updateParameters(1)

      local err = (expected - actual):abs():max()
      local err2 = (expected - actual2):abs():max()

      local gicheck = torch.Tensor():resizeAs(expectedgi)
      local gicheck2 = actualgi2[2]

      for i=1,#actualgi[2] do
         gicheck[i]:copy(actualgi[2][i])
      end
      local gierr = (expectedgi - gicheck):abs():max()
      local gierr2 = (expectedgi - gicheck2):abs():max()

      mytester:assertle(err, precision, 'error on result for tensor array with ntimes = '..ntimes)
      mytester:assertle(err2, precision, 'error on result for batched tensor with ntimes = '..ntimes)

      mytester:assertle(gierr, precision, 'error on gradInput for tensor array with ntimes = '..ntimes)
      mytester:assertle(gierr2, precision, 'error on gradInput for batched tensor with ntimes = '..ntimes)

      for _,var in ipairs(cmps) do
         local err, err2
         if var == 'weight' then
            err = (ilinear[var]:t() - linear[var]):abs():max()
            err2 = (ilinear2[var]:t() - linear[var]):abs():max()
         else
            err = (ilinear[var] - linear[var]):abs():max()
            err2 = (ilinear2[var] - linear[var]):abs():max()
         end
         mytester:assertle(err, precision, 'error on '..var..' for tensor array')
         mytester:assertle(err2, precision, 'error on '..var..' for batched tensor')
      end

      ilinear:zeroGradParameters()
      ilinear2:zeroGradParameters()
      linear:zeroGradParameters()
      mytester:assertle(ilinear.gradBias:sum(), precision, 'error zeroing gradbias for tensor array')
      mytester:assertle(ilinear2.gradBias:sum(), precision, 'error zeroing gradbias for batched tensor')
   end
   test_n_times(1)
   test_n_times(2)
   test_n_times(3)
end

function nntest.IndexLinear()
   testIndexLinear(4, 40 , 10, 30)
   testIndexLinear(4, 40 , 500, 30)
   testIndexLinear(4, 200000 , 5, 150000)

   local sizes = {
      {osize = 1, isize = 10000, nnz = 10000, bsize = 16},
      {osize = 10, isize = 10000, nnz = 10000, bsize = 16},
      {osize = 100, isize = 10000, nnz = 10000, bsize = 16},

      {osize = 1, isize = 10000, nnz = 200000, bsize = 1},
      {osize = 10, isize = 10000, nnz = 200000, bsize = 1},
      {osize = 100, isize = 10000, nnz = 200000, bsize = 1},

      {osize = 1, isize = 10000, nnz = 200000, bsize = 2},
      {osize = 10, isize = 10000, nnz = 200000, bsize = 2},
      {osize = 100, isize = 10000, nnz = 200000, bsize = 2},
   }

   for i, lsizes in ipairs(sizes) do
      -- Test multithreaded updates
      local isize = lsizes.isize
      local osize = lsizes.osize
      local il = nn.IndexLinear(isize, osize)
      local batch = {{},{}}
      local idx = 100
      local nnz = lsizes.nnz
      local bsize = lsizes.bsize
      for i=1,bsize do
         batch[1][i] = torch.LongTensor(nnz):fill(idx)
         batch[2][i] = torch.DoubleTensor(nnz):fill(1)
      end
      local totalSize = bsize*nnz
      local lr = 0.01
      -- Update the same index all over
      local out = il:updateOutput(batch)
      out:fill(1)
      il:backwardUpdate(batch, out, lr)
      il:backward(batch, out, 1)
      il:updateParameters(lr)
      for i=1,osize do
         mytester:assertlt(math.abs(il.weight[idx][i] + totalSize * lr * 2), precision, 'parameters update was wrong.')
      end
   end
end

function nntest.Bilinear()

   -- set up data:
   local N = 10
   local D1 = 5
   local D2 = 4
   local K  = 3
   local input  = {torch.randn(N, D1), torch.randn(N, D2)}
   local target = torch.randn(N, K)

   -- test forward
   local module = nn.Bilinear(D1, D2, K)
   local expected = torch.zeros(N,K)
   for k = 1, K do
      local temp = torch.mm(module.weight[k], input[2]:t())
      temp:cmul(input[1]:t())
      temp = temp:sum(1)
      temp:add(module.bias[k])
      expected[{{},k}] = temp:view(-1)
   end
   local output = module:forward(input)
   mytester:assertTensorEq(expected, output, 0.000001, 'Bilinear forward 2D err')

   -- For testing grads we'll follow the nn.DotProduct strategy of using a SplitTable
   local input2 = torch.randn(2, N, D1)
   local module2 = nn.Sequential()
   module2:add(nn.SplitTable(1))
   module2:add(nn.ParallelTable():add(nn.Linear(D1,D1)):add(nn.Linear(D1,D2)))
   module2:add(nn.Bilinear(D1, D2, K))
   module2:add(nn.Linear(K,1))

   local err = jac.testJacobian(module2, input2)
   mytester:assertlt(err, precision, 'error on state ')

   local err = jac.testJacobianParameters(module2, input2, module2:get(3).weight, module2:get(3).gradWeight)
   mytester:assertlt(err, precision, 'error on weight ')

   local err = jac.testJacobianParameters(module2, input2, module2:get(3).bias, module2:get(3).gradBias)
   mytester:assertlt(err, precision, 'error on bias ')

end

function nntest.PartialLinear()

   -- settings for experiment:
   local N = 10
   local D = 5
   local K = 15

   -- test forward-backward pass of module:
   local module = nn.PartialLinear(D, K)
   for sub_K = 1,K do

      -- get random test case:
      local input  = torch.randn(N, D)
      local partition = torch.randperm(K):narrow(1, 1, sub_K)

      -- do forward-backward pass:
      module:setPartition(partition)
      module:forward(input)
      mytester:asserteq(module.output:size(1), N)
      mytester:asserteq(module.output:size(2), sub_K)
      module:backward(input, torch.ones(N, sub_K))
      mytester:asserteq(module.gradInput:size(1), input:size(1))
      mytester:asserteq(module.gradInput:size(2), input:size(2))

      -- do parameter update:
      local lr = .01
      module:updateParameters(lr)
   end
   module:resetPartition()

   -- compare output with linear layer:
   local module2 = nn.Linear(D, K)
   module2.weight:copy(module.network:get(1):get(2).weight)
   module2.bias:fill(0)
   if module.bias then module2.bias:copy(module.bias) end
   local input = torch.randn(N, D)
   local diff = (module:forward(input) - module2:forward(input)):abs():sum()
   mytester:assertlt(diff, 1e-7)

   -- gradient checks:
   local sub_K = 5
   local partition = torch.randperm(K):narrow(1, 1, sub_K)
   module:setPartition(partition)
   local err = sjac.testJacobian(module, input)
   mytester:assertlt(err, precision, 'error on state ')

   local err = sjac.testJacobianParameters(module, input, module.network:get(1):get(2).weight, module.network:get(1):get(2).gradWeight)
   mytester:assertlt(err,precision, 'error on weight ')

   local err = sjac.testJacobianParameters(module, input, module.bias, module.gradBias)
   mytester:assertlt(err,precision, 'error on bias ')

   local err = sjac.testJacobianUpdateParameters(module, input, module.network:get(1):get(2).weight)
   mytester:assertlt(err,precision, 'error on weight [direct update] ')

   local err = sjac.testJacobianUpdateParameters(module, input, module.bias)
   mytester:assertlt(err,precision, 'error on bias [direct update] ')

   local ferr, berr = sjac.testIO(module, input)
   mytester:eq(0, ferr, torch.typename(module) .. ' - i/o forward err ', precision)
   mytester:eq(0, berr, torch.typename(module) .. ' - i/o backward err ', precision)
end

function nntest.Euclidean()
   local ini = math.random(5,7)
   local inj = math.random(5,7)
   local input = torch.randn(ini)
   local gradOutput = torch.randn(inj)
   local module = nn.Euclidean(ini,inj)
   local output = module:forward(input):clone()

   local output2 = torch.Tensor(inj):zero()
   for o = 1,module.weight:size(2) do
      output2[o] = input:dist(module.weight:select(2,o))
   end
   mytester:assertTensorEq(output, output2, 0.000001, 'Euclidean forward 1D err')

   local input2 = torch.randn(8, ini)
   input2[2]:copy(input)
   local output2 = module:forward(input2)
   mytester:assertTensorEq(output2[2], output, 0.000001, 'Euclidean forward 2D err')

   local output = module:forward(input):clone()
   module:zeroGradParameters()
   local gradInput = module:backward(input, gradOutput, 1):clone()
   local gradInput2 = torch.zeros(ini)
   local temp = input:clone()
   for o = 1,module.weight:size(2) do
      temp:copy(input)
      temp:add(-1,module.weight:select(2,o))
      temp:mul(gradOutput[o]/output[o])
      gradInput2:add(temp)
   end
   mytester:assertTensorEq(gradInput, gradInput2, 0.000001, 'Euclidean updateGradInput 1D err')

   local gradWeight = module.gradWeight:clone():zero()
   for o = 1,module.weight:size(2) do
      temp:copy(module.weight:select(2,o)):add(-1,input)
      temp:mul(gradOutput[o]/output[o])
      gradWeight:select(2,o):add(1, temp)
   end
   mytester:assertTensorEq(gradWeight, module.gradWeight, 0.000001, 'Euclidean accGradParameters 1D err')

   local input2 = input:view(1, -1):repeatTensor(8, 1)
   local gradOutput2 = gradOutput:view(1, -1):repeatTensor(8, 1)
   local output2 = module:forward(input2)
   module:zeroGradParameters()
   local gradInput2 = module:backward(input2, gradOutput2, 1/8)
   mytester:assertTensorEq(gradInput2[2], gradInput, 0.000001, 'Euclidean updateGradInput 2D err')

   mytester:assertTensorEq(gradWeight, module.gradWeight, 0.000001, 'Euclidean accGradParameters 2D err')

   input:zero()
   module.fastBackward = false
   local err = jac.testJacobian(module,input)
   mytester:assertlt(err,precision, 'error on state ')

   local err = jac.testJacobianParameters(module, input, module.weight, module.gradWeight)
   mytester:assertlt(err,precision, 'error on weight ')

   local ferr,berr = jac.testIO(module,input)
   mytester:eq(ferr, 0, torch.typename(module) .. ' - i/o forward err ', precision)
   mytester:eq(berr, 0, torch.typename(module) .. ' - i/o backward err ', precision)
end

function nntest.WeightedEuclidean()
   local ini = math.random(5,7)
   local inj = math.random(5,7)
   local input = torch.randn(ini)
   local gradOutput = torch.randn(inj)
   local module = nn.WeightedEuclidean(ini,inj)

   local output = module:forward(input):clone()

   local output2 = torch.Tensor(inj):zero()
   local temp = input:clone()
   for o = 1,module.weight:size(2) do
      temp:copy(input):add(-1,module.weight:select(2,o))
      temp:cmul(temp)
      temp:cmul(module.diagCov:select(2,o)):cmul(module.diagCov:select(2,o))
      output2[o] = math.sqrt(temp:sum())
   end
   mytester:assertTensorEq(output, output2, 0.000001, 'WeightedEuclidean forward 1D err')

   local input2 = torch.randn(8, ini)
   input2[2]:copy(input)
   local output2 = module:forward(input2)
   mytester:assertTensorEq(output2[2], output, 0.000001, 'WeightedEuclidean forward 2D err')

   local output = module:forward(input):clone()
   module:zeroGradParameters()
   local gradInput = module:backward(input, gradOutput, 1):clone()
   local gradInput2 = torch.zeros(ini)
   for o = 1,module.weight:size(2) do
      temp:copy(input)
      temp:add(-1,module.weight:select(2,o))
      temp:cmul(module.diagCov:select(2,o)):cmul(module.diagCov:select(2,o))
      temp:mul(gradOutput[o]/output[o])
      gradInput2:add(temp)
   end
   mytester:assertTensorEq(gradInput, gradInput2, 0.000001, 'WeightedEuclidean updateGradInput 1D err')

   local gradWeight = module.gradWeight:clone():zero()
   local gradDiagCov = module.gradDiagCov:clone():zero()
   for o = 1,module.weight:size(2) do
      if output[o] ~= 0 then
         temp:copy(module.weight:select(2,o)):add(-1,input)
         temp:cmul(module.diagCov:select(2,o)):cmul(module.diagCov:select(2,o))
         temp:mul(gradOutput[o]/output[o])
         gradWeight:select(2,o):add(temp)

         temp:copy(module.weight:select(2,o)):add(-1,input)
         temp:cmul(temp)
         temp:cmul(module.diagCov:select(2,o))
         temp:mul(gradOutput[o]/output[o])
         gradDiagCov:select(2,o):add(temp)
      end
   end
   mytester:assertTensorEq(gradWeight, module.gradWeight, 0.000001, 'WeightedEuclidean accGradParameters gradWeight 1D err')
   mytester:assertTensorEq(gradDiagCov, module.gradDiagCov, 0.000001, 'WeightedEuclidean accGradParameters gradDiagCov 1D err')

   local input2 = input:view(1, -1):repeatTensor(8, 1)
   local gradOutput2 = gradOutput:view(1, -1):repeatTensor(8, 1)
   local output2 = module:forward(input2)
   module:zeroGradParameters()
   local gradInput2 = module:backward(input2, gradOutput2, 1/8)
   mytester:assertTensorEq(gradInput2[2], gradInput, 0.000001, 'WeightedEuclidean updateGradInput 2D err')

   mytester:assertTensorEq(gradWeight, module.gradWeight, 0.000001, 'WeightedEuclidean accGradParameters gradWeight 2D err')
   mytester:assertTensorEq(gradDiagCov, module.gradDiagCov, 0.000001, 'WeightedEuclidean accGradParameters gradDiagCov 2D err')

   input:zero()
   module.fastBackward = false

   local err = jac.testJacobian(module,input)
   mytester:assertlt(err,precision, 'error on state ')

   local err = jac.testJacobianParameters(module, input, module.weight, module.gradWeight)
   mytester:assertlt(err,precision, 'error on weight ')

   local err = jac.testJacobianParameters(module, input, module.diagCov, module.gradDiagCov)
   mytester:assertlt(err,precision, 'error on bias ')

   local ferr,berr = jac.testIO(module,input)
   mytester:eq(ferr, 0, torch.typename(module) .. ' - i/o forward err ', precision)
   mytester:eq(berr, 0, torch.typename(module) .. ' - i/o backward err ', precision)

   input:zero()
   module:zeroGradParameters()
   local err = jac.testJacobian(module,input)
   mytester:assertlt(err,precision, 'error on state ')

   local err = jac.testJacobianParameters(module, input, module.weight, module.gradWeight)
   mytester:assertlt(err,precision, 'error on weight ')

   local err = jac.testJacobianParameters(module, input, module.diagCov, module.gradDiagCov)
   mytester:assertlt(err,precision, 'error on bias ')

   local ferr,berr = jac.testIO(module,input2)
   mytester:eq(ferr, 0, torch.typename(module) .. ' - i/o forward err ', precision)
   mytester:eq(berr, 0, torch.typename(module) .. ' - i/o backward err ', precision)
end

local function criterionJacobianTest(cri, input, target)
   local eps = 1e-6
   local _ = cri:forward(input, target)
   local dfdx = cri:backward(input, target)
   -- for each input perturbation, do central difference
   local centraldiff_dfdx = torch.Tensor():resizeAs(dfdx)
   local input_s = input:storage()
   local centraldiff_dfdx_s = centraldiff_dfdx:storage()
   for i=1,input:nElement() do
      -- f(xi + h)
      input_s[i] = input_s[i] + eps
      local fx1 = cri:forward(input, target)
      -- f(xi - h)
      input_s[i] = input_s[i] - 2*eps
      local fx2 = cri:forward(input, target)
      -- f'(xi) = (f(xi + h) - f(xi - h)) / 2h
      local cdfx = (fx1 - fx2) / (2*eps)
      -- store f' in appropriate place
      centraldiff_dfdx_s[i] = cdfx
      -- reset input[i]
      input_s[i] = input_s[i] + eps
   end

   -- compare centraldiff_dfdx with :backward()
   local err = (centraldiff_dfdx - dfdx):abs():max()
   mytester:assertlt(err, precision, 'error in difference between central difference and :backward')
end

local function criterionJacobianTest1DTable(cri, input0, target)
   -- supposes input is a tensor, which is splitted in the first dimension
   local input = input0:split(1,1)
   for i=1,#input do
      input[i] = input[i][1]
   end
   local eps = 1e-6
   local _ = cri:forward(input, target)
   local dfdx = cri:backward(input, target)
   -- for each input perturbation, do central difference
   local centraldiff_dfdx = torch.Tensor():resizeAs(input0)
   local input_s = input0:storage()
   local centraldiff_dfdx_s = centraldiff_dfdx:storage()
   for i=1,input0:nElement() do
      -- f(xi + h)
      input_s[i] = input_s[i] + eps
      local fx1 = cri:forward(input, target)
      -- f(xi - h)
      input_s[i] = input_s[i] - 2*eps
      local fx2 = cri:forward(input, target)
      -- f'(xi) = (f(xi + h) - f(xi - h)) / 2h
      local cdfx = (fx1 - fx2) / (2*eps)
      -- store f' in appropriate place
      centraldiff_dfdx_s[i] = cdfx
      -- reset input[i]
      input_s[i] = input_s[i] + eps
   end
   local centraldiff_dfdx_t = centraldiff_dfdx:split(1,1)
   for i=1,#centraldiff_dfdx_t do
      centraldiff_dfdx_t[i] = centraldiff_dfdx_t[i][1]
   end
   for i=1,#centraldiff_dfdx_t do
      -- compare centraldiff_dfdx with :backward()
      local err = (centraldiff_dfdx_t[i] - dfdx[i]):abs():max()
      mytester:assertlt(err, precision, 'error in difference between central difference and :backward')
   end
end

function nntest.SmoothL1Criterion()
   local input = torch.rand(10)
   local target = input:clone():add(torch.rand(10))
   local cri = nn.SmoothL1Criterion()
   criterionJacobianTest(cri, input, target)
end

function nntest.MSECriterion()
   local input = torch.rand(10)
   local target = input:clone():add(torch.rand(10))
   local cri = nn.MSECriterion()
   criterionJacobianTest(cri, input, target)
end

function nntest.SpatialAutoCropMSECriterion()
   -- Tests the assumptions on input and target dimensions for the
   -- nn.SpatialAutoCropMSECriterion criterion
   local function testInputBounds()
      for _, average in pairs({true, false}) do
         local sMSE = nn.SpatialAutoCropMSECriterion(average)

         local input = torch.Tensor(3, 3, 3)
         local target = torch.Tensor(4, 3, 3)
         mytester:assertError(function() sMSE:forward(input, target) end,
                          "Target and input must have same number of channels")

         input = torch.Tensor(2, 4, 3, 3)
         target = torch.Tensor(2, 3, 3, 3)
         mytester:assertError(function() sMSE:forward(input, target) end,
                        "Target and input must have same number of channels")

         input = torch.Tensor(2, 3, 3, 3)
         target = torch.Tensor(1, 3, 3, 3)
         mytester:assertError(function() sMSE:forward(input, target) end,
                         "Target and input must have same batch size")

         input = torch.Tensor(2, 5, 5)
         target = torch.Tensor(2, 5, 4)
         mytester:assertError(function() sMSE:forward(input, target) end,
                         "input resolution must be smaller or equal to the spatial resolution of the target")

         input = torch.Tensor(1, 2, 5, 5)
         target = torch.Tensor(1, 2, 4, 5)
         mytester:assertError(function() sMSE:forward(input, target) end,
                         "input resolution must be smaller or equal to the spatial resolution of the target")
      end
   end

   -- Tests that the forward pass of nn.SpatialAutoCropMSECriterion
   -- is equivalent to the forward pass of nn.MSECriterion with a pre-cropped target
   local function testSpatialAutoCropMSECriterionBatched()
      for _, average in pairs({true, false}) do
         local sMSE = nn.SpatialAutoCropMSECriterion(average)
         local MSE = nn.MSECriterion(average)

         local batchSize = math.random(1,10)
         local channels = math.random(1,10)
         local inputHeight = math.random(1, 50)
         local inputWidth = math.random(1, 50)
         local targetHeight = inputHeight + math.random(0,5)
         local targetWidth = inputWidth + math.random(0,5)

         local input = torch.Tensor(batchSize, channels, inputHeight, inputWidth):uniform()
         local target = torch.Tensor(batchSize, channels, targetHeight, targetWidth):uniform()

         local heightStartIdx = 1 + math.floor((targetHeight - inputHeight)/2.0)
         local heightEndIdx = heightStartIdx + inputHeight - 1
         local widthStartIdx = 1 +  math.floor((targetWidth - inputWidth)/2.0)
         local widthEndIdx = widthStartIdx + inputWidth - 1

         local croppedTarget = target[{{}, {}, {heightStartIdx, heightEndIdx}, {widthStartIdx, widthEndIdx}}]

         local sMSEOut = nn.SpatialAutoCropMSECriterion(average):forward(input, target)
         local MSEOut = MSE:forward(input, croppedTarget)
         mytester:asserteq(sMSEOut, MSEOut)

         local gradOutput = torch.Tensor():resizeAs(croppedTarget):uniform()
         local sMSEGradInput = sMSE:backward(input, gradOutput)
         local MSEGradInput = MSE:backward(input, gradOutput)
         mytester:assertTensorEq(sMSEGradInput, MSEGradInput, 1e-7)
         criterionJacobianTest(sMSE, input, gradOutput)
      end
   end

   local function testSpatialAutoCropMSECriterionNonBatched()
      for _, average in pairs({true, false}) do
         local sMSE = nn.SpatialAutoCropMSECriterion(average)
         local MSE = nn.MSECriterion(average)

         local channels = math.random(1,10)
         local inputHeight = math.random(1, 50)
         local inputWidth = math.random(1, 50)
         local targetHeight = inputHeight + math.random(0,5)
         local targetWidth = inputWidth + math.random(0,5)

         local input = torch.Tensor(channels, inputHeight, inputWidth):uniform()
         local target = torch.Tensor(channels, targetHeight, targetWidth):uniform()

         local heightStartIdx = 1 + math.floor((targetHeight - inputHeight)/2.0)
         local heightEndIdx = heightStartIdx + inputHeight - 1
         local widthStartIdx = 1 +  math.floor((targetWidth - inputWidth)/2.0)
         local widthEndIdx = widthStartIdx + inputWidth - 1

         local croppedTarget = target[{{}, {heightStartIdx, heightEndIdx}, {widthStartIdx, widthEndIdx}}]

         local sMSEOut = nn.SpatialAutoCropMSECriterion(average):forward(input, target)
         local MSEOut = MSE:forward(input, croppedTarget)
         mytester:asserteq(sMSEOut, MSEOut)

         local gradOutput = torch.Tensor():resizeAs(croppedTarget):uniform()
         local sMSEGradInput = sMSE:backward(input, gradOutput)
         local MSEGradInput = MSE:backward(input, gradOutput)
         mytester:assertTensorEq(sMSEGradInput, MSEGradInput, 1e-7)
         criterionJacobianTest(sMSE, input, gradOutput)
      end
   end

   testInputBounds()
   testSpatialAutoCropMSECriterionBatched()
   testSpatialAutoCropMSECriterionNonBatched()
end

function nntest.ClassSimplexCriterion()
   local nClasses = torch.random(3,15)
   local input = torch.rand(nClasses)
   local target = torch.random(1,nClasses)
   local cri = nn.ClassSimplexCriterion(nClasses)
   criterionJacobianTest(cri, input, target)
end


function nntest.MarginCriterion()
   local input = torch.rand(100)
   local target = input:clone():add(torch.rand(100))
   local cri = nn.MarginCriterion()
   criterionJacobianTest(cri, input, target)
end

function nntest.SoftMarginCriterion()
   local input = torch.rand(100)
   local target = input:clone():add(torch.rand(100))
   local cri = nn.SoftMarginCriterion()
   criterionJacobianTest(cri, input, target)
end

function nntest.MultiMarginCriterion()
   local input = torch.rand(100)
   local target = math.random(1,100)
   local cri = nn.MultiMarginCriterion(math.random(1,2), nil, 0.1)
   criterionJacobianTest(cri, input, target)

   local cri = nn.MultiMarginCriterion()
   criterionJacobianTest(cri, input, target)

   local cri = nn.MultiMarginCriterion(2)
   criterionJacobianTest(cri, input, target)

   local weights = torch.randn(100)
   local cri = nn.MultiMarginCriterion(1, weights)
end

function nntest.MarginRankingCriterion()
   local input = {torch.rand(1), torch.rand(1)}
   local mrc = nn.MarginRankingCriterion()
   local output = mrc:forward(input, 1)
   local gradInput = mrc:backward(input, 1)
   -- cast to float
   local input2 = {input[1]:float(), input[2]:float()}
   local mrc2 = mrc:clone():float()
   local output2 = mrc2:forward(input2, 1)
   local gradInput2 = mrc2:backward(input2, 1)
   mytester:assert(math.abs(output2 - output) < 0.00001, "MRC:type() forward error")
   mytester:assertTensorEq(gradInput[1]:float(), gradInput2[1], 0.00001, "MRC:type() backward error 1")
   mytester:assert(torch.type(gradInput2[1]) == 'torch.FloatTensor', "MRC:type() error 1")
   mytester:assertTensorEq(gradInput[2]:float(), gradInput2[2], 0.00001, "MRC:type() backward error 2")
   mytester:assert(torch.type(gradInput2[2]) == 'torch.FloatTensor', "MRC:type() error 2")

   -- batch, sizeAverage true, jacobian
   local margin = math.random() * 2 - 1
   local batch_size = math.random(1,10)
   local crit = nn.MarginRankingCriterion(margin)
   crit.sizeAverage = true
   local v = torch.rand(2, batch_size)
   local t = torch.Tensor(batch_size):random(0,1):mul(2):add(-1)
   criterionJacobianTest1DTable(crit,v,t)

   -- batch, sizeAverage false, jacobian
   local margin = math.random() * 2 - 1
   local crit = nn.MarginRankingCriterion(margin)
   crit.sizeAverage = false
   local v = torch.rand(2, batch_size)
   local t = torch.Tensor(batch_size):random(0,1):mul(2):add(-1)
   criterionJacobianTest1DTable(crit,v,t)
end

function nntest.ModuleCriterion()
   local input = torch.randn(8,4)
   local target = torch.randn(8,4)
   local inputModule = nn.Tanh()
   local criterion = nn.MSECriterion()
   local mc = nn.ModuleCriterion(criterion, inputModule)

   local err = mc:forward(input, target)
   local gradInput = mc:backward(input, target)

   local output = inputModule:forward(input)
   local err2 = criterion:forward(output, target)
   local gradOutput = criterion:backward(output, target)
   local gradInput2 = inputModule:backward(input, gradOutput)

   mytester:assert(err == err2, "ModuleCriterion backward err")
   mytester:assertTensorEq(gradInput, gradInput2, 0.000001, "ModuleCriterion backward err")
end

function nntest.MaskedSelect()
   local input = torch.randn(4, 5)
   local mask = torch.ByteTensor(4, 5):bernoulli()
   local module = nn.MaskedSelect()
   local out = module:forward({input, mask})
   local err = out:dist(input:maskedSelect(mask))
   mytester:assertlt(err, 1e-15, torch.typename(module) .. ' - forward err ')

   local gradOut = torch.Tensor({20, 80})
   input = torch.Tensor({{10, 20}, {30, 40}})
   local inTarget = torch.Tensor({{20, 0}, {0, 80}})
   local mask = torch.ByteTensor({{1, 0}, {0, 1}})
   local module = nn.MaskedSelect()
   module:forward({input, mask})
   local gradIn = module:backward({input, mask}, gradOut)
   mytester:assertTensorEq(inTarget, gradIn[1], 1e-15, torch.typename(module) .. ' - backward err ')
end

function nntest.ParallelCriterion()
   local input = {torch.rand(2,10), torch.randn(2,10)}
   local target = {torch.IntTensor{1,8}, torch.randn(2,10)}
   local nll = nn.ClassNLLCriterion()
   local mse = nn.MSECriterion()
   local pc = nn.ParallelCriterion():add(nll, 0.5):add(mse)
   local output = pc:forward(input, target)
   local output2 = nll:forward(input[1], target[1])/2 + mse:forward(input[2], target[2])
   mytester:assert(math.abs(output2 - output) < 0.00001, "ParallelCriterion forward error")
   local gradInput2 = {nll:backward(input[1], target[1]):clone():div(2), mse:backward(input[2], target[2])}
   local gradInput = pc:backward(input, target)
   mytester:assertTensorEq(gradInput[1], gradInput2[1], 0.000001, "ParallelCriterion backward error 1")
   mytester:assertTensorEq(gradInput[2], gradInput2[2], 0.000001, "ParallelCriterion backward error 2")

   -- test type
   pc:float()
   gradInput[1], gradInput[2] = gradInput[1]:clone(), gradInput[2]:clone()
   local input3 = {input[1]:float(), input[2]:float()}
   local target3 = {target[1]:float(), target[2]:float()}
   local output3 = pc:forward(input3, target3)
   local gradInput3 = pc:backward(input3, target3)
   mytester:assert(math.abs(output3 - output) < 0.00001, "ParallelCriterion forward error type")
   mytester:assertTensorEq(gradInput[1]:float(), gradInput3[1], 0.000001, "ParallelCriterion backward error 1 type")
   mytester:assertTensorEq(gradInput[2]:float(), gradInput3[2], 0.000001, "ParallelCriterion backward error 2 type")

   -- test repeatTarget
   local input = {torch.rand(2,10), torch.randn(2,10)}
   local target = torch.randn(2,10)
   local mse = nn.MSECriterion()
   local pc = nn.ParallelCriterion(true):add(mse, 0.5):add(mse:clone())
   local output = pc:forward(input, target)
   local output2 = mse:forward(input[1], target)/2 + mse:forward(input[2], target)
   mytester:assert(math.abs(output2 - output) < 0.00001, "ParallelCriterion repeatTarget forward error")
   local gradInput = pc:backward(input, target)
   local gradInput2 = {mse:backward(input[1], target):clone():div(2), mse:backward(input[2], target)}
   mytester:assertTensorEq(gradInput[1], gradInput2[1], 0.000001, "ParallelCriterion repeatTarget backward error 1")
   mytester:assertTensorEq(gradInput[2], gradInput2[2], 0.000001, "ParallelCriterion repeatTarget backward error 2")

   -- table input
   local input = {torch.randn(2,10), {torch.rand(2,10), torch.randn(2,10)}}
   local target = {torch.IntTensor{2,5}, {torch.IntTensor{1,8}, torch.randn(2,10)}}
   local nll2 = nn.ClassNLLCriterion()
   local nll = nn.ClassNLLCriterion()
   local mse = nn.MSECriterion()
   local pc = nn.ParallelCriterion():add(nll, 0.5):add(mse)
   local pc2 = nn.ParallelCriterion():add(nll2, 0.4):add(pc)
   local output = pc2:forward(input, target)
   local output2 = nll2:forward(input[1], target[1])*0.4 + nll:forward(input[2][1], target[2][1])/2 + mse:forward(input[2][2], target[2][2])
   mytester:assert(math.abs(output2 - output) < 0.00001, "ParallelCriterion table forward error")
   local gradInput2 = {
       nll2:backward(input[1], target[1]):clone():mul(0.4),
      {nll:backward(input[2][2], target[2][1]):clone():div(2), mse:backward(input[2][2], target[2][2])}
   }
   local gradInput = pc2:backward(input, target)
   mytester:assertTensorEq(gradInput[1], gradInput2[1], 0.000001, "ParallelCriterion table backward error 1")
   mytester:assertTensorEq(gradInput[2][1], gradInput2[2][1], 0.000001, "ParallelCriterion table backward error 2")
   mytester:assertTensorEq(gradInput[2][2], gradInput2[2][2], 0.000001, "ParallelCriterion table backward error 3")
end

function nntest.MultiCriterion()
   local input = torch.rand(2,10)
   local target = torch.IntTensor{1,8}
   local nll = nn.ClassNLLCriterion()
   local nll2 = nn.CrossEntropyCriterion()
   local mc = nn.MultiCriterion():add(nll, 0.5):add(nll2)
   local output = mc:forward(input, target)
   local output2 = nll:forward(input, target)/2 + nll2:forward(input, target)
   mytester:assert(math.abs(output2 - output) < 0.00001, "MultiCriterion forward error")
   local gradInput = mc:backward(input, target)
   local gradInput2 = nll:backward(input, target):clone():div(2):add(nll2:backward(input, target))
   mytester:assertTensorEq(gradInput, gradInput2, 0.000001, "MultiCriterion backward error ")

   -- test type
   mc:float()
   gradInput = gradInput:clone()
   local input3 = input:float()
   local target3 = target:float()
   local output3 = mc:forward(input3, target3)
   local gradInput3 = mc:backward(input3, target3)
   mytester:assert(math.abs(output3 - output) < 0.00001, "MultiCriterion forward error type")
   mytester:assertTensorEq(gradInput:float(), gradInput3, 0.000001, "MultiCriterion backward error type")

   -- test table input
   mc:double()
   local input = {torch.randn(2,10), {torch.randn(2,10), torch.randn(2,10)}}
   local target = {torch.IntTensor{1,8}, {torch.IntTensor{5,6}, torch.IntTensor{4,3}}}
   local pnllc = nn.ParallelCriterion():add(nll):add(nn.ParallelCriterion():add(nll:clone()):add(nll:clone()))
   local pnllc2 = nn.ParallelCriterion():add(nll2):add(nn.ParallelCriterion():add(nll2:clone()):add(nll2:clone()))
   local mc = nn.MultiCriterion():add(pnllc, 0.5):add(pnllc2)
   local output = mc:forward(input, target)
   local output2 = pnllc:forward(input, target)/2 + pnllc2:forward(input, target)
   mytester:assert(math.abs(output2 - output) < 0.00001, "MultiCriterion forward table error")
   local gradInput = mc:backward(input, target)
   local gradInput2 = pnllc:clone():backward(input, target)
   local gradInput2b = pnllc2:backward(input, target)
   gradInput2[1]:div(2):add(gradInput2b[1])
   gradInput2[2][1]:div(2):add(gradInput2b[2][1])
   gradInput2[2][2]:div(2):add(gradInput2b[2][2])
   mytester:assertTensorEq(gradInput[1], gradInput2[1], 0.000001, "MultiCriterion backward table 1 error ")
   mytester:assertTensorEq(gradInput[2][1], gradInput2[2][1], 0.000001, "MultiCriterion backward table 2 error ")
   mytester:assertTensorEq(gradInput[2][2], gradInput2[2][2], 0.000001, "MultiCriterion backward table 3 error ")
end

function nntest.WeightedMSECriterion()
   local input = torch.rand(10)
   local target = input:clone():add(torch.rand(10))
   local cri = nn.WeightedMSECriterion(torch.rand(10))
   criterionJacobianTest(cri, input, target)
end

function nntest.BCECriterion()
   local eps = 1e-2
   local input = torch.rand(10)*(1-eps) + eps/2
   local target = torch.rand(10)*(1-eps) + eps/2
   local cri = nn.BCECriterion()
   criterionJacobianTest(cri, input, target)
   --with weights
   local weights= torch.rand(10)*(1-eps) + eps/2
   local cri = nn.BCECriterion(weights)
   criterionJacobianTest(cri, input, target)
   -- with weights + batch
   local bsz = 5
   local input = torch.rand(bsz, 10)*(1-eps) + eps/2
   local target = torch.rand(bsz, 10)*(1-eps) + eps/2
   criterionJacobianTest(cri, input, target)
end

function nntest.DistKLDivCriterion()
   local input = torch.rand(10)
   local target = input:clone():add(torch.rand(10))
   local cri = nn.DistKLDivCriterion(true)  -- sizeAverage = true
   criterionJacobianTest(cri, input, target)
   cri = nn.DistKLDivCriterion(false)  -- sizeAverage = false
   criterionJacobianTest(cri, input, target)
end

function nntest.ClassNLLCriterion()
   local batchsize = math.random(2,4)
   local numLabels = math.random(5,10)

   local function testclassnll(input, target)
      -- default ClassNLLCriterion
      local cri = nn.ClassNLLCriterion()
      criterionJacobianTest(cri, input, target)

      -- ClassNLLCriterion with weights
      local weights = torch.rand(numLabels)
      weights = weights / weights:sum()
      cri = nn.ClassNLLCriterion(weights)
      criterionJacobianTest(cri, input, target)
   end

   -- input/target: 1D/number
   testclassnll(torch.rand(numLabels), math.random(1,numLabels))
   -- input/target: 1D/1D
   testclassnll(torch.rand(numLabels), torch.LongTensor(1):random(1, numLabels))
   -- input/target: 2D/1D
   testclassnll(torch.rand(batchsize, numLabels), torch.LongTensor(batchsize):random(1,numLabels))
   -- test ignoreIndex
   local ignoreIndex = -1
   local cri = nn.ClassNLLCriterion(nil, nil, ignoreIndex)
   local input = torch.randn(numLabels)
   local target = ignoreIndex
   mytester:assert(cri:forward(input, target) == 0)
   mytester:assert(cri:backward(input, target):abs():sum() == 0)
   local input = torch.randn(batchsize, numLabels)
   local target = torch.LongTensor(batchsize):random(1,numLabels)
   target[1] = ignoreIndex
   local output = cri:forward(input, target)
   local gradInput = cri:backward(input, target):clone()
   mytester:assert(gradInput[1]:abs():sum() == 0)
   local input, target = input:sub(2,batchsize), target:sub(2,batchsize)
   local output2 = cri:forward(input, target)
   mytester:assert(math.abs(output2 - output) < 0.0000001)
   local gradInput2 = cri:backward(input, target)
   mytester:assertTensorEq(gradInput2, gradInput:sub(2,batchsize), 0.0000001)
end

function nntest.SpatialClassNLLCriterion()
   local numLabels = math.random(5,10)
   local h = math.random(5, 20)
   local w = math.random(5, 20)
   local batchSize = math.random(1, 4)
   local input = torch.rand(batchSize, numLabels, h, w)
   local target = torch.Tensor(batchSize, h, w)
   target:apply(function() return math.random(1, numLabels) end)

   -- default ClassNLLCriterion
   local cri = nn.SpatialClassNLLCriterion()
   criterionJacobianTest(cri, input, target)

   -- ClassNLLCriterion with weights
   local weights = torch.rand(numLabels)
   cri = nn.SpatialClassNLLCriterion(weights)
   criterionJacobianTest(cri, input, target)

   -- check with ClassNLLCriterion
   local spatial = nn.SpatialClassNLLCriterion(weights)
   local regular = nn.ClassNLLCriterion(weights)
   local spatial_out = spatial:forward(input, target)
   local regular_out = regular:forward(input:permute(1, 3, 4, 2):contiguous():view(-1, numLabels),
                                       target:view(-1))
   mytester:eq(spatial_out, regular_out, 1e-6,
         "spatial and regular criterions give different results")
end

function nntest.MultiLabelSoftMarginCriterion()
   -- test w/o weights

   local cri = nn.MultiLabelSoftMarginCriterion()

   -- stochastic
   local numLabels = math.random(5, 10)
   local input = torch.randn(numLabels)
   local target = torch.round(torch.rand(numLabels))
   criterionJacobianTest(cri, input, target)

   -- batch
   local numLabels = math.random(5, 10)
   local bsz = math.random(3, 7)
   local input = torch.randn(bsz, numLabels)
   local target = torch.round(torch.rand(bsz, numLabels))
   criterionJacobianTest(cri, input, target)

   -- test weights

   local numLabels = math.random(5, 10)
   local weights = torch.randn(numLabels)
   local cri = nn.MultiLabelSoftMarginCriterion(weights)

   -- stochastic
   local input = torch.randn(numLabels)
   local target = torch.round(torch.rand(numLabels))
   criterionJacobianTest(cri, input, target)

   -- batch
   local bsz = math.random(3, 7)
   local input = torch.randn(bsz, numLabels)
   local target = torch.round(torch.rand(bsz, numLabels))
   criterionJacobianTest(cri, input, target)
end

function nntest.CrossEntropyCriterion()
   -- stochastic
   local numLabels = math.random(5, 10)
   local input = torch.zeros(numLabels)
   local target = torch.random(1, numLabels)

   local cri = nn.CrossEntropyCriterion()
   criterionJacobianTest(cri, input, target)

   -- batch
   local numLabels = math.random(5,10)
   local bsz = math.random(3, 7)
   local input = torch.zeros(bsz, numLabels)
   local target = torch.Tensor(bsz):random(1, numLabels)

   local cri = nn.CrossEntropyCriterion()
   criterionJacobianTest(cri, input, target)

   -- with weights
   local weights = torch.rand(numLabels)
   weights = weights / weights:sum()
   cri = nn.CrossEntropyCriterion(weights)
   criterionJacobianTest(cri, input, target)

   -- verify nll.sizeAverage preservation
   cri = nn.CrossEntropyCriterion(weights)
   cri.nll.sizeAverage = false
   criterionJacobianTest(cri, input, target)
   mytester:eq(cri.nll.sizeAverage, false,
      "ClassNLLCriterion.sizeAverage overwritten")

   -- verify nll.sizeAverage propagation
   cri = nn.CrossEntropyCriterion(weights)
   cri.sizeAverage = false
   criterionJacobianTest(cri, input, target)
   mytester:eq(cri.nll.sizeAverage, false,
      "ClassNLLCriterion.sizeAverage not propagated")
end

function nntest.LogSigmoid()
   local ini = math.random(3,5)
   local inj = math.random(3,5)
   local ink = math.random(3,5)
   local input = torch.Tensor(ini,inj,ink):zero()
   local module = nn.LogSigmoid()

   local err = jac.testJacobian(module,input)
   mytester:assertlt(err,precision, 'error on state ')

   local ferr,berr = jac.testIO(module,input)
   mytester:eq(ferr, 0, torch.typename(module) .. ' - i/o forward err ', precision)
   mytester:eq(berr, 0, torch.typename(module) .. ' - i/o backward err ', precision)
end

function nntest.LogSoftmax()
   local ini = math.random(3,5)
   local inj = math.random(3,5)
   local input = torch.Tensor(ini,inj):zero()
   local module = nn.LogSoftMax()

   local err = jac.testJacobian(module,input)
   mytester:assertlt(err, 1e-3, 'error on state ')

   local ferr,berr = jac.testIO(module,input)
   mytester:eq(ferr, 0, torch.typename(module) .. ' - i/o forward err ', precision)
   mytester:eq(berr, 0, torch.typename(module) .. ' - i/o backward err ', precision)

   -- test logsoftmax when gradOutput is non-contiguous
   local layer = nn.LogSoftMax()
   layer:zeroGradParameters()
   local input = torch.randn(4, 10)
   local data = torch.randn(4, 20)
   local gradOutput = data:narrow(2, 1, 10):fill(0)
   local output = layer:forward(input)
   local gradInput1 = layer:backward(input, gradOutput):clone()
   local output = layer:forward(input)
   gradOutput = gradOutput:clone()
   local gradInput2 = layer:backward(input, gradOutput):clone()

   mytester:assertlt(gradInput1:add(-1, gradInput2):abs():max(),
           1e-10,
           torch.typename(layer)
         .. ' non-contiguous gradOutput check')




end

function nntest.SpatialLogSoftMax()
   local ini = math.random(3,5)
   local inj = math.random(3,5)
   local ink = math.random(3,5)
   local inl = math.random(3,5)
   local input = torch.Tensor(inl, ink, inj, ini):zero()
   local module = nn.SpatialLogSoftMax()

   local err = jac.testJacobian(module,input)
   mytester:assertlt(err,expprecision, 'error on state ')

   local ferr,berr = jac.testIO(module,input)
   mytester:asserteq(ferr, 0, torch.typename(module) .. ' - i/o forward err ')
   mytester:asserteq(berr, 0, torch.typename(module) .. ' - i/o backward err ')
end

-- function nntest.TemporalLogSoftmax()
--    local ini = math.random(10,20)
--    local inj = math.random(10,20)
--    local input = torch.Tensor(ini,inj):zero()
--    local module = nn.TemporalLogSoftMax()

--    local err = jac.testJacobian(module,input)
--    mytester:assertlt(err,precision, 'error on state ')

--    local ferr,berr = jac.testIO(module,input)
--    mytester:eq(ferr, 0, torch.typename(module) .. ' - i/o forward err ', precision)
--    mytester:eq(berr, 0, torch.typename(module) .. ' - i/o backward err ', precision)
-- end

function nntest.Max()
   -- 1D
   local ini = math.random(3,7)
   local input = torch.Tensor(ini):zero()
   local module = nn.Max(1)

   local err = jac.testJacobian(module,input)
   mytester:assertlt(err,precision, 'error on state ')

   -- negative dimension
   local module = nn.Max(-1)
   local input = torch.Tensor({1, 2, 3})
   local expected = torch.Tensor({3})
   local output = module:forward(input)
   mytester:assertlt(torch.norm(output-expected), precision, 'error on forward ')
   -- batch
   local module = nn.Max(1, 1)
   local input = torch.Tensor({{1, 2, 3},{4, 5, 6}})
   local expected = torch.Tensor({3, 6})
   local output = module:forward(input)
   mytester:assertlt(torch.norm(output-expected), precision, 'error on forward ')

   -- 3D
   local ini = math.random(3,5)
   local inj = math.random(3,5)
   local ink = math.random(3,5)
   local input = torch.Tensor(ini,inj*ink):zero()
   local module = nn.Max(1)

   local err = jac.testJacobian(module,input)
   mytester:assertlt(err,precision, 'error on state ')

   local ferr,berr = jac.testIO(module,input)
   mytester:eq(ferr, 0, torch.typename(module) .. ' - i/o forward err ', precision)
   mytester:eq(berr, 0, torch.typename(module) .. ' - i/o backward err ', precision)
end

function nntest.Min()
   -- 1D
   local ini = math.random(3,7)
   local input = torch.Tensor(ini):zero()
   local module = nn.Min(1)

   local err = jac.testJacobian(module,input)
   mytester:assertlt(err,precision, 'error on state ')

   -- negative dimension
   local module = nn.Min(-1)
   local input = torch.Tensor({1, 2, 3})
   local expected = torch.Tensor({1})
   local output = module:forward(input)
   mytester:assertlt(torch.norm(output-expected), precision, 'error on forward ')
   -- batch
   local module = nn.Min(1, 1)
   local input = torch.Tensor({{1, 2, 3},{4, 5, 6}})
   local expected = torch.Tensor({1, 4})
   local output = module:forward(input)
   mytester:assertlt(torch.norm(output-expected), precision, 'error on forward ')

   -- 3D
   local ini = math.random(3,5)
   local inj = math.random(3,5)
   local ink = math.random(3,5)
   local input = torch.Tensor(ini,inj*ink):zero()
   local module = nn.Min(1)

   local err = jac.testJacobian(module,input)
   mytester:assertlt(err,precision, 'error on state ')

   local ferr,berr = jac.testIO(module,input)
   mytester:eq(ferr, 0, torch.typename(module) .. ' - i/o forward err ', precision)
   mytester:eq(berr, 0, torch.typename(module) .. ' - i/o backward err ', precision)
end

function nntest.Mean()
   -- 1D
   local ini = math.random(3,7)
   local input = torch.Tensor(ini):zero()
   local module = nn.Mean(1)

   local err = jac.testJacobian(module,input)
   mytester:assertlt(err,precision, 'error on state ')

   -- negative dimension
   local module = nn.Mean(-1)
   local input = torch.Tensor({1, 2, 3})
   local expected = torch.Tensor({2})
   local output = module:forward(input)
   mytester:assertlt(torch.norm(output-expected), precision, 'error on forward ')
   -- batch
   local module = nn.Mean(1, 1)
   local input = torch.Tensor({{1, 2, 3},{4, 5, 6}})
   local expected = torch.Tensor({2, 5})
   local output = module:forward(input)
   mytester:assertlt(torch.norm(output-expected), precision, 'error on forward ')

   -- 3D
   local ini = math.random(3,5)
   local inj = math.random(3,5)
   local ink = math.random(3,5)
   local input = torch.Tensor(ini,inj,ink):zero()
   local module = nn.Mean(torch.random(1,3))

   local err = jac.testJacobian(module,input)
   mytester:assertlt(err,precision, 'error on state ')

   local ferr,berr = jac.testIO(module,input)
   mytester:eq(ferr, 0, torch.typename(module) .. ' - i/o forward err ', precision)
   mytester:eq(berr, 0, torch.typename(module) .. ' - i/o backward err ', precision)
end

function nntest.Mul()
   local ini = math.random(3,5)
   local inj = math.random(3,5)
   local ink = math.random(3,5)
   local input = torch.Tensor(ini,inj,ink):zero()
   local module = nn.Mul()

   local err = jac.testJacobian(module,input)
   mytester:assertlt(err,precision, 'error on state ')
   local err = jac.testJacobianParameters(module, input, module.weight, module.gradWeight)
   mytester:assertlt(err,precision, 'error on weight ')
   local err = jac.testJacobianUpdateParameters(module, input, module.weight)
   mytester:assertlt(err,precision, 'error on weight [direct update] ')

   for t,err in pairs(jac.testAllUpdate(module, input, 'weight', 'gradWeight')) do
      mytester:assertlt(err, precision, string.format(
                         'error on weight [%s]', t))
   end

   local ferr,berr = jac.testIO(module,input)
   mytester:eq(ferr, 0, torch.typename(module) .. ' - i/o forward err ', precision)
   mytester:eq(berr, 0, torch.typename(module) .. ' - i/o backward err ', precision)
end

function nntest.Sigmoid()
   local ini = math.random(3,5)
   local inj = math.random(3,5)
   local ink = math.random(3,5)
   local input = torch.Tensor(ini,inj,ink):zero()
   local module = nn.Sigmoid()

   local err = jac.testJacobian(module,input)
   mytester:assertlt(err,precision, 'error on state ')

   local ferr,berr = jac.testIO(module,input)
   mytester:eq(ferr, 0, torch.typename(module) .. ' - i/o forward err ', precision)
   mytester:eq(berr, 0, torch.typename(module) .. ' - i/o backward err ', precision)
end

function nntest.Softmax()
   local ini = math.random(3,5)
   local ink = math.random(3,5)
   local input = torch.Tensor(ink, ini):zero()
   local module = nn.SoftMax()

   local err = jac.testJacobian(module,input)
   mytester:assertlt(err,expprecision, 'error on state ')

   local ferr,berr = jac.testIO(module,input)
   mytester:eq(ferr, 0, torch.typename(module) .. ' - i/o forward err ', precision)
   mytester:eq(berr, 0, torch.typename(module) .. ' - i/o backward err ', precision)
end

function nntest.SpatialSoftMax()
   local ini = math.random(3,5)
   local inj = math.random(3,5)
   local ink = math.random(3,5)
   local inl = math.random(3,5)
   local input = torch.Tensor(inl, ink, inj, ini):zero()
   local module = nn.SpatialSoftMax()

   local err = jac.testJacobian(module,input)
   mytester:assertlt(err,expprecision, 'error on state ')

   local ferr,berr = jac.testIO(module,input)
   mytester:eq(ferr, 0, torch.typename(module) .. ' - i/o forward err ', precision)
   mytester:eq(berr, 0, torch.typename(module) .. ' - i/o backward err ', precision)
end

function nntest.Softmin()
   local ini = math.random(3,5)
   local ink = math.random(3,5)
   local input = torch.Tensor(ink, ini):zero()
   local module = nn.SoftMin()

   local err = jac.testJacobian(module,input)
   mytester:assertlt(err,expprecision, 'error on state ')

   local ferr,berr = jac.testIO(module,input)
   mytester:eq(ferr, 0, torch.typename(module) .. ' - i/o forward err ', precision)
   mytester:eq(berr, 0, torch.typename(module) .. ' - i/o backward err ', precision)
end

function nntest.Softsign()
   local ini = math.random(3,5)
   local ink = math.random(3,5)
   local input = torch.Tensor(ink, ini):zero()
   local module = nn.SoftSign()

   local err = jac.testJacobian(module,input)
   mytester:assertlt(err,precision, 'error on state ')

   local ferr,berr = jac.testIO(module,input)
   mytester:eq(ferr, 0, torch.typename(module) .. ' - i/o forward err ', precision)
   mytester:eq(berr, 0, torch.typename(module) .. ' - i/o backward err ', precision)
end

function nntest.SoftPlus()
   local ini = math.random(3,5)
   local inj = math.random(3,5)
   local ink = math.random(3,5)
   local input = torch.Tensor(ini,inj,ink):zero()
   local module = nn.SoftPlus()

   local err = jac.testJacobian(module,input)
   mytester:assertlt(err,precision, 'error on state ')

   local ferr,berr = jac.testIO(module,input)
   mytester:eq(ferr, 0, torch.typename(module) .. ' - i/o forward err ', precision)
   mytester:eq(berr, 0, torch.typename(module) .. ' - i/o backward err ', precision)
end

function nntest.SpatialSubtractiveNormalization_2dkernel()
   local inputSize = math.random(6,9)
   local kersize = 3
   local nbfeatures = math.random(3,5)
   local kernel = torch.Tensor(kersize,kersize):fill(1)
   local module = nn.SpatialSubtractiveNormalization(nbfeatures,kernel)
   local input = torch.rand(nbfeatures,inputSize,inputSize/2)

   local err = jac.testJacobian(module,input)
   mytester:assertlt(err,precision, 'error on state ')

   local ferr,berr = jac.testIO(module,input)
   mytester:eq(ferr, 0, torch.typename(module) .. ' - i/o forward err ', precision)
   mytester:eq(berr, 0, torch.typename(module) .. ' - i/o backward err ', precision)

    -- test batch mode
   local output = module:forward(input):clone()
   local gradOutput = output:clone():uniform(0,1)
   local gradInput = module:backward(input, gradOutput):clone()
   local batchSize = 4
   local input2 = torch.rand(batchSize,nbfeatures,inputSize,inputSize/2)
   input2[2]:copy(input)

   local output2 = module:forward(input2)
   local gradOutput2 = output2:clone():uniform(0,1)
   gradOutput2[2]:copy(gradOutput)
   local gradInput2 = module:backward(input2, gradOutput2)

   mytester:assertTensorEq(output2[2], output, 0.000001, "SpatialSubstractiveNormalization 2d forward batch err")
   mytester:assertTensorEq(gradOutput2[2], gradOutput, 0.000001, "SpatialSubstractiveNormalization 2d backward batch err")

   local err = jac.testJacobian(module,input2)
   mytester:assertlt(err,precision, 'error on state ')

   local ferr,berr = jac.testIO(module,input2)
   mytester:eq(ferr, 0, torch.typename(module) .. ' - i/o forward err ', precision)
   mytester:eq(berr, 0, torch.typename(module) .. ' - i/o backward err ', precision)

end

function nntest.SpatialSubtractiveNormalization_1dkernel()
   local inputSize = math.random(6,9)
   local kersize = 3
   local nbfeatures = math.random(3,5)
   local kernel = torch.Tensor(kersize):fill(1)
   local module = nn.SpatialSubtractiveNormalization(nbfeatures,kernel)
   local input = torch.rand(nbfeatures,inputSize,inputSize/2)

   local err = jac.testJacobian(module,input)
   mytester:assertlt(err,precision, 'error on state ')

   local ferr,berr = jac.testIO(module,input)
   mytester:eq(ferr, 0, torch.typename(module) .. ' - i/o forward err ', precision)
   mytester:eq(berr, 0, torch.typename(module) .. ' - i/o backward err ', precision)

    -- test batch mode
   local output = module:forward(input):clone()
   local gradOutput = output:clone():uniform(0,1)
   local gradInput = module:backward(input, gradOutput):clone()
   local batchSize = 4
   local input2 = torch.rand(batchSize,nbfeatures,inputSize,inputSize/2)
   input2[2]:copy(input)

   local output2 = module:forward(input2)
   local gradOutput2 = output2:clone():uniform(0,1)
   gradOutput2[2]:copy(gradOutput)
   local gradInput2 = module:backward(input2, gradOutput2)

   mytester:assertTensorEq(output2[2], output, 0.000001, "SpatialSubstractiveNormalization 1d forward batch err")
   mytester:assertTensorEq(gradOutput2[2], gradOutput, 0.000001, "SpatialSubstractiveNormalization 1d backward batch err")

   local err = jac.testJacobian(module,input2)
   mytester:assertlt(err,precision, 'error on state ')

   local ferr,berr = jac.testIO(module,input2)
   mytester:eq(ferr, 0, torch.typename(module) .. ' - i/o forward err ', precision)
   mytester:eq(berr, 0, torch.typename(module) .. ' - i/o backward err ', precision)
end

function nntest.SpatialDivisiveNormalization_2dkernel()
   local inputSize = math.random(6,9)
   local kersize = 3
   local nbfeatures = math.random(3,5)
   local kernel = torch.Tensor(kersize,kersize):fill(1)
   local module = nn.SpatialDivisiveNormalization(nbfeatures,kernel)
   local input = torch.rand(nbfeatures,inputSize,inputSize/2)

   local err = jac.testJacobian(module,input)
   mytester:assertlt(err,precision, 'error on state ')

   local ferr,berr = jac.testIO(module,input)
   mytester:eq(ferr, 0, torch.typename(module) .. ' - i/o forward err ', precision)
   mytester:eq(berr, 0, torch.typename(module) .. ' - i/o backward err ', precision)

   -- test batch mode
   local output = module:forward(input):clone()
   local gradOutput = output:clone():uniform(0,1)
   local gradInput = module:backward(input, gradOutput):clone()
   local batchSize = 4
   local input2 = torch.rand(batchSize,nbfeatures,inputSize,inputSize/2)
   input2[2]:copy(input)

   local output2 = module:forward(input2)
   local gradOutput2 = output2:clone():uniform(0,1)
   gradOutput2[2]:copy(gradOutput)
   local gradInput2 = module:backward(input2, gradOutput2)

   mytester:assertTensorEq(output2[2], output, 0.000001, "SpatialDivisiveNormalization 2d forward batch err")
   mytester:assertTensorEq(gradOutput2[2], gradOutput, 0.000001, "SpatialDivisiveNormalization 2d backward batch err")

   local err = jac.testJacobian(module,input2)
   mytester:assertlt(err,precision, 'error on state ')

   local ferr,berr = jac.testIO(module,input2)
   mytester:eq(ferr, 0, torch.typename(module) .. ' - i/o forward err ', precision)
   mytester:eq(berr, 0, torch.typename(module) .. ' - i/o backward err ', precision)
end

function nntest.SpatialDivisiveNormalization_1dkernel()
   local inputSize = math.random(6,9)
   local kersize = 3
   local nbfeatures = math.random(3,5)
   local kernel = torch.Tensor(kersize):fill(1)
   local module = nn.SpatialDivisiveNormalization(nbfeatures,kernel)
   local input = torch.rand(nbfeatures,inputSize,inputSize/2)

   local err = jac.testJacobian(module,input)
   mytester:assertlt(err,precision, 'error on state ')

   local ferr,berr = jac.testIO(module,input)
   mytester:eq(ferr, 0, torch.typename(module) .. ' - i/o forward err ', precision)
   mytester:eq(berr, 0, torch.typename(module) .. ' - i/o backward err ', precision)

    -- test batch mode
   local output = module:forward(input):clone()
   local gradOutput = output:clone():uniform(0,1)
   local gradInput = module:backward(input, gradOutput):clone()
   local batchSize = 4
   local input2 = torch.rand(batchSize,nbfeatures,inputSize,inputSize/2)
   input2[2]:copy(input)

   local output2 = module:forward(input2)
   local gradOutput2 = output2:clone():uniform(0,1)
   gradOutput2[2]:copy(gradOutput)
   local gradInput2 = module:backward(input2, gradOutput2)

   mytester:assertTensorEq(output2[2], output, 0.000001, "SpatialDivisiveNormalization 1d forward batch err")
   mytester:assertTensorEq(gradOutput2[2], gradOutput, 0.000001, "SpatialDivisiveNormalization 1d backward batch err")

   local err = jac.testJacobian(module,input2)
   mytester:assertlt(err,precision, 'error on state ')

   local ferr,berr = jac.testIO(module,input2)
   mytester:eq(ferr, 0, torch.typename(module) .. ' - i/o forward err ', precision)
   mytester:eq(berr, 0, torch.typename(module) .. ' - i/o backward err ', precision)
end

function nntest.SpatialContrastiveNormalization()
   local inputSize = math.random(6,9)
   local kersize = 3
   local nbfeatures = math.random(3,5)
   local kernel = torch.Tensor(kersize,kersize):fill(1)
   local module = nn.SpatialContrastiveNormalization(nbfeatures,kernel)
   local input = torch.rand(nbfeatures,inputSize,inputSize/2)

   local err = jac.testJacobian(module,input)
   mytester:assertlt(err,precision, 'error on state ')

   local ferr,berr = jac.testIO(module,input)
   mytester:eq(ferr, 0, torch.typename(module) .. ' - i/o forward err ', precision)
   mytester:eq(berr, 0, torch.typename(module) .. ' - i/o backward err ', precision)

   -- test batch mode and type
   local output = module:forward(input):clone()
   local gradOutput = output:clone():uniform(0,1)
   local gradInput = module:backward(input, gradOutput):clone()
   local batchSize = 4
   local input2 = torch.rand(batchSize,nbfeatures,inputSize,inputSize/2):float()
   input2[2]:copy(input)

   module:float() -- type-cast
   local output2 = module:forward(input2)
   local gradOutput2 = output2:clone():uniform(0,1)
   gradOutput2[2]:copy(gradOutput)
   local gradInput2 = module:backward(input2, gradOutput2)

   mytester:assertTensorEq(output2[2], output:float(), 0.000002, "SpatialContrastiveNormalization 2d forward batch err")
   mytester:assertTensorEq(gradOutput2[2], gradOutput:float(), 0.000002, "SpatialContrastiveNormalization 2d backward batch err")

   module:double()
   input2 = input2:double()
   local err = jac.testJacobian(module,input2)
   mytester:assertlt(err,precision, 'error on state ')

   local ferr,berr = jac.testIO(module,input2)
   mytester:eq(ferr, 0, torch.typename(module) .. ' - i/o forward err ', precision)
   mytester:eq(berr, 0, torch.typename(module) .. ' - i/o backward err ', precision)
end

function nntest.SpatialCrossMapLRN()
   local inputSize = math.random(6,9)
   local size = math.random(1,3)*2+1
   local nbfeatures = math.random(3,8)
   local alpha = math.random(1,100)/100
   local beta  = math.random(0,100)/100
   local k = math.random(1,3)
   local module = nn.SpatialCrossMapLRN(size, alpha, beta, k)
   local input = torch.rand(nbfeatures,inputSize,inputSize)

   local err = jac.testJacobian(module,input)
   mytester:assertlt(err,precision, 'error on state ')

   local ferr,berr = jac.testIO(module,input)
   mytester:eq(ferr, 0, torch.typename(module) .. ' - i/o forward err ', precision)
   mytester:eq(berr, 0, torch.typename(module) .. ' - i/o backward err ', precision)

   -- test batch mode and type
   local output = module:forward(input):clone()
   local gradOutput = output:clone():uniform(0,1)
   local gradInput = module:backward(input, gradOutput):clone()
   local batchSize = 4
   local input2 = torch.rand(batchSize,nbfeatures,inputSize,inputSize):float()
   input2[2]:copy(input)

   module:float() -- type-cast
   local output2 = module:forward(input2)
   local gradOutput2 = output2:clone():uniform(0,1)
   gradOutput2[2]:copy(gradOutput)
   local gradInput2 = module:backward(input2, gradOutput2)

   mytester:assertTensorEq(output2[2], output:float(), 0.000001, "SpatialCrossMapLRN 2d forward batch err")
   mytester:assertTensorEq(gradOutput2[2], gradOutput:float(), 0.000001, "SpatialCrossMapLRN 2d backward batch err")

   module:double()
   input2 = input2:double()
   local err = jac.testJacobian(module,input2)
   mytester:assertlt(err,precision, 'error on state ')

   local ferr,berr = jac.testIO(module,input2)
   mytester:eq(ferr, 0, torch.typename(module) .. ' - i/o forward err ', precision)
   mytester:eq(berr, 0, torch.typename(module) .. ' - i/o backward err ', precision)
end


function nntest.SpatialConvolution()
   local from = math.random(1,5)
   local to = math.random(1,5)
   local ki = math.random(1,5)
   local kj = math.random(1,5)
   local si = math.random(1,4)
   local sj = math.random(1,4)
   local outi = math.random(5,7)
   local outj = math.random(5,7)
   local ini = (outi-1)*si+ki
   local inj = (outj-1)*sj+kj
   local module = nn.SpatialConvolution(from, to, ki, kj, si, sj)
   local input = torch.Tensor(from, inj, ini):zero()

   local function jacTests(module)
      -- stochastic

      local err = jac.testJacobian(module, input)
      mytester:assertlt(err, precision, 'error on state ')

      local err = jac.testJacobianParameters(module, input, module.weight, module.gradWeight)
      mytester:assertlt(err , precision, 'error on weight ')

      if module.bias then
         local err = jac.testJacobianParameters(module, input, module.bias, module.gradBias)
         mytester:assertlt(err , precision, 'error on bias ')
      end

      local err = jac.testJacobianUpdateParameters(module, input, module.weight)
      mytester:assertlt(err , precision, 'error on weight [direct update] ')

      if module.bias then
         local err = jac.testJacobianUpdateParameters(module, input, module.bias)
         mytester:assertlt(err , precision, 'error on bias [direct update] ')
      end

      nn.hessian.enable()

      local err = jac.testDiagHessianInput(module, input)
      mytester:assertlt(err , precision, 'error on diagHessianInput')

      local err = jac.testDiagHessianWeight(module, input)
      mytester:assertlt(err , precision, 'error on diagHessianWeight')

      if module.bias then
         local err = jac.testDiagHessianBias(module, input)
         mytester:assertlt(err , precision, 'error on diag HessianBias')
      end

      for t,err in pairs(jac.testAllUpdate(module, input, 'weight', 'gradWeight')) do
         mytester:assertlt(err, precision, string.format(
                              'error on weight [%s]', t))
      end

      if module.bias then
         for t,err in pairs(jac.testAllUpdate(module, input, 'bias', 'gradBias')) do
            mytester:assertlt(err, precision, string.format(
                                 'error on bias [%s]', t))
         end
      end

      -- batch

      --verbose = true
      local batch = math.random(2,5)
      outi = math.random(4,8)
      outj = math.random(4,8)
      ini = (outi-1)*si+ki
      inj = (outj-1)*sj+kj
      module = nn.SpatialConvolution(from, to, ki, kj, si, sj)
      input = torch.Tensor(batch,from,inj,ini):zero()

      local err = jac.testJacobian(module, input)
      mytester:assertlt(err, precision, 'batch error on state ')

      local err = jac.testJacobianParameters(module, input, module.weight, module.gradWeight)
      mytester:assertlt(err , precision, 'batch error on weight ')

      if module.bias then
         local err = jac.testJacobianParameters(module, input, module.bias, module.gradBias)
         mytester:assertlt(err , precision, 'batch error on bias ')
      end

      local err = jac.testJacobianUpdateParameters(module, input, module.weight)
      mytester:assertlt(err , precision, 'batch error on weight [direct update] ')

      if module.bias then
         local err = jac.testJacobianUpdateParameters(module, input, module.bias)
         mytester:assertlt(err , precision, 'batch error on bias [direct update] ')
      end

      local err = jac.testDiagHessianInput(module, input)
      mytester:assertlt(err , precision, 'error on diagHessianInput')

      local err = jac.testDiagHessianWeight(module, input)
      mytester:assertlt(err , precision, 'error on diagHessianWeight')

      if module.bias then
         local err = jac.testDiagHessianBias(module, input)
         mytester:assertlt(err , precision, 'error on diag HessianBias')
      end

      for t,err in pairs(jac.testAllUpdate(module, input, 'weight', 'gradWeight')) do
         mytester:assertlt(err, precision, string.format(
                              'error on weight [%s]', t))
      end

      if module.bias then
         for t,err in pairs(jac.testAllUpdate(module, input, 'bias', 'gradBias')) do
            mytester:assertlt(err, precision, string.format(
                                 'batch error on bias [%s]', t))
         end
      end

      local ferr, berr = jac.testIO(module, input)
      mytester:eq(0, ferr, torch.typename(module) .. ' - i/o forward err ', precision)
      mytester:eq(0, berr, torch.typename(module) .. ' - i/o backward err ', precision)
   end

   jacTests(module)
   module:noBias()
   jacTests(module)
   module.bias = torch.Tensor(module.nOutputPlane):zero()
   module.gradBias = torch.Tensor(module.nOutputPlane):zero()
   module:reset()
   jacTests(module)

   local output = module:forward(input):clone()
   local gradOutput = output:clone():normal()
   local gradInput = module:forward(input, gradOutput):clone()
   local bigWeight = module.weight.new(module.weight:nElement() * 4):fill(0/0) -- fill with nans
   local newWeight = bigWeight:narrow(1, module.weight:nElement() * 3, module.weight:nElement())
   newWeight = newWeight:viewAs(module.weight):copy(module.weight)
   module.weight = newWeight
   local newOutput = module:forward(input)
   local newGradInput = module:forward(input, gradOutput)
   mytester:asserteq((newOutput - output):abs():max(), 0,
      torch.typename(module) .. ' forward failure case in a getParameters setting ')
   mytester:asserteq((newGradInput - gradInput):abs():max(), 0,
      torch.typename(module) .. ' backward failure case in a getParameters setting ')

end

function nntest.SpatialConvolutionMM()
   local from = math.random(2,5)
   local to = math.random(1,5)
   local ki = math.random(1,5)
   local kj = math.random(1,5)
   local di =  math.random(1,4)
   local dj =  math.random(1,4)
   local padW = math.random(0,2)
   local padH = math.random(0,2)
   local outi = math.random(5,9)
   local outj = math.random(5,9)
   local ini = (outi-1)*di+ki-padW*2
   local inj = (outj-1)*dj+kj-padH*2
   local module = nn.SpatialConvolutionMM(from, to, ki, kj, di, dj, padW, padH)
   local input = torch.Tensor(from, inj, ini):zero()

   -- stochastic

   local err = jac.testJacobian(module, input)
   mytester:assertlt(err, precision, 'error on state ')

   local err = jac.testJacobianParameters(module, input, module.weight, module.gradWeight)
   mytester:assertlt(err , precision, 'error on weight ')

   local err = jac.testJacobianParameters(module, input, module.bias, module.gradBias)
   mytester:assertlt(err , precision, 'error on bias ')

   local err = jac.testJacobianUpdateParameters(module, input, module.weight)
   mytester:assertlt(err , precision, 'error on weight [direct update] ')

   local err = jac.testJacobianUpdateParameters(module, input, module.bias)
   mytester:assertlt(err , precision, 'error on bias [direct update] ')

   for t,err in pairs(jac.testAllUpdate(module, input, 'weight', 'gradWeight')) do
      mytester:assertlt(err, precision, string.format(
                         'error on weight [%s]', t))
   end

   for t,err in pairs(jac.testAllUpdate(module, input, 'bias', 'gradBias')) do
      mytester:assertlt(err, precision, string.format(
                         'error on bias [%s]', t))
   end

   -- batch

   --verbose = true
   local batch = math.random(2,5)

   module = nn.SpatialConvolutionMM(from, to, ki, kj, di, dj, padW, padH)
   input = torch.Tensor(batch,from,inj,ini):zero()

   local err = jac.testJacobian(module, input)
   mytester:assertlt(err, precision, 'batch error on state ')

   local err = jac.testJacobianParameters(module, input, module.weight, module.gradWeight)
   mytester:assertlt(err , precision, 'batch error on weight ')

   local err = jac.testJacobianParameters(module, input, module.bias, module.gradBias)
   mytester:assertlt(err , precision, 'batch error on bias ')

   local err = jac.testJacobianUpdateParameters(module, input, module.weight)
   mytester:assertlt(err , precision, 'batch error on weight [direct update] ')

   local err = jac.testJacobianUpdateParameters(module, input, module.bias)
   mytester:assertlt(err , precision, 'batch error on bias [direct update] ')

   for t,err in pairs(jac.testAllUpdate(module, input, 'weight', 'gradWeight')) do
      mytester:assertlt(err, precision, string.format(
                         'error on weight [%s]', t))
   end

   for t,err in pairs(jac.testAllUpdate(module, input, 'bias', 'gradBias')) do
      mytester:assertlt(err, precision, string.format(
                         'batch error on bias [%s]', t))
   end

   local ferr, berr = jac.testIO(module, input)
   mytester:eq(0, ferr, torch.typename(module) .. ' - i/o forward err ', precision)
   mytester:eq(0, berr, torch.typename(module) .. ' - i/o backward err ', precision)

   -- non-contiguous
   local input = torch.randn(batch,from,ini,inj):transpose(3,4) -- non-contiguous
   local inputc = input:contiguous() -- contiguous
   local output = module:forward(input):clone()
   local outputc = module:forward(inputc):clone()
   mytester:asserteq(0, (output-outputc):abs():max(), torch.typename(module) .. ' - contiguous err ')
   local gradInput = module:backward(input, output):clone()
   local gradInputc = module:backward(inputc, outputc):clone()
   mytester:asserteq(0, (gradInput-gradInputc):abs():max(), torch.typename(module) .. ' - contiguous err ')
end

function nntest.SpatialConvolutionLocal()
   local from = math.random(1,4)
   local to = math.random(1,4)
   local ki = math.random(1,3)
   local kj = math.random(1,3)
   local si = math.random(1,3)
   local sj = math.random(1,3)
   local outi = math.random(5,6)
   local outj = math.random(5,6)
   local ini = (outi-1)*si+ki
   local inj = (outj-1)*sj+kj
   local module = nn.SpatialConvolutionLocal(from, to, ini, inj, ki, kj, si, sj)
   local input = torch.Tensor(from, inj, ini):zero()

   -- stochastic

   local err = jac.testJacobian(module, input)
   mytester:assertlt(err, precision, 'error on state ')

   local err = jac.testJacobianParameters(module, input, module.weight, module.gradWeight)
   mytester:assertlt(err , precision, 'error on weight ')

   local err = jac.testJacobianParameters(module, input, module.bias, module.gradBias)
   mytester:assertlt(err , precision, 'error on bias ')

   local err = jac.testJacobianUpdateParameters(module, input, module.weight)
   mytester:assertlt(err , precision, 'error on weight [direct update] ')

   local err = jac.testJacobianUpdateParameters(module, input, module.bias)
   mytester:assertlt(err , precision, 'error on bias [direct update] ')

   nn.hessian.enable()

   local err = jac.testDiagHessianInput(module, input)
   mytester:assertlt(err , precision, 'error on diagHessianInput')

   local err = jac.testDiagHessianWeight(module, input)
   mytester:assertlt(err , precision, 'error on diagHessianWeight')

   local err = jac.testDiagHessianBias(module, input)
   mytester:assertlt(err , precision, 'error on diag HessianBias')

   for t,err in pairs(jac.testAllUpdate(module, input, 'weight', 'gradWeight')) do
      mytester:assertlt(err, precision, string.format(
                         'error on weight [%s]', t))
   end

   for t,err in pairs(jac.testAllUpdate(module, input, 'bias', 'gradBias')) do
      mytester:assertlt(err, precision, string.format(
                         'error on bias [%s]', t))
   end

   -- batch

   --verbose = true
   local batch = math.random(2,5)
   outi = math.random(4,6)
   outj = math.random(4,6)
   ini = (outi-1)*si+ki
   inj = (outj-1)*sj+kj
   module = nn.SpatialConvolutionLocal(from, to, ini, inj, ki, kj, si, sj)
   input = torch.Tensor(batch, from, inj, ini):zero()

   local err = jac.testJacobian(module, input)
   mytester:assertlt(err, precision, 'batch error on state ')

   local err = jac.testJacobianParameters(module, input, module.weight, module.gradWeight)
   mytester:assertlt(err , precision, 'batch error on weight ')

   local err = jac.testJacobianParameters(module, input, module.bias, module.gradBias)
   mytester:assertlt(err , precision, 'batch error on bias ')

   local err = jac.testJacobianUpdateParameters(module, input, module.weight)
   mytester:assertlt(err , precision, 'batch error on weight [direct update] ')

   local err = jac.testJacobianUpdateParameters(module, input, module.bias)
   mytester:assertlt(err , precision, 'batch error on bias [direct update] ')

   local err = jac.testDiagHessianInput(module, input)
   mytester:assertlt(err , precision, 'error on diagHessianInput')

   local err = jac.testDiagHessianWeight(module, input)
   mytester:assertlt(err , precision, 'error on diagHessianWeight')

   local err = jac.testDiagHessianBias(module, input)
   mytester:assertlt(err , precision, 'error on diag HessianBias')

   for t,err in pairs(jac.testAllUpdate(module, input, 'weight', 'gradWeight')) do
      mytester:assertlt(err, precision, string.format(
                         'error on weight [%s]', t))
   end

   for t,err in pairs(jac.testAllUpdate(module, input, 'bias', 'gradBias')) do
      mytester:assertlt(err, precision, string.format(
                         'batch error on bias [%s]', t))
   end

   local ferr, berr = jac.testIO(module, input)
   mytester:eq(0, ferr, torch.typename(module) .. ' - i/o forward err ', precision)
   mytester:eq(0, berr, torch.typename(module) .. ' - i/o backward err ', precision)

   -- check against nn.SpatialConvolution
   local conv = nn.SpatialConvolution(from, to, ki, kj, si, sj)
   torch.repeatTensor(module.bias, conv.bias:view(to, 1, 1), 1, outj, outi)
   torch.repeatTensor(module.weight, conv.weight:view(1, 1, from, to, ki, kj), outi, outj, 1, 1, 1, 1)
   local input = torch.rand(batch, from, inj, ini)
   local output = module:forward(input)
   local outputConv = conv:forward(input)
   local err = torch.dist(output, outputConv)
   mytester:assertlt(err, precision, 'error checking against nn.SpatialConvolution')
end

function nntest.SpatialFullConvolution()
   local from = math.random(2,5)
   local to = math.random(1,5)
   local ki = math.random(1,5)
   local kj = math.random(1,5)
   local di =  math.random(1,4)
   local dj =  math.random(1,4)
   local padW = math.random(0,2)
   local padH = math.random(0,2)
   local outi = math.random(5,9)
   local outj = math.random(5,9)
   local adjW = (outi + padW*2 - ki) % di
   local adjH = (outj + padH*2 - kj) % dj
   local ini = math.floor((outi + padW*2 - ki)/di + 1)
   local inj = math.floor((outj + padH*2 - kj)/dj + 1)
   local module = nn.SpatialFullConvolution(from, to, ki, kj, di, dj, padW, padH, adjW, adjH)
   local input = torch.Tensor(from, inj, ini):zero()

   local function jacTests(module)
      -- stochastic

      local err = jac.testJacobian(module, input)
      mytester:assertlt(err, precision, 'error on state ')

      local err = jac.testJacobianParameters(module, input, module.weight, module.gradWeight)
      mytester:assertlt(err , precision, 'error on weight ')

      if module.bias then
         local err = jac.testJacobianParameters(module, input, module.bias, module.gradBias)
         mytester:assertlt(err , precision, 'error on bias ')
      end

      local err = jac.testJacobianUpdateParameters(module, input, module.weight)
      mytester:assertlt(err , precision, 'error on weight [direct update] ')

      if module.bias then
         local err = jac.testJacobianUpdateParameters(module, input, module.bias)
         mytester:assertlt(err , precision, 'error on bias [direct update] ')
      end

      for t,err in pairs(jac.testAllUpdate(module, input, 'weight', 'gradWeight')) do
         mytester:assertlt(err, precision, string.format(
                            'error on weight [%s]', t))
      end

      if module.bias then
         for t,err in pairs(jac.testAllUpdate(module, input, 'bias', 'gradBias')) do
            mytester:assertlt(err, precision, string.format(
                               'error on bias [%s]', t))
         end
      end

      -- batch

      --verbose = true
      local batch = math.random(2,5)

      module = nn.SpatialFullConvolution(from, to, ki, kj, di, dj, padW, padH, adjW, adjH)
      input = torch.Tensor(batch,from,inj,ini):zero()

      -- Check that the required output size matches the actual output size
      local output = module:forward(input)
      mytester:asserteq(output:size(3), outj, 'output height error')
      mytester:asserteq(output:size(4), outi, 'output width error')

      local err = jac.testJacobian(module, input)
      mytester:assertlt(err, precision, 'batch error on state ')

      local err = jac.testJacobianParameters(module, input, module.weight, module.gradWeight)
      mytester:assertlt(err , precision, 'batch error on weight ')

      if module.bias then
         local err = jac.testJacobianParameters(module, input, module.bias, module.gradBias)
         mytester:assertlt(err , precision, 'batch error on bias ')
      end

      local err = jac.testJacobianUpdateParameters(module, input, module.weight)
      mytester:assertlt(err , precision, 'batch error on weight [direct update] ')

      if module.bias then
         local err = jac.testJacobianUpdateParameters(module, input, module.bias)
         mytester:assertlt(err , precision, 'batch error on bias [direct update] ')
      end

      for t,err in pairs(jac.testAllUpdate(module, input, 'weight', 'gradWeight')) do
         mytester:assertlt(err, precision, string.format(
                            'error on weight [%s]', t))
      end

      if module.bias then
         for t,err in pairs(jac.testAllUpdate(module, input, 'bias', 'gradBias')) do
            mytester:assertlt(err, precision, string.format(
                               'batch error on bias [%s]', t))
         end
      end

      local ferr, berr = jac.testIO(module, input)
      mytester:eq(0, ferr, torch.typename(module) .. ' - i/o forward err ', precision)
      mytester:eq(0, berr, torch.typename(module) .. ' - i/o backward err ', precision)
   end

   jacTests(module)
   module:noBias()
   jacTests(module)
   module.bias = torch.Tensor(module.nOutputPlane):zero()
   module.gradBias = torch.Tensor(module.nOutputPlane):zero()
   module:reset()
   jacTests(module)

   -- non-contiguous
   local batch = math.random(2,5)
   local input = torch.randn(batch,from,ini,inj):transpose(3,4) -- non-contiguous
   local inputc = input:contiguous() -- contiguous
   local output = module:forward(input)
   local outputc = module:forward(inputc)
   mytester:asserteq(0, (output-outputc):abs():max(), torch.typename(module) .. ' - contiguous err ')
   local gradInput = module:backward(input, output)
   local gradInputc = module:backward(inputc, outputc)
   mytester:asserteq(0, (gradInput-gradInputc):abs():max(), torch.typename(module) .. ' - contiguous err ')
end

function nntest.SpatialFullConvolutionDualInput()
   local from = math.random(2,5)
   local to = math.random(1,5)
   local ki = math.random(1,5)
   local kj = math.random(1,5)
   local di =  math.random(1,4)
   local dj =  math.random(1,4)
   local padW = math.random(0,2)
   local padH = math.random(0,2)
   local outi = math.random(5,9)
   local outj = math.random(5,9)
   local ini = math.floor((outi + padW*2 - ki)/di + 1)
   local inj = math.floor((outj + padH*2 - kj)/dj + 1)
   local adjW = (outi + 2 * padW - ki) % di
   local adjH = (outj + 2 * padH - kj) % dj
   local targetTensor = torch.Tensor(outj, outi):zero()
   local input = torch.Tensor(from, inj, ini):zero()

   local module = nn.SpatialFullConvolution(from, to, ki, kj, di, dj, padW, padH)
   local moduleRef = nn.SpatialFullConvolution(from, to, ki, kj, di, dj, padW, padH, adjW, adjH)
   moduleRef.weight:copy(module.weight)
   moduleRef.bias:copy(module.bias)

   -- Check that the required output size matches the actual output size
   -- when using the dual input mode
   local output = module:forward({input, targetTensor})
   mytester:asserteq(output:size(2), outj, 'output height error')
   mytester:asserteq(output:size(3), outi, 'output width error')

   -- Check that backward and forward match the reference module
   local outputRef = moduleRef:forward(input)
   mytester:asserteq(0, (output-outputRef):abs():max(), torch.typename(module) .. ' - output err ')
   local gradOutput = outputRef:clone():uniform()
   local gradInputRef = moduleRef:backward(input, gradOutput)
   local gradInput = module:backward({input, targetTensor}, gradOutput)
   mytester:asserteq(0, (gradInput[1]-gradInputRef):abs():max(), torch.typename(module) .. ' - gradInput[1] err ')

   -- Check that gradInput[2] is the singleton tensor {0}
   mytester:asserteq(gradInput[2]:storage():size(), 1, torch.typename(module) .. ' - gradInput[2] size err ')
   mytester:asserteq(gradInput[2]:storage()[1], 0, torch.typename(module) .. ' - gradInput[2] value err ')
end

function nntest.SpatialDilatedConvolution()
   local from = math.random(1,5)
   local to = math.random(1,5)
   local ki = math.random(1,5)
   local kj = math.random(1,5)
   local di =  math.random(1,4)
   local dj =  math.random(1,4)
   local padW = math.random(0,2)
   local padH = math.random(0,2)
   local outi = math.random(5,9)
   local outj = math.random(5,9)
   local dilationW = math.random(1,10)
   local dilationH = math.random(1,10)
   local ini = (outi - 1) * di - 2 * padW + dilationW * (ki-1) + 1
   local inj = (outj - 1) * dj - 2 * padH + dilationH * (kj-1) + 1

   local module = nn.SpatialDilatedConvolution(from, to, ki, kj, di, dj, padW, padH, dilationW, dilationH)
   local input = torch.Tensor(from, inj, ini):zero()

   -- stochastic

   local err = jac.testJacobian(module, input)
   mytester:assertlt(err, precision, 'error on state ')

   local err = jac.testJacobianParameters(module, input, module.weight, module.gradWeight)
   mytester:assertlt(err , precision, 'error on weight ')

   local err = jac.testJacobianParameters(module, input, module.bias, module.gradBias)
   mytester:assertlt(err , precision, 'error on bias ')

   local err = jac.testJacobianUpdateParameters(module, input, module.weight)
   mytester:assertlt(err , precision, 'error on weight [direct update] ')

   local err = jac.testJacobianUpdateParameters(module, input, module.bias)
   mytester:assertlt(err , precision, 'error on bias [direct update] ')

   for t,err in pairs(jac.testAllUpdate(module, input, 'weight', 'gradWeight')) do
      mytester:assertlt(err, precision, string.format(
                         'error on weight [%s]', t))
   end

   for t,err in pairs(jac.testAllUpdate(module, input, 'bias', 'gradBias')) do
      mytester:assertlt(err, precision, string.format(
                         'error on bias [%s]', t))
   end

   -- batch

   --verbose = true
   local batch = math.random(2,5)

   module = nn.SpatialDilatedConvolution(from, to, ki, kj, di, dj, padW, padH, dilationW, dilationH)
   input = torch.Tensor(batch,from,inj,ini):zero()

   -- Check that the required output size matches the actual output size
   local output = module:forward(input)
   mytester:asserteq(output:size(3), outj, 'output height error')
   mytester:asserteq(output:size(4), outi, 'output width error')

   local err = jac.testJacobian(module, input)
   mytester:assertlt(err, precision, 'batch error on state ')

   local err = jac.testJacobianParameters(module, input, module.weight, module.gradWeight)
   mytester:assertlt(err , precision, 'batch error on weight ')

   local err = jac.testJacobianParameters(module, input, module.bias, module.gradBias)
   mytester:assertlt(err , precision, 'batch error on bias ')

   local err = jac.testJacobianUpdateParameters(module, input, module.weight)
   mytester:assertlt(err , precision, 'batch error on weight [direct update] ')

   local err = jac.testJacobianUpdateParameters(module, input, module.bias)
   mytester:assertlt(err , precision, 'batch error on bias [direct update] ')

   for t,err in pairs(jac.testAllUpdate(module, input, 'weight', 'gradWeight')) do
      mytester:assertlt(err, precision, string.format(
                         'error on weight [%s]', t))
   end

   for t,err in pairs(jac.testAllUpdate(module, input, 'bias', 'gradBias')) do
      mytester:assertlt(err, precision, string.format(
                         'batch error on bias [%s]', t))
   end

   local ferr, berr = jac.testIO(module, input)
   mytester:eq(0, ferr, torch.typename(module) .. ' - i/o forward err ', precision)
   mytester:eq(0, berr, torch.typename(module) .. ' - i/o backward err ', precision)

   -- non-contiguous
   local input = torch.randn(batch,from,ini,inj):transpose(3,4) -- non-contiguous
   local inputc = input:contiguous() -- contiguous
   local output = module:forward(input)
   local outputc = module:forward(inputc)
   mytester:asserteq(0, (output-outputc):abs():max(), torch.typename(module) .. ' - contiguous err ')
   local gradInput = module:backward(input, output)
   local gradInputc = module:backward(inputc, outputc)
   mytester:asserteq(0, (gradInput-gradInputc):abs():max(), torch.typename(module) .. ' - contiguous err ')
end

function nntest.SpatialConvolutionMap()
   local from = math.random(1,5)
   local fanin = math.random(1, from)
   local to = math.random(1,5)
   local ki = math.random(1,5)
   local kj = math.random(1,5)
   local si = math.random(1,3)
   local sj = math.random(1,3)
   local outi = math.random(5,9)
   local outj = math.random(5,9)
   local ini = (outi-1)*si+ki
   local inj = (outj-1)*sj+kj

   local module = nn.SpatialConvolutionMap(nn.tables.random(from, to, fanin), ki, kj, si, sj)
   local input = torch.Tensor(from, inj, ini):zero()

   local err = jac.testJacobian(module, input)
   mytester:assertlt(err, precision, 'error on state ')

   local err = jac.testJacobianParameters(module, input, module.weight, module.gradWeight)
   mytester:assertlt(err , precision, 'error on weight ')

   local err = jac.testJacobianParameters(module, input, module.bias, module.gradBias)
   mytester:assertlt(err , precision, 'error on bias ')

   nn.hessian.enable()

   local err = jac.testDiagHessianInput(module, input)
   mytester:assertlt(err , precision, 'error on diagHessianInput')

   local err = jac.testDiagHessianWeight(module, input)
   mytester:assertlt(err , precision, 'error on diagHessianWeight')

   local err = jac.testDiagHessianBias(module, input)
   mytester:assertlt(err , precision, 'error on diag HessianBias')

   for t,err in pairs(jac.testAllUpdate(module, input, 'weight', 'gradWeight')) do
      mytester:assertlt(err, precision, string.format(
                         'error on weight [%s]', t))
   end

   for t,err in pairs(jac.testAllUpdate(module, input, 'bias', 'gradBias')) do
      mytester:assertlt(err, precision, string.format(
                         'error on bias [%s]', t))
   end

   local ferr, berr = jac.testIO(module, input)
   mytester:eq(0, ferr, torch.typename(module) .. ' - i/o forward err ', precision)
   mytester:eq(0, berr, torch.typename(module) .. ' - i/o backward err ', precision)



    -- batch

   --verbose = true
   local batch = math.random(2,6)
   module = nn.SpatialConvolutionMap(nn.tables.random(from, to, fanin), ki, kj, si, sj)
   input = torch.Tensor(batch,from,inj,ini):zero()

   local err = jac.testJacobian(module, input)
   mytester:assertlt(err, precision, 'batch error on state ')

   local err = jac.testJacobianParameters(module, input, module.weight, module.gradWeight)
   mytester:assertlt(err , precision, 'batch error on weight ')

   local err = jac.testJacobianParameters(module, input, module.bias, module.gradBias)
   mytester:assertlt(err , precision, 'batch error on bias ')

   local err = jac.testJacobianUpdateParameters(module, input, module.weight)
   mytester:assertlt(err , precision, 'batch error on weight [direct update] ')

   local err = jac.testJacobianUpdateParameters(module, input, module.bias)
   mytester:assertlt(err , precision, 'batch error on bias [direct update] ')

   local err = jac.testDiagHessianInput(module, input)
   mytester:assertlt(err , precision, 'error on diagHessianInput')

   local err = jac.testDiagHessianWeight(module, input)
   mytester:assertlt(err , precision, 'error on diagHessianWeight')

   local err = jac.testDiagHessianBias(module, input)
   mytester:assertlt(err , precision, 'error on diag HessianBias')

   for t,err in pairs(jac.testAllUpdate(module, input, 'weight', 'gradWeight')) do
      mytester:assertlt(err, precision, string.format(
                         'error on weight [%s]', t))
   end

   for t,err in pairs(jac.testAllUpdate(module, input, 'bias', 'gradBias')) do
      mytester:assertlt(err, precision, string.format(
                         'batch error on bias [%s]', t))
   end

   local ferr, berr = jac.testIO(module, input)
   mytester:eq(0, ferr, torch.typename(module) .. ' - i/o forward err ', precision)
   mytester:eq(0, berr, torch.typename(module) .. ' - i/o backward err ', precision)
end

function nntest.SpatialFullConvolutionMap()
   local from = math.random(2,4)
   local to = math.random(2,5)
   local fanin = math.random(1, from)
   local tt = nn.tables.random(from, to, fanin)
   local ki = math.random(2,5)
   local kj = math.random(2,5)
   local si = math.random(1,3)
   local sj = math.random(1,3)
   local ini = math.random(5,7)
   local inj = math.random(5,7)
   local module = nn.SpatialFullConvolutionMap(tt, ki, kj, si, sj)
   local input = torch.Tensor(from, inj, ini):zero()

   -- stochastic
      local err = jac.testJacobian(module, input)
   mytester:assertlt(err, precision, 'error on state ')

   local err = jac.testJacobianParameters(module, input, module.weight, module.gradWeight)
   mytester:assertlt(err , precision, 'error on weight ')

   local err = jac.testJacobianParameters(module, input, module.bias, module.gradBias)
   mytester:assertlt(err , precision, 'error on bias ')

   local err = jac.testJacobianUpdateParameters(module, input, module.weight)
   mytester:assertlt(err , precision, 'error on weight [direct update] ')

   local err = jac.testJacobianUpdateParameters(module, input, module.bias)
   mytester:assertlt(err , precision, 'error on bias [direct update] ')

   nn.hessian.enable()

   local err = jac.testDiagHessianInput(module, input)
   mytester:assertlt(err , precision, 'error on diagHessianInput')

   local err = jac.testDiagHessianWeight(module, input)
   mytester:assertlt(err , precision, 'error on diagHessianWeight')

   local err = jac.testDiagHessianBias(module, input)
   mytester:assertlt(err , precision, 'error on diag HessianBias')

   for t,err in pairs(jac.testAllUpdate(module, input, 'weight', 'gradWeight')) do
      mytester:assertlt(err, precision, string.format(
                         'error on weight [%s]', t))
   end

   for t,err in pairs(jac.testAllUpdate(module, input, 'bias', 'gradBias')) do
      mytester:assertlt(err, precision, string.format(
                         'error on bias [%s]', t))
   end

   local ferr, berr = jac.testIO(module, input)
   mytester:eq(0, ferr, torch.typename(module) .. ' - i/o forward err ', precision)
   mytester:eq(0, berr, torch.typename(module) .. ' - i/o backward err ', precision)
end

function nntest.SpatialFullConvolutionCompare()
    local from = math.random(2,4)
    local to = math.random(2,5)
    local tt = nn.tables.full(from, to)
    local ki = math.random(2,5)
    local kj = math.random(2,5)
    local si = math.random(1,3)
    local sj = math.random(1,3)
    local ini = math.random(7,8)
    local inj = math.random(7,8)
    local module1 = nn.SpatialFullConvolutionMap(tt, ki, kj, si, sj)
    local module2 = nn.SpatialFullConvolution(from, to, ki, kj, si, sj)
    local input = torch.rand(from, inj, ini)
    for k=1,tt:size(1) do
       module1.weight[k]:copy(module2.weight[tt[k][1]][tt[k][2]])
       module1.bias:copy(module2.bias)
    end

    local o1 = module1:updateOutput(input)
    local o2 = module2:updateOutput(input)
    mytester:assertlt(o1:dist(o2), precision, 'error on output')

    local go1 = torch.rand(o1:size())
    local go2 = go1:clone()

    local gi1= module1:updateGradInput(input,go1)
    local gi2 = module2:updateGradInput(input,go2)
    mytester:assertlt(gi1:dist(gi2), precision, 'error on gradInput')

    module1:zeroGradParameters()
    module2:zeroGradParameters()

    module1:accGradParameters(input,go1)
    module2:accGradParameters(input,go2)
    for k=1,tt:size(1) do
      mytester:assertlt(module1.gradWeight[k]:dist(module2.gradWeight[tt[k][1]][tt[k][2]]),precision,'error on gradWeight ' .. k)
    end
    mytester:assertlt(module1.gradBias:dist(module2.gradBias),precision,'error on gradBias ')
end

local function batchcompare(smod, sin, plist)
   local bs = torch.LongStorage(sin:dim()+1)
   bs[1] = 1
   for i=1,sin:dim() do bs[i+1] = sin:size()[i] end
   local bin = torch.Tensor(bs):copy(sin)
   local bmod = smod:clone()

   local sout = smod:forward(sin):clone()
   local bout = bmod:forward(bin):clone()

   local sgout = torch.randn(sout:size())
   local bgout = torch.Tensor(bout:size())
   bgout:copy(sgout)

   local sgin = smod:backward(sin, sgout)
   local bgin = bmod:backward(bin, bgout)

   smod:accGradParameters(sin, sgout, 1)
   bmod:accGradParameters(bin, bgout, 1)

   mytester:assertTensorEq(sout,bout:select(1,1), 1e-8, 'batchcompare error on output')
   mytester:assertTensorEq(sgin,bgin:select(1,1), 1e-8, 'batchcompare error on gradInput')

   for i,v in pairs(plist) do
      mytester:assertTensorEq(smod[v],bmod[v], 1e-8, 'batchcompare error on ' .. v)
   end
end

function nntest.SpatialConvolutionBatchCompare()
   local from = math.random(1,5)
   local to = math.random(1,5)
   local ki = math.random(1,5)
   local kj = math.random(1,5)
   local si = math.random(1,4)
   local sj = math.random(1,4)
   local outi = math.random(5,9)
   local outj = math.random(5,9)
   local ini = (outi-1)*si+ki
   local inj = (outj-1)*sj+kj

   local module = nn.SpatialConvolution(from, to, ki, kj, si, sj)
   module:zeroGradParameters()
   local input = torch.randn(from,inj,ini)

   batchcompare(module,input, {'weight','bias','gradWeight','gradBias'})
end

function nntest.SpatialFullConvolutionBatchCompare()
   local from = math.random(1,5)
   local to = math.random(1,5)
   local ki = math.random(1,5)
   local kj = math.random(1,5)
   local si = math.random(1,4)
   local sj = math.random(1,4)
   local ini = math.random(5,9)
   local inj = math.random(5,9)

   local module = nn.SpatialFullConvolution(from, to, ki, kj, si, sj)
   module:zeroGradParameters()
   local input = torch.randn(from, inj, ini)

   batchcompare(module,input, {'weight','bias','gradWeight','gradBias'})
end



function nntest.SpatialSubSamplingBatchCompare()
   local from = math.random(1,6)
   local ki = math.random(1,5)
   local kj = math.random(1,5)
   local si = math.random(1,4)
   local sj = math.random(1,4)
   local outi = math.random(6,10)
   local outj = math.random(6,10)
   local ini = (outi-1)*si+ki
   local inj = (outj-1)*sj+kj
   local module = nn.SpatialSubSampling(from, ki, kj, si, sj)
   module:zeroGradParameters()
   local input = torch.randn(from,inj,ini)--torch.Tensor(from, inj, ini):zero()

   batchcompare(module,input, {'weight','bias','gradWeight','gradBias'})
end

function nntest.SpatialSubSampling()
   local from = math.random(1,6)
   local ki = math.random(1,5)
   local kj = math.random(1,5)
   local si = math.random(1,4)
   local sj = math.random(1,4)
   local outi = math.random(6,10)
   local outj = math.random(6,10)
   local ini = (outi-1)*si+ki
   local inj = (outj-1)*sj+kj
   local module = nn.SpatialSubSampling(from, ki, kj, si, sj)
   local input = torch.Tensor(from, inj, ini):zero()

   local err = jac.testJacobian(module, input)
   mytester:assertlt(err, precision, 'error on state ')

   local err = jac.testJacobianParameters(module, input, module.weight, module.gradWeight)
   mytester:assertlt(err , precision, 'error on weight ')

   local err = jac.testJacobianParameters(module, input, module.bias, module.gradBias)
   mytester:assertlt(err , precision, 'error on bias ')

   local err = jac.testJacobianUpdateParameters(module, input, module.weight)
   mytester:assertlt(err , precision, 'error on weight [direct update] ')

   local err = jac.testJacobianUpdateParameters(module, input, module.bias)
   mytester:assertlt(err , precision, 'error on bias [direct update] ')

   for t,err in pairs(jac.testAllUpdate(module, input, 'weight', 'gradWeight')) do
      mytester:assertlt(err, precision, string.format(
                         'error on weight [%s]', t))
   end

   for t,err in pairs(jac.testAllUpdate(module, input, 'bias', 'gradBias')) do
      mytester:assertlt(err, precision, string.format(
                         'error on bias [%s]', t))
   end

   local batch = math.random(2,5)
   outi = math.random(4,8)
   outj = math.random(4,8)
   ini = (outi-1)*si+ki
   inj = (outj-1)*sj+kj
   module = nn.SpatialSubSampling(from, ki, kj, si, sj)
   input = torch.Tensor(batch,from,inj,ini):zero()

   local err = jac.testJacobian(module, input)
   mytester:assertlt(err, precision, 'batch error on state ')

   local err = jac.testJacobianParameters(module, input, module.weight, module.gradWeight)
   mytester:assertlt(err , precision, 'batch error on weight ')

   local err = jac.testJacobianParameters(module, input, module.bias, module.gradBias)
   mytester:assertlt(err , precision, 'batch error on bias ')

   local err = jac.testJacobianUpdateParameters(module, input, module.weight)
   mytester:assertlt(err , precision, 'batch error on weight [direct update] ')

   local err = jac.testJacobianUpdateParameters(module, input, module.bias)
   mytester:assertlt(err , precision, 'batch error on bias [direct update] ')

   for t,err in pairs(jac.testAllUpdate(module, input, 'weight', 'gradWeight')) do
      mytester:assertlt(err, precision, string.format(
                         'batch error on weight [%s]', t))
   end

   for t,err in pairs(jac.testAllUpdate(module, input, 'bias', 'gradBias')) do
      mytester:assertlt(err, precision, string.format(
                         'batch error on bias [%s]', t))
   end

   local ferr, berr = jac.testIO(module, input)
   mytester:eq(0, ferr, torch.typename(module) .. ' - i/o forward err ', precision)
   mytester:eq(0, berr, torch.typename(module) .. ' - i/o backward err ', precision)
end

function nntest.SpatialMaxPooling()
   for _,ceil_mode in pairs({true,false}) do
      local from = math.random(1,5)
      local ki = math.random(1,4)
      local kj = math.random(1,4)
      local si = math.random(1,3)
      local sj = math.random(1,3)
      local outi = math.random(4,5)
      local outj = math.random(4,5)
      local padW = math.min(math.random(0,1),math.floor(ki/2))
      local padH =  math.min(math.random(0,1),math.floor(kj/2))
      local ini = (outi-1)*si+ki-2*padW
      local inj = (outj-1)*sj+kj-2*padH

      local ceil_string = ceil_mode and 'ceil' or 'floor'
      local module = nn.SpatialMaxPooling(ki,kj,si,sj,padW,padH)
      if ceil_mode then module:ceil() else module:floor() end
      local input = torch.rand(from,inj,ini)

      local err = jac.testJacobian(module, input)
      mytester:assertlt(err, precision, 'error '..ceil_string..' mode on state ')

      local ferr, berr = jac.testIO(module, input)
      mytester:eq(ferr, 0, torch.typename(module) .. ' - i/o forward err ', precision)
      mytester:eq(berr, 0, torch.typename(module) .. ' - i/o backward err ', precision)

      -- batch
      local nbatch = math.random(2,5)
      input = torch.rand(nbatch,from,inj,ini)
      module = nn.SpatialMaxPooling(ki,kj,si,sj,padW,padH)
      if ceil_mode then module:ceil() else module:floor() end

      local err = jac.testJacobian(module, input)
      mytester:assertlt(err, precision, 'error '..ceil_string..' mode on state (Batch)')

      local ferr, berr = jac.testIO(module, input)
      mytester:eq(ferr, 0, torch.typename(module) .. ' - i/o forward err (Batch) ', precision)
      mytester:eq(berr, 0, torch.typename(module) .. ' - i/o backward err (Batch) ', precision)
  end
end

function nntest.SpatialMaxUnpooling()
   for _,ceil_mode in pairs({true,false}) do
      local from = math.random(1,5)
      local ki = math.random(2,4)
      local kj = math.random(2,4)
      local si, sj = ki, kj
      local outi = math.random(4,5)
      local outj = math.random(4,5)
      local padW = math.min(math.random(0,1),math.floor(ki/2))
      local padH = math.min(math.random(0,1),math.floor(kj/2))
      local ini = (outi-1)*si+ki-2*padW
      local inj = (outj-1)*sj+kj-2*padH

      local ceil_string = ceil_mode and 'ceil' or 'floor'
      local poolingModule = nn.SpatialMaxPooling(ki,kj,si,sj,padW,padH)
      if ceil_mode then poolingModule:ceil() else poolingModule:floor() end
      local module = nn.SpatialMaxUnpooling(poolingModule)

      local original = torch.rand(from,inj,ini)
      local input = poolingModule:forward(original)
      local output = module:forward(input)

      mytester:assert(output:isSameSizeAs(original),'SpatialMaxUnpooling output size err')

      local err = jac.testJacobian(module, input)
      mytester:assertlt(err, precision, 'error '..ceil_string..' mode on state ')

      local ferr, berr = jac.testIO(module, input)
      mytester:eq(ferr, 0, torch.typename(module) .. ' - i/o forward err ', precision)
      mytester:eq(berr, 0, torch.typename(module) .. ' - i/o backward err ', precision)

      -- batch
      local nbatch = math.random(2,5)
      original = torch.rand(nbatch,from,inj,ini)
      input = poolingModule:forward(original)
      output = module:forward(input)

      mytester:assert(output:isSameSizeAs(original),'SpatialMaxUnpooling batch output size err')

      local err = jac.testJacobian(module, input)
      mytester:assertlt(err, precision, 'error '..ceil_string..' mode on state (Batch)')

      local ferr, berr = jac.testIO(module, input)
      mytester:eq(ferr, 0, torch.typename(module) .. ' - i/o forward err (Batch) ', precision)
      mytester:eq(berr, 0, torch.typename(module) .. ' - i/o backward err (Batch) ', precision)
  end
end

function nntest.SpatialDilatedMaxPooling()
   for _,ceil_mode in pairs({true,false}) do
      local from = math.random(1,5)
      local ki = math.random(1,4)
      local kj = math.random(1,4)
      local si = math.random(1,3)
      local sj = math.random(1,3)
      local outi = math.random(4,5)
      local outj = math.random(4,5)
      local padW = math.min(math.random(0,1),math.floor(ki/2))
      local padH =  math.min(math.random(0,1),math.floor(kj/2))
      local dilationW = math.random(1,5)
      local dilationH = math.random(1,5)
      local ini = (outi-1)*si+(dilationW*(ki-1)+1)-2*padW
      local inj = (outj-1)*sj+(dilationH*(kj-1)+1)-2*padH

      local ceil_string = ceil_mode and 'ceil' or 'floor'
      local module = nn.SpatialDilatedMaxPooling(ki,kj,si,sj,padW,padH,dilationW, dilationH)
      if ceil_mode then module:ceil() else module:floor() end
      local input = torch.rand(from,inj,ini)

      local err = jac.testJacobian(module, input)
      mytester:assertlt(err, precision, 'error '..ceil_string..' mode on state ')

      local ferr, berr = jac.testIO(module, input)
      mytester:asserteq(ferr, 0, torch.typename(module) .. ' - i/o forward err ')
      mytester:asserteq(berr, 0, torch.typename(module) .. ' - i/o backward err ')

      -- batch
      local nbatch = math.random(2,5)
      input = torch.rand(nbatch,from,inj,ini)
      module = nn.SpatialDilatedMaxPooling(ki,kj,si,sj,padW,padH,dilationW,dilationH)
      if ceil_mode then module:ceil() else module:floor() end

      local err = jac.testJacobian(module, input)
      mytester:assertlt(err, precision, 'error '..ceil_string..' mode on state (Batch)')

      local ferr, berr = jac.testIO(module, input)
      mytester:asserteq(ferr, 0, torch.typename(module) .. ' - i/o forward err (Batch) ')
      mytester:asserteq(berr, 0, torch.typename(module) .. ' - i/o backward err (Batch) ')
  end
end

function nntest.SpatialFractionalMaxPooling()
    local batch = math.random(1, 3)
    local plane = math.random(1, 3)
    local outW = math.random(1, 7)
    local outH = math.random(1, 7)
    local poolSizeW = math.random(2, 4)
    local poolSizeH = math.random(2, 4)

    local minInW = outW + poolSizeW
    local minInH = outH + poolSizeH

    local inW = math.random(minInW, minInW + 6)
    local inH = math.random(minInH, minInH + 6)

    -- fix the pooling regions so they aren't regenerated with every
    -- forward(), so testJacobian can work properly
    local module =
        nn.SpatialFractionalMaxPooling(poolSizeW, poolSizeH, outW, outH)
        :fixPoolingRegions()
    local input = nil
    if batch == 1 then
        input = torch.Tensor(plane, inH, inW):zero()
    else
        input = torch.Tensor(batch, plane, inH, inW):zero()
    end

    local err = nn.Jacobian.testJacobian(module, input)
    mytester:assertlt(err, precision, 'error on state')
end

function nntest.SpatialFractionalMaxPooling_Ratio()
    -- Fix a reduction ratio, and test with two different input sizes
    local reductionRatioW = torch.uniform(0.4, 0.74)
    local reductionRatioH = torch.uniform(0.4, 0.74)

    for tries = 1, 2 do
        local batch = math.random(1, 3)
        local plane = math.random(1, 3)
        local poolSizeW = math.random(2, 3)
        local poolSizeH = math.random(2, 3)

        local minInW = math.random(5, 8) + poolSizeW
        local minInH = math.random(5, 8) + poolSizeH

        local inW = math.random(minInW, minInW + 6)
        local inH = math.random(minInH, minInH + 6)

        -- fix the pooling regions so they aren't regenerated with every
        -- forward(), so testJacobian can work properly
        local module =
            nn.SpatialFractionalMaxPooling(poolSizeW, poolSizeH,
                                           reductionRatioW, reductionRatioH)
            :fixPoolingRegions()
        local input = nil
        if batch == 1 then
            input = torch.Tensor(plane, inH, inW):zero()
        else
            input = torch.Tensor(batch, plane, inH, inW):zero()
        end

        -- Make sure that the output size is based on our ratio
        local output = module:updateOutput(input)
        if batch == 1 then
            mytester:asserteq(output:size(3), math.floor(reductionRatioW * inW))
            mytester:asserteq(output:size(2), math.floor(reductionRatioH * inH))
        else
            mytester:asserteq(output:size(4), math.floor(reductionRatioW * inW))
            mytester:asserteq(output:size(3), math.floor(reductionRatioH * inH))
        end

        local err = nn.Jacobian.testJacobian(module, input)
        mytester:assertlt(err, precision, 'error on state')
    end
end

function nntest.SpatialAveragePooling()
   for _,count_include_pad in pairs({true,false}) do
      for _,ceil_mode in pairs({true,false}) do
        local from = math.random(1,5)
        local ki = math.random(1,4)
        local kj = math.random(1,4)
        local si = math.random(1,3)
        local sj = math.random(1,3)
        local outi = math.random(4,5)
        local outj = math.random(4,5)
        local padW = math.min(math.random(0,1),math.floor(ki/2))
        local padH =  math.min(math.random(0,1),math.floor(kj/2))
        local ini = (outi-1)*si+ki-2*padW
        local inj = (outj-1)*sj+kj-2*padH

        local mode_string = ceil_mode and 'ceil' or 'floor'

        local module = nn.SpatialAveragePooling(ki, kj, si, sj, padW, padH)
        if ceil_mode then module:ceil() else module:floor() end
        if count_include_pad then
           module:setCountIncludePad()
           mode_string = mode_string .. ' - count include padding'
        else
           module:setCountExcludePad()
           mode_string = mode_string .. ' - count exclude padding'
        end
        local input = torch.Tensor(from, inj, ini):uniform()

        local err = jac.testJacobian(module, input)
        mytester:assertlt(err, precision, 'error'..mode_string..' on state ')

        local ferr, berr = jac.testIO(module, input)
        mytester:eq(ferr, 0, torch.typename(module) .. ' - i/o forward err ', precision)
        mytester:eq(berr, 0, torch.typename(module) .. ' - i/o backward err ', precision)

        -- batch
        local batch = math.random(2,5)
        outi = math.random(4,5)
        outj = math.random(4,5)
        local padW = math.min(math.random(0,1),math.floor(ki/2))
        local padH =  math.min(math.random(0,1),math.floor(kj/2))
        local ini = (outi-1)*si+ki-2*padW
        local inj = (outj-1)*sj+kj-2*padH

        module = nn.SpatialAveragePooling(ki, kj, si, sj, padW, padH)
        if ceil_mode then module:ceil() else module:floor() end
        if count_include_pad then
           module:setCountIncludePad()
        else
           module:setCountExcludePad()
        end
        input = torch.Tensor(batch,from,inj,ini):uniform()

        local err = jac.testJacobian(module, input)
        mytester:assertlt(err, precision, 'batch error'..mode_string..' on state ')

        local ferr, berr = jac.testIO(module, input)
        mytester:eq(0, ferr, torch.typename(module) .. ' - i/o forward err ', precision)
        mytester:eq(0, berr, torch.typename(module) .. ' - i/o backward err ', precision)

        local ferr, berr = jac.testIO(module, input)
        mytester:eq(ferr, 0, torch.typename(module) .. ' - i/o forward err (Batch) ', precision)
        mytester:eq(berr, 0, torch.typename(module) .. ' - i/o backward err (Batch) ', precision)

      end
   end
   -- test against SpatialSubSampling
   local from = math.random(1,6)
   local ki = math.random(1,5)
   local kj = math.random(1,5)
   local si = math.random(1,4)
   local sj = math.random(1,4)
   local outi = math.random(6,10)
   local outj = math.random(6,10)
   local padW = 0
   local padH = 0
   local ini = (outi-1)*si+ki-2*padW
   local inj = (outj-1)*sj+kj-2*padH

   local module = nn.SpatialAveragePooling(ki, kj, si, sj, padW, padH)
   local sap = nn.SpatialSubSampling(from, ki, kj, si, sj)
   sap.weight:fill(1.0/(ki*kj))
   sap.bias:fill(0.0)

   local input = torch.Tensor(from, inj, ini):uniform()

   local output = module:forward(input)
   local gradInput = module:backward(input, output)
   local output2 = sap:forward(input)
   local gradInput2 = sap:updateGradInput(input, output)

   mytester:assertTensorEq(output, output2, 0.000001, torch.typename(module) .. ' forward err ')
   mytester:assertTensorEq(gradInput, gradInput2, 0.000001, torch.typename(module) .. ' backward err ')

   -- test against SpatialSubSampling, batch mode
   local batch = math.random(2,5)
   outi = math.random(4,8)
   outj = math.random(4,8)
   local padW = 0
   local padH = 0
   local ini = (outi-1)*si+ki-2*padW
   local inj = (outj-1)*sj+kj-2*padH

   module = nn.SpatialAveragePooling(ki, kj, si, sj, padW, padH)
   input = torch.Tensor(batch,from,inj,ini):uniform()

   local sap = nn.SpatialSubSampling(from, ki, kj, si, sj)
   sap.weight:fill(1.0/(ki*kj))
   sap.bias:fill(0.0)

   local output = module:forward(input)
   local gradInput = module:backward(input, output)
   local output2 = sap:forward(input)
   local gradInput2 = sap:updateGradInput(input, output)

   mytester:assertTensorEq(output, output2, 0.000001, torch.typename(module) .. ' forward err (Batch) ')
   mytester:assertTensorEq(gradInput, gradInput2, 0.000001, torch.typename(module) .. ' backward err (Batch) ')

end

function nntest.SpatialAdaptiveMaxPooling()
   local from = math.random(1,5)
   local ki = math.random(1,5)
   local kj = math.random(1,5)
   local ini = math.random(1,16)
   local inj = math.random(1,16)

   local module = nn.SpatialAdaptiveMaxPooling(ki,kj)
   local input = torch.rand(from,ini,inj)

   local err = jac.testJacobian(module, input)
   mytester:assertlt(err, precision, 'error on state ')

   local ferr, berr = jac.testIO(module, input)
   mytester:eq(ferr, 0, torch.typename(module) .. ' - i/o forward err ', precision)
   mytester:eq(berr, 0, torch.typename(module) .. ' - i/o backward err ', precision)

   -- batch
   local nbatch = math.random(1,3)
   input = torch.rand(nbatch,from,ini,inj)
   module = nn.SpatialAdaptiveMaxPooling(ki,kj)

   local err = jac.testJacobian(module, input)
   mytester:assertlt(err, precision, 'error on state (Batch) ')

   local ferr, berr = jac.testIO(module, input)
   mytester:eq(ferr, 0, torch.typename(module) .. ' - i/o forward err (Batch) ', precision)
   mytester:eq(berr, 0, torch.typename(module) .. ' - i/o backward err (Batch) ', precision)

   -- non-contiguous

   input = torch.rand(from,ini,inj):transpose(2,3)
   module = nn.SpatialAdaptiveMaxPooling(ki,kj)
   local inputc = input:contiguous() -- contiguous
   local output = module:forward(input):clone()
   local outputc = module:forward(inputc):clone()
   mytester:asserteq(0, (output-outputc):abs():max(), torch.typename(module) .. ' - non-contiguous err ')
   local gradInput = module:backward(input, output):clone()
   local gradInputc = module:backward(inputc, outputc):clone()
   mytester:asserteq(0, (gradInput-gradInputc):abs():max(), torch.typename(module) .. ' - non-contiguous err ')

   -- non-contiguous batch
   local nbatch = math.random(1,3)
   input = torch.rand(nbatch,from,ini,inj):transpose(1,3):transpose(2,4)
   local inputc = input:contiguous() -- contiguous
   module = nn.SpatialAdaptiveMaxPooling(ki,kj)

   local output = module:forward(input):clone()
   local outputc = module:forward(inputc):clone()
   mytester:asserteq(0, (output-outputc):abs():max(), torch.typename(module) .. ' - batch non-contiguous err ')
   local gradInput = module:backward(input, output):clone()
   local gradInputc = module:backward(inputc, outputc):clone()
   mytester:asserteq(0, (gradInput-gradInputc):abs():max(), torch.typename(module) .. ' - batch non-contiguous err ')

end

function nntest.SpatialAdaptiveAveragePooling()
   local from = math.random(1,5)
   local ki = math.random(1,5)
   local kj = math.random(1,5)
   local ini = math.random(1,16)
   local inj = math.random(1,16)

   local module = nn.SpatialAdaptiveAveragePooling(ki,kj)
   local input = torch.rand(from,ini,inj)

   local err = jac.testJacobian(module, input)
   mytester:assertlt(err, precision, 'error on state ')

   local ferr, berr = jac.testIO(module, input)
   mytester:eq(ferr, 0, torch.typename(module) .. ' - i/o forward err ', precision)
   mytester:eq(berr, 0, torch.typename(module) .. ' - i/o backward err ', precision)

   -- batch
   local nbatch = math.random(1,3)
   input = torch.rand(nbatch,from,ini,inj)
   module = nn.SpatialAdaptiveAveragePooling(ki,kj)

   local err = jac.testJacobian(module, input)
   mytester:assertlt(err, precision, 'error on state (Batch) ')

   local ferr, berr = jac.testIO(module, input)
   mytester:eq(ferr, 0, torch.typename(module) .. ' - i/o forward err (Batch) ', precision)
   mytester:eq(berr, 0, torch.typename(module) .. ' - i/o backward err (Batch) ', precision)

   -- non-contiguous

   input = torch.rand(from,ini,inj):transpose(2,3)
   module = nn.SpatialAdaptiveAveragePooling(ki,kj)
   local inputc = input:contiguous() -- contiguous
   local output = module:forward(input):clone()
   local outputc = module:forward(inputc):clone()
   mytester:asserteq(0, (output-outputc):abs():max(), torch.typename(module) .. ' - non-contiguous err ')
   local gradInput = module:backward(input, output):clone()
   local gradInputc = module:backward(inputc, outputc):clone()
   mytester:asserteq(0, (gradInput-gradInputc):abs():max(), torch.typename(module) .. ' - non-contiguous err ')

   -- non-contiguous batch
   local nbatch = math.random(1,3)
   input = torch.rand(nbatch,from,ini,inj):transpose(1,3):transpose(2,4)
   local inputc = input:contiguous() -- contiguous
   module = nn.SpatialAdaptiveAveragePooling(ki,kj)

   local output = module:forward(input):clone()
   local outputc = module:forward(inputc):clone()
   mytester:asserteq(0, (output-outputc):abs():max(), torch.typename(module) .. ' - batch non-contiguous err ')
   local gradInput = module:backward(input, output):clone()
   local gradInputc = module:backward(inputc, outputc):clone()
   mytester:asserteq(0, (gradInput-gradInputc):abs():max(), torch.typename(module) .. ' - batch non-contiguous err ')

end

function nntest.SpatialLPPooling()
   local fanin = math.random(1,4)
   local osizex = math.random(1,4)
   local osizey = math.random(1,4)
   local p = 2
   local mx = math.random(2,6)
   local my = math.random(2,6)
   local dx = math.random(2,mx)
   local dy = math.random(2,my)
   local sizex = osizex*mx
   local sizey = osizey*my
   local module = nn.SpatialLPPooling(fanin,p,mx,my,dx,dy)
   local input = torch.rand(fanin,sizey,sizex)

   local err = jac.testJacobian(module, input)
   mytester:assertlt(err, precision, 'error on state ')

   local ferr, berr = jac.testIO(module, input)
   mytester:eq(ferr, 0, torch.typename(module) .. ' - i/o forward err ', precision)
   mytester:eq(berr, 0, torch.typename(module) .. ' - i/o backward err ', precision)
end

function nntest.Sum()
   -- 1D
   local ini = math.random(3,7)
   local input = torch.Tensor(ini):zero()
   local module = nn.Sum(1)

   local err = jac.testJacobian(module,input)
   mytester:assertlt(err,precision, 'error on state ')

   -- negative dimension
   local module   = nn.Sum(-1)
   local input    = torch.Tensor({1, 2, 3})
   local expected = torch.Tensor({6})
   local output   = module:forward(input)
   mytester:assertlt(torch.norm(output-expected), precision, 'error on forward ')

   -- batch
   local dimension = 1
   local module    = nn.Sum(dimension, 1)
   local input     = torch.Tensor({{1, 2, 3},{4, 5, 6}})
   local expected  = torch.Tensor({6, 15})
   local output    = module:forward(input)
   mytester:assertlt(torch.norm(output-expected), precision, 'error on forward ')

   local err       = jac.testJacobian(module, input)
   mytester:assertlt(err,precision, 'error on state ')

   -- mean + batch
   local dimension = 1
   local module    = nn.Sum(dimension, 1, true)
   local input     = torch.Tensor({{1, 2, 3},{4, 5, 6}})
   local expected  = input:mean(dimension + 1)
   local output    = module:forward(input)

   mytester:assertlt(torch.norm(output-expected), precision, 'error on forward ')

   local err       = jac.testJacobian(module, input)
   mytester:assertlt(err,precision, 'error on state ')

   -- squeeze
   local dimension = 1
   local module    = nn.Sum(dimension, nil, nil, false)
   local input     = torch.Tensor({{1, 2, 3},{4, 5, 6}})
   local expected  = torch.Tensor({5, 7, 9}):view(1, 3)
   local output    = module:forward(input)

   mytester:assertlt(torch.norm(output-expected), precision, 'error on forward ')
   mytester:assert(output:isSameSizeAs(expected), 'sizes mismatch')

   local err       = jac.testJacobian(module, input)
   mytester:assertlt(err,precision, 'error on state ')

   -- squeeze + batch
   local dimension = 1
   local module    = nn.Sum(dimension, 1, nil, false)
   local input     = torch.Tensor({{1, 2, 3},{4, 5, 6}})
   local expected  = torch.Tensor({6, 15}):view(2, 1)
   local output    = module:forward(input)

   mytester:assertlt(torch.norm(output-expected), precision, 'error on forward ')
   mytester:assert(output:isSameSizeAs(expected), 'sizes mismatch')

   local err       = jac.testJacobian(module, input)
   mytester:assertlt(err,precision, 'error on state ')

   -- 3D
   local ini = math.random(3,5)
   local inj = math.random(3,5)
   local ink = math.random(3,5)
   local input = torch.Tensor(ini,inj,ink):zero()
   local module = nn.Sum(torch.random(1,3))

   local err = jac.testJacobian(module,input)
   mytester:assertlt(err,precision, 'error on state ')

   local ferr,berr = jac.testIO(module,input)
   mytester:eq(ferr, 0, torch.typename(module) .. ' - i/o forward err ', precision)
   mytester:eq(berr, 0, torch.typename(module) .. ' - i/o backward err ', precision)
end

function nntest.Tanh()
   local ini = math.random(3,5)
   local inj = math.random(3,5)
   local ink = math.random(3,5)
   local input = torch.Tensor(ink, inj, ini):zero()

   local module = nn.Tanh()

   local err = jac.testJacobian(module, input)
   mytester:assertlt(err, precision ,  'error on state ')

   local ferr, berr = jac.testIO(module, input)
   mytester:eq(ferr, 0, torch.typename(module) .. ' - i/o forward err ', precision)
   mytester:eq(berr, 0, torch.typename(module) .. ' - i/o backward err ', precision)
end

function nntest.TemporalConvolution()
   -- 1D
   local from = math.random(1,5)
   local to = math.random(1,5)
   local ki = math.random(1,5)
   local si = math.random(1,4)
   local outi = math.random(5,7)
   local ini = (outi-1)*si+ki
   local module = nn.TemporalConvolution(from, to, ki,si)
   local input = torch.Tensor(ini, from):zero()

   local err = jac.testJacobian(module, input)
   mytester:assertlt(err, precision, 'error on state ')

   local err = jac.testJacobianParameters(module, input, module.weight, module.gradWeight)
   mytester:assertlt(err , precision, 'error on weight ')

   local err = jac.testJacobianParameters(module, input, module.bias, module.gradBias)
   mytester:assertlt(err , precision, 'error on bias ')

   local err = jac.testJacobianUpdateParameters(module, input, module.weight)
   mytester:assertlt(err , precision, 'error on weight [direct update]')

   local err = jac.testJacobianUpdateParameters(module, input, module.bias)
   mytester:assertlt(err , precision, 'error on bias [direct update]')

   for t,err in pairs(jac.testAllUpdate(module, input, 'weight', 'gradWeight')) do
      mytester:assertlt(err, precision, string.format(
                         'error on weight [%s]', t))
   end

   for t,err in pairs(jac.testAllUpdate(module, input, 'bias', 'gradBias')) do
      mytester:assertlt(err, precision, string.format(
                         'error on bias [%s]', t))
   end

   -- 2D
   local nBatchFrame = 4
   local input = torch.Tensor(nBatchFrame, ini, from):zero()

   local err = jac.testJacobian(module, input)
   mytester:assertlt(err, precision, 'error on state ')

   local err = jac.testJacobianParameters(module, input, module.weight, module.gradWeight)
   mytester:assertlt(err , precision, 'error on weight ')

   local err = jac.testJacobianParameters(module, input, module.bias, module.gradBias)
   mytester:assertlt(err , precision, 'error on bias ')

   local err = jac.testJacobianUpdateParameters(module, input, module.weight)
   mytester:assertlt(err , precision, 'error on weight [direct update]')

   local err = jac.testJacobianUpdateParameters(module, input, module.bias)
   mytester:assertlt(err , precision, 'error on bias [direct update]')

   for t,err in pairs(jac.testAllUpdate(module, input, 'weight', 'gradWeight')) do
      mytester:assertlt(err, precision, string.format(
                         'error on weight [%s]', t))
   end

   for t,err in pairs(jac.testAllUpdate(module, input, 'bias', 'gradBias')) do
      mytester:assertlt(err, precision, string.format(
                         'error on bias [%s]', t))
   end

   local ferr, berr = jac.testIO(module, input)
   mytester:eq(0, ferr, torch.typename(module) .. ' - i/o forward err ', precision)
   mytester:eq(0, berr, torch.typename(module) .. ' - i/o backward err ', precision)

   -- 2D matches 1D
   local output = module:forward(input):clone()
   local outputGrad = torch.randn(output:size())
   local inputGrad = module:backward(input, outputGrad):clone()

   local input1D = input:select(1, 2)
   local output1D = module:forward(input1D)
   local outputGrad1D = outputGrad:select(1, 2)
   local inputGrad1D = module:backward(input1D, outputGrad1D)

   mytester:assertTensorEq(output:select(1,2), output1D, 0.000001, 'error on 2D vs 1D forward)')
   mytester:assertTensorEq(inputGrad:select(1,2), inputGrad1D, 0.000001, 'error on 2D vs 1D backward)')
end

function nntest.TemporalDynamicKMaxPooling()
   local features = math.random(5,10)
   local seqLen = math.random(6,9)
   local minK = math.random(3,6)
   local factor = math.random(1,100)*0.01
   local nBatchFrame = math.random(2,4)
   local module = nn.TemporalDynamicKMaxPooling(minK, factor)

   -- 1D
   local input = torch.Tensor(seqLen, features)
   local err = jac.testJacobian(module, input)
   mytester:assertlt(err, precision, 'error on state ')

   local ferr, berr = jac.testIO(module, input)
   mytester:asserteq(0, ferr, torch.typename(module) .. ' - i/o forward err ')
   mytester:asserteq(0, berr, torch.typename(module) .. ' - i/o backward err ')

   -- 2D
   local input = torch.Tensor(nBatchFrame, seqLen, features)
   local err = jac.testJacobian(module, input)
   mytester:assertlt(err, precision, 'error on state ')

   local ferr, berr = jac.testIO(module, input)
   mytester:asserteq(0, ferr, torch.typename(module) .. ' - i/o forward err ')
   mytester:asserteq(0, berr, torch.typename(module) .. ' - i/o backward err ')

   -- 2D matches 1D
   local output = module:forward(input):clone()
   local outputGrad = torch.randn(output:size())
   local inputGrad = module:backward(input, outputGrad):clone()

   local input1D = input:select(1, 2)
   local output1D = module:forward(input1D)
   local outputGrad1D = outputGrad:select(1, 2)
   local inputGrad1D = module:backward(input1D, outputGrad1D)

   mytester:assertTensorEq(output:select(1,2), output1D, 0.000001, 'error on 2D vs 1D forward)')
   mytester:assertTensorEq(inputGrad:select(1,2), inputGrad1D, 0.000001, 'error on 2D vs 1D backward)')


end

function nntest.TemporalSubSampling()
   local from = math.random(1,5)
   local ki = math.random(1,6)
   local si = math.random(1,4)
   local outi = math.random(6,9)
   local ini = (outi-1)*si+ki
   local module = nn.TemporalSubSampling(from, ki, si)
   local input = torch.Tensor(ini, from):zero()

   local err = jac.testJacobian(module, input)
   mytester:assertlt(err, precision, 'error on state ')

   local err = jac.testJacobianParameters(module, input, module.weight, module.gradWeight)
   mytester:assertlt(err , precision, 'error on weight ')

   local err = jac.testJacobianParameters(module, input, module.bias, module.gradBias)
   mytester:assertlt(err , precision, 'error on bias ')

   local err = jac.testJacobianUpdateParameters(module, input, module.weight)
   mytester:assertlt(err , precision, 'error on weight [direct update] ')

   local err = jac.testJacobianUpdateParameters(module, input, module.bias)
   mytester:assertlt(err , precision, 'error on bias [direct update] ')

   for t,err in pairs(jac.testAllUpdate(module, input, 'weight', 'gradWeight')) do
      mytester:assertlt(err, precision, string.format(
                         'error on weight [%s]', t))
   end

   for t,err in pairs(jac.testAllUpdate(module, input, 'bias', 'gradBias')) do
      mytester:assertlt(err, precision, string.format(
                         'error on bias [%s]', t))
   end

   local ferr, berr = jac.testIO(module, input)
   mytester:eq(0, ferr, torch.typename(module) .. ' - i/o forward err ', precision)
   mytester:eq(0, berr, torch.typename(module) .. ' - i/o backward err ', precision)
end


function nntest.TemporalRowConvolution()
  if true then return end -- until this unit test is fixed...
  local from = math.random(1,5)
  local ki = math.random(1,5)
  local si = math.random(1,2)
  local outi = math.random(5,7)
  local ini = (outi-1)*si+ki

  local function jacTest(module)

    local input
    if module.featFirst then
      input = torch.Tensor(from, ini):zero()
    else
      input = torch.Tensor(ini, from):zero()
    end

    -- 1D
    local err = jac.testJacobian(module, input)
    mytester:assertlt(err, precision, "error on state" )

    local err = jac.testJacobianParameters(module, input, module.weight, module.gradWeight)
    mytester:assertlt(err, precision, "error on weight ")

    if module.bias then
      local err = jac.testJacobianParameters(module, input, module.bias, module.gradBias)
      mytester:assertlt(err, precision, "error on bias ")
    end

    local err = jac.testJacobianUpdateParameters(module, input, module.weight)
    mytester:assertlt(err, precision, "error on weight [direct update] ")

    if module.bias then
      local err = jac.testJacobianUpdateParameters(module, input, module.bias)
      mytester:assertlt(err, precision, "error on bias [direct update] ")
    end

    for t, err in pairs(jac.testAllUpdate(module, input, "weight", "gradWeight")) do
      mytester:assertlt(err, precision, string.format(
          "error on weight [%s] ", t))
    end

    if module.bias then
      for t,err in pairs(jac.testAllUpdate(module, input, 'bias', 'gradBias')) do
        mytester:assertlt(err, precision, string.format(
            "error on bias [%s] ", t))
      end
    end

    -- 2D
    local nBatchFrame = 4
    if module.featFirst then
      input = torch.Tensor(nBatchFrame, from, ini):zero()
    else
      input = torch.Tensor(nBatchFrame, ini, from):zero()
    end


    local err = jac.testJacobian(module, input)
    mytester:assertlt(err, precision, "error on state" )

    local err = jac.testJacobianParameters(module, input, module.weight, module.gradWeight)
    mytester:assertlt(err, precision, "error on weight ")

    if module.bias then
      local err = jac.testJacobianParameters(module, input, module.bias, module.gradBias)
      mytester:assertlt(err, precision, "error on bias ")
    end

    local err = jac.testJacobianUpdateParameters(module, input, module.weight)
    mytester:assertlt(err, precision, "error on weight [direct update] ")

    if module.bias then
      local err = jac.testJacobianUpdateParameters(module, input, module.bias)
      mytester:assertlt(err, precision, "error on bias [direct update] ")
    end

    for t, err in pairs(jac.testAllUpdate(module, input, "weight", "gradWeight")) do
      mytester:assertlt(err, precision, string.format(
          "error on weight [%s] ", t))
    end

    if module.bias then
      for t,err in pairs(jac.testAllUpdate(module, input, 'bias', 'gradBias')) do
        mytester:assertlt(err, precision, string.format(
            "error on bias [%s] ", t))
      end
    end

    local ferr, berr = jac.testIO(module, input)
    mytester:eq(0, ferr, torch.typename(module) .. " - i/o forward err ", precision)
    mytester:eq(0, berr, torch.typename(module) .. " - i/o forward err ", precision)

    -- 2D matches 1D
    local output = module:forward(input):clone()
    local outputGrad = torch.randn(output:size())
    local inputGrad = module:backward(input, outputGrad):clone()

    local input1D = input:select(1, 2)
    local output1D = module:forward(input1D)
    local outputGrad1D = outputGrad:select(1, 2)
    local inputGrad1D = module:backward(input1D, outputGrad1D)

    mytester:assertTensorEq(output:select(1,2), output1D, 0.000001,
    "error on 2D vs 1D forward")
    mytester:assertTensorEq(inputGrad:select(1,2), inputGrad1D, 0.000001,
    "error on 2D vs 1D backward")
  end

  local module = nn.TemporalRowConvolution(from, ki, si)
  jacTest(module)
  module:noBias()
  jacTest(module)
  module.bias = torch.Tensor(module.inputFrameSize):zero()
  module.gradBias = torch.Tensor(module.inputFrameSize):zero()
  module:reset()
  module.featFirst = true
  jacTest(module)
  module:noBias()
  jacTest(module, true)
end

function nntest.TemporalMaxPooling()
   local from = math.random(2,4)
   local ki = math.random(5,7)
   local si = math.random(1,2)
   local outi = math.random(30,40)
   local ini = (outi-1)*si+ki
   local module = nn.TemporalMaxPooling(ki, si)
   local input = torch.Tensor(ini, from):zero()

   -- 1D
   local err = jac.testJacobian(module, input)
   mytester:assertlt(err, precision, 'error on state ')

   local ferr, berr = jac.testIO(module, input)
   mytester:eq(0, ferr, torch.typename(module) .. ' - i/o forward err ', precision)
   mytester:eq(0, berr, torch.typename(module) .. ' - i/o backward err ', precision)

   -- 2D
   local nBatchFrame = 2
   local input = torch.Tensor(nBatchFrame, ini, from):zero()
   local err = jac.testJacobian(module, input)
   mytester:assertlt(err, precision, 'error on state ')

   local ferr, berr = jac.testIO(module, input)
   mytester:eq(0, ferr, torch.typename(module) .. ' - i/o forward err ', precision)
   mytester:eq(0, berr, torch.typename(module) .. ' - i/o backward err ', precision)

   -- 2D matches 1D
   local output = module:forward(input):clone()
   local outputGrad = torch.randn(output:size())
   local inputGrad = module:backward(input, outputGrad):clone()

   local input1D = input:select(1, 2)
   local output1D = module:forward(input1D)
   local outputGrad1D = outputGrad:select(1, 2)
   local inputGrad1D = module:backward(input1D, outputGrad1D)

   mytester:assertTensorEq(output:select(1,2), output1D, 0.000001, 'error on 2D vs 1D forward)')
   mytester:assertTensorEq(inputGrad:select(1,2), inputGrad1D, 0.000001, 'error on 2D vs 1D backward)')
end

function nntest.VolumetricFullConvolution_simple_test()
    local module = nn.VolumetricFullConvolution(3, 1, 3, 3, 3, 3, 3, 3);
    module.weight:fill(1);
    module.bias:fill(0.1);

    local input = torch.Tensor(1, 3, 2, 2, 2):zero();
    for c = 1,3 do
        input[1][c][1][1][1] = 1
    end
    local output = module:forward(input)
    for t = 1,6 do
        for h = 1,6 do
            for w = 1,6 do
                if t <= 3 and h <= 3 and w <= 3 then
                    mytester:assertlt(output[1][1][t][h][w] - 3.1, precision, 'error on forward ')
                else
                    mytester:assertlt(output[1][1][t][h][w] - 0.1, precision, 'error on forward ')
                end
            end
        end
    end

    module:zeroGradParameters()
    local gradOut = torch.Tensor(1, 1, 6, 6, 6):fill(0.1);
    local gradIn = module:backward(input, gradOut)
    for t = 1,2 do
        for h = 1,2 do
            for w = 1,2 do
                mytester:assertlt(gradIn[1][1][t][h][w] - 2.7, precision,
                                  'error on backward input gradients ')
            end
        end
    end

    mytester:assertlt(module.gradBias[1] - 21.6, precision,
                      'error on backward gradBias ')
    for c = 1,3 do
        for t = 1,3 do
            for h = 1,3 do
                for w = 1,3 do
                    mytester:assertlt(module.gradWeight[c][1][t][h][w] - 0.1, precision,
                                      'error on backward weight gradients ')
                end
            end
        end
    end
end

function nntest.VolumetricFullConvolution()
    local from = math.random(2,3)
    local to = math.random(2,3)
    local kt = math.random(3,4)
    local ki = math.random(3,4)
    local kj = ki
    local st = math.random(1,3)
    local si = math.random(1,3)
    local sj = si
    local int = math.random(3,4)
    local ini = math.random(3,4)
    local inj = math.random(3,4)
    local bs = math.random(1, 6)
    local module = nn.VolumetricFullConvolution(from, to, kt, ki, kj, st, si, sj)

    local input = torch.Tensor(bs, from, int, ini, inj):zero()

    local function jacTests(module)
      local err = jac.testJacobian(module, input)
      mytester:assertlt(err, precision, 'error on state ')

      local err = jac.testJacobianParameters(module, input, module.weight, module.gradWeight)
      mytester:assertlt(err , precision, 'error on weight ')

      if module.bias then
        local err = jac.testJacobianParameters(module, input, module.bias, module.gradBias)
        mytester:assertlt(err , precision, 'error on bias ')
      end

      local ferr, berr = jac.testIO(module, input)
      mytester:eq(0, ferr, torch.typename(module) .. ' - i/o forward err ', precision)
      mytester:eq(0, berr, torch.typename(module) .. ' - i/o backward err ', precision)
    end

    jacTests(module)
    module:noBias()
    jacTests(module)
    module.bias = torch.Tensor(module.nOutputPlane):zero()
    module.gradBias = torch.Tensor(module.nOutputPlane):zero()
    module:reset()
    jacTests(module)
end

function nntest.VolumetricFullConvolutionDualInput()
   local from = math.random(2,3)
   local to = math.random(2,3)
   local kt = math.random(3,4)
   local ki = math.random(3,4)
   local kj = math.random(3,4)
   local dt =  math.random(1,3)
   local di =  math.random(1,3)
   local dj =  math.random(1,3)
   local padT = math.random(0,2)
   local padW = math.random(0,2)
   local padH = math.random(0,2)
   local outt = math.random(5,9)
   local outi = math.random(5,9)
   local outj = math.random(5,9)
   local int = math.floor((outt + padT*2 - kt)/dt + 1)
   local ini = math.floor((outi + padW*2 - ki)/di + 1)
   local inj = math.floor((outj + padH*2 - kj)/dj + 1)
   local adjT = (outt + 2 * padT - kt) % dt
   local adjW = (outi + 2 * padW - ki) % di
   local adjH = (outj + 2 * padH - kj) % dj
   local targetTensor = torch.Tensor(outt, outj, outi):zero()
   local input = torch.Tensor(from, int, inj, ini):zero()

   local module = nn.VolumetricFullConvolution(from, to, kt, ki, kj, dt, di, dj, padT, padW, padH)
   local moduleRef = nn.VolumetricFullConvolution(from, to, kt, ki, kj, dt, di, dj, padT, padW, padH, adjT, adjW, adjH)
   moduleRef.weight:copy(module.weight)
   moduleRef.bias:copy(module.bias)

   -- Check that the required output size matches the actual output size
   -- when using the dual input mode
   local output = module:forward({input, targetTensor})
   mytester:asserteq(output:size(2), outt, 'output depth error')
   mytester:asserteq(output:size(3), outj, 'output height error')
   mytester:asserteq(output:size(4), outi, 'output width error')

   -- Check that backward and forward match the reference module
   local outputRef = moduleRef:forward(input)
   mytester:asserteq(0, (output-outputRef):abs():max(), torch.typename(module) .. ' - output err ')
   local gradOutput = outputRef:clone():uniform()
   local gradInputRef = moduleRef:backward(input, gradOutput)
   local gradInput = module:backward({input, targetTensor}, gradOutput)
   mytester:asserteq(0, (gradInput[1]-gradInputRef):abs():max(), torch.typename(module) .. ' - gradInput[1] err ')

   -- Check that gradInput[2] is the singleton tensor {0}
   mytester:asserteq(gradInput[2]:storage():size(), 1, torch.typename(module) .. ' - gradInput[2] size err ')
   mytester:asserteq(gradInput[2]:storage()[1], 0, torch.typename(module) .. ' - gradInput[2] value err ')
end

function nntest.VolumetricConvolution()
   local from = math.random(2,4)
   local to = math.random(1,4)
   local kt = math.random(1,4)
   local ki = math.random(1,4)
   local kj = math.random(1,4)
   local st = math.random(1,3)
   local si = math.random(1,3)
   local sj = math.random(1,3)
   local padT = math.random(0,2)
   local padW = math.random(0,2)
   local padH = math.random(0,2)
   local outt = math.random(5,7)
   local outi = math.random(5,7)
   local outj = math.random(5,7)
   local int = (outt-1)*st+kt-padT*2
   local ini = (outi-1)*si+ki-padW*2
   local inj = (outj-1)*sj+kj-padH*2
   local module = nn.VolumetricConvolution(from, to, kt, ki, kj, st, si, sj, padT, padW, padH)
   local input = torch.Tensor(from, int, inj, ini):zero()

   local function jacTests(module)
     local err = jac.testJacobian(module, input)
     mytester:assertlt(err, precision, 'error on state ')

     local err = jac.testJacobianParameters(module, input, module.weight, module.gradWeight)
     mytester:assertlt(err , precision, 'error on weight ')

     if module.bias then
       local err = jac.testJacobianParameters(module, input, module.bias, module.gradBias)
       mytester:assertlt(err , precision, 'error on bias ')
     end

     local err = jac.testJacobianUpdateParameters(module, input, module.weight)
     mytester:assertlt(err , precision, 'error on weight [direct update] ')

     if module.bias then
       local err = jac.testJacobianUpdateParameters(module, input, module.bias)
       mytester:assertlt(err , precision, 'error on bias [direct update] ')
     end

     for t,err in pairs(jac.testAllUpdate(module, input, 'weight', 'gradWeight')) do
        mytester:assertlt(err, precision, string.format(
                           'error on weight [%s]', t))
     end

     if module.bias then
       for t,err in pairs(jac.testAllUpdate(module, input, 'bias', 'gradBias')) do
         mytester:assertlt(err, precision, string.format(
                            'error on bias [%s]', t))
       end
     end

     local ferr, berr = jac.testIO(module, input)
     mytester:eq(0, ferr, torch.typename(module) .. ' - i/o forward err ', precision)
     mytester:eq(0, berr, torch.typename(module) .. ' - i/o backward err ', precision)
   end

   jacTests(module)
   module:noBias()
   jacTests(module)
   module.bias = torch.Tensor(module.nOutputPlane):zero()
   module.gradBias = torch.Tensor(module.nOutputPlane):zero()
   module:reset()
   jacTests(module)
end

function nntest.VolumetricDilatedConvolution()
   local from = math.random(1,5)
   local to = math.random(1,5)
   local ki = math.random(1,5)
   local kj = math.random(1,5)
   local kk = math.random(1,5)
   local di =  math.random(1,4)
   local dj =  math.random(1,4)
   local dk =  math.random(1,4)
   local padW = 0 -- math.random(0,2)
   local padH = 0 -- math.random(0,2)
   local padT = 0 -- math.random(0,2)
   local outi = math.random(2,3)
   local outj = math.random(2,5)
   local outk = math.random(2,5)
   local dilationW = math.random(1,3)
   local dilationH = math.random(1,3)
   local dilationT = math.random(1,3)
   local ini = (outi - 1) * di - 2 * padW + dilationW * (ki-1) + 1
   local inj = (outj - 1) * dj - 2 * padH + dilationH * (kj-1) + 1
   local ink = (outk - 1) * dk - 2 * padT + dilationT * (kk-1) + 1

   local module = nn.VolumetricDilatedConvolution(from, to, kk, ki, kj, dk, di, dj, padT, padW, padH, dilationT, dilationW, dilationH)
   local input = torch.Tensor(from, ink, inj, ini):zero()

   -- stochastic

   local err = jac.testJacobian(module, input)
   mytester:assertlt(err, precision, 'error on state ')

   local err = jac.testJacobianParameters(module, input, module.weight, module.gradWeight)
   mytester:assertlt(err , precision, 'error on weight ')

   local err = jac.testJacobianParameters(module, input, module.bias, module.gradBias)
   mytester:assertlt(err , precision, 'error on bias ')

   local err = jac.testJacobianUpdateParameters(module, input, module.weight)
   mytester:assertlt(err , precision, 'error on weight [direct update] ')

   local err = jac.testJacobianUpdateParameters(module, input, module.bias)
   mytester:assertlt(err , precision, 'error on bias [direct update] ')

   for t,err in pairs(jac.testAllUpdate(module, input, 'weight', 'gradWeight')) do
      mytester:assertlt(err, precision, string.format(
                         'error on weight [%s]', t))
   end

   for t,err in pairs(jac.testAllUpdate(module, input, 'bias', 'gradBias')) do
      mytester:assertlt(err, precision, string.format(
                         'error on bias [%s]', t))
   end

   -- batch

   --verbose = true
   local batch = math.random(2,5)

   module = nn.VolumetricDilatedConvolution(from, to, kk, ki, kj, dk, di, dj, padT, padW, padH, dilationT, dilationW, dilationH)
   input = torch.Tensor(batch,from,ink,inj,ini):zero()

   -- Check that the required output size matches the actual output size
   local output = module:forward(input)
   mytester:asserteq(output:size(3), outk, 'output width error')
   mytester:asserteq(output:size(4), outj, 'output height error')
   mytester:asserteq(output:size(5), outi, 'output width error')

   local err = jac.testJacobian(module, input)
   mytester:assertlt(err, precision, 'batch error on state ')

   local err = jac.testJacobianParameters(module, input, module.weight, module.gradWeight)
   mytester:assertlt(err , precision, 'batch error on weight ')

   local err = jac.testJacobianParameters(module, input, module.bias, module.gradBias)
   mytester:assertlt(err , precision, 'batch error on bias ')

   local err = jac.testJacobianUpdateParameters(module, input, module.weight)
   mytester:assertlt(err , precision, 'batch error on weight [direct update] ')

   local err = jac.testJacobianUpdateParameters(module, input, module.bias)
   mytester:assertlt(err , precision, 'batch error on bias [direct update] ')

   for t,err in pairs(jac.testAllUpdate(module, input, 'weight', 'gradWeight')) do
      mytester:assertlt(err, precision, string.format(
                         'error on weight [%s]', t))
   end

   for t,err in pairs(jac.testAllUpdate(module, input, 'bias', 'gradBias')) do
      mytester:assertlt(err, precision, string.format(
                         'batch error on bias [%s]', t))
   end

   local ferr, berr = jac.testIO(module, input)
   mytester:eq(0, ferr, torch.typename(module) .. ' - i/o forward err ', precision)
   mytester:eq(0, berr, torch.typename(module) .. ' - i/o backward err ', precision)

   -- non-contiguous
   local input = torch.randn(batch,from,ink,ini,inj):transpose(4,5) -- non-contiguous
   local inputc = input:contiguous() -- contiguous
   local output = module:forward(input)
   local outputc = module:forward(inputc)
   mytester:asserteq(0, (output-outputc):abs():max(), torch.typename(module) .. ' - contiguous err ')
   local gradInput = module:backward(input, output)
   local gradInputc = module:backward(inputc, outputc)
   mytester:asserteq(0, (gradInput-gradInputc):abs():max(), torch.typename(module) .. ' - contiguous err ')
end

function nntest.VolumetricConvolutionBatchCompare()
   local from = math.random(2,3)
   local to = math.random(2,3)
   local kt = math.random(3,4)
   local ki = math.random(3,4)
   local kj = math.random(3,4)
   local st = math.random(2,3)
   local si = math.random(2,3)
   local sj = math.random(2,3)
   local padT = math.random(0,2)
   local padW = math.random(0,2)
   local padH = math.random(0,2)
   local outt = math.random(3,4)
   local outi = math.random(3,4)
   local outj = math.random(3,4)
   local int = (outt-1)*st+kt-padT*2
   local ini = (outi-1)*si+ki-padW*2
   local inj = (outj-1)*sj+kj-padH*2
   local module = nn.VolumetricConvolution(from, to, kt, ki, kj, st, si, sj, padT, padW, padH)
   module:zeroGradParameters()
   local input = torch.randn(from, int, inj, ini)
   batchcompare(module,input, {'weight','bias','gradWeight','gradBias'})
end

function nntest.VolumetricAveragePooling()
   local from = math.random(2,3)
   local kt = math.random(3,4)
   local ki = math.random(3,4)
   local kj = math.random(3,4)
   local st = math.random(2,3)
   local si = math.random(2,3)
   local sj = math.random(2,3)
   local outt = math.random(3,4)
   local outi = math.random(3,4)
   local outj = math.random(3,4)
   local int = (outt-1)*st+kt
   local ini = (outi-1)*si+ki
   local inj = (outj-1)*sj+kj
   local module = nn.VolumetricAveragePooling(kt, ki, kj, st, si, sj)
   local input = torch.Tensor(from, int, inj, ini):zero()

   local err = jac.testJacobian(module, input)
   mytester:assertlt(err, precision, 'error on state ')

   local ferr, berr = jac.testIO(module, input)
   mytester:eq(0, ferr, torch.typename(module) .. ' - i/o forward err ', precision)
   mytester:eq(0, berr, torch.typename(module) .. ' - i/o backward err ', precision)

      -- batch
   local nbatch = math.random(2,3)
   module = nn.VolumetricAveragePooling(kt, ki, kj, st, si, sj)
   input = torch.Tensor(nbatch, from, int, inj, ini):zero()

   local err = jac.testJacobian(module, input)
   mytester:assertlt(err, precision, 'error on state (Batch) ')

   local ferr, berr = jac.testIO(module, input)
   mytester:eq(ferr, 0, torch.typename(module) .. ' - i/o forward err (Batch) ', precision)
   mytester:eq(berr, 0, torch.typename(module) .. ' - i/o backward err (Batch) ', precision)
end

function nntest.VolumetricMaxPooling()
   local from = math.random(2,3)
   local kt = math.random(3,4)
   local ki = math.random(3,4)
   local kj = math.random(3,4)
   local st = math.random(2,3)
   local si = math.random(2,3)
   local sj = math.random(2,3)
   local outt = math.random(3,4)
   local outi = math.random(3,4)
   local outj = math.random(3,4)
   local padT = math.min(math.random(0,2),math.floor(kt/2))
   local padW = math.min(math.random(0,2),math.floor(ki/2))
   local padH =  math.min(math.random(0,2),math.floor(kj/2))
   local int = (outt-1)*st+kt-2*padT
   local ini = (outi-1)*si+ki-2*padW
   local inj = (outj-1)*sj+kj-2*padH
   local module = nn.VolumetricMaxPooling(kt, ki, kj, st, si, sj, padT, padW, padH)
   local input = torch.Tensor(from, int, inj, ini):zero()

   local err = jac.testJacobian(module, input)
   mytester:assertlt(err, precision, 'error on state ')

   local ferr, berr = jac.testIO(module, input)
   mytester:eq(0, ferr, torch.typename(module) .. ' - i/o forward err ', precision)
   mytester:eq(0, berr, torch.typename(module) .. ' - i/o backward err ', precision)

   -- batch
   local nbatch = math.random(2,3)
   module = nn.VolumetricMaxPooling(kt, ki, kj, st, si, sj, padT, padW, padH)
   input = torch.Tensor(nbatch, from, int, inj, ini):zero()

   local err = jac.testJacobian(module, input)
   mytester:assertlt(err, precision, 'error on state (Batch) ')

   local ferr, berr = jac.testIO(module, input)
   mytester:eq(ferr, 0, torch.typename(module) .. ' - i/o forward err (Batch) ', precision)
   mytester:eq(berr, 0, torch.typename(module) .. ' - i/o backward err (Batch) ', precision)
end

function nntest.VolumetricDilatedMaxPooling()
   for _,ceil_mode in pairs({true,false}) do
      local from = math.random(2,3)
      local kt = math.random(3,4)
      local ki = math.random(3,4)
      local kj = math.random(3,4)
      local st = math.random(2,3)
      local si = math.random(2,3)
      local sj = math.random(2,3)
      local outt = math.random(3,4)
      local outi = math.random(3,4)
      local outj = math.random(3,4)
      local padT = math.min(math.random(0,1),math.floor(kt/2))
      local padW = math.min(math.random(0,1),math.floor(ki/2))
      local padH =  math.min(math.random(0,1),math.floor(kj/2))
      local dilationT = math.random(1,3)
      local dilationW = math.random(1,3)
      local dilationH = math.random(1,3)
      local int = (outt-1)*st+(dilationT*(kt-1)+1)-2*padT
      local ini = (outi-1)*si+(dilationW*(ki-1)+1)-2*padW
      local inj = (outj-1)*sj+(dilationH*(kj-1)+1)-2*padH

      local ceil_string = ceil_mode and 'ceil' or 'floor'
      local module = nn.VolumetricDilatedMaxPooling(kt,ki,kj,st,si,sj,padT,padW,padH,dilationT,dilationW,dilationH)
      if ceil_mode then module:ceil() else module:floor() end
      local input = torch.rand(from,int,inj,ini)

      local err = jac.testJacobian(module, input)
      mytester:assertlt(err, precision, 'error '..ceil_string..' mode on state ')

      local ferr, berr = jac.testIO(module, input)
      mytester:asserteq(ferr, 0, torch.typename(module) .. ' - i/o forward err ')
      mytester:asserteq(berr, 0, torch.typename(module) .. ' - i/o backward err ')

      -- batch
      local nbatch = math.random(2,5)
      input = torch.rand(nbatch,from,int,inj,ini)
      module = nn.VolumetricDilatedMaxPooling(kt,ki,kj,st,si,sj,padT,padW,padH,dilationT,dilationW,dilationH)
      if ceil_mode then module:ceil() else module:floor() end

      local err = jac.testJacobian(module, input)
      mytester:assertlt(err, precision, 'error '..ceil_string..' mode on state (Batch)')

      local ferr, berr = jac.testIO(module, input)
      mytester:asserteq(ferr, 0, torch.typename(module) .. ' - i/o forward err (Batch) ')
      mytester:asserteq(berr, 0, torch.typename(module) .. ' - i/o backward err (Batch) ')
  end
end

function nntest.VolumetricFractionalMaxPooling()
   local batch = math.random(1, 3)
   local plane = math.random(1, 3)
   local outT = math.random(1, 7)
   local outW = math.random(1, 7)
   local outH = math.random(1, 7)
   local poolSizeT = math.random(2, 4)
   local poolSizeW = math.random(2, 4)
   local poolSizeH = math.random(2, 4)

   local minInT = outT + poolSizeT
   local minInW = outW + poolSizeW
   local minInH = outH + poolSizeH

   local inT = math.random(minInT, minInT + 6)
   local inW = math.random(minInW, minInW + 6)
   local inH = math.random(minInH, minInH + 6)

   -- fix the pooling regions so they aren't regenerated with every
   -- forward(), so testJacobian can work properly
   local module =
      nn.VolumetricFractionalMaxPooling(poolSizeT, poolSizeW, poolSizeH, outT, outW, outH)
      :fixPoolingRegions()
   local input = nil
   if batch == 1 then
      input = torch.Tensor(plane, inH, inW, inT):zero()
   else
      input = torch.Tensor(batch, plane, inH, inW, inT):zero()
   end

   local err = nn.Jacobian.testJacobian(module, input)
   mytester:assertlt(err, precision, 'error on state')
end

function nntest.VolumetricFractionalMaxPooling_Ratio()
   -- Fix a reduction ratio, and test with two different input sizes
   local reductionRatioT = torch.uniform(0.4, 0.74)
   local reductionRatioW = torch.uniform(0.4, 0.74)
   local reductionRatioH = torch.uniform(0.4, 0.74)

   for tries = 1, 2 do
      local batch = math.random(1, 3)
      local plane = math.random(1, 3)
      local poolSizeT = math.random(2, 3)
      local poolSizeW = math.random(2, 3)
      local poolSizeH = math.random(2, 3)

      local minInT = math.random(5, 8) + poolSizeT
      local minInW = math.random(5, 8) + poolSizeW
      local minInH = math.random(5, 8) + poolSizeH

      local inT = math.random(minInT, minInT + 6)
      local inW = math.random(minInW, minInW + 6)
      local inH = math.random(minInH, minInH + 6)

      -- fix the pooling regions so they aren't regenerated with every
      -- forward(), so testJacobian can work properly
      local module =
         nn.VolumetricFractionalMaxPooling(poolSizeT, poolSizeW, poolSizeH,
                                        reductionRatioT, reductionRatioW,
                                        reductionRatioH)
         :fixPoolingRegions()
      local input = nil
      if batch == 1 then
         input = torch.Tensor(plane, inH, inW, inT):zero()
      else
         input = torch.Tensor(batch, plane, inH, inW, inT):zero()
      end

      -- Make sure that the output size is based on our ratio
      local output = module:updateOutput(input)
      if batch == 1 then
         mytester:asserteq(output:size(4), math.floor(reductionRatioT * inT))
         mytester:asserteq(output:size(3), math.floor(reductionRatioW * inW))
         mytester:asserteq(output:size(2), math.floor(reductionRatioH * inH))
      else
         mytester:asserteq(output:size(5), math.floor(reductionRatioT * inT))
         mytester:asserteq(output:size(4), math.floor(reductionRatioW * inW))
         mytester:asserteq(output:size(3), math.floor(reductionRatioH * inH))
      end

      local err = nn.Jacobian.testJacobian(module, input)
      mytester:assertlt(err, precision, 'error on state')
   end
end

function nntest.VolumetricMaxUnpooling()
   local from = math.random(2,3)
   local kt = math.random(3,4)
   local ki = math.random(3,4)
   local kj = math.random(3,4)
   local st, si, sj = kt, ki, kj
   local outt = math.random(3,4)
   local outi = math.random(3,4)
   local outj = math.random(3,4)
   local padT = math.min(math.random(0,2),math.floor(kt/2))
   local padW = math.min(math.random(0,2),math.floor(ki/2))
   local padH = math.min(math.random(0,2),math.floor(kj/2))
   local int = (outt-1)*st+kt-2*padT
   local ini = (outi-1)*si+ki-2*padW
   local inj = (outj-1)*sj+kj-2*padH

   local poolingModule = nn.VolumetricMaxPooling(kt, ki, kj, st, si, sj, padT, padW, padH)
   local module = nn.VolumetricMaxUnpooling(poolingModule)

   local original = torch.rand(from,int,inj,ini)
   local input = poolingModule:forward(original)
   local output = module:forward(input)
   mytester:assert(output:isSameSizeAs(original),'VolumetricMaxUnpooling output size err')

   local err = jac.testJacobian(module, input)
   mytester:assertlt(err, precision, 'error ')

   local ferr, berr = jac.testIO(module, input)
   mytester:eq(ferr, 0, torch.typename(module) .. ' - i/o forward err ', precision)
   mytester:eq(berr, 0, torch.typename(module) .. ' - i/o backward err ', precision)

   -- batch
   local nbatch = math.random(2,3)
   original = torch.rand(nbatch,from,int,inj,ini)
   input = poolingModule:forward(original)
   output = module:forward(input)

   mytester:assert(output:isSameSizeAs(original),'VolumetricMaxUnpooling batch output size err')

   local err = jac.testJacobian(module, input)
   mytester:assertlt(err, precision, 'error on Batch')

   local ferr, berr = jac.testIO(module, input)
   mytester:eq(ferr, 0, torch.typename(module) .. ' - i/o forward err (Batch) ', precision)
   mytester:eq(berr, 0, torch.typename(module) .. ' - i/o backward err (Batch) ', precision)
end

function nntest.VolumetricMaxPooling_boundary()
   -- simple kernel 2x2x2 with striding 2x2x2
   local module = nn.VolumetricMaxPooling(2, 2, 2, 2, 2, 2):ceil()
   local nip = math.random(3,256)
   local input = torch.rand(nip, 2, 7, 7)

   -- do a forward pass
   local output = module:forward(input)

   -- checking output size
   mytester:asserteq(output:size(1), nip, 'wrong output channels')
   mytester:asserteq(output:size(2), 1, 'wrong output temporal length')
   mytester:asserteq(output:size(3), 4, 'wrong output height')
   mytester:asserteq(output:size(4), 4, 'wrong output width')

   -- checking output signals at top right
   for c = 1,nip do
      local max_val = input[c][1][1][7]
      for t = 1,2 do
        for h = 1,2 do
          max_val = math.max(max_val, input[c][t][h][7])
        end
      end
      mytester:asserteq(output[c][1][1][4], max_val, 'wrong forward execution')
   end
   -- checking output signals at bottom left
   for c = 1,nip do
       local max_val = input[c][1][7][1]
       for t = 1,2 do
         for w = 1,2 do
           max_val = math.max(max_val, input[c][t][7][w])
         end
       end
       mytester:asserteq(output[c][1][4][1], max_val, 'wrong forward execution')
   end

   -- check output signals at right bottom
    for c = 1,nip do
      local max_val = math.max(input[c][1][7][7], input[c][2][7][7])
      mytester:asserteq(output[c][1][4][4], max_val, 'wrong forward execution')
    end


   -- backward is supposed to be tested in nntest.VolumetricMaxPooling
   -- This is only test the boundary cases
end

function nntest.Module_getParameters_1()
   local n = nn.Sequential()
   n:add( nn.Linear(10,10) )
   local p = n:getParameters()

   mytester:asserteq((p[{ {1,100} }] - n.modules[1].weight):norm(), 0, 'getParameters(): weights wrong')
   mytester:asserteq((p[{ {101,110} }] - n.modules[1].bias):norm(), 0, 'getParameters(): bias wrong')
end

function nntest.Module_getParameters_2()
   local n = nn.Sequential()
   n:add( nn.Linear(10,10) )
   local _ = n:getParameters()

   n:add( nn.Linear(10,10) )
   local p = n:getParameters()

   mytester:asserteq((p[{ {111,210} }] - n.modules[2].weight):norm(), 0, 'error when appending new module')
   mytester:asserteq((p[{ {211,220} }] - n.modules[2].bias):norm(), 0, 'error when appending new module')
end

function nntest.Module_getParameters_3()
   local n = nn.Sequential()
   n:add( nn.Linear(10,10) )
   n:add( n.modules[1]:clone() )
   local p = n:getParameters()

   mytester:asserteq((p[{ {1,100} }] - n.modules[1].weight):norm(), 0, 'error when using cloning')
   mytester:asserteq((p[{ {101,110} }] - n.modules[1].bias):norm(), 0, 'error when using cloning')

   mytester:asserteq((p[{ {111,210} }] - n.modules[2].weight):norm(), 0, 'error when using cloning')
   mytester:asserteq((p[{ {211,220} }] - n.modules[2].bias):norm(), 0, 'error when using cloning')

   mytester:asserteq((p[{ {111,210} }] - n.modules[1].weight):norm(), 0, 'error when using cloning')
   mytester:asserteq((p[{ {211,220} }] - n.modules[1].bias):norm(), 0, 'error when using cloning')

   n:reset()

   mytester:assertgt((p[{ {111,210} }] - n.modules[1].weight):norm(), 0, 'error when using cloning')
   mytester:assertgt((p[{ {211,220} }] - n.modules[1].bias):norm(), 0, 'error when using cloning')
end

function nntest.Module_getParameters_4()
   local n = nn.Sequential()
   n:add( nn.Linear(10,10) )
   n:add( n.modules[1]:clone() )
   local _ = n:getParameters()

   n:add(nn.Linear(10,10))
   local p = n:getParameters()

   mytester:asserteq((p[{ {1,100} }] - n.modules[1].weight):norm(), 0, 'error when using cloning')
   mytester:asserteq((p[{ {101,110} }] - n.modules[1].bias):norm(), 0, 'error when using cloning')

   mytester:asserteq((p[{ {111,210} }] - n.modules[2].weight):norm(), 0, 'error when using cloning')
   mytester:asserteq((p[{ {211,220} }] - n.modules[2].bias):norm(), 0, 'error when using cloning')

   mytester:asserteq((p[{ {221,320} }] - n.modules[3].weight):norm(), 0, 'error when using cloning')
   mytester:asserteq((p[{ {321,330} }] - n.modules[3].bias):norm(), 0, 'error when using cloning')

   mytester:asserteq(p:nElement(), 3*(10*10+10), 'error: incorrect number of elements in flat vector')
end

function nntest.Module_getParameters_5()
   local n = nn.Sequential()
   n:add( nn.Linear(10,10) )
   n:add( n.modules[1]:clone('weight','bias','gradWeight','gradBias') )
   local p = n:getParameters()

   mytester:asserteq((p[{ {1,100} }] - n.modules[1].weight):norm(), 0, 'error when using cloning+sharing')
   mytester:asserteq((p[{ {101,110} }] - n.modules[1].bias):norm(), 0, 'error when using cloning+sharing')

   mytester:asserteq((p[{ {1,100} }] - n.modules[2].weight):norm(), 0, 'error when using cloning+sharing')
   mytester:asserteq((p[{ {101,110} }] - n.modules[2].bias):norm(), 0, 'error when using cloning+sharing')

   n:reset()

   mytester:asserteq((p[{ {1,100} }] - n.modules[2].weight):norm(), 0, 'error when using cloning+sharing')
   mytester:asserteq((p[{ {101,110} }] - n.modules[2].bias):norm(), 0, 'error when using cloning+sharing')

   mytester:asserteq(p:nElement(), (10*10+10), 'error: incorrect number of elements in flat vector')
end

function nntest.Module_getParameters_6()
   local n = nn.Sequential()
   n:add( nn.Linear(10,10) )
   n:add( n.modules[1]:clone('weight','bias','gradWeight','gradBias') )
   local _ = n:getParameters()

   n:add(nn.Linear(10,10))
   local p = n:getParameters()

   mytester:asserteq((p[{ {1,100} }] - n.modules[1].weight):norm(), 0, 'error when using cloning+sharing')
   mytester:asserteq((p[{ {101,110} }] - n.modules[1].bias):norm(), 0, 'error when using cloning+sharing')

   mytester:asserteq((p[{ {1,100} }] - n.modules[2].weight):norm(), 0, 'error when using cloning+sharing')
   mytester:asserteq((p[{ {101,110} }] - n.modules[2].bias):norm(), 0, 'error when using cloning+sharing')

   mytester:asserteq((p[{ {111,210} }] - n.modules[3].weight):norm(), 0, 'error when using cloning+sharing')
   mytester:asserteq((p[{ {211,220} }] - n.modules[3].bias):norm(), 0, 'error when using cloning+sharing')

   mytester:asserteq(p:nElement(), 2*(10*10+10), 'error: incorrect number of elements in flat vector')
end

function nntest.Module_getParameters_7()
   local n = nn.Sequential()
   n:add( nn.Linear(10,10) )
   n:add( n.modules[1]:clone('weight','bias','gradWeight','gradBias') )
   local _ = n:getParameters()

   n:add(nn.Linear(10,10))
   local _ = n:getParameters()

   local n1 = nn.Sequential()
   n1:add( nn.Linear(10,10) )

   local n2 = nn.Sequential()
   n2:add( nn.Linear(10,10) )

   local n = nn.Sequential()
   n:add( n1 )
   n:add( n2 )

   local _ = n:getParameters()

   local nf = nn.Sequential()
   nf:add( n1 )
   nf:add( nn.Linear(10,1) )

   local p = nf:getParameters()

   mytester:asserteq((p[{ {1,100} }] - n1.modules[1].weight):norm(), 0, 'error when using cloning+partial realloc')
   mytester:asserteq((p[{ {101,110} }] - n1.modules[1].bias):norm(), 0, 'error when using cloning+partial realloc')

   mytester:asserteq((p[{ {111,120} }] - nf.modules[2].weight):norm(), 0, 'error when using cloning+partial realloc')
   mytester:asserteq((p[{ {121,121} }] - nf.modules[2].bias):norm(), 0, 'error when using cloning+partial realloc')

   mytester:asserteq(p:nElement(), 121, 'error: incorrect number of elements in flat vector')
end

function nntest.Module_getParameters_8()
   local function makeMLP(nin, ns)
      local net = nn.Sequential()

      for k,v in ipairs(ns) do
         net:add(nn.Linear(nin, v))
         nin = v
      end
      local _,_ = net:getParameters()
      return net
   end

  local mlp1 = makeMLP(10, {10,10})
  local mlp2 = makeMLP(10, {10,10})

  local net = nn.Sequential():add(mlp1:get(1))
                             :add(mlp2:get(1))

  -- clone the second MLP to ensure that the weights before calling getParameters are preserved
  mlp2 = mlp2:clone()

  local p, _ = net:getParameters()

  mytester:asserteq((p[{ {1,100} }] - net.modules[1].weight):norm(), 0, 'error when using partial realloc')
  mytester:asserteq((p[{ {111,210} }] - net.modules[2].weight):norm(), 0, 'error when using partial realloc')
  -- check that the weights have the same values as before get Parameters was called
  mytester:asserteq((net.modules[1].weight - mlp1.modules[1].weight):norm(), 0, ' error when using partial realloc')
  mytester:asserteq((net.modules[2].weight - mlp2.modules[1].weight):norm(), 0, ' error when using partial realloc')

end

function nntest.Module_getParameters_10()
   -- tensors are non-contiguous but compact; they can be gathered
   local L = nn.Linear(10,10)
   L.weight = torch.Tensor(10,10):t():fill(1)
   local tmp = torch.Tensor(10,10):fill(2)
   L.bias = tmp:select(1,2)
   local P = L:getParameters()
   mytester:asserteq(L.weight:mean(), 1)
   mytester:asserteq(L.bias:mean(), 2)
   mytester:asserteq(L.weight:storage(), L.bias:storage())
   mytester:asserteq(P:nElement(), 110)
   mytester:asserteq(P:storage():size(), 110)
   mytester:assertlt(L.bias[{ {10} }]:storageOffset() - 1, L.bias:storage():size())
end

function nntest.Module_getParameters_11()
   -- tensors are non-compact; they can't be gathered
   local L = nn.Linear(10,10)
   local tmp = torch.Tensor(10,10):fill(2)
   L.bias = tmp:select(2,2)
   local ok, err = pcall(L.getParameters, L)
   mytester:assert(not ok)
end

function nntest.Module_getParameters_12()
   -- tensors are expanded (i.e. have dimension 0)
   local L = nn.Linear(10,10)
   L.weight = torch.Tensor(10, 1):fill(1)
   torch.expand(L.weight, 10, 10)
   L.gradWeight = torch.Tensor(10, 1):fill(1)
   torch.expand(L.gradWeight, 10, 10)
   L.bias = torch.Tensor(10):fill(2)
   local P = L:getParameters()
   mytester:asserteq(L.weight:mean(), 1)
   mytester:asserteq(L.bias:mean(), 2)
   mytester:asserteq(L.weight:storage(), L.bias:storage())
   mytester:asserteq(P:nElement(), 20)
   mytester:asserteq(P:storage():size(), 20)
   mytester:assertlt(L.bias[{ {10} }]:storageOffset() - 1, L.bias:storage():size())
end

function nntest.Module_listModules()
   local batchSize = 4
   local inputSize, outputSize = 7, 6
   local linear = nn.Linear(inputSize, outputSize)
   local tanh = nn.Tanh()
   local reshape = nn.Reshape(outputSize/2, 2)
   local mlp3 = nn.Sequential()
   mlp3:add(linear)
   mlp3:add(tanh)
   mlp3:add(reshape)

   local mlp2 = nn.Sequential()
   local view = nn.View(outputSize)
   local linear2 = nn.Linear(outputSize, inputSize)
   local tanh2 = nn.Tanh()
   mlp2:add(mlp3)
   mlp2:add(view)
   mlp2:add(linear2)
   mlp2:add(tanh2)

   local concat = nn.ConcatTable()
   local id = nn.Identity()
   concat:add(mlp2)
   concat:add(id)
   local mlp = nn.Sequential()
   local add = nn.CAddTable()
   mlp:add(concat)
   mlp:add(add)

   local modules2 = {mlp, concat, mlp2, mlp3, linear, tanh, reshape, view, linear2, tanh2, id, add}
   local modules = mlp:listModules()

   mytester:assert(#modules2 == #modules, 'missing modules error')

   for i,module in ipairs(modules) do
      mytester:assert(torch.type(module) == torch.type(modules2[i]), 'module error')
   end
end

function nntest.PairwiseDistance()
   -- Note: testJacobian doesn't support table inputs, and rather than re-write
   -- it so that it does, I'll just use a split table module on the input.
   -- I assume both SplitTable and Sequential do not have bugs, otherwise this
   -- test will break.
   for p = 1,4 do  -- test a few Lp norms
      -- TEST CASE 1: non-batch input, same code path but includes a resize
      local ini = math.random(3,5)
      local input = torch.Tensor(2, ini):zero()
      local module = nn.Sequential()
      module:add(nn.SplitTable(1))
      module:add(nn.PairwiseDistance(p))

      local err = jac.testJacobian(module,input)
      mytester:assertlt(err, 1e-4, ' error on state ')

      local ferr,berr = jac.testIO(module,input)
      mytester:asserteq(ferr, 0, torch.typename(module)..' - i/o forward err ')
      mytester:asserteq(berr, 0, torch.typename(module)..' - i/o backward err ')

      -- Also check that the forward prop result is correct.
      input = torch.rand(2, ini)
      err = torch.dist(input:select(1,1), input:select(1,2), p) -
        module:forward(input)[1]
      mytester:assertlt(err,precision, ' error on non-batch fprop ')

      -- TEST CASE 2: batch input
      local inj = math.random(3,5)
      input = torch.Tensor(2, inj, ini):zero()

      -- (Rebuild the module to avoid correlated tests)
      module = nn.Sequential()
      module:add(nn.SplitTable(1))
      module:add(nn.PairwiseDistance(p))

      err = jac.testJacobian(module,input)
      mytester:assertlt(err, 1e-4, ' error on state ')

      -- Also check that the forward prop result is correct.
      -- manually calculate each distance separately
      local inputa = torch.rand(inj,ini)
      local inputb = torch.rand(inj,ini)
      local dist_manual = torch.Tensor(inj)
      for i=1, inputa:size(1) do
         dist_manual[i] = torch.dist(inputa:select(1,i), inputb:select(1,i),p)
      end
      -- compare the distances to the module's fprop
      local dist = module:forward(torch.cat(inputa,inputb,1):resize(2,inj,ini))
      err = dist - dist_manual
      mytester:assertlt(err:norm(), precision, torch.typename(module) ..
         ' error on batch fprop ')
  end
end

function nntest.Index()
    local net = nn.Index(1)

    -- test 1D
    local input = {torch.Tensor{10, 20, 30}, torch.LongTensor{1, 2, 2, 3}}
    local output = net:forward(input)
    equal(output, torch.Tensor{10, 20, 20, 30}, "error in 1D forward pass")

    local gradOutput = torch.Tensor{1, 1, 1, 3 }
    local gradInput = net:backward(input, gradOutput)
    equal(gradInput[1], torch.Tensor{1, 2, 3}, "error in 1D backward pass")

    -- test 2D
    local input = {torch.Tensor{{10, 20}, {30, 40}}, torch.LongTensor{1, 1}}
    local output = net:forward(input)
    equal(output, torch.Tensor{{10, 20}, {10, 20}}, "error in 2D forward pass")

    local gradOutput = torch.Tensor{{1, 2}, {1, 2}}
    local gradInput = net:backward(input, gradOutput)
    equal(gradInput[1], torch.Tensor{{2, 4}, {0, 0}}, "error in 2D backward pass")

    -- test clearState
    local m = nn.Index(1)
    local tensor = torch.Tensor(10, 3)
    local indices = torch.LongTensor{ 2,3,4}

    m:clearState()
    m:forward({tensor, indices})
    m:backward({tensor,indices}, torch.rand(3,3))

end

function nntest.Squeeze()
   local input  = torch.Tensor(2,1,3):zero()
   local module = nn.Squeeze()
   equal(module:forward(input), input:squeeze(), "error in forward pass")
   local output = input:squeeze()
   equal(module:backward(input, output), input, "error in backward pass")

   -- testing the dimension option:
   local input  = torch.Tensor(2,1,1,3):zero()
   local module = nn.Squeeze(2)
   equal(module:forward(input), input:squeeze(2), "error in forward pass with dimension")
   local output = input:squeeze(2)
   equal(module:backward(input, output), input, "error in backward pass with dimension")

   -- with batch
   local input  = torch.Tensor(2,1,1,3):zero()
   local module = nn.Squeeze(2, 3)
   equal(module:forward(input), input:squeeze(3), "error in forward pass with dimension")
   local output = input:squeeze(3)
   equal(module:backward(input, output), input, "error in backward pass with dimension")


   -- ... of size one
   local input  = torch.Tensor(1,1,1,3):zero()
   local module = nn.Squeeze(2, 3)
   equal(module:forward(input), input:squeeze(3), "error in forward pass with dimension")
   local output = input:squeeze(3)
   equal(module:backward(input, output), input, "error in backward pass with dimension")
end

function nntest.Unsqueeze()
   local function assertInputOutputSize(inputSize, outputSize, tf)
      local input = torch.Tensor(table.unpack(inputSize)):zero()
      local output = torch.Tensor(table.unpack(outputSize)):zero()
      local gradInput = input:clone()
      local gradOutput = output:clone()
      equal(tf:forward(input), output, "error in forward pass")
      equal(tf:backward(input, gradOutput), gradInput, "error in backward pass")
   end

   local function test_normal()
      -- insert dim 1 at head
      local inputSize, outputSize = {2,3,4}, {1, 2,3,4}
      local pos = 1
      assertInputOutputSize(inputSize,outputSize, nn.Unsqueeze(pos))

      -- insert dim 1 at tail
      local inputSize, outputSize = {2,3,4}, {2,3,4, 1}
      local pos = 4
      assertInputOutputSize(inputSize,outputSize, nn.Unsqueeze(pos))

      -- insert dim 1 in between
      local inputSize, outputSize = {2,3,4}, {2, 1, 3,4}
      local pos = 2
      assertInputOutputSize(inputSize,outputSize, nn.Unsqueeze(pos))
   end

   local function test_batchmode()
      -- batch mode: insert dim 1 at head
      local inputSize, outputSize = {5, 2, 3, 4}, {5, 1, 2, 3, 4}
      local pos = 1
      local numInputDims = 3
      assertInputOutputSize(inputSize,outputSize, nn.Unsqueeze(pos, numInputDims))

      -- batch mode: insert dim 1 at tail
      local inputSize, outputSize = {5, 2, 3, 4}, {5, 2, 3, 4, 1}
      local pos = 4
      local numInputDims = 3
      assertInputOutputSize(inputSize,outputSize, nn.Unsqueeze(pos, numInputDims))

      -- batch mode: insert dim 1 in between
      local inputSize, outputSize = {5, 2, 3, 4}, {5, 2, 1, 3, 4}
      local pos = 2
      local numInputDims = 3
      assertInputOutputSize(inputSize,outputSize, nn.Unsqueeze(pos, numInputDims))
   end

   local function test_sizeone()
      local inputSize, outputSize = {1,1,3,1}, {1,1, 1, 3,1}
      local pos = 3
      assertInputOutputSize(inputSize,outputSize, nn.Unsqueeze(pos))

      local inputSize, outputSize = {1,1,3,2}, {1,1,3,2, 1}
      local pos = 3
      local numInputDims = 2
      assertInputOutputSize(inputSize,outputSize, nn.Unsqueeze(pos, numInputDims))
   end

   local function test_sizestrange()
      local inputSize, outputSize = {2}, {2,1}
      local pos = 2
      assertInputOutputSize(inputSize,outputSize, nn.Unsqueeze(pos))

      local inputSize, outputSize = {1}, {1, 1}
      local pos = 1
      assertInputOutputSize(inputSize,outputSize, nn.Unsqueeze(pos))
   end

   test_normal()
   test_batchmode()
   test_sizeone()
   test_sizestrange()
end

function nntest.LookupTable()
   local totalIndex = math.random(6,9)
   local nIndex = math.random(3,5)
   local entry_size = math.random(2,5)

   local function dotest(module, input, minval, maxval)
       local output = module:forward(input)
       module:backwardUpdate(input, output, 0.1)
       input:zero()

       -- 1D
       local err = jac.testJacobianParameters(module, input, module.weight, module.gradWeight, minval, maxval)
       mytester:assertlt(err,precision, '1D error on weight ')

       local err = jac.testJacobianUpdateParameters(module, input, module.weight, minval, maxval)
       mytester:assertlt(err,precision, '1D error on weight [direct update] ')

       module.gradWeight:zero()
       for t,err in pairs(jac.testAllUpdate(module, input, 'weight', 'gradWeight')) do
          mytester:assertlt(err, precision, string.format(
                             '1D error on weight [%s]', t))
       end

       -- 2D
       local nframe = math.random(2,5)
       local input = torch.IntTensor(nframe, nIndex):zero()

       local err = jac.testJacobianParameters(module, input, module.weight, module.gradWeight, minval, maxval)
       mytester:assertlt(err,precision, '2D error on weight ')

       local err = jac.testJacobianUpdateParameters(module, input, module.weight, minval, maxval)
       mytester:assertlt(err,precision, '2D error on weight [direct update] ')

       module.gradWeight:zero()
       for t,err in pairs(jac.testAllUpdate(module, input, 'weight', 'gradWeight')) do
          mytester:assertlt(err, precision, string.format(
                             '2D error on weight [%s]', t))
       end

       -- IO
       module.gradInput = torch.Tensor(3,4):zero() --fixes an error
       local ferr,berr = jac.testIO(module,input,minval,maxval)
       mytester:eq(ferr, 0, torch.typename(module) .. ' - i/o forward err ', precision)
       mytester:eq(berr, 0, torch.typename(module) .. ' - i/o backward err ', precision)

       -- accUpdate
       module:accUpdateOnly()
       mytester:assert(not module.gradWeight, 'gradWeight is nil')
       module:float()
       local output = module:forward(input)
       module:backwardUpdate(input, output, 0.1)
   end
   -- test without padding
   local input = torch.randperm(totalIndex):narrow(1,1,nIndex):int()
   local module = nn.LookupTable(totalIndex, entry_size)
   dotest(module, input, 1, totalIndex)
   -- test with padding set to 1, but no padding in inputs
   local input = torch.randperm(totalIndex):narrow(1,1,nIndex):int()
   local module = nn.LookupTable(totalIndex, entry_size, 1)
   dotest(module, input, 2, totalIndex)
   -- test whether padding weights remain unchanged
   local paddingValue = math.random(totalIndex)
   local module = nn.LookupTable(totalIndex, entry_size, paddingValue)
   local padw = module.weight:select(1,paddingValue):fill(1)
   local padw_sum = padw:sum()
   local input = torch.IntTensor(nIndex)
   for i = 1, 100 do
       input:apply(
       function() -- set randomly half of the input as padding
           if torch.random(2) == 1 then return paddingValue end
           return torch.random(totalIndex)
       end)
       local y = module:updateOutput(input)
       module:updateGradInput(input, y)
       module:accUpdateGradParameters(input, y, 0.1)
   end
   local err = padw_sum - padw:sum()
   mytester:assertlt(err,precision, 'padding update error ')
   -- test whether the weights changes accordingly when maxNorm is not nil
   local all_index = torch.randperm(totalIndex):int()
   -- input can have duplicates
   local input = torch.repeatTensor(all_index:narrow(1,1,nIndex), 2)
   local maxNorm = math.random()
   for _, normType in ipairs{1, 2, math.random()} do
      local module = nn.LookupTable(totalIndex, entry_size, 0, maxNorm, normType)
      local oriW = module.weight:clone()
      local output = module:updateOutput(input)
      -- check output is of small norm
      for j = 1,output:size(1) do
         local norm = torch.norm(output:select(1, j), normType)
         if norm > maxNorm then
            local err = norm - maxNorm;
            mytester:assertlt(math.abs(err), precision, string.format(
               'output after renorm exceeds maxNorm=[%f] with normType=[%f]', maxNorm, normType))
         end
      end
      -- check the update of the module.weight
      for j = 1,totalIndex do
         local k = all_index[j]
         if j <= nIndex then -- k is an index in "input"
            local norm = torch.norm(module.weight:select(1, k), normType)
            local oriNorm = torch.norm(oriW:select(1, k), normType)
            if oriNorm > maxNorm then
               local err = norm - maxNorm
               mytester:assertlt(math.abs(err), precision, 'unexpected norm after renorm')
            else
               local err = norm - oriNorm
               mytester:assertlt(math.abs(err), precision, 'unpexpected norm after renorm')
            end
         else -- k is not an index in "input"
            local err = module.weight:select(1,k):sum() - oriW:select(1,k):sum()
            mytester:assertlt(math.abs(err), precision, 'unexpected changes in weight after renorm')
         end
      end
   end
end

function nntest.AddConstant()
  local nbatch = torch.random(3, 5)
  local f = torch.random(3, 5)
  local h = torch.random(7,9)
  local w = torch.random(7,9)
  local input = torch.rand(nbatch, f, h, w):mul(20):add(-10)  -- [-10, 10]

  local constant = torch.randn(1):squeeze()
  local mod = nn.AddConstant(constant)

  -- Test FPROP
  local output = mod:forward(input)
  local delta = output - input
  mytester:assertlt(delta:add(-constant):abs():max(), precision, 'fprop error')

  -- Test BPROP
  local err = jac.testJacobian(mod, input)
  mytester:assertlt(err, precision, 'bprop error ')

  -- inplace comparisons
  local ini = math.random(3,5)
  local inj = math.random(3,5)
  local ink = math.random(3,5)
  local constant = torch.uniform()*math.random(1,10)

  local input1 = torch.rand(ink, inj, ini)
  local input2 = input1:clone()

  local module1 = nn.AddConstant(constant,true)
  local module2 = nn.AddConstant(constant)

  local gradOutput1 = torch.rand(ink, inj, ini)
  local gradOutput2 = gradOutput1:clone()

  local out1 = module1:forward(input1)
  local out2 = module2:forward(input2)

  mytester:asserteq(0, (out1-out2):abs():max(), torch.typename(module1) ..
                    ' - in-place forward err ')

  local gradInput1 = module1:backward(input1, gradOutput1)
  local gradInput2 = module2:backward(input2, gradOutput2)

  mytester:asserteq(0, (gradInput1-gradInput2):abs():max(),
                torch.typename(module1) .. ' - in-place backward err ')

  local input1 = torch.rand(ink, inj, ini)
  local input2 = input1:clone()

  module1:forward(input1)
  module1:backward(module1.output,torch.rand(input1:size()))

  local err = (input1-input2):abs():max()
  mytester:asserteq(err, 0, torch.typename(module1) ..
                          ' - inplace input change err ')

  local module3 = nn.AddConstant(torch.Tensor{1,2,3})
  local out3 = module3:forward(torch.Tensor{-1,-2,-3})
  mytester:asserteq(0, out3:abs():max(), torch.typename(module3) ..
                      ' - tensor constant forward err ')
  local module4 = nn.AddConstant(torch.Tensor{1,2,3})
  local out4 = module3:forward(torch.Tensor{{-1,-2,-3},{-1,-2,-3}})
  mytester:asserteq(0, out4:abs():max(), torch.typename(module4) ..
                      ' - batch tensor constant forward err ')
end

function nntest.MulConstant()
  local nbatch = torch.random(3, 5)
  local f = torch.random(3, 5)
  local h = torch.random(7,9)
  local w = torch.random(7,9)
  local input = torch.rand(nbatch, f, h, w):mul(20):add(-10)  -- [-10, 10]

  local constant = torch.randn(1):squeeze()
  local mod = nn.MulConstant(constant)

  -- Test FPROP
  local output = mod:forward(input)
  local scale = output:clone():cdiv(input)
  mytester:assertlt(scale:add(-constant):abs():max(), precision, 'fprop error')

  -- Test BPROP
  local err = jac.testJacobian(mod, input)
  mytester:assertlt(err, precision, 'bprop error ')

  -- inplace comparisons
  local ini = math.random(3,5)
  local inj = math.random(3,5)
  local ink = math.random(3,5)
  local constant = torch.uniform()*math.random(1,10)

  local input1 = torch.rand(ink, inj, ini)
  local input2 = input1:clone()

  local module1 = nn.MulConstant(constant,true)
  local module2 = nn.MulConstant(constant)

  local gradOutput1 = torch.rand(ink, inj, ini)
  local gradOutput2 = gradOutput1:clone()

  local out1 = module1:forward(input1)
  local out2 = module2:forward(input2)

  mytester:asserteq(0, (out1-out2):abs():max(), torch.typename(module1) ..
                    ' - in-place forward err ')

  local gradInput1 = module1:backward(input1, gradOutput1)
  local gradInput2 = module2:backward(input2, gradOutput2)

  mytester:asserteq(0, (gradInput1-gradInput2):abs():max(),
                torch.typename(module1) .. ' - in-place backward err ')

  local input1 = torch.rand(ink, inj, ini)
  local input2 = input1:clone()

  module1:forward(input1)
  module1:backward(module1.output,torch.rand(input1:size()))

  local err = (input1-input2):abs():max()
  mytester:assertalmosteq(err, 0, 1e-15, torch.typename(module1) ..
                          ' - inplace input change err ')
end

function nntest.Copy()
   local input = torch.randn(3,4):double()
   local c = nn.Copy('torch.DoubleTensor', 'torch.FloatTensor')
   local output = c:forward(input)
   mytester:assert(torch.type(output) == 'torch.FloatTensor', 'copy forward type err')
   mytester:assertTensorEq(output, input:float(), 0.000001, 'copy forward value err')
   local gradInput = c:backward(input, output)
   mytester:assert(torch.type(gradInput) == 'torch.DoubleTensor', 'copy backward type err')
   mytester:assertTensorEq(gradInput, input, 0.000001, 'copy backward value err')
   c.dontCast = true
   c:double()
   mytester:assert(torch.type(output) == 'torch.FloatTensor', 'copy forward type err')
end

function nntest.CMaxTable()
   local input1 = torch.Tensor{{1,3},{2,4}}
   local input2 = torch.Tensor{{4,2},{3,1}}
   local input = {input1, input2}
   local module = nn.CMaxTable()
   local err1 = torch.add(module:forward(input), -1, torch.Tensor{{4,3},{3,4}})
   mytester:assertalmosteq(err1:abs():max(), 0, 1e-15, "CMaxTable forward call")
   local gradOutputs = torch.Tensor{5,6,7,8}
   local gradInputs = module:backward(input, gradOutputs)
   local err2 = torch.add(gradInputs[1], -1, torch.Tensor{{0,6},{0,8}})
   local err3 = torch.add(gradInputs[2], -1, torch.Tensor{{5,0},{7,0}})
   mytester:assertalmosteq(err2:abs():max(), 0, 1e-15, "CMaxTable backward call")
   mytester:assertalmosteq(err3:abs():max(), 0, 1e-15, "CMaxTable backward call")
end

function nntest.CMinTable()
   local input1 = torch.Tensor{{1,3},{2,4}}
   local input2 = torch.Tensor{{4,2},{3,1}}
   local input = {input1, input2}
   local module = nn.CMinTable()
   local err1 = torch.add(module:forward(input), -1, torch.Tensor{{1,2},{2,1}})
   mytester:assertalmosteq(err1:abs():max(), 0, 1e-15, "CMinTable forward call")
   local gradOutputs = torch.Tensor{5,6,7,8}
   local gradInputs = module:backward(input, gradOutputs)
   local err2 = torch.add(gradInputs[1], -1, torch.Tensor{{5,0},{7,0}})
   local err3 = torch.add(gradInputs[2], -1, torch.Tensor{{0,6},{0,8}})
   mytester:assertalmosteq(err2:abs():max(), 0, 1e-15, "CMinTable backward call")
   mytester:assertalmosteq(err3:abs():max(), 0, 1e-15, "CMinTable backward call")
end

function nntest.JoinTable()
   local tensor = torch.rand(3,4,5)
   local input = {tensor, tensor}
   local module
   for d = 1,tensor:dim() do
      module = nn.JoinTable(d)
      mytester:asserteq(module:forward(input):size(d), tensor:size(d)*2, "dimension " .. d)
   end

   -- Minibatch
   local tensor = torch.rand(3,4,5)
   local input = {tensor, tensor}
   local module
   for d = 1,tensor:dim()-1 do
      module = nn.JoinTable(d, 2)
      mytester:asserteq(module:forward(input):size(d+1), tensor:size(d+1)*2, "dimension " .. d)
   end
end

function nntest.SplitTable()
   local input = torch.randn(3,4,5)
   local module
   for d = 1,input:dim() do
      module = nn.SplitTable(d)
      mytester:asserteq(#module:forward(input), input:size(d), "dimension " .. d)
   end

   -- Minibatch
   local input = torch.randn(3,4,5)
   local module
   for d = 1,input:dim()-1 do
      module = nn.SplitTable(d, 2)
      mytester:asserteq(#module:forward(input), input:size(d+1), "dimension " .. d)
   end

   -- Negative indices
   local module = nn.SplitTable(-3)
   local input = torch.randn(3,4,5)
   mytester:asserteq(#module:forward(input), 3, "negative index")
   local input = torch.randn(2,3,4,5)
   mytester:asserteq(#module:forward(input), 3, "negative index (minibatch)")
end

function nntest.Select()
  -- Test negative Select
  local input = torch.Tensor{{4,6,7}, {8,0,1}}
  mytester:asserteq(nn.Select(1,-1):forward(input)[1], 8, "negative index")
  mytester:asserteq(nn.Select(1,-1):forward(input)[2], 0, "negative index")
  mytester:asserteq(nn.Select(1,-2):forward(input)[2], 6, "negative index")
  mytester:asserteq(nn.Select(-1,-1):forward(input)[1], 7, "negative dim + negative index")
  mytester:asserteq(nn.Select(-1,-1):forward(input)[2], 1, "negative dim + negative index")
end

function nntest.SelectTable()
   local input = {
      torch.rand(3,4,5), torch.rand(3,4,5),
      {torch.rand(3,4,5)},
      {torch.rand(3,4,5), {torch.rand(3,4,5)}}
   }
   local gradOutputs = {
      torch.rand(3,4,5), torch.rand(3,4,5),
      {torch.rand(3,4,5)},
      {torch.rand(3,4,5), {torch.rand(3,4,5)}}
   }
   local zeros = {
      torch.Tensor(3,4,5):zero(), torch.Tensor(3,4,5):zero(),
      {torch.Tensor(3,4,5):zero()},
      {torch.Tensor(3,4,5):zero(), {torch.Tensor(3,4,5):zero()}}
   }
   local nonIdx = {2,3,4,1}
   local module
   for idx = 1,#input do
      module = nn.SelectTable(idx)
      local output = module:forward(input)
      equal(output, input[idx], "output dimension " .. idx)
      local gradInput = module:backward(input, gradOutputs[idx])
      equal(gradInput[idx], gradOutputs[idx], "gradInput[idx] dimension " .. idx)
      equal(gradInput[nonIdx[idx]], zeros[nonIdx[idx]], "gradInput[nonIdx] dimension " .. idx)
   end

   -- test negative index
   local idx = -2
   module = nn.SelectTable(idx)
   local output = module:forward(input)
   equal(output, input[#input+idx+1], "output dimension " .. idx)
   local gradInput = module:backward(input, gradOutputs[#input+idx+1])
   equal(gradInput[#input+idx+1], gradOutputs[#input+idx+1], "gradInput[idx] dimension " .. idx)
   equal(gradInput[nonIdx[#input+idx+1]], zeros[nonIdx[#input+idx+1]], "gradInput[nonIdx] dimension " .. idx)

   -- test typecast
   local idx = #input
   module = nn.SelectTable(idx)
   module:float()
   local output = module:forward(input)
   equal(output, input[idx], "type output")
   local gradInput = module:backward(input, gradOutputs[idx])
   equal(gradInput[idx], gradOutputs[idx], "gradInput[idx] dimension " .. idx)
   equal(gradInput[nonIdx[idx]], zeros[nonIdx[idx]], "gradInput[nonIdx] dimension " .. idx)

   -- test on differently sized sub-input tables given consequetively
   local input1 = {
      torch.rand(3,4,5),
      {torch.rand(3,4,5), torch.rand(3,4,5), torch.rand(3,4,5)}
   }
   local input2 = {
      torch.rand(3,4,5),
      {torch.rand(3,4,5), torch.rand(3,4,5)}
   }

   module = nn.SelectTable(1)
   local output = module:forward(input1)
   equal(output, input1[1], "output dimension 1")
   local gradInput = module:backward(input1, output)
   mytester:assert(#gradInput == #input1, "Table lengths")
   mytester:assert(#gradInput[2] == #input1[2], "Sub-Table lengths")
   output = module:forward(input2)
   equal(output, input2[1], "output dimension 1")
   gradInput = module:backward(input2, output)
   mytester:assert(#gradInput == #input2, "Table lengths")
   mytester:assert(#gradInput[2] == #input2[2], "Sub-Table lengths")

   -- test on tables of increasing size
   local input1 = {torch.rand(3,4,5), torch.rand(3,4,5)}
   local input2 = {torch.rand(3,4,5), torch.rand(3,4,5), torch.rand(3,4,5)}
   local gradOutput1 = torch.randn(3,4,5)
   local gradOutput2 = torch.randn(3,4,5)

   local module1 = nn.SelectTable(-1)
   local output1 = module1:forward(input1):clone()
   local output2 = module1:forward(input2)
   local gradInput_ = module1:backward(input1, gradOutput1)
   local gradInput1 = {}
   for k,v in ipairs(gradInput_) do gradInput1[k] = v:clone() end
   local gradInput2 = module1:backward(input2, gradOutput2)

   local module3 = nn.SelectTable(-1)
   local module4 = nn.SelectTable(-1)
   local output3 = module3:forward(input1)
   local output4 = module4:forward(input2)
   local gradInput3 = module3:backward(input1, gradOutput1)
   local gradInput4 = module4:backward(input2, gradOutput2)

   equal(output1, output3, "output 1 and 3")
   equal(output2, output4, "output 2 and 4")
   equal(gradInput1, gradInput3, "gradInput 1 and 3")
   equal(gradInput2, gradInput4, "gradInput 2 and 4")
end

function nntest.MixtureTable()
   -- 2D
   -- expertInput is a Table:
   local expertInput = torch.randn(5,3,6)
   local gradOutput = torch.randn(5,6)
   local input = {
      torch.rand(5,3),
      {expertInput:select(2,1), expertInput:select(2,2), expertInput:select(2,3)}
   }
   local module = nn.MixtureTable()
   local output = module:forward(input)
   local output2 = torch.cmul(input[1]:view(5,3,1):expand(5,3,6), expertInput):sum(2):squeeze(2)
   mytester:assertTensorEq(output, output2, 0.000001, "mixture output")
   local gradInput = module:backward(input, gradOutput)
   local gradOutput2 = torch.view(gradOutput, 5, 1, 6):expandAs(expertInput)
   local gaterGradInput2 = torch.cmul(gradOutput2, expertInput):sum(3):select(3,1)
   mytester:assertTensorEq(gradInput[1], gaterGradInput2, 0.000001, "mixture gater gradInput")
   local expertGradInput2 = torch.cmul(input[1]:view(5,3,1):expand(5,3,6), gradOutput:view(5,1,6):expand(5,3,6))
   for i, expertGradInput in ipairs(gradInput[2]) do
      mytester:assertTensorEq(expertGradInput, expertGradInput2:select(2,i), 0.000001, "mixture expert "..i.." gradInput")
   end
   -- expertInput is a Tensor:
   local input = {input[1], expertInput}
   local module = nn.MixtureTable(2)
   local output = module:forward(input)
   mytester:assertTensorEq(output, output2, 0.000001, "mixture2 output")
   local gradInput = module:backward(input, gradOutput)
   mytester:assertTensorEq(gradInput[1], gaterGradInput2, 0.000001, "mixture2 gater gradInput")
   mytester:assertTensorEq(gradInput[2], expertGradInput2, 0.000001, "mixture2 expert gradInput")

   -- 3D
   local expertInput = torch.randn(5,6,3,2)
   local gradOutput = torch.randn(5,6,2)
   -- expertInput is a Table:
   local input = {
      torch.rand(5,3),
      {expertInput:select(3,1), expertInput:select(3,2), expertInput:select(3,3)}
   }
   local module = nn.MixtureTable()
   local output = module:forward(input)
   local output2 = torch.cmul(input[1]:view(5,1,3,1):expand(5,6,3,2), expertInput):sum(3):squeeze(3)
   mytester:assertTensorEq(output, output2, 0.000001, "mixture3 output")
   local gradInput = module:backward(input, gradOutput)
   local gradOutput2 = torch.view(gradOutput,5,6,1,2):expandAs(expertInput)
   local gaterGradInput2 = torch.cmul(gradOutput2, expertInput):sum(4):select(4,1):sum(2):select(2,1)
   mytester:assertTensorEq(gradInput[1], gaterGradInput2, 0.000001, "mixture3 gater gradInput")
   local expertGradInput2 = torch.cmul(input[1]:view(5,1,3,1):expand(5,6,3,2), gradOutput2)
   for i, expertGradInput in ipairs(gradInput[2]) do
      mytester:assertTensorEq(expertGradInput, expertGradInput2:select(3,i), 0.000001, "mixture3 expert "..i.." gradInput")
   end
   -- expertInput is a Tensor
   local input = {input[1], expertInput}
   local module = nn.MixtureTable(3)
   local output = module:forward(input)
   mytester:assertTensorEq(output, output2, 0.000001, "mixture4 output")
   local gradInput = module:backward(input, gradOutput)
   mytester:assertTensorEq(gradInput[1], gaterGradInput2, 0.000001, "mixture4 gater gradInput")
   mytester:assertTensorEq(gradInput[2], expertGradInput2, 0.000001, "mixture4 expert gradInput")

   -- 1D
   -- expertInput is a Table:
   local expertInput = torch.randn(3,6)
   local gradOutput = torch.randn(6)
   local input = {
      torch.rand(3),
      {expertInput:select(1,1), expertInput:select(1,2), expertInput:select(1,3)}
   }
   local module = nn.MixtureTable()
   local output = module:forward(input)
   local output2 = torch.cmul(input[1]:view(3,1):expand(3,6), expertInput):sum(1):squeeze(1)
   mytester:assertTensorEq(output, output2, 0.000001, "mixture5 output")
   local gradInput = module:backward(input, gradOutput)
   local gradOutput2 = torch.view(gradOutput, 1, 6):expandAs(expertInput)
   local gaterGradInput2 = torch.cmul(gradOutput2, expertInput):sum(2):select(2,1)
   mytester:assertTensorEq(gradInput[1], gaterGradInput2, 0.000001, "mixture5 gater gradInput")
   local expertGradInput2 = torch.cmul(input[1]:view(3,1):expand(3,6), gradOutput:view(1,6):expand(3,6))
   for i, expertGradInput in ipairs(gradInput[2]) do
      mytester:assertTensorEq(expertGradInput, expertGradInput2:select(1,i), 0.000001, "mixture5 expert "..i.." gradInput")
   end
   -- test type-cast
   module:float()
   local input2 = {
      input[1]:float(),
      {input[2][1]:float(), input[2][2]:float(), input[2][3]:float()}
   }
   local output = module:forward(input2)
   mytester:assertTensorEq(output, output2:float(), 0.000001, "mixture5B output")
   local gradInput = module:backward(input2, gradOutput:float())
   mytester:assertTensorEq(gradInput[1], gaterGradInput2:float(), 0.000001, "mixture5B gater gradInput")
   for i, expertGradInput in ipairs(gradInput[2]) do
      mytester:assertTensorEq(expertGradInput, expertGradInput2:select(1,i):float(), 0.000001, "mixture5B expert "..i.." gradInput")
   end
   -- expertInput is a Tensor:
   local input = {input[1], expertInput}
   local module = nn.MixtureTable(1)
   local output = module:forward(input)
   mytester:assertTensorEq(output, output2, 0.000001, "mixture6 output")
   local gradInput = module:backward(input, gradOutput)
   mytester:assertTensorEq(gradInput[1], gaterGradInput2, 0.000001, "mixture6 gater gradInput")
   mytester:assertTensorEq(gradInput[2], expertGradInput2, 0.000001, "mixture6 expert gradInput")
   -- test type-cast:
   module:float()
   local input2 = {input[1]:float(), expertInput:float()}
   local output = module:forward(input2)
   mytester:assertTensorEq(output, output2:float(), 0.000001, "mixture6B output")
   local gradInput = module:backward(input2, gradOutput:float())
   mytester:assertTensorEq(gradInput[1], gaterGradInput2:float(), 0.000001, "mixture6B gater gradInput")
   mytester:assertTensorEq(gradInput[2], expertGradInput2:float(), 0.000001, "mixture6B expert gradInput")

   --2D gater, 1D expert
   -- expertInput is a Table:
   local expertInput = torch.randn(5,3)
   local gradOutput = torch.randn(5)
   local input = {
      torch.rand(5,3),
      {expertInput:select(2,1), expertInput:select(2,2), expertInput:select(2,3)}
   }
   local module = nn.MixtureTable()
   local output = module:forward(input)
   local output2 = torch.cmul(input[1], expertInput):sum(2):squeeze(2)
   mytester:assertTensorEq(output, output2, 0.000001, "mixture7 output")
   local gradInput = module:backward(input, gradOutput)
   local gradOutput2 = torch.view(gradOutput, 5, 1):expandAs(expertInput)
   local gaterGradInput2 = torch.cmul(gradOutput2, expertInput)
   mytester:assertTensorEq(gradInput[1], gaterGradInput2, 0.000001, "mixture7 gater gradInput")
   local expertGradInput2 = torch.cmul(input[1], gradOutput:view(5,1):expand(5,3))
   for i, expertGradInput in ipairs(gradInput[2]) do
      mytester:assertTensorEq(expertGradInput, expertGradInput2:select(2,i), 0.000001, "mixture7 expert "..i.." gradInput")
   end
end

function nntest.Narrow()
   -- check basic narrow functionality #1
   local input = torch.rand(9, 4, 14)
   local output = input:narrow(1, 3, 5)
   local gradOutput = torch.rand(5, 4, 14)
   local gradInput = torch.zeros(9, 4, 14)
   gradInput:narrow(1, 3, 5):copy(gradOutput)
   local module1 = nn.Narrow(1, 3, 5)
   local output1 = module1:forward(input)
   local gradInput1 = module1:backward(input, gradOutput)
   local module2 = nn.Narrow(1, 3, -3)
   local output2 = module2:forward(input)
   local gradInput2 = module2:backward(input, gradOutput)
   mytester:assertTensorEq(output, output1, 0.0000001, "Narrow #1 output err")
   mytester:assertTensorEq(gradInput, gradInput1, 0.00001, "Narrow #1 gradInput err")
   mytester:assertTensorEq(output, output2, 0.0000001, "Narrow #1 negative output err")
   mytester:assertTensorEq(gradInput, gradInput2, 0.00001, "Narrow #1 negative gradInput err")

   -- check basic narrow functionality #2
   local input = torch.rand(3, 10, 4)
   local output = input:narrow(2, 5, 3)
   local gradOutput = torch.rand(3, 3, 4)
   local gradInput = torch.zeros(3, 10, 4)
   gradInput:narrow(2, 5, 3):copy(gradOutput)
   local module1 = nn.Narrow(2, 5, 3)
   local output1 = module1:forward(input)
   local gradInput1 = module1:backward(input, gradOutput)
   local module2 = nn.Narrow(2, 5, -4)
   local output2 = module2:forward(input)
   local gradInput2 = module2:backward(input, gradOutput)
   mytester:assertTensorEq(output, output1, 0.0000001, "Narrow #2 output err")
   mytester:assertTensorEq(gradInput, gradInput1, 0.00001, "Narrow #2 gradInput err")
   mytester:assertTensorEq(output, output2, 0.0000001, "Narrow #2 negative output err")
   mytester:assertTensorEq(gradInput, gradInput2, 0.00001, "Narrow #2 negative gradInput err")

   -- check basic narrow functionality #3
   local input = torch.rand(6, 11, 7)
   local output = input:narrow(3, 1, 1)
   local gradOutput = torch.rand(6, 11, 1)
   local gradInput = torch.zeros(6, 11, 7)
   gradInput:narrow(3, 1, 1):copy(gradOutput)
   local module1 = nn.Narrow(3, 1, 1)
   local output1 = module1:forward(input)
   local gradInput1 = module1:backward(input, gradOutput)
   local module2 = nn.Narrow(3, 1, -7)
   local output2 = module2:forward(input)
   local gradInput2 = module2:backward(input, gradOutput)
   mytester:assertTensorEq(output, output1, 0.0000001, "Narrow #3 output err")
   mytester:assertTensorEq(gradInput, gradInput1, 0.00001, "Narrow #3 gradInput err")
   mytester:assertTensorEq(output, output2, 0.0000001, "Narrow #3 negative output err")
   mytester:assertTensorEq(gradInput, gradInput2, 0.00001, "Narrow #3 negative gradInput err")

   -- check basic narrow functionality #4
   local input = torch.rand(3, 10, 4)
   local output = input:narrow(2, 5, 3)
   local gradOutput = torch.rand(3, 3, 4)
   local gradInput = torch.zeros(3, 10, 4)
   gradInput:narrow(2, 5, 3):copy(gradOutput)
   local module1 = nn.Narrow(-2, 5, 3)
   local output1 = module1:forward(input)
   local gradInput1 = module1:backward(input, gradOutput)
   local module2 = nn.Narrow(-2, 5, -4)
   local output2 = module2:forward(input)
   local gradInput2 = module2:backward(input, gradOutput)
   mytester:assertTensorEq(output, output1, 0.0000001, "Narrow #4 output err")
   mytester:assertTensorEq(gradInput, gradInput1, 0.00001, "Narrow #4 gradInput err")
   mytester:assertTensorEq(output, output2, 0.0000001, "Narrow #4 negative output err")
   mytester:assertTensorEq(gradInput, gradInput2, 0.00001, "Narrow #4 negative gradInput err")

   -- check narrow negative offset
   local input = torch.rand(3, 10, 4)
   local output = input:narrow(2, 1, 3)
   local gradOutput = torch.rand(3, 3, 4)
   local gradInput = torch.zeros(3, 10, 4)
   gradInput:narrow(2, 1, 3):copy(gradOutput)
   local module1 = nn.Narrow(2, -1, 7)
   local output1 = module1:forward(input)
   local gradInput1 = module1:backward(input, gradOutput)
   local module2 = nn.Narrow(2, 1, 3)
   local output2 = module2:forward(input)
   local gradInput2 = module2:backward(input, gradOutput)
   mytester:assertTensorEq(output, output1, 0.0000001, "Narrow #5 output err")
   mytester:assertTensorEq(gradInput, gradInput1, 0.00001, "Narrow #5 gradInput err")
   mytester:assertTensorEq(output, output2, 0.0000001, "Narrow #5 negative output err")
   mytester:assertTensorEq(gradInput, gradInput2, 0.00001, "Narrow #5 negative gradInput err")
end

function nntest.NarrowTable()
   local input = torch.randn(3,10,4)
   local gradOutput = torch.randn(3,3,4)
   local nt = nn.NarrowTable(5,3)
   local seq = nn.Sequential()
   seq:add(nn.SplitTable(1,2))
   seq:add(nt)
   seq:add(nn.JoinTable(1,1))
   seq:add(nn.Reshape(3,3,4))
   local seq2 = nn.Narrow(2,5,3)
   local output = seq:forward(input)
   local gradInput = seq:backward(input, gradOutput)
   local output2 = seq2:forward(input)
   local gradInput2 = seq2:backward(input, gradOutput)
   mytester:assertTensorEq(output, output2, 0.0000001, "NarrowTable output err")
   mytester:assertTensorEq(gradInput, gradInput2, 0.00001, "NarrowTable gradInput err")

   -- now try it with a smaller input
   local input = input:narrow(2, 1, 8)
   local output = seq:forward(input)
   local gradInput = seq:backward(input, gradOutput)
   local output2 = seq2:forward(input)
   local gradInput2 = seq2:backward(input, gradOutput)
   mytester:assertTensorEq(output, output2, 0.0000001, "NarrowTable small output err")
   mytester:assertTensorEq(gradInput, gradInput2, 0.00001, "NarrowTable small gradInput err")

   -- test type-cast
   local input = input:float()
   local gradOutput = gradOutput:float()
   seq:float()
   seq2:float()
   local output = seq:forward(input)
   local gradInput = seq:backward(input, gradOutput)
   local output2 = seq2:forward(input)
   local gradInput2 = seq2:backward(input, gradOutput)
   mytester:assertTensorEq(output, output2, 0.0000001, "NarrowTable output float err")
   mytester:assertTensorEq(gradInput, gradInput2, 0.00001, "NarrowTable gradInput float err")
end

function nntest.View()
   local input = torch.rand(10)
   local template = torch.rand(5,2)
   local target = template:size():totable()
   local module = nn.View(template:size())
   mytester:assertTableEq(module:forward(input):size():totable(), target, "Error in forward (1)")
   local module = nn.View(table.unpack(target))
   mytester:assertTableEq(module:forward(input):size():totable(), target, "Error in forward (2)")

   -- Minibatch
   local minibatch = torch.rand(5,10)
   mytester:asserteq(module:forward(minibatch):size(1),
      minibatch:size(1),
      "Error in minibatch dimension")
   mytester:asserteq(module:forward(minibatch):nElement(),
      minibatch:nElement(),
      "Error in minibatch nElement")
   local module = nn.View(-1):setNumInputDims(1)
   mytester:asserteq(module:forward(minibatch):size(1),
      minibatch:size(1),
      "Error in minibatch dimension with size -1")
   mytester:asserteq(module:forward(minibatch):nElement(),
      minibatch:nElement(),
      "Error in minibatch nElement with size -1")

   -- another setNumInputDims case
   local minibatch = torch.rand(5,4,10)
   local module = nn.View(-1):setNumInputDims(2)
   mytester:asserteq(module:forward(minibatch):size(1),
      minibatch:size(1),
      "Error in minibatch dimension with size -1")

   -- another setNumInputDims case
   local minibatch = torch.rand(2,5,4,10)
   local module = nn.View(4,-1):setNumInputDims(2)
   local out = module:forward(minibatch)
   mytester:asserteq(out:size(1), minibatch:size(1)*minibatch:size(2),
                          "Error in minibatch dimension with size -1")
   mytester:asserteq(out:size(2), minibatch:size(3),
                          "Error in minibatch dimension with size -1")
   mytester:asserteq(out:size(3), minibatch:size(4),
                          "Error in minibatch dimension with size -1")

   -- Minibatch Generalization
   local minibatch = torch.rand(5,2,6)
   local module = nn.View(6)
   mytester:asserteq(
      module:forward(minibatch):size(1),
      minibatch:size(1)*minibatch:size(2),
      "Error in minibatch generalization dimension")
   mytester:asserteq(
      module:forward(minibatch):nElement(),
      minibatch:nElement(),
      "Error in minibatch generalization nElement")
end

function nntest.Reshape()
   local input = torch.rand(10)
   local template = torch.rand(5,2)
   local target = template:size():totable()
   local module = nn.Reshape(template:size())
   mytester:assertTableEq(module:forward(input):size():totable(), target, "Error in forward (1)")
   local module = nn.View(table.unpack(target))
   mytester:assertTableEq(module:forward(input):size():totable(), target, "Error in forward (2)")

   -- Minibatch
   local minibatch = torch.rand(5,10)
   mytester:asserteq(module:forward(minibatch):size(1),
      minibatch:size(1),
      "Error in minibatch dimension")
   mytester:asserteq(module:forward(minibatch):nElement(),
      minibatch:nElement(),
      "Error in minibatch nElement")
end

-- Define a test for SpatialUpSamplingCuda
function nntest.SpatialUpSamplingNearest()
  local scale = torch.random(2,4)
  for dim = 3,4 do
    local m = nn.SpatialUpSamplingNearest(scale)

    -- Create a randomly sized dimD vector
    local shape = {}
    for i = 1, dim do
      table.insert(shape, torch.random(2, 2+dim-1))
    end

    -- Check that the gradient is correct by using finite elements
    local input = torch.Tensor(table.unpack(shape)):zero()

    local err = jac.testJacobian(m, input)
    mytester:assertlt(err, precision, ' error on state ')

    local ferr, berr = jac.testIO(m, input)
    mytester:asserteq(ferr, 0, torch.typename(m)..' - i/o forward err ')
    mytester:asserteq(berr, 0, torch.typename(m)..' - i/o backward err ')
  end
end

function nntest.SpatialUpSamplingBilinear()
  for scale=2,4 do
     for dim = 3,4 do
       local m = nn.SpatialUpSamplingBilinear(scale)

       -- Create a randomly sized dimD vector
       local shape = {}
       for i = 1, dim do
         table.insert(shape, torch.random(2, 2+dim-1))
       end

       -- Check that the gradient is correct by using finite elements
       local input = torch.DoubleTensor(table.unpack(shape)):normal()

       local err = jac.testJacobian(m, input)
       mytester:assertlt(err, precision, ' error on state ')

       local ferr, berr = jac.testIO(m, input)
       mytester:asserteq(ferr, 0, torch.typename(m)..' - i/o forward err ')
       mytester:asserteq(berr, 0, torch.typename(m)..' - i/o backward err ')
   end
  end
end

function nntest.Concat()
   local input = torch.randn(4, 2)
   local num_modules = math.random(2, 5)
   local linears = {}
   for i = 1,num_modules do
       linears[i] = nn.Linear(2,5)
   end

   local m = nn.Concat(1)
   for _,module in ipairs(linears) do
      m:add(module)
      module:zeroGradParameters()
      module.weight:fill(1)
      module.bias:fill(0)
   end
   mytester:asserteq(m:size(), num_modules)

   local output = m:forward(input)
   local output2 = input:sum(2):expand(4, 5):repeatTensor(num_modules, 1)
   mytester:assertTensorEq(output2, output, 0.000001, 'Concat forward err')

   local gradInput = m:backward(input, torch.ones(output2:size()))
   local gradInput2 = torch.ones(4, 2):fill(num_modules * 5)
   mytester:assertTensorEq(gradInput, gradInput2, 0.000001, 'Concat backward err (gradInput)')

   local gradWeight = input:sum(1):expand(5, 2)
   for _,module in ipairs(linears) do
      mytester:assertTensorEq(gradWeight, module.gradWeight, 0.000001, 'Concat backward err (gradWeight)')
   end
end

function nntest.Parallel()
   local input = torch.randn(3, 4, 5)
   local m = nn.Parallel(1,3)
   m:add(nn.View(4,5,1))
   m:add(nn.View(4,5,1))
   m:add(nn.View(4,5,1))

   local output = m:forward(input)
   local output2 = input:transpose(1,3):transpose(1,2)
   mytester:assertTensorEq(output2, output, 0.000001, 'Parallel forward err')

   local gradInput = m:backward(input, output2)
   mytester:assertTensorEq(gradInput, input, 0.000001, 'Parallel backward err')
end

function nntest.ParallelTable()
   local input = torch.randn(3, 4, 5)
   local p = nn.ParallelTable()
   p:add(nn.View(4,5,1))
   p:add(nn.View(4,5,1))
   p:add(nn.View(4,5,1))
   local m = nn.Sequential()
   m:add(nn.SplitTable(1))
   m:add(p)
   m:add(nn.JoinTable(3))

   local output = m:forward(input)
   local output2 = input:transpose(1,3):transpose(1,2)
   mytester:assertTensorEq(output2, output, 0.000001, 'ParallelTable forward err')

   local gradInput = m:backward(input, output2)
   mytester:assertTensorEq(gradInput, input, 0.000001, 'ParallelTable backward err')
end

function nntest.ConcatTable()
   -- Test tensor input
   local input = torch.rand(5, 5, 5)
   local m = nn.Sequential()

   local concat = nn.ConcatTable()
   concat:add(nn.Identity())

   m:add(concat)  -- Output of concat is a table of length 1
   m:add(nn.JoinTable(1))  -- jac needs a tensor tensor output

   local err = jac.testJacobian(m, input)
   mytester:assertlt(err, precision, ' error on state ')

   local ferr, berr = jac.testIO(m, input)
   mytester:asserteq(ferr, 0, torch.typename(m)..' - i/o forward err ')
   mytester:asserteq(berr, 0, torch.typename(m)..' - i/o backward err ')

   -- Now test a table input
   local input = {
      torch.randn(3,4):float(), torch.randn(3,4):float(), {torch.randn(3,4):float()}
   }
   local _gradOutput = {
      torch.randn(3,3,4):float(), torch.randn(3,3,4):float(), torch.randn(3,3,4):float()
   }
   local gradOutput = {
      {_gradOutput[1][1], _gradOutput[2][1], {_gradOutput[3][1]}},
      {_gradOutput[1][2], _gradOutput[2][2], {_gradOutput[3][2]}},
      {_gradOutput[1][3], _gradOutput[2][3], {_gradOutput[3][3]}}
   }
   local module = nn.ConcatTable()
   module:add(nn.Identity())
   module:add(nn.Identity())
   module:add(nn.Identity())
   module:float()

   local output = module:forward(input)
   local output2 = {input, input, input}
   equal(output2, output, "ConcatTable table output")
   local gradInput = module:backward(input, gradOutput)
   local gradInput2 = {_gradOutput[1]:sum(1):squeeze(1), _gradOutput[2]:sum(1):squeeze(1), {_gradOutput[3]:sum(1):squeeze(1)}}
   equal(gradInput, gradInput2, "ConcatTable table gradInput")

   -- test outputs for variable length inputs
   local test = nn.ConcatTable()
   test:add(nn.Identity())
   test:add(nn.Identity())

   local x = {torch.randn(5), torch.randn(5)}
   local y = {torch.randn(5)}

   local o1 = #(test:forward(x))
   local go1 = #(test:backward(x, {x, x}))
   local o2 = #(test:forward(y))
   local go2 = #(test:backward(y, {y, y}))
   mytester:assert(o1 == 2, "ConcatTable table variable length")
   mytester:assert(go1 == 2, "ConcatTable table variable length")
   mytester:assert(o2 == 2, "ConcatTable table variable length")
   mytester:assert(go2 == 1, "ConcatTable table variable length")
end

function nntest.MapTable()
   local map = nn.MapTable(nn.Linear(10,5))
   local lin = map:get(1):clone()

   -- ParalleTable with clones as reference
   local parallel = nn.ParallelTable()
   parallel:add(lin)
   parallel:add(lin:clone('weight','bias'))
   parallel:add(lin:clone('weight','bias'))

   local input = {torch.rand(10), torch.rand(10), torch.rand(10)}
   local gradOutput = {torch.ones(5), torch.ones(5), torch.ones(5)}

   local outputM = map:forward(input)
   local outputP = parallel:forward(input)
   mytester:assertTensorEq(outputM[1], outputP[1])
   mytester:assertTensorEq(outputM[2], outputP[2])
   mytester:assertTensorEq(outputM[3], outputP[3])
   mytester:assert(map:size() == #input)

   map:zeroGradParameters()
   parallel:zeroGradParameters()
   local gradInputM = map:backward(input, gradOutput)
   local gradInputP = parallel:backward(input, gradOutput)
   mytester:assertTensorEq(gradInputM[1], gradInputP[1])
   mytester:assertTensorEq(gradInputM[2], gradInputP[2])
   mytester:assertTensorEq(gradInputM[3], gradInputP[3])

   map:updateParameters(1)
   parallel:updateParameters(1)
   mytester:assertTensorEq(map:get(1).weight, parallel:get(1).weight, 0.00001)

   local output = map:forward({input[1], input[2], input[3], input[3]})
   mytester:assert(#output == 4)
   local output = map:forward({input[1], input[2]})
   mytester:assert(#output == 2)

   map:resize(10)
   mytester:assert(map:size() == 10)
   map:resize(4)
   mytester:assert(map:size() == 4)
   mytester:assert(torch.pointer(map:get(4).weight:storage())
      == torch.pointer(map:get(1).weight:storage()))
   map:clearState()
   mytester:assert(map:size() == 1)

  -- check if gradients are correctly reset
  -- share weights and gradients
  map = nn.MapTable(nn.Linear(10,5))
  map:forward(input)
  _, gradParams = map:getParameters()
  gradParams:uniform()
  map:zeroGradParameters()
  mytester:assertlt(gradParams:sum(),precision)

  -- check if gradients are correctly reset
  -- do not share weights and gradients
  map = nn.MapTable(nn.Linear(10,5),false)
  map:forward(input)
  _, gradParams = map:getParameters()
  gradParams:uniform()
  map:zeroGradParameters()
  mytester:assertlt(gradParams:sum(),precision)
end

function nntest.FlattenTable()
   -- Create a nested table.  Obviously we can't even stochastically test
   -- the space of all possible nested tables (it's infinite), but here is a
   -- hand-coded one that covers all the cases we need:
   local input = {
     torch.rand(1),
     {
       torch.rand(2),
       {
         torch.rand(3)
       },
     },
     torch.rand(4)
   }
   local gradOutput = {
     torch.rand(1),
     torch.rand(2),
     torch.rand(3),
     torch.rand(4)
   }

   -- Check the FPROP
   local m = nn.FlattenTable()
   local output = m:forward(input)
   mytester:assert(#output == 4, torch.typename(m)..' - fprop err ')
   -- This is ugly, but check that the mapping from input to output is correct
   mytester:assert(output[1] == input[1])
   mytester:assert(output[2] == input[2][1])
   mytester:assert(output[3] == input[2][2][1])
   mytester:assert(output[4] == input[3])

   -- Check the BPROP
   local gradInput = m:backward(input, gradOutput)
   -- Again, check that the mapping is correct
   mytester:assert(gradOutput[1] == gradInput[1])
   mytester:assert(gradOutput[2] == gradInput[2][1])
   mytester:assert(gradOutput[3] == gradInput[2][2][1])
   mytester:assert(gradOutput[4] == gradInput[3])

   -- More uglyness: FlattenTable doesn't rebuild the table every updateOutput
   -- call, so we need to make sure that modifications to the input are
   -- detected correctly (and that the table is correctly rebuilt.
   -- CASE 1: Nothing changes so the output table shouldn't be redefined
   local old_input_map = m.input_map
   local old_output = m.output
   local _ = m:forward(input)
   mytester:assert(old_input_map == m.input_map and old_output == m.output)

   -- CASE 2: An element is added to the input table
   old_input_map = m.input_map
   old_output = m.output
   input[2][#(input[2])+1] = torch.rand(5)
   m:forward(input)
   mytester:assert(old_input_map ~= m.input_map and old_output ~= m.output)

   -- CASE 3: An element is removed from the input table
   old_input_map = m.input_map
   old_output = m.output
   input[#input] = nil
   m:forward(input)
   mytester:assert(old_input_map ~= m.input_map and old_output ~= m.output)

   -- At this point further testing is not necessary I think, but just to be
   -- consistent: perform a jacobian test by using SplitTable and JointTable
   -- elements
   m = nn.Sequential()
   local par = nn.ParallelTable()
   par:add(nn.SplitTable(1))
   par:add(nn.SplitTable(1))
   m:add(nn.SplitTable(1))
   m:add(par)  -- this will create a nested table
   m:add(nn.FlattenTable())  -- This will flatten the nested table
   m:add(nn.JoinTable(1))  -- Finally, this will create a 1D tensor

   input = torch.Tensor(2,2,2)
   local err = jac.testJacobian(m, input)
   mytester:assertlt(err, precision, 'error on bprop ')
end

function nntest.L1Penalty()
   local weight = 1
   local sizeAverage = false
   local m = nn.L1Penalty(weight, sizeAverage, false)

   local input = torch.rand(2,10):add(-0.5)
   input[1][1] = 0

   local _ = m:forward(input)
   local grad = m:backward(input, torch.ones(input:size()))

   local err = input:clone():abs():sum()*weight - m.loss
   mytester:assertlt(math.abs(err), precision, 'error on fprop ')

   local true_grad = (input:gt(0):typeAs(grad) +
      input:lt(0):typeAs(grad):mul(-1)):mul(weight)
   mytester:assertlt((true_grad - grad):abs():max(), precision,
      'error on bprop ')

   -- Note: We cannot use the Jacobian test for this Module since the backward
   -- gradient cannot be estimated using finite differences (ie, the loss
   -- during BPROP is not included in the FPROP output)
end

function nntest.L1Cost()
   local input = torch.rand(10) * 2 - 1
   local m = nn.L1Cost()
   local output = m:forward(input)
   local err = output - torch.abs(input):sum()
   mytester:assertalmosteq(err, 0, 1e-15, 'L1Cost forward')
end

function nntest.DepthConcat()
   local outputSize = torch.IntTensor{5,6,7,8}
   local input = torch.randn(2,3,12,12)
   local gradOutput = torch.randn(2, outputSize:sum(), 12, 12)
   local concat = nn.DepthConcat(2)
   concat:add(nn.SpatialConvolutionMM(3, outputSize[1], 1, 1, 1, 1)) --> 2, 5, 12, 12
   concat:add(nn.SpatialConvolutionMM(3, outputSize[2], 3, 3, 1, 1)) --> 2, 6, 10, 10
   concat:add(nn.SpatialConvolutionMM(3, outputSize[3], 4, 4, 1, 1)) --> 2, 7, 9, 9
   concat:add(nn.SpatialConvolutionMM(3, outputSize[4], 5, 5, 1, 1)) --> 2, 8, 8, 8
   concat:zeroGradParameters()
   -- forward/backward
   local outputConcat = concat:forward(input)
   local gradInputConcat = concat:backward(input, gradOutput)
   -- the spatial dims are the largest, the nFilters is the sum
   local output = torch.Tensor(2, outputSize:sum(), 12, 12):zero() -- zero for padding
   local narrows = { {{},{1,5},{},{}}, {{},{6,11},{2,11},{2,11}}, {{},{12,18},{2,10},{2,10}}, {{},{19,26},{3,10},{3,10}} }
   local gradInput = input:clone():zero()
   for i=1,4 do
      local conv = concat:get(i)
      local gradWeight = conv.gradWeight:clone()
      conv:zeroGradParameters()
      output[narrows[i]]:copy(conv:forward(input))
      gradInput:add(conv:backward(input, gradOutput[narrows[i]]))
      mytester:assertTensorEq(gradWeight, conv.gradWeight, 0.000001, "Error in SpatialConcat:accGradParameters for conv "..i)
   end
   mytester:assertTensorEq(output, outputConcat, 0.000001, "Error in SpatialConcat:updateOutput")
   mytester:assertTensorEq(gradInput, gradInputConcat, 0.000001, "Error in SpatialConcat:updateGradInput")
end

function nntest.MV()
  local mv = nn.MV(false)
  local outdim = torch.random(10,20)
  local indim = torch.random(10,20)
  local M = torch.randn(outdim, indim)
  local V = torch.randn(indim)

  -- Test forward pass.
  local output = mv:forward({M, V})
  mytester:assertTableEq(output:size():totable(), {outdim},
  'Output has wrong dimensionality')
  mytester:assertTensorEq(output, M * V, 1e-10,
  'Wrong output')

  -- Test backward pass.
  local gradOutput = torch.randn(outdim)
  local gradInput = mv:backward({M, V}, gradOutput)
  mytester:assert(#gradInput == 2, 'gradInput must be table of size 2')
  local gradM, gradV = table.unpack(gradInput)
  mytester:assertTableEq(gradM:size():totable(), M:size():totable(),
  'Gradient for input M has wrong size')
  mytester:assertTableEq(gradV:size():totable(), V:size():totable(),
  'Gradient for input V has wrong size')
  mytester:assertTensorEq(gradM, torch.ger(gradOutput, V), 1e-10,
  'Wrong gradient for input M')
  -- d/dV(j) (A(i,j)V(j)) = (
  mytester:assertTensorEq(gradV, M:t() * gradOutput, 1e-10,
  'Wrong gradient for input V')
end

function nntest.BatchMVNoTranspose()
  local mv = nn.MV()
  local outdim = torch.random(10,20)
  local indim = torch.random(10,20)
  for bSize = 1, 11, 5 do
    local M = torch.randn(bSize, outdim, indim)
    local V = torch.randn(bSize, indim)

    -- Test forward pass.
    local output = mv:forward({M, V})
    mytester:assertTableEq(output:size():totable(), {bSize, outdim},
    'Output has wrong dimensionality')
    for i = 1, bSize do
      mytester:assertTensorEq(output[i], M[i] * V[i], 1e-10,
      'Output wrong for bSize = ' .. bSize .. ' and i = ' .. i)
    end

    -- Test backward pass.
    local gradOutput = torch.randn(bSize, outdim)
    local gradInput = mv:backward({M, V}, gradOutput)
    mytester:assert(#gradInput == 2, 'gradInput must be table of size 2')
    local gradM, gradV = table.unpack(gradInput)
    mytester:assertTableEq(gradM:size():totable(), M:size():totable(),
    'Gradient for input M has wrong size')
    mytester:assertTableEq(gradV:size():totable(), V:size():totable(),
    'Gradient for input V has wrong size')
    for i = 1, bSize do
      mytester:assertTensorEq(gradM[i], torch.ger(gradOutput[i], V[i]), 1e-10,
      'Gradient for input M wrong for bSize = ' .. bSize .. ' and i = ' .. i)
      mytester:assertTensorEq(gradV[i], M[i]:t() * gradOutput[i], 1e-10,
      'Gradient for input V wrong for bSize = ' .. bSize .. ' and i = ' .. i)
    end
  end
end

function nntest.BatchMVTranspose()
  local mv = nn.MV(true)
  local outdim = torch.random(10,20)
  local indim = torch.random(10,20)
  for bSize = 1, 11, 5 do
    local M = torch.randn(bSize, indim, outdim)
    local V = torch.randn(bSize, indim)

    -- Test forward pass.
    local output = mv:forward({M, V})
    mytester:assertTableEq(output:size():totable(), {bSize, outdim},
    'Output has wrong dimensionality')
    for i = 1, bSize do
      mytester:assertTensorEq(output[i], M[i]:t() * V[i], 1e-10,
      'Output wrong for bSize = ' .. bSize .. ' and i = ' .. i)
    end

    -- Test backward pass.
    local gradOutput = torch.randn(bSize, outdim)
    local gradInput = mv:backward({M, V}, gradOutput)
    mytester:assert(#gradInput == 2, 'gradInput must be table of size 2')
    local gradM, gradV = table.unpack(gradInput)
    mytester:assertTableEq(gradM:size():totable(), M:size():totable(),
    'Gradient for input M has wrong size')
    mytester:assertTableEq(gradV:size():totable(), V:size():totable(),
    'Gradient for input V has wrong size')
    for i = 1, bSize do
      mytester:assertTensorEq(gradM[i], torch.ger(V[i], gradOutput[i]), 1e-10,
      'Gradient for input M wrong for bSize = ' .. bSize .. ' and i = ' .. i)
      mytester:assertTensorEq(gradV[i], M[i] * gradOutput[i], 1e-10,
      'Gradient for input V wrong for bSize = ' .. bSize .. ' and i = ' .. i)
    end
  end
end

local function createMatrixInputSizes()
  local M = torch.random(10, 20)
  local N = torch.random(10, 20)
  local P = torch.random(10, 20)
  return M, N, P
end

function nntest.MM()
  local mm = nn.MM(false, true)
  local M, N, P = createMatrixInputSizes()
  local A = torch.randn(M, N)
  local B = torch.randn(P, N)

  -- Test forward pass.
  local output = mm:forward({A, B})
  mytester:assertTableEq(output:size():totable(), {M, P},
                         'Output has wrong dimensionality')
  mytester:assertTensorEq(output, A * B:t(), 1e-10,
                          'Wrong output')

  -- Test backward pass.
  local gradOutput = torch.randn(M, P)
  local gradInput = mm:backward({A, B}, gradOutput)
  mytester:assert(#gradInput == 2, 'gradInput must be table of size 2')
  local gradA, gradB = table.unpack(gradInput)
  mytester:assertTableEq(gradA:size():totable(), A:size():totable(),
                         'Gradient for input A has wrong size')
  mytester:assertTableEq(gradB:size():totable(), B:size():totable(),
                         'Gradient for input B has wrong size')
  mytester:assertTensorEq(gradA, gradOutput * B, 1e-10,
                          'Wrong gradient for input A')
  mytester:assertTensorEq(gradB, gradOutput:t() * A, 1e-10,
                          'Wrong gradient for input B')
end

function nntest.BatchMMNoTranspose()
  local mm = nn.MM()
  local M, N, P = createMatrixInputSizes()
  for bSize = 1, 11, 5 do
    local A = torch.randn(bSize, M, N)
    local B = torch.randn(bSize, N, P)

    -- Test forward pass.
    local output = mm:forward({A, B})
    mytester:assertTableEq(output:size():totable(), {bSize, M, P},
                           'Output has wrong dimensionality')
    for i = 1, bSize do
      mytester:assertTensorEq(output[i], A[i] * B[i], 1e-10,
                              'Output wrong for bSize = ' .. bSize .. ' and i = ' .. i)
    end

    -- Test backward pass.
    local gradOutput = torch.randn(bSize, M, P)
    local gradInput = mm:backward({A, B}, gradOutput)
    mytester:assert(#gradInput == 2, 'gradInput must be table of size 2')
    local gradA, gradB = table.unpack(gradInput)
    mytester:assertTableEq(gradA:size():totable(), A:size():totable(),
                           'Gradient for input A has wrong size')
    mytester:assertTableEq(gradB:size():totable(), B:size():totable(),
                           'Gradient for input B has wrong size')
    for i = 1, bSize do
      mytester:assertTensorEq(gradA[i], gradOutput[i] * B[i]:t(), 1e-10,
                              'Gradient for input A wrong for bSize = ' .. bSize .. ' and i = ' .. i)
      mytester:assertTensorEq(gradB[i], A[i]:t() * gradOutput[i], 1e-10,
                              'Gradient for input B wrong for bSize = ' .. bSize .. ' and i = ' .. i)
    end
  end
end

function nntest.BatchMMTransposeA()
  local mm = nn.MM(true, false)
  local M, N, P = createMatrixInputSizes()
  for bSize = 1, 11, 5 do
    local A = torch.randn(bSize, N, M)
    local B = torch.randn(bSize, N, P)

    -- Test forward pass.
    local output = mm:forward({A, B})
    mytester:assertTableEq(output:size():totable(), {bSize, M, P},
                           'Output has wrong dimensionality')
    for i = 1, bSize do
      mytester:assertTensorEq(output[i], A[i]:t() * B[i], 1e-10,
                              'Output wrong for bSize = ' .. bSize .. ' and i = ' .. i)
    end

    -- Test backward pass.
    local gradOutput = torch.randn(bSize, M, P)
    local gradInput = mm:backward({A, B}, gradOutput)
    mytester:assert(#gradInput == 2, 'gradInput must be table of size 2')
    local gradA, gradB = table.unpack(gradInput)
    mytester:assertTableEq(gradA:size():totable(), A:size():totable(),
                           'Gradient for input A has wrong size')
    mytester:assertTableEq(gradB:size():totable(), B:size():totable(),
                           'Gradient for input B has wrong size')
    for i = 1, bSize do
      mytester:assertTensorEq(gradA[i], B[i] * gradOutput[i]:t(), 1e-10,
                              'Gradient for input A wrong for bSize = ' .. bSize .. ' and i = ' .. i)
      mytester:assertTensorEq(gradB[i], A[i] * gradOutput[i], 1e-10,
                              'Gradient for input B wrong for bSize = ' .. bSize .. ' and i = ' .. i)
    end
  end
end

function nntest.BatchMMTransposeB()
  local mm = nn.MM(false, true)
  local M, N, P = createMatrixInputSizes()
  for bSize = 1, 11, 5 do
    local A = torch.randn(bSize, M, N)
    local B = torch.randn(bSize, P, N)

    -- Test forward pass.
    local output = mm:forward({A, B})
    mytester:assertTableEq(output:size():totable(), {bSize, M, P},
                           'Output has wrong dimensionality')
    for i = 1, bSize do
      mytester:assertTensorEq(output[i], A[i] * B[i]:t(), 1e-10,
                              'Output wrong for bSize = ' .. bSize .. ' and i = ' .. i)
    end

    -- Test backward pass.
    local gradOutput = torch.randn(bSize, M, P)
    local gradInput = mm:backward({A, B}, gradOutput)
    mytester:assert(#gradInput == 2, 'gradInput must be table of size 2')
    local gradA, gradB = table.unpack(gradInput)
    mytester:assertTableEq(gradA:size():totable(), A:size():totable(),
                           'Gradient for input A has wrong size')
    mytester:assertTableEq(gradB:size():totable(), B:size():totable(),
                           'Gradient for input B has wrong size')
    for i = 1, bSize do
      mytester:assertTensorEq(gradA[i], gradOutput[i] * B[i], 1e-10,
                              'Gradient for input A wrong for bSize = ' .. bSize .. ' and i = ' .. i)
      mytester:assertTensorEq(gradB[i], gradOutput[i]:t() * A[i], 1e-10,
                              'Gradient for input B wrong for bSize = ' .. bSize .. ' and i = ' .. i)
    end
  end
end

function nntest.BatchMMTransposeBoth()
  local mm = nn.MM(true, true)
  local M, N, P = createMatrixInputSizes()
  for bSize = 1, 11, 5 do
    local A = torch.randn(bSize, N, M)
    local B = torch.randn(bSize, P, N)

    -- Test forward pass.
    local output = mm:forward({A, B})
    mytester:assertTableEq(output:size():totable(), {bSize, M, P},
                           'Output has wrong dimensionality')
    for i = 1, bSize do
      mytester:assertTensorEq(output[i], A[i]:t() * B[i]:t(), 1e-10,
                              'Output wrong for bSize = ' .. bSize .. ' and i = ' .. i)
    end

    -- Test backward pass.
    local gradOutput = torch.randn(bSize, M, P)
    local gradInput = mm:backward({A, B}, gradOutput)
    mytester:assert(#gradInput == 2, 'gradInput must be table of size 2')
    local gradA, gradB = table.unpack(gradInput)
    mytester:assertTableEq(gradA:size():totable(), A:size():totable(),
                           'Gradient for input A has wrong size')
    mytester:assertTableEq(gradB:size():totable(), B:size():totable(),
                           'Gradient for input B has wrong size')
    for i = 1, bSize do
      mytester:assertTensorEq(gradA[i], B[i]:t() * gradOutput[i]:t(), 1e-10,
                              'Gradient for input A wrong for bSize = ' .. bSize .. ' and i = ' .. i)
      mytester:assertTensorEq(gradB[i], gradOutput[i]:t() * A[i]:t(), 1e-10,
                              'Gradient for input B wrong for bSize = ' .. bSize .. ' and i = ' .. i)
    end
  end
end

function nntest.DotProduct()
  local indim = math.random(1,10)

  -- test 1D forward
  local input = {torch.rand(indim),torch.rand(indim)}
  local module = nn.DotProduct()
  local expected = input[1]:dot(input[2])
  local output = module:forward(input)
  mytester:assertlt(math.abs(expected-output[1]), precision, 'error on forward ')

  -- check gradients
  -- Note: testJacobian doesn't support table inputs, and rather than re-write
  -- it so that it does, I'll just use a split table module on the input.
  -- I assume both SplitTable and Sequential do not have bugs, otherwise this
  -- test will break.
  local input = torch.rand(2,indim)
  local module = nn.Sequential()
  module:add(nn.SplitTable(1))
  module:add(nn.DotProduct())

  local err = jac.testJacobian(module,input)
  mytester:assertlt(err,precision, 'error on state ')

  -- IO
  local ferr,berr = jac.testIO(module,input)
  mytester:eq(ferr, 0, torch.typename(module) .. ' - i/o forward err ', precision)
  mytester:eq(berr, 0, torch.typename(module) .. ' - i/o backward err ', precision)

  -- batch
  -- rebuild module to avoid correlated tests
  local module = nn.Sequential()
  module:add(nn.SplitTable(1))
  module:add(nn.DotProduct())

  local nframes = math.random(1,10)
  local indim = math.random(1,10)
  local input = torch.rand(2,nframes,indim)

  local err = jac.testJacobian(module,input)
  mytester:assertlt(err,precision, 'batch error on state ')
end

function nntest.CosineDistance()
  local indim = math.random(1,10)
  local input = {torch.rand(indim),torch.rand(indim)}

  -- check forward against previous implementation
  local module = nn.CosineDistance()

  local w1 = input[1]:dot(input[2])
  local w2 = math.sqrt(input[1]:dot(input[1]))
  local w3 = math.sqrt(input[2]:dot(input[2]))
  local output_old = w1/w2/w3

  local output = module:forward(input)

  mytester:assertlt(math.abs(output_old-output[1]),precision,'error on forward ')


  -- check gradients
  -- Note: testJacobian doesn't support table inputs, and rather than re-write
  -- it so that it does, I'll just use a split table module on the input.
  -- I assume both SplitTable and Sequential do not have bugs, otherwise this
  -- test will break.
  local input = torch.rand(2,indim)
  local module = nn.Sequential()
  module:add(nn.SplitTable(1))
  module:add(nn.CosineDistance())

  local err = jac.testJacobian(module,input)
  mytester:assertlt(err,precision, 'error on state ')

  -- IO
  local ferr,berr = jac.testIO(module,input)
  mytester:eq(ferr, 0, torch.typename(module) .. ' - i/o forward err ', precision)
  mytester:eq(berr, 0, torch.typename(module) .. ' - i/o backward err ', precision)

  -- batch
  -- rebuild module to avoid correlated tests
  local module = nn.Sequential()
  module:add(nn.SplitTable(1))
  module:add(nn.CosineDistance())

  local nframes = math.random(1,10)
  local indim = math.random(1,10)
  local input = torch.rand(2,nframes,indim)

  local err = jac.testJacobian(module,input)
  mytester:assertlt(err,precision, 'batch error on state ')

end

function nntest.CosineEmbeddingCriterion()
  local v1 = torch.Tensor{1, 0}
  local v2 = torch.Tensor{0.5, math.sqrt(3)*0.5}

  local crit = nn.CosineEmbeddingCriterion(0.6)
  local output = crit:forward({v1, v2}, -1) -- must be Called before backward
  local grads = crit:backward({v1, v2}, -1)

  local zero = torch.Tensor(2):zero()
  equal(grads[1], zero, 'gradient should be zero')
  equal(grads[2], zero, 'gradient should be zero')

  -- check jacobians
  local margin = math.random()*2-1
  local dim = 5
  local batch_size = 1
  local crit = nn.CosineEmbeddingCriterion(margin)
  local v = torch.rand(2,dim)
  criterionJacobianTest1DTable(crit,v,1)
  criterionJacobianTest1DTable(crit,v,-1)

  -- batch with hand-computed values
  local v1 = torch.Tensor{{1, 0}, {0.5, math.sqrt(3)*0.5}}
  local v2 = torch.Tensor{{0.5, math.sqrt(3)*0.5}, {1, 0}}

  local t = torch.Tensor{-1,-1}
  local crit = nn.CosineEmbeddingCriterion(0.6)
  local output = crit:forward({v1, v2}, t) -- must be Called before backward
  local grads = crit:backward({v1, v2}, t)

  local zero = torch.Tensor(2,2):zero()
  equal(grads[1], zero, 'gradient should be zero')
  equal(grads[2], zero, 'gradient should be zero')

  -- batch, sizeAverage true, jacobian
  local margin = math.random()*2-1
  local dim = 5
  local batch_size = 2
  local crit = nn.CosineEmbeddingCriterion(margin)
  crit.sizeAverage = true
  local v = torch.rand(2,batch_size,dim)
  local t = torch.Tensor(batch_size):random(0,1):mul(2):add(-1)
  criterionJacobianTest1DTable(crit,v,t)

  -- batch, sizeAverage false, jacobian
  local margin = math.random()*2-1
  local crit = nn.CosineEmbeddingCriterion(margin)
  crit.sizeAverage = false
  local v = torch.rand(2,batch_size,dim)
  local t = torch.Tensor(batch_size):random(0,1):mul(2):add(-1)
  criterionJacobianTest1DTable(crit,v,t)
end

function nntest.HingeEmbeddingCriterion()
  local x = torch.Tensor{0.3,2.1,1.8,0}
  local y = torch.Tensor{1,-1,-1,1}
  local expgrads = torch.Tensor{1,0,-1,1} / 4

  local crit = nn.HingeEmbeddingCriterion(2)
  local output = crit:forward(x, y) -- must be called before backward
  local grads = crit:backward(x, y)

  mytester:assert(math.abs(output - (0.3 + 0.2) / 4) < 1e-10)
  equal(grads, expgrads)
end

function nntest.Replicate()
   local vector = torch.rand(3)

   local r1 = nn.Replicate(2, 1)
   local r2 = nn.Replicate(2, 2)

   local vOutput1 = r1:forward(vector):clone()
   local vOutput2 = r2:forward(vector):clone()

   local expected1 = torch.zeros(2, 3)
   local expected2 = torch.zeros(3, 2)
   expected1:select(1, 1):copy(vector)
   expected1:select(1, 2):copy(vector)
   expected2:select(2, 1):copy(vector)
   expected2:select(2, 2):copy(vector)

   mytester:assertTensorEq(vOutput1, expected1, precision, 'Wrong tiling of data when replicating vector.')
   mytester:assertTensorEq(vOutput2, expected2, precision, 'Wrong tiling of data when replicating vector.')

   -- batch mode
   local vector = torch.rand(4,3)

   local r1 = nn.Replicate(2, 1, 1)
   local r2 = nn.Replicate(2, 2, 1)

   local vOutput1 = r1:forward(vector):clone()
   local vOutput2 = r2:forward(vector):clone()

   local expected1 = torch.zeros(4, 2, 3)
   local expected2 = torch.zeros(4, 3, 2)
   expected1:select(2, 1):copy(vector)
   expected1:select(2, 2):copy(vector)
   expected2:select(3, 1):copy(vector)
   expected2:select(3, 2):copy(vector)

   mytester:assertTensorEq(vOutput1, expected1, precision, 'Wrong tiling of data when replicating batch vector.')
   mytester:assertTensorEq(vOutput2, expected2, precision, 'Wrong tiling of data when replicating batch vector.')
end

local function testBatchNormalization(moduleName, dim, k)
   local planes = torch.random(1,k)
   local size = { torch.random(2, k), planes }
   for i=1,dim do
      table.insert(size, torch.random(1,k))
   end
   local input = torch.zeros(table.unpack(size)):uniform()

   local function jacTests(module, input, affine)
      local err = jac.testJacobian(module,input)
      mytester:assertlt(err,precision, 'error on state ')

      if affine then
         local err = jac.testJacobianParameters(module, input,
                                            module.weight, module.gradWeight)
         mytester:assertlt(err,precision, 'error on weight ')

         local err = jac.testJacobianParameters(module, input,
                                            module.bias, module.gradBias)
         mytester:assertlt(err,precision, 'error on weight ')

         local err = jac.testJacobianUpdateParameters(module, input, module.weight)
         mytester:assertlt(err,precision, 'error on weight [direct update] ')

         local err = jac.testJacobianUpdateParameters(module, input, module.bias)
         mytester:assertlt(err,precision, 'error on bias [direct update] ')

         for t,err in pairs(jac.testAllUpdate(module, input, 'weight', 'gradWeight')) do
            mytester:assertlt(err, precision, string.format(
               'error on weight [%s]', t))
         end

         for t,err in pairs(jac.testAllUpdate(module, input, 'bias', 'gradBias')) do
            mytester:assertlt(err, precision, string.format('error on bias [%s]', t))
         end
      end

      -- IO
      local ferr,berr = jac.testIO(module,input)
      mytester:eq(ferr, 0, torch.typename(module) .. ' - i/o forward err ', precision)
      mytester:eq(berr, 0, torch.typename(module) .. ' - i/o backward err ', precision)
   end

   local module = nn[moduleName](planes)
   module:training()
   jacTests(module, input, true)
   module:evaluate()
   jacTests(module, input, true)
   jacTests(module, input[1], true)

   -- batch norm without affine transform
   module = nn[moduleName](planes, 1e-5, 0.1, false)
   module:training()
   jacTests(module, input, false)
   module:evaluate()
   jacTests(module, input, false)
   jacTests(module, input[1], false)
end

function nntest.BatchNormalization()
   testBatchNormalization('BatchNormalization', 0, 20)
end

function nntest.SpatialBatchNormalization()
   testBatchNormalization('SpatialBatchNormalization', 2, 6)
end

function nntest.VolumetricBatchNormalization()
   testBatchNormalization('VolumetricBatchNormalization', 3, 4)
end

function nntest.GradientReversal()
   local ini = math.random(3,5)
   local inj = math.random(3,5)
   local ink = math.random(3,5)
   local input = torch.Tensor(ini,inj,ink):zero()
   -- Two GradientReversal layers should cancel each other out
   local module = nn.Sequential()
   module:add(nn.GradientReversal())
   module:add(nn.GradientReversal())

   local err = jac.testJacobian(module,input, 0.1, 10)
   mytester:assertlt(err,precision, 'error on state ')

   local ferr,berr = jac.testIO(module,input, 0.1, 10)
   mytester:eq(ferr, 0, torch.typename(module) .. ' - i/o forward err ', precision)
   mytester:eq(berr, 0, torch.typename(module) .. ' - i/o backward err ', precision)
end

function nntest.Padding()
   local fanin = math.random(1,3)
   local sizex = math.random(4,16)
   local sizey = math.random(4,16)
   local pad = math.random(-3,3)
   local index = math.random(1, fanin)
   local val = torch.randn(1):squeeze()
   local module = nn.Padding(1, pad, 3, val, index)
   local input = torch.rand(fanin,sizey,sizex)
   local size = input:size():totable()
   size[1] = size[1] + math.abs(pad)

   local output = module:forward(input)
   mytester:assertTableEq(size, output:size():totable(), 0.00001, "Padding size error")

   local gradInput = module:backward(input, output)
   mytester:assertTensorEq(gradInput, input, 0.00001, "Padding backward error")
end

function nntest.addSingletonDimension()
   local dims = torch.random(5)
   local size = torch.LongTensor(dims):random(10)
   local perm = torch.randperm(dims):totable()
   local tensor = torch.Tensor(table.unpack(size:totable())):uniform():permute(table.unpack(perm))
   size = torch.gather(size, 1, torch.LongTensor(perm))

   local firstDim = nn.utils.addSingletonDimension(tensor)
   mytester:assertTableEq(firstDim:size():totable(), {1, table.unpack(size:totable())},
                          "wrong size for singleton dimension 1")
   mytester:assertTensorEq(firstDim[1], tensor, 0,
                           "wrong content for singleton dimension 1")

   local dim = torch.random(dims + 1)
   local result = nn.utils.addSingletonDimension(tensor, dim)
   local resultSize = size:totable()
   table.insert(resultSize, dim, 1)
   mytester:assertTableEq(result:size():totable(), resultSize,
                          "wrong size for random singleton dimension")
   mytester:assertTensorEq(result:select(dim, 1), tensor, 0,
                           "wrong content for random singleton dimension")

   mytester:assertError(function() nn.utils.addSingletonDimension(tensor, dims + 2) end,
                        "invalid dimension not detected")

   -- passing output tensor as argument
   local resultArg = torch.Tensor()
   local resultR = nn.utils.addSingletonDimension(resultArg, tensor, dim)
   mytester:eq(resultArg:size():totable(), resultSize,
               'wrong content for random singleton dimension '..
               'when the result is passed as argument')
   mytester:eq(resultArg, result, 'wrong content for random singleton dimension '..
               'when the result is passed as argument')

   mytester:eq(resultR == resultArg, true,
               'new tensor is created when it should use the provided tensor')
end

function nntest.SpatialReflectionPadding()
   local batch = math.random(1,3)
   local plane = math.random(1,3)
   local sizeY = math.random(7,16)
   local sizeX = math.random(7,16)
   local padL = math.random(-3,3)
   local padR = math.random(-3,3)
   local padT = math.random(-3,3)
   local padB = math.random(-3,3)
   local jac = nn.Jacobian
   local layer = nn.SpatialReflectionPadding(padL, padR, padT, padB)
   local input = torch.rand(batch, plane, sizeY, sizeX)
   local err = jac.testJacobian(layer, input)
   mytester:assertalmosteq(err, 0.0, 1e-7)
end

function nntest.SpatialReplicationPadding()
   local batch = math.random(1,3)
   local plane = math.random(1,3)
   local sizeY = math.random(7,16)
   local sizeX = math.random(7,16)
   local padL = math.random(-3,3)
   local padR = math.random(-3,3)
   local padT = math.random(-3,3)
   local padB = math.random(-3,3)
   local jac = nn.Jacobian
   local layer = nn.SpatialReplicationPadding(padL, padR, padT, padB)
   local input = torch.rand(batch, plane, sizeY, sizeX)
   local err = jac.testJacobian(layer, input)
   mytester:assertalmosteq(err, 0.0, 1e-7)
end

function nntest.VolumetricReplicationPadding()
   for batch = 0, 1 do
      local nbatch
      if batch == 1 then
         nbatch = math.random(1,3)
      end
      local plane = math.random(1,3)
      local sizeZ = math.random(1,4)
      local sizeY = math.random(7,11)
      local sizeX = math.random(7,11)
      local padLeft = math.random(-3,3)
      local padRight = math.random(-3,3)
      local padTop = math.random(-3,3)
      local padBottom = math.random(-3,3)
      local padFront = math.random(3,3)
      local padBack = math.random(3,3)
      local jac = nn.Jacobian
      local layer =
          nn.VolumetricReplicationPadding(padLeft, padRight, padTop,
                                          padBottom, padFront, padBack)
      local input
      if batch == 1 then
         input = torch.rand(nbatch, plane, sizeZ, sizeY, sizeX)
      else
         input = torch.rand(plane, sizeZ, sizeY, sizeX)
      end
      local err = jac.testJacobian(layer, input)
      mytester:assertalmosteq(err, 0.0, 1e-7)
   end
end

function nntest.PixelShuffle()
   -- Checks whether a given tensor has the specified size
   local function tensorHasSize(tensor, size)
      local tensorSize = tensor:size()

      if tensorSize:size() ~= #size then
         return false
      end
      for i,v in ipairs(size) do
         if tensorSize[i] ~= size[i] then
            return false
         end
      end
      return true
   end

   --Verifies that the output is the input re-shuffled as per Eq 4. in
   -- "Real-Time Single Image and Video Super-Resolution Using an Efficient
   -- Sub-Pixel Convolutional Neural Network", Shi et al.
   -- @param - the input, low-resolution image of shape [1, c, h , w]
   -- @param - the output, super resolved image of shape [1, c, h ,w]
   -- @param - upscale factor of the super resolutin
   -- @returns true if output complies with Eq 4.
   local function verifyPixelShuffle(_input, _output, upscaleFactor)
      local input = _input
      local output = _output

      if input:nDimension() == 3 then
         input = input:view(1, input:size(1), input:size(2), input:size(3))
         output = output:view(1, output:size(1), output:size(2), output:size(3))
      end

      for c = 1, output:size(2)  do
         for h = 1, output:size(3) do
            for w = 1, output:size(4) do
               local heightIdx = torch.floor((h - 1)/upscaleFactor) + 1
               local widthIdx = torch.floor((w - 1)/upscaleFactor) + 1
                  --c does not need to be (c - 1) as it starts at 1 not zero
                  local channelIdx = upscaleFactor * ((h-1) % upscaleFactor) + ((w-1) % upscaleFactor) + 1 + (c-1)*upscaleFactor*upscaleFactor

                  mytester:assertTensorEq(output[{{}, {c}, {h}, {w}}], input[{{}, {channelIdx}, {heightIdx}, {widthIdx}}],
                                        string.format("output at location (%d, %d, %d) is incorrect", c, h, w))
            end
         end
      end
      return true
   end

   -- Checks the nn.PixelShuffle layer's forward pass. It checks that is
   -- re-arranges input pixels correctly according to Eq. 4 of
   -- "Real-Time Single Image and Video Super-Resolution Using an Efficient
   -- Sub-Pixel Convolutional Neural Network", Shi et al.
   -- This function tests for multip batch sizes, multiple channels and multiple input dimensions (square)
   -- It also tests for normal tensors (un-batched)
   local function testPixelShuffleUpdateOutput()
      --Test with batched input
      for h = 1, 3 do
         local batchSize = torch.round(torch.uniform(1, 3))
         for i = 1, 3 do
            local upscaleFactor = torch.round(torch.uniform(2,5))
            local pixelShuffle = nn.PixelShuffle(upscaleFactor)
            for j = 1, 3 do
               local channels = torch.round(torch.uniform(1, 4))
               for k = 1, 3 do

                     local inputDim = torch.round(torch.uniform(5, 10))
                     local input = torch.Tensor(batchSize, channels * upscaleFactor * upscaleFactor, inputDim, inputDim)
                     input:uniform()

                     local output = pixelShuffle:forward(input)
                     local expectedOutputDim = inputDim * upscaleFactor
                     mytester:assert(tensorHasSize(output, {batchSize, channels, expectedOutputDim, expectedOutputDim}),
                     string.format("Output tensor should have size (%d, %d, %d, %d) not %s", batchSize, channels, expectedOutputDim, expectedOutputDim, tostring(output:size())))
                     verifyPixelShuffle(input, output, upscaleFactor)
               end
            end
         end
      end

      --Test with non-batched input
      local inputDim = torch.round(torch.uniform(5, 10))
      local channels = torch.round(torch.uniform(1, 4))
      local upscaleFactor = torch.round(torch.uniform(2,5))

      local input = torch.Tensor(channels * upscaleFactor * upscaleFactor, inputDim, inputDim)
      input:uniform()

      local pixelShuffle = nn.PixelShuffle(upscaleFactor)
      local output = pixelShuffle:forward(input)
      local expectedOutputDim = inputDim * upscaleFactor
      mytester:assert(tensorHasSize(output, {channels, expectedOutputDim, expectedOutputDim}),
      string.format("Output tensor should have size (%d, %d, %d) not %s", channels, expectedOutputDim, expectedOutputDim, tostring(output:size())))

      verifyPixelShuffle(input, output, upscaleFactor)
   end

   -- Checks the nn.PixelShuffle layer's backward pass. It checks that is
   -- essentially performs the inverse of Eq 4. in
   -- "Real-Time Single Image and Video Super-Resolution Using an Efficient
   -- Sub-Pixel Convolutional Neural Network", Shi et al.
   -- This function tests for multip batch sizes, multiple channels and multiple input dimensions (square)
   -- It also tests for normal tensors (un-batched)
   local function testPixelShuffleUpdateGradInput()
      --Test with batched input
      for h = 1, 3 do
         local batchSize = torch.round(torch.uniform(1, 3))
         for i = 1, 3 do
            local upscaleFactor = torch.round(torch.uniform(2,5))
            local pixelShuffle = nn.PixelShuffle(upscaleFactor)
               for j = 1, 3 do
                  local channels = torch.round(torch.uniform(1, 4))
                  for k = 1, 3 do
                     local inputDim = torch.round(torch.uniform(5, 10))
                     local input = torch.Tensor(batchSize, channels * upscaleFactor * upscaleFactor, inputDim, inputDim)

                     input:uniform()

                     local output = pixelShuffle:forward(input)
                     --here we treat output as the same as gradOutput as they have the same shape
                     local reconstructedInput = pixelShuffle:backward(input, output)
                     mytester:assertTensorEq(reconstructedInput, input, 0)
                  end
            end
         end
      end

      --Test with non-batched input
      local inputDim = torch.round(torch.uniform(5, 10))
      local channels = torch.round(torch.uniform(1, 4))
      local upscaleFactor = torch.round(torch.uniform(2,5))
      local input = torch.Tensor(channels * upscaleFactor * upscaleFactor, inputDim, inputDim)
      input:uniform()

      local pixelShuffle = nn.PixelShuffle(upscaleFactor)
      local output = pixelShuffle:forward(input)
      --here we treat output as the same as gradOutput as they have the same shape
      local reconstructedInput = pixelShuffle:backward(input, output)
      mytester:assertTensorEq(reconstructedInput, input, 0)

      local err = jac.testJacobian(pixelShuffle, input)
      mytester:assertlt(err,precision, "error computing gradiens w.r.t. inputs")
   end

   local function testModuleIO()
      --Test with non-batched input
      local inputDim = torch.round(torch.uniform(5, 10))
      local channels = torch.round(torch.uniform(1, 4))
      local upscaleFactor = torch.round(torch.uniform(2,5))
      local input = torch.Tensor(channels * upscaleFactor * upscaleFactor, inputDim, inputDim):uniform()
      local pixelShuffle = nn.PixelShuffle(upscaleFactor)

      local fwdErr,bkwdErr = jac.testIO(pixelShuffle,input)
      mytester:asserteq(fwdErr, 0, torch.typename(pixelShuffle) .. " - i/o forward err ")
      mytester:asserteq(bkwdErr, 0, torch.typename(pixelShuffle) .. " - i/o backward err ")
   end

   testPixelShuffleUpdateOutput()
   testPixelShuffleUpdateGradInput()
   testModuleIO()
end

function nntest.Typecast()
  local function make_network()
    local seq = nn.Sequential()
    seq:add(nn.Linear(15, 10))
    seq:add(nn.Linear(15, 10))
    seq.modules[1].bias:fill(1)
    seq.modules[2].bias:fill(2)
    return seq
  end

  -- make sure that the typecasts aren't nops
  assert(torch.getdefaulttensortype() == 'torch.DoubleTensor')

  -- basic net
  local net = make_network()
  net.modules[1].empty_tensor = torch.Tensor()
  net:float()
  assert(net.modules[1].bias:type() == 'torch.FloatTensor',
      net.modules[1].bias:type())
  assert(net.modules[1].empty_tensor:type() == 'torch.FloatTensor')
  assert(net.modules[1].bias ~= net.modules[2].bias)
  net.modules[1].bias:fill(3)
  assert(net.modules[1].bias[1] == 3)
  assert(net.modules[2].bias[1] == 2)

  -- shared tensors remain shared
  local net = make_network()
  net.modules[2].bias = net.modules[1].bias
  net:float()
  assert(net.modules[1].bias:type() == 'torch.FloatTensor')
  assert(net.modules[1].bias == net.modules[2].bias)
  assert(net.modules[1].bias[1] == 1)

  -- shared storages remain shared
  local net = make_network()
  net.modules[2].bias:set(net.modules[1].bias)
  local net = net:float()
  assert(net.modules[1].bias:type() == 'torch.FloatTensor')
  assert(net.modules[1].bias ~= net.modules[2].bias)
  net.modules[1].bias:fill(3)
  assert(net.modules[1].bias[1] == 3)
  assert(net.modules[2].bias[1] == 3)

  -- tricky: overlapping views on the same storage are preserved
  local net = make_network()
  local overlap_storage = torch.Tensor(15):fill(1)
  net.modules[1].bias = overlap_storage:narrow(1, 1, 10)
  net.modules[2].bias = overlap_storage:narrow(1, 6, 10)
  net:float()
  assert(net.modules[1].bias:type() == 'torch.FloatTensor')
  assert(net.modules[1].bias ~= net.modules[2].bias)
  net.modules[1].bias:fill(3)
  assert(net.modules[1].bias[1] == 3)
  assert(net.modules[2].bias[1] == 3)
  assert(net.modules[2].bias[6] == 1) -- only the first 5 elements overlapped

  -- check recursiveType on a table
  local net1 = make_network()
  local net2 = make_network()
  net2.modules[1].bias:set(net1.modules[1].bias)
  net1:float()
  net2:float()
  net1.modules[1].bias:fill(3)
  assert(net2.modules[1].bias[1] == 1)

  local net1 = make_network()
  local net2 = make_network()
  net2.modules[1].bias:set(net1.modules[1].bias)

  local tensorCache = {}
  net1:type('torch.FloatTensor', tensorCache)
  net2:type('torch.FloatTensor', tensorCache)
  net1.modules[1].bias:fill(3)
  assert(net2.modules[1].bias[1] == 3)

  local net1 = make_network()
  local net2 = make_network()
  net2.modules[1].bias:set(net1.modules[1].bias)

  nn.utils.recursiveType({net1, net2}, 'torch.FloatTensor')
  net1.modules[1].bias:fill(3)
  assert(net2.modules[1].bias[1] == 3)

  -- smoke test some modules with custom type methods
  local custom_type_modules = {
    nn.MixtureTable(3),
    nn.ConcatTable(),
    nn.Copy(),
    nn.Copy(nil, nil, nil, true),
    nn.SpatialContrastiveNormalization(),
    nn.DotProduct(),
    nn.PairwiseDistance(1),
    nn.SpatialDivisiveNormalization(),
    nn.SpatialSubtractiveNormalization()
  }
  for _, module in ipairs(custom_type_modules) do
    module:float()
  end
end

function nntest.Module_apply()
  local s = nn.Sequential()
  s:add(nn.Linear(10,10))
  local s2 = nn.Sequential()
  s2:add(nn.Linear(10,5))
  s:add(s2)
  s:add(nn.Tanh())

  local seen = 0
  s:apply(function(module)
    if torch.type(module) == 'nn.Linear' then
      module.bias:resize(20)
      seen = seen + 1
    end
  end)
  mytester:asserteq(seen, 2)
  mytester:asserteq(s.modules[1].bias:size(1), 20)
  mytester:asserteq(s2.modules[1].bias:size(1), 20)
end

function nntest.Module_replace()
   -- test replace in container
   local s = nn.Sequential()
   s:add(nn.Linear(10,10))
   s:add(nn.Sigmoid())
   s:replace(function(module)
      return torch.type(module) == 'nn.Sigmoid' and nn.Tanh() or module
   end)
   -- test replace of a single module
   local single = nn.Tanh()
   local replaced = single:replace(function(module)
      return torch.type(module) == 'nn.Tanh' and nn.Sigmoid() or module
   end)
   mytester:asserteq(torch.type(s:get(2)), 'nn.Tanh', 'replace in container')
   mytester:asserteq(torch.type(replaced), 'nn.Sigmoid', 'replace in single module')
end

function nntest.Cosine()
   local inputSize = 4
   local outputSize = 5

   -- test 1D
   local input = torch.randn(inputSize)
   local gradOutput = torch.randn(outputSize)
   local cosine = nn.Cosine(inputSize,outputSize)
   local output = cosine:forward(input)
   local inputNorm = input:norm()+1e-12
   local weight2 = cosine.weight[2]
   local output2 = torch.dot(weight2, input)/((weight2:norm()+1e-12)*inputNorm)
   mytester:assert(math.abs(output2 - output[2]) < 0.000001,"Cosine output 1D err weight[2]")
   local output2 = torch.mv(cosine.weight, input)
   output2:cdiv(cosine.weight:norm(2,2)+1e-12):div(inputNorm)
   mytester:assertTensorEq(output, output2, 0.000001, "Cosine output 1D err")
   local gradInput = cosine:updateGradInput(input, gradOutput)
   local gradInput2 = gradInput:clone():zero()
   for j=1,outputSize do
      local w_j = cosine.weight[j]
      local nw_j = w_j:norm()+1e-12
      for i=1,inputSize do
         local w_ij = w_j[i]
         local grad_i = (w_ij/(inputNorm*nw_j))
         grad_i = grad_i - (output[j]*input[i]/(inputNorm*inputNorm))
         grad_i = grad_i * gradOutput[j]
         gradInput2[i] = gradInput2[i] + grad_i
      end
   end
   mytester:assertTensorEq(gradInput2, gradInput, 0.000001, "Cosine gradInput 1D err")
   cosine:zeroGradParameters()
   cosine:accGradParameters(input, gradOutput, 1)
   local gradWeight2 = cosine.weight:clone():zero()
   for j=1,outputSize do
      local w_j = cosine.weight[j]
      local nw_j = w_j:norm()+1e-12
      for i=1,inputSize do
         local w_ij = w_j[i]
         local gW_ij = (gradOutput[j]/nw_j)  * ( ( input[i] / inputNorm ) - (output[j] * w_ij / nw_j) )
         gradWeight2[{j,i}] = gW_ij
      end
   end
   mytester:assertTensorEq(cosine.gradWeight, gradWeight2, 0.000001, "Cosine gradWeight 2D err")

   -- test 2D
   local batchSize = 3
   local input = torch.randn(batchSize, inputSize)
   local gradOutput = torch.randn(batchSize, outputSize)
   cosine:zeroGradParameters()
   local cosine2 = cosine:clone()
   local output = cosine:forward(input)
   local output2 = cosine2:forward(input[2])
   mytester:assertTensorEq(output[2], output2, 0.000001, "Cosine output 2D err")
   local gradInput = cosine:backward(input, gradOutput)

   local gradInput2 = gradInput:clone():zero()
   for i=1,batchSize do
      cosine2:forward(input[i], gradOutput[i])
      gradInput2[i]:copy(cosine2:backward(input[i], gradOutput[i]))
   end
   mytester:assertTensorEq(gradInput, gradInput2, 0.000001, "Cosine gradInput 2D err")
   mytester:assertTensorEq(cosine.gradWeight, cosine2.gradWeight, 0.000001, "Cosine gradWeight 2D err")
end

function nntest.DistanceRatioCriterion()
   local sizeAverage = true
   local crit = nn.DistanceRatioCriterion(sizeAverage)
   local X = torch.rand(32,1):fill(1)
   local Y = torch.rand(32,1):fill(1)

   -- Unit Test updateOutput
   local loss = crit:forward({X, Y})
   local trueLoss = 1 + math.log(math.exp(-1) + math.exp(-1))
   assert(math.abs(loss - trueLoss) < 0.000001,
          "DistanceRatioCriterion forward incorrect output")

   -- Unit Test updateGradInput
   local dxdy = crit:backward({X, Y})
   local dx = dxdy[1]
   local dy = dxdy[2]
   assert(math.abs(dx:sum() - 0.5) < 0.000001,
          "DistanceRatioCriterion backward (dx) incorrect output")
   assert(math.abs(dy:sum() + 0.5) < 0.000001,
          "DistanceRatioCriterion backward (dy) incorrect output")
end

function nntest.ErrorHandling()
   local l = nn.Linear(1, 1)
   local p = nn.Parallel(1, 1):add(l)
   local c = nn.Concat(1):add(p)
   local model = nn.Sequential():add(nn.Identity()):add(c):add(nn.Identity())
   local function errmsg(module, i)
       return 'In ' .. i .. ' module of ' .. torch.type(module) .. ':\n'
   end
   local expected_err = errmsg(model, 2) .. errmsg(c, 1) .. errmsg(p, 1)
   mytester:assertErrorObj(
       function()
           model:forward(torch.randn(1,2,2))
       end,
       function(err)
           return err:find(expected_err) and err:find('size mismatch')
       end,
       "Failure expected or bad error message (missing information or reason)"
   )
end

function nntest.GPU()
   -- this is a placeholder to let you know that the nn.GPU unit test
   -- is located in cunn package.
end

function nntest.Profile()
   local mx_overhead = 0.05
   local print_every = 3
   local net = nn.Profile(nn.Linear(3,4), print_every)
   local input, gradOutput = torch.randn(1, 3), torch.randn(1, 4)
   local output, gradInput = net:forward(input), net:backward(input, gradOutput)
   mytester:assertTensorEq(net.modules[1].output, output, 0.000001)
   mytester:assertTensorEq(net.modules[1].gradInput, gradInput, 0.000001)
end

function nntest.NaN()
   local _ = require 'moses'
   local input = torch.randn(2,3)
   local gradOutput = torch.randn(2,4)
   local lin = nn.Linear(3,4)
   lin:zeroGradParameters()
   local nan = nn.NaN(lin)
   mytester:assert(nan.id == 1)
   -- test that it works when no NaNs are present
   local output = nan:forward(input):clone()
   local gradInput = nan:backward(input, gradOutput):clone()
   local gradWeight = lin.gradWeight:clone()
   local gradBias = lin.gradBias:clone()
   lin:zeroGradParameters()
   local output2 = lin:forward(input)
   local gradInput2 = lin:backward(input, gradOutput)
   mytester:assertTensorEq(output, output2, 0.000001)
   mytester:assertTensorEq(gradInput, gradInput2, 0.000001)
   mytester:assertTensorEq(gradWeight, lin.gradWeight, 0.000001)
   mytester:assertTensorEq(gradBias, lin.gradBias, 0.000001)
   -- test with some NaNs
   input:zero():log():log()
   local sum = input:sum()
   mytester:assert(_.isNaN(sum))
   mytester:assert(not pcall(function() nan:forward(input) end))
   lin.bias:fill(sum)
   input = torch.randn(2,3)
   mytester:assert(not pcall(function() nan:forward(input) end))
   lin.bias:uniform(0,1)
   gradOutput:fill(sum)
   mytester:assert(not pcall(function() nan:backward(input, gradOutput) end))
   gradOutput:uniform(0,1)
   lin.gradBias:fill(sum)
   mytester:assert(not pcall(function() nan:backward(input, gradOutput) end))
end

function nntest.DontCast()
   local input = torch.randn(3,4)
   local gradOutput = torch.randn(3,2)
   local linear = nn.Linear(4,2):float()
   local mlp = nn.DontCast(linear, true)
   linear:zeroGradParameters()
   local linear = linear:clone()
   local output = mlp:forward(input)
   local gradInput = mlp:backward(input, gradOutput)
   mytester:assert(torch.type(output) == 'torch.DoubleTensor')
   mytester:assert(torch.type(gradInput) == 'torch.DoubleTensor')
   local output2 = linear:forward(input:float())
   local gradInput2 = linear:backward(input:float(), gradOutput:float())
   mytester:assertTensorEq(output:float(), output2, 0.000001)
   mytester:assertTensorEq(gradInput:float(), gradInput2, 0.000001)
   local mlp3 = nn.DontCast(linear:clone())
   mlp3:zeroGradParameters()
   local output3 = mlp3:forward(input:float())
   local gradInput3 = mlp3:backward(input:float(), gradOutput:float())
   mytester:assert(torch.type(output3) == 'torch.FloatTensor')
   mytester:assert(torch.type(gradInput3) == 'torch.FloatTensor')
   mytester:assertTensorEq(output3, output2, 0.000001)
   mytester:assertTensorEq(gradInput3, gradInput2, 0.000001)

   mlp:float()
   local output4 = mlp:forward(input:float())
   local gradInput4 = mlp:backward(input:float(), gradOutput:float())
   mytester:assert(torch.type(output4) == 'torch.FloatTensor')
   mytester:assert(torch.type(gradInput4) == 'torch.FloatTensor')
   mytester:assertTensorEq(output3, output4, 0.000001)
   mytester:assertTensorEq(gradInput3, gradInput4, 0.000001)
   mlp:double()
   mytester:assert(torch.type(linear.output) == 'torch.FloatTensor')
   local output = mlp:forward(input)
   local gradInput = mlp:backward(input, gradOutput)
   mytester:assert(torch.type(output4) == 'torch.FloatTensor')
   mytester:assert(torch.type(gradInput4) == 'torch.FloatTensor')
   mytester:assertTensorEq(output3, output:float(), 0.000001)
   mytester:assertTensorEq(gradInput3, gradInput:float(), 0.000001)

   -- test table inputs/outputs
   local input = {torch.randn(3,4), torch.randn(3,4)}
   local gradOutput = {torch.randn(3,2), torch.randn(3,2)}
   local linear = nn.ParallelTable():add(nn.Linear(4,2)):add(nn.Linear(4,2)):float()
   local mlp = nn.DontCast(linear, true)
   linear:zeroGradParameters()
   local linear = linear:clone()
   local output = mlp:forward(input)
   local gradInput = mlp:backward(input, gradOutput)
   mytester:assert(torch.type(output[1]) == 'torch.DoubleTensor')
   mytester:assert(torch.type(gradInput[1]) == 'torch.DoubleTensor')
   mytester:assert(torch.type(output[2]) == 'torch.DoubleTensor')
   mytester:assert(torch.type(gradInput[2]) == 'torch.DoubleTensor')
   local _ = require 'moses'
   local finput = _.map(input, function(k,v) return v:float() end)
   local foutput = _.map(output, function(k,v) return v:float() end)
   local fgradInput = _.map(gradInput, function(k,v) return v:float() end)
   local fgradOutput = _.map(gradOutput, function(k,v) return v:float() end)
   local output2 = linear:forward(finput)
   local gradInput2 = linear:backward(finput, fgradOutput)
   mytester:assertTensorEq(foutput[1], output2[1], 0.000001)
   mytester:assertTensorEq(foutput[2], output2[2], 0.000001)
   mytester:assertTensorEq(fgradInput[1], gradInput2[1], 0.000001)
   mytester:assertTensorEq(fgradInput[2], gradInput2[2], 0.000001)
   local mlp3 = nn.DontCast(linear:clone())
   mlp3:zeroGradParameters()
   local output3 = mlp3:forward(finput)
   local gradInput3 = mlp3:backward(finput, fgradOutput)
   mytester:assert(torch.type(output3[1]) == 'torch.FloatTensor')
   mytester:assert(torch.type(gradInput3[1]) == 'torch.FloatTensor')
   mytester:assert(torch.type(output3[2]) == 'torch.FloatTensor')
   mytester:assert(torch.type(gradInput3[2]) == 'torch.FloatTensor')
   mytester:assertTensorEq(output3[1], output2[1], 0.000001)
   mytester:assertTensorEq(gradInput3[1], gradInput2[1], 0.000001)
   mytester:assertTensorEq(output3[2], output2[2], 0.000001)
   mytester:assertTensorEq(gradInput3[2], gradInput2[2], 0.000001)
   mlp:float()
   local output4 = mlp:forward(finput)
   local gradInput4 = mlp:backward(finput, fgradOutput)
   mytester:assert(torch.type(output4[1]) == 'torch.FloatTensor')
   mytester:assert(torch.type(gradInput4[1]) == 'torch.FloatTensor')
   mytester:assert(torch.type(output4[2]) == 'torch.FloatTensor')
   mytester:assert(torch.type(gradInput4[2]) == 'torch.FloatTensor')
   mytester:assertTensorEq(output3[1], output4[1], 0.000001)
   mytester:assertTensorEq(gradInput3[1], gradInput4[1], 0.000001)
   mytester:assertTensorEq(output3[2], output4[2], 0.000001)
   mytester:assertTensorEq(gradInput3[2], gradInput4[2], 0.000001)
   mlp:double()
   mytester:assert(torch.type(linear.output) == 'table')
   mytester:assert(torch.type(linear.output[1]) == 'torch.FloatTensor')
   mytester:assert(torch.type(linear.output[2]) == 'torch.FloatTensor')
   local output = mlp:forward(input)
   local gradInput = mlp:backward(input, gradOutput)
   mytester:assertTensorEq(output3[1], output[1]:float(), 0.000001)
   mytester:assertTensorEq(gradInput3[1], gradInput[1]:float(), 0.000001)
end

function nntest.SpatialDepthWiseConvolution()
   local epsilon = 0.00001

   local SC = nn.SpatialConvolution
   local SDWC = nn.SpatialDepthWiseConvolution

   local function spatialDepthWiseConv(
         nInputPlane, multiplier, kernel, stride, padding, inputSize, weight, bias
      )
      local conv = SDWC(nInputPlane, multiplier, kernel, kernel, stride, stride, padding, padding)
      conv.weight = weight
      conv.bias = bias
      return conv
   end

   -- Utility spatialDepthWiseConv_util() function --------------------------------
   -- By Alfredo Canziani, alfredo.canziani@gmail.com -----------------------------
   local function spatialDepthWiseConv_util(
         nInputPlane, multiplier, kernel, stride, padding, inputSize, weight, bias
      )

      local conv = nn.Sequential()
      conv:add(nn.Contiguous())
      conv:add(nn.View(-1, 1, inputSize, inputSize))
      conv:add(SC(1, multiplier, kernel, kernel, stride, stride, padding, padding))

      local depthWiseConv = nn.Parallel(2, 2)
      for channel = 1, nInputPlane do
         local tempConv = conv:clone()
         tempConv:get(3).weight = weight:narrow(2, channel, 1):clone()
         tempConv:get(3).bias = bias:select(2, channel):clone()
        depthWiseConv:add(tempConv)
      end
      depthWiseConv:add(nn.Contiguous())
      return depthWiseConv
   end

   local n = 3 -- nInputPlane
   local s = 28 -- input height and width
   local b = 3 -- batch size
   local m = 4 -- multiplier
   local k = 3 -- kernel size
   local p = 1 -- padding
   local st = 1 -- stride

   local testBatch = 1e3 -- number of repetition

   local X = torch.rand(b, n, s, s) -- 1x3x299x299 images
   local weight = torch.rand(m, n, k, k) -- weight
   local bias = torch.rand(m, n) -- bias

   local model = spatialDepthWiseConv(n, m, k, st, p, s, weight, bias)
   local model_util = spatialDepthWiseConv_util(n, m, k, st, p, s, weight, bias)

   local Y_util = model_util:forward(X)
   local Y = model:forward(X)

   local abs_diff = Y_util:clone():csub(Y):abs()
   mytester:assert(torch.all(abs_diff:lt(epsilon)))
end

function nntest.Constant()
   local input = torch.randn(20,3,7)
   local gradOutput = torch.randn(20,30,6)
   local value = torch.randn(30,6)
   local const = nn.Constant(value:clone(), 2)
   local output = const:forward(input)
   local gradInput = const:backward(input, output)
   local output2 = value:view(1,30,6):expand(20,30,6)
   mytester:assertTensorEq(output2, output, 0.000001, "Constant forward err")
   mytester:assertTensorEq(gradInput, input:zero(), 0.000001, "Constant backward err")
end

function nntest.WhiteNoise()
   local input = torch.zeros(3, 28, 28)
   local addNoise = nn.WhiteNoise()
   local output = addNoise:forward(input)
   local meanValue = output:mean()
   local stdValue = output:std()
   mytester:assert(meanValue > -0.01 and meanValue < 0.01)
   mytester:assert(stdValue < 0.15 and stdValue >= 0)

   -- Evaluate
   addNoise:evaluate()
   output = addNoise:forward(input)
   meanValue = output:mean()
   stdValue = output:std()
   mytester:assert(meanValue == 0)
   mytester:assert(stdValue == 0)

   -- backprop
   addNoise:training()
   local gradOutput = torch.rand(3, 28, 28)
   local gradInput = addNoise:updateGradInput(input, gradOutput)
   mytester:assertTensorEq(gradOutput, gradInput, 0.000001, "WhiteNoise backward err")
end

function nntest.OneHot()
   local nClass = 10

   -- batch mode
   local batchSize = 3
   local input = torch.LongTensor(batchSize):random(1, nClass)
   local gradOutput = torch.randn(batchSize, nClass)

   local oh = nn.OneHot(nClass)

   local output = oh:forward(input)
   local output2 = torch.Tensor(batchSize, nClass):zero()
   local eye = torch.eye(nClass)
   output2:index(eye, 1, input)
   mytester:assertTensorEq(output, output2, 0.000001, "OneHot forward batch err")
   mytester:assert(output:dim() == 2)

   -- non-batch mode (number input)
   local num = 3
   local output3 = torch.zeros(nClass)
   output3[num] = 1.0
   mytester:assertTensorEq(oh:forward(num), output3, 0.000001, "OneHot forward number err")

   local gradInput = oh:backward(input, gradOutput)
   mytester:assertTensorEq(gradInput, input:double():zero(), 0.000001, "OneHot backward batch err")

   if pcall(function() require 'cunn' end) then
      oh:cuda()

      -- test with long input
      local output = oh:forward(input)
      mytester:assert(torch.type(output) == 'torch.CudaTensor')
      mytester:assertTensorEq(output:double(), output2, 0.000001, "OneHot forward batch long-cuda err")

      -- test with cuda input
      local input = input:cuda()
      gradOutput = gradOutput:cuda()

      local output = oh:forward(input)
      mytester:assert(torch.type(output) == 'torch.CudaTensor')
      mytester:assertTensorEq(output:double(), output2, 0.000001, "OneHot forward batch cuda err")

      local gradInput2 = oh:backward(input, gradOutput)
      mytester:assertTensorEq(gradInput, gradInput2:double(), 0.000001, "OneHot backward batch err")
      cutorch.synchronize()

      -- non-batch mode (number input)
      mytester:assertTensorEq(oh:forward(num), output3:cuda(), 0.000001, "OneHot forward number err")
   end

   -- multi-dimensional input
   local inputSize = 2
   local input = torch.LongTensor(batchSize, inputSize):random(1, nClass)
   local gradOutput = torch.randn(batchSize, inputSize, nClass)

   local oh = nn.OneHot(nClass, 2)

   local output = oh:forward(input)
   local output2 = torch.Tensor(batchSize*inputSize, nClass):zero()
   local eye = torch.eye(nClass)
   output2:index(eye, 1, input:view(-1))
   output2:resize(batchSize, inputSize, nClass)
   mytester:assertTensorEq(output, output2, 0.000001, "OneHot 2d forward batch err")
   mytester:assert(output:dim() == 3)

   local gradInput = oh:backward(input, gradOutput)
   mytester:assertTensorEq(gradInput, input:double():zero(), 0.000001, "OneHot 2d backward batch err")

   if pcall(function() require 'cunn' end) then
      oh:cuda()

      -- test with long input
      local output = oh:forward(input)
      mytester:assert(torch.type(output) == 'torch.CudaTensor')
      mytester:assertTensorEq(output:double(), output2, 0.000001, "OneHot 2d forward batch long-cuda err")

      -- test with cuda input
      local input = input:cuda()
      gradOutput = gradOutput:cuda()

      local output = oh:forward(input)
      mytester:assert(torch.type(output) == 'torch.CudaTensor')
      mytester:assertTensorEq(output:double(), output2, 0.000001, "OneHot 2d forward batch cuda err")

      local gradInput2 = oh:backward(input, gradOutput)
      mytester:assertTensorEq(gradInput, gradInput2:double(), 0.000001, "OneHot 2d backward batch err")

      local benchmark = false
      if benchmark then
         local input = torch.FloatTensor(50, 50):random(1,65):cuda()

         local oh = nn.OneHot(65):cuda()

         oh:forward(input)
         cutorch.synchronize()
         local a = torch.Timer()
         for i=1,10 do
            oh:forward(input)
         end
         cutorch.synchronize()
         local gputime = a:time().real

         oh:float()
         input = input:float()
         oh:forward(input)
         a = torch.Timer()
         for i=1,10 do
            oh:forward(input)
         end
         local cputime = a:time().real
         print("Onehot GPU vs CPU time", gputime, cputime)
      end
   end
end

function nntest.ZeroGrad()
   local input = torch.randn(3,4)
   local zg = nn.ZeroGrad()
   local output = zg:forward(input)
   mytester:assertTensorEq(input, output, 0.00000001)
   local gradInput = zg:backward(input, input)
   local gradInput2 = gradInput:clone():zero()
   mytester:assertTensorEq(gradInput, gradInput2, 0.0000001)
end

function nntest.ZipTable()
   -- input : { {a1,a2}, {b1,b2}, {c1,c2} }
   -- output : { {a1,b1,c1}, {a2,b2,c2} }
   local z = nn.ZipTable()
   local input = {
      {torch.randn(3,4), torch.randn(3,4)},
      {torch.randn(3,4), torch.randn(3,4)},
      {torch.randn(3,4), torch.randn(3,4)}
   }
   local output = z:forward(input)
   mytester:assert(#output == 2, "ZipTable #output")
   mytester:assert(#(output[1]) == 3, "ZipTable #output[1]")
   mytester:assertTensorEq(input[1][1], output[1][1], 0.000001, "ZipTable input11")
   mytester:assertTensorEq(input[1][2], output[2][1], 0.000001, "ZipTable input12")
   mytester:assertTensorEq(input[3][2], output[2][3], 0.000001, "ZipTable input32")
   local gradInput = z:backward(input, output)
   mytester:assert(#gradInput == 3, "ZipTable #gradInput")
   mytester:assert(#(gradInput[1]) == 2, "ZipTable #gradInput[1]")
   mytester:assertTensorEq(input[1][1], gradInput[1][1], 0.000001, "ZipTable gradInput11")
   mytester:assertTensorEq(input[1][2], gradInput[1][2], 0.000001, "ZipTable gradInput12")
   mytester:assertTensorEq(input[3][2], gradInput[3][2], 0.000001, "ZipTable gradInput32")
end

function nntest.ZipTableOneToMany()
   -- input : { v, {a,b,c} }
   -- output : { {v,a}, {v,b}, {v,c} }
   local z = nn.ZipTableOneToMany()
   local input = { torch.randn(3), { torch.randn(4), torch.rand(4), torch.rand(4) } }
   local output = z:forward(input)
   mytester:assert(#output == 3, "ZipTableOneToMany #output")
   mytester:assert(#(output[1]) == 2, "ZipTableOneToMany #output[1]")
   mytester:assert(#(output[2]) == 2, "ZipTableOneToMany #output[2]")
   mytester:assert(#(output[3]) == 2, "ZipTableOneToMany #output[3]")
   mytester:assertTensorEq(input[1], output[1][1], 0.000001, "ZipTableOneToMany input1 output11")
   mytester:assertTensorEq(input[1], output[2][1], 0.000001, "ZipTableOneToMany input1 output21")
   mytester:assertTensorEq(input[1], output[3][1], 0.000001, "ZipTableOneToMany input1 output31")
   mytester:assertTensorEq(input[2][1], output[1][2], 0.000001, "ZipTableOneToMany input21")
   mytester:assertTensorEq(input[2][2], output[2][2], 0.000001, "ZipTableOneToMany input22")
   mytester:assertTensorEq(input[2][3], output[3][2], 0.000001, "ZipTableOneToMany input23")
   local gradInput = z:backward(input, output)
   mytester:assert(#gradInput == 2, "ZipTableOneToMany #gradInput")
   mytester:assert(#(gradInput[2]) == 3, "ZipTableOneToMany #gradInput[2]")
   mytester:assertTensorEq(input[2][1], gradInput[2][1], 0.000001, "ZipTableOneToMany gradInput21")
   mytester:assertTensorEq(input[2][2], gradInput[2][2], 0.000001, "ZipTableOneToMany gradInput22")
   mytester:assertTensorEq(input[2][3], gradInput[2][3], 0.000001, "ZipTableOneToMany gradInput32")
   mytester:assertTensorEq(torch.mul(input[1], 3), gradInput[1], 0.000001, "ZipTableOneToMany gradInput21")
end

function nntest.Collapse()
   local c = nn.Collapse(3)
   local input = torch.randn(8,3,4,5)
   local output = c:forward(input)
   mytester:assertTensorEq(input:view(8,-1), output, 0.000001, "Collapse:forward")
   local gradInput = c:backward(input, output)
   mytester:assertTensorEq(gradInput, input, 0.000001, "Collapse:backward")
   mytester:assertTableEq(gradInput:size():totable(), input:size():totable(), 0.000001, "Collapse:backward size")
   local input2 = input:transpose(1,4)
   local output2 = c:forward(input2)
   mytester:assertTensorEq(input2:contiguous():view(5,-1), output2, 0.000001, "Collapse:forward non-contiguous")
   local gradInput2 = c:backward(input2, output2)
   mytester:assertTensorEq(gradInput2, input2, 0.000001, "Collapse:backward non-contiguous")
   mytester:assertTableEq(gradInput2:size():totable(), input2:size():totable(), 0.000001, "Collapse:backward size non-contiguous")
end

function nntest.Convert()
   -- batch mode
   local c = nn.Convert('bchw', 'chwb')
   local input = torch.randn(8,3,5,5)
   local output = c:forward(input)
   local output2 = input:transpose(1,4):transpose(1,3):transpose(1,2)
   mytester:assertTensorEq(output, output2, 0.000001, "Convert fwd bchw->chwb")
   local gradInput = c:backward(input, output)
   mytester:assertTensorEq(gradInput, input, 0.000001, "Convert bwd bchw->chwb")
   local c = nn.Convert('bchw', 'bf')
   local output = c:forward(input)
   local output2 = input:view(8,-1)
   mytester:assertTensorEq(output, output2, 0.000001, "Convert fwd bchw->bf")
   c:float()
   local output = c:forward(input:float())
   mytester:assertTensorEq(output, output2:float(), 0.000001, "Convert:type()")
   local output = c:forward(input)
   mytester:assertTensorEq(output, output2:float(), 0.000001, "Convert:type() double->float")
   -- non-batch mode
   local c = nn.Convert('chw', 'hwc')
   local input = torch.randn(3,5,5)
   local output = c:forward(input)
   local output2 = input:transpose(1,3):transpose(1,2)
   mytester:assertTensorEq(output, output2, 0.000001, "Convert fwd chw->hwc non-batch")
   local gradInput = c:backward(input, output)
   mytester:assertTensorEq(gradInput, input, 0.000001, "Convert bwd chw->hwc non-batch")
   local c = nn.Convert('chw', 'f')
   local output = c:forward(input)
   local output2 = input:view(-1)
   mytester:assertTensorEq(output, output2, 0.000001, "Convert fwd chw->bf non-batch")
   c:float()
   local output = c:forward(input:float())
   mytester:assertTensorEq(output, output2:float(), 0.000001, "Convert:type() non-batch")
   local output = c:forward(input)
   mytester:assertTensorEq(output, output2:float(), 0.000001, "Convert:type() double->float non-batch")
end

function nntest.CAddTensorTable()
   -- input : { v, {a,b,c} }
   -- output : { v+a, v+b, v+c }
   local z = nn.CAddTensorTable()
   local input = { torch.randn(3), { torch.randn(3), torch.rand(3), torch.rand(3) } }
   local output = z:forward(input)
   mytester:assert(#output == 3, "CAddTensorTable #output")
   mytester:assertTensorEq(input[1]+input[2][1], output[1], 0.00001, "CAddTensorTable input21 output1")
   mytester:assertTensorEq(input[1]+input[2][2], output[2], 0.00001, "CAddTensorTable input22 output2")
   mytester:assertTensorEq(input[1]+input[2][3], output[3], 0.00001, "CAddTensorTable input23 output3")
   local gradInput = z:backward(input, output)
   mytester:assert(#gradInput == 2, "CAddTensorTable #gradInput")
   mytester:assert(#(gradInput[2]) == 3, "CAddTensorTable #gradInput[2]")
   mytester:assertTensorEq(output[1], gradInput[2][1], 0.000001, "CAddTensorTable gradInput21")
   mytester:assertTensorEq(output[2], gradInput[2][2], 0.000001, "CAddTensorTable gradInput22")
   mytester:assertTensorEq(output[3], gradInput[2][3], 0.000001, "CAddTensorTable gradInput23")
   mytester:assertTensorEq(output[1]+output[2]+output[3], gradInput[1], 0.000001, "CAddTensorTable gradInput1")
end

-- Unit Test Kmeans layer
function nntest.Kmeans()
   local k = 3
   local dim = 5
   local batchSize = 200
   local input = torch.Tensor(batchSize, dim)
   for i=1, batchSize do
      input[i]:fill(torch.random(1, k))
   end

   local verbose = false

   local attempts = 10
   local iter = 100
   local bestLoss = 100000000
   local bestKm = nil
   local tempLoss = 0
   local learningRate = 1

   local initTypes = {'random', 'kmeans++'}
   local useCudas = {false}
   if pcall(function() require 'cunn' end) then
      useCudas[2] = true
   end
   for _, initType in pairs(initTypes) do
      for _, useCuda in pairs(useCudas) do

         if useCuda then
            input = input:cuda()
         else
            input = input:double()
         end

         local timer = torch.Timer()
         for j=1, attempts do
            local km = nn.Kmeans(k, dim)
            if useCuda then km:cuda() end

            if initType == 'kmeans++' then
               km:initKmeansPlus(input)
            else
               km:initRandom(input)
            end

            for i=1, iter do
               km:zeroGradParameters()

               km:forward(input)
               km:backward(input, gradOutput)

               -- Gradient descent
               km.weight:add(-learningRate, km.gradWeight)
               tempLoss = km.loss
            end
            if verbose then print("Attempt Loss " .. j ..": " .. tempLoss) end
            if tempLoss < bestLoss then
               bestLoss = tempLoss
            end
            if (initType == 'kmeans++' and bestLoss < 0.00001) or (initType == 'random' and bestLoss < 500) then
               break
            end
         end
         if verbose then
            print("InitType: " .. initType .. " useCuda: " .. tostring(useCuda))
            print("Best Loss: " .. bestLoss)
            print("Total time: " .. timer:time().real)
         end
         if initType == 'kmeans++' then
            mytester:assert(bestLoss < 0.00001, "Kmeans++ error ("..(useCuda and 'cuda' or 'double')..")")
         else
            mytester:assert(bestLoss < 500, "Kmeans error ("..(useCuda and 'cuda' or 'double')..")")
         end
      end
   end
end

mytester:add(nntest)

jac = nn.Jacobian
sjac = nn.SparseJacobian
function nn.test(tests, seed)
   -- Limit number of threads since everything is small
   local nThreads = torch.getnumthreads()
   torch.setnumthreads(1)
   -- randomize stuff
   local seed = seed or (1e5 * torch.tic())
   print('Seed: ', seed)
   math.randomseed(seed)
   torch.manualSeed(seed)
   mytester:run(tests)
   torch.setnumthreads(nThreads)
   return mytester
end

function nn.testTHNN(tests, seed)
   require 'test.LinearTHNN'
   nn.Linear = nn.LinearTHNN
   return nn.test(tests,seed)
end
