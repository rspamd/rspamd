--[[ An implementation of AdaMax http://arxiv.org/pdf/1412.6980.pdf

ARGS:

- 'opfunc' : a function that takes a single input (X), the point
             of a evaluation, and returns f(X) and df/dX
- 'x'      : the initial point
- 'config` : a table with configuration parameters for the optimizer
- 'config.learningRate'      : learning rate
- 'config.beta1'             : first moment coefficient
- 'config.beta2'             : second moment coefficient
- 'config.epsilon'           : for numerical stability
- 'state'                    : a table describing the state of the optimizer;
                               after each call the state is modified.

RETURN:
- `x`     : the new x vector
- `f(x)`  : the function, evaluated before the update

]]

function optim.adamax(opfunc, x, config, state)
   -- (0) get/update state
   local config = config or {}
   local state = state or config
   local lr = config.learningRate or 0.002

   local beta1 = config.beta1 or 0.9
   local beta2 = config.beta2 or 0.999
   local epsilon = config.epsilon or 1e-38
   local wd = config.weightDecay or 0

   -- (1) evaluate f(x) and df/dx
   local fx, dfdx = opfunc(x)

   -- (2) weight decay
   if wd ~= 0 then
      dfdx:add(wd, x)
   end

   -- Initialization
   state.t = state.t or 0
   -- Exponential moving average of gradient values
   state.m = state.m or x.new(dfdx:size()):zero()
   -- Exponential moving average of the infinity norm
   state.u = state.u or x.new(dfdx:size()):zero()
   -- A tmp tensor to hold the input to max()
   state.max = state.max or x.new(2, unpack(dfdx:size():totable())):zero()

   state.t = state.t + 1

   -- Update biased first moment estimate.
   state.m:mul(beta1):add(1-beta1, dfdx)
   -- Update the exponentially weighted infinity norm.
   state.max[1]:copy(state.u):mul(beta2)
   state.max[2]:copy(dfdx):abs():add(epsilon)
   state.u:max(state.max, 1)

   local biasCorrection1 = 1 - beta1^state.t
   local stepSize = lr/biasCorrection1
   -- (2) update x
   x:addcdiv(-stepSize, state.m, state.u)

   -- return x*, f(x) before optimization
   return x, {fx}
end
