--[[ A plain implementation of RPROP

ARGS:
- `opfunc` : a function that takes a single input (X), the point of
             evaluation, and returns f(X) and df/dX
- `x`      : the initial point
- `state`  : a table describing the state of the optimizer; after each
             call the state is modified
- `state.stepsize`    : initial step size, common to all components
- `state.etaplus`     : multiplicative increase factor, > 1 (default 1.2)
- `state.etaminus`    : multiplicative decrease factor, < 1 (default 0.5)
- `state.stepsizemax` : maximum stepsize allowed (default 50)
- `state.stepsizemin` : minimum stepsize allowed (default 1e-6)
- `state.niter`       : number of iterations (default 1)

RETURN:
- `x`     : the new x vector
- `f(x)`  : the function, evaluated before the update

(Martin Riedmiller, Koray Kavukcuoglu 2013)
--]]
function optim.rprop(opfunc, x, config, state)
   if config == nil and state == nil then
      print('no state table RPROP initializing')
   end
   -- (0) get/update state
   local config = config or {}
   local state = state or config
   local stepsize = config.stepsize or 0.1
   local etaplus = config.etaplus or 1.2
   local etaminus = config.etaminus or 0.5
   local stepsizemax = config.stepsizemax or 50.0
   local stepsizemin = config.stepsizemin or 1E-06
   local niter = config.niter or 1

   local hfx = {}

   for i=1,niter do

      -- (1) evaluate f(x) and df/dx
      local fx,dfdx = opfunc(x)

      -- init temp storage
      if not state.delta then
         state.delta    = dfdx.new(dfdx:size()):zero()
         state.stepsize = dfdx.new(dfdx:size()):fill(stepsize)
         state.sign     = dfdx.new(dfdx:size())
         state.psign    = torch.ByteTensor(dfdx:size())
         state.nsign    = torch.ByteTensor(dfdx:size())
         state.zsign    = torch.ByteTensor(dfdx:size())
         state.dminmax  = torch.ByteTensor(dfdx:size())
         if torch.type(x)=='torch.CudaTensor' then
            -- Push to GPU
            state.psign    = state.psign:cuda()
            state.nsign    = state.nsign:cuda()
            state.zsign    = state.zsign:cuda()
            state.dminmax  = state.dminmax:cuda()
         end
      end

      -- sign of derivative from last step to this one
      torch.cmul(state.sign, dfdx, state.delta)
      torch.sign(state.sign, state.sign)

      -- get indices of >0, <0 and ==0 entries
      state.sign.gt(state.psign, state.sign, 0)
      state.sign.lt(state.nsign, state.sign, 0)
      state.sign.eq(state.zsign, state.sign, 0)

      -- get step size updates
      state.sign[state.psign] = etaplus
      state.sign[state.nsign] = etaminus
      state.sign[state.zsign] = 1

      -- update stepsizes with step size updates
      state.stepsize:cmul(state.sign)

      -- threshold step sizes
      -- >50 => 50
      state.stepsize.gt(state.dminmax, state.stepsize, stepsizemax)
      state.stepsize[state.dminmax] = stepsizemax
      -- <1e-6 ==> 1e-6
      state.stepsize.lt(state.dminmax, state.stepsize, stepsizemin)
      state.stepsize[state.dminmax] = stepsizemin

      -- for dir<0, dfdx=0
      -- for dir>=0 dfdx=dfdx
      dfdx[state.nsign] = 0
      -- state.sign = sign(dfdx)
      torch.sign(state.sign,dfdx)

      -- update weights
      x:addcmul(-1,state.sign,state.stepsize)

      -- update state.dfdx with current dfdx
      state.delta:copy(dfdx)

      table.insert(hfx,fx)
   end

   -- return x*, f(x) before optimization
   return x,hfx
end
