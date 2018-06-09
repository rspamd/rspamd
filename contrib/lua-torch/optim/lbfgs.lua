--[[ An implementation of L-BFGS, heavily inspired by minFunc (Mark Schmidt)

This implementation of L-BFGS relies on a user-provided line
search function (state.lineSearch). If this function is not
provided, then a simple learningRate is used to produce fixed
size steps. Fixed size steps are much less costly than line
searches, and can be useful for stochastic problems.

The learning rate is used even when a line search is provided.
This is also useful for large-scale stochastic problems, where
opfunc is a noisy approximation of f(x). In that case, the learning
rate allows a reduction of confidence in the step size.

ARGS:

- `opfunc` : a function that takes a single input (X), the point of
         evaluation, and returns f(X) and df/dX
- `x` : the initial point
- `state` : a table describing the state of the optimizer; after each
         call the state is modified
- `state.maxIter` : Maximum number of iterations allowed
- `state.maxEval` : Maximum number of function evaluations
- `state.tolFun` : Termination tolerance on the first-order optimality
- `state.tolX` : Termination tol on progress in terms of func/param changes
- `state.lineSearch` : A line search function
- `state.learningRate` : If no line search provided, then a fixed step size is used

RETURN:
- `x*` : the new `x` vector, at the optimal point
- `f`  : a table of all function values:
     `f[1]` is the value of the function before any optimization and
     `f[#f]` is the final fully optimized value, at `x*`

(Clement Farabet, 2012)
]]
function optim.lbfgs(opfunc, x, config, state)
   -- get/update state
   local config = config or {}
   local state = state or config
   local maxIter = tonumber(config.maxIter) or 20
   local maxEval = tonumber(config.maxEval) or maxIter*1.25
   local tolFun = config.tolFun or 1e-5
   local tolX = config.tolX or 1e-9
   local nCorrection = config.nCorrection or 100
   local lineSearch = config.lineSearch
   local lineSearchOpts = config.lineSearchOptions
   local learningRate = config.learningRate or 1
   local isverbose = config.verbose or false

   state.funcEval = state.funcEval or 0
   state.nIter = state.nIter or 0

   -- verbose function
   local verbose
   if isverbose then
      verbose = function(...) print('<optim.lbfgs> ', ...) end
   else
      verbose = function() end
   end

   -- import some functions
   local abs = math.abs
   local min = math.min

   -- evaluate initial f(x) and df/dx
   local f,g = opfunc(x)
   local f_hist = {f}
   local currentFuncEval = 1
   state.funcEval = state.funcEval + 1
   local p = g:size(1)

   -- check optimality of initial point
   state.tmp1 = state.tmp1 or g.new(g:size()):zero(); local tmp1 = state.tmp1
   tmp1:copy(g):abs()
   if tmp1:sum() <= tolFun then
      -- optimality condition below tolFun
      verbose('optimality condition below tolFun')
      return x,f_hist
   end

   if not state.dir_bufs then
      -- reusable buffers for y's and s's, and their histories
      verbose('creating recyclable direction/step/history buffers')
      state.dir_bufs = state.dir_bufs or g.new(nCorrection+1, p):split(1)
      state.stp_bufs = state.stp_bufs or g.new(nCorrection+1, p):split(1)
      for i=1,#state.dir_bufs do
         state.dir_bufs[i] = state.dir_bufs[i]:squeeze(1)
         state.stp_bufs[i] = state.stp_bufs[i]:squeeze(1)
      end
   end

   -- variables cached in state (for tracing)
   local d = state.d
   local t = state.t
   local old_dirs = state.old_dirs
   local old_stps = state.old_stps
   local Hdiag = state.Hdiag
   local g_old = state.g_old
   local f_old = state.f_old

   -- optimize for a max of maxIter iterations
   local nIter = 0
   while nIter < maxIter do
      -- keep track of nb of iterations
      nIter = nIter + 1
      state.nIter = state.nIter + 1

      ------------------------------------------------------------
      -- compute gradient descent direction
      ------------------------------------------------------------
      if state.nIter == 1 then
         d = g:clone():mul(-1) -- -g
         old_dirs = {}
         old_stps = {}
         Hdiag = 1
      else
         -- do lbfgs update (update memory)
         local y = table.remove(state.dir_bufs)  -- pop
         local s = table.remove(state.stp_bufs)
         y:add(g, -1, g_old)  -- g - g_old
         s:mul(d, t)          -- d*t
         local ys = y:dot(s)  -- y*s
         if ys > 1e-10 then
            -- updating memory
            if #old_dirs == nCorrection then
               -- shift history by one (limited-memory)
               local removed1 = table.remove(old_dirs, 1)
               local removed2 = table.remove(old_stps, 1)
               table.insert(state.dir_bufs, removed1)
               table.insert(state.stp_bufs, removed2)
            end

            -- store new direction/step
            table.insert(old_dirs, s)
            table.insert(old_stps, y)

            -- update scale of initial Hessian approximation
            Hdiag = ys / y:dot(y)  -- (y*y)
         else
            -- put y and s back into the buffer pool
            table.insert(state.dir_bufs, y)
            table.insert(state.stp_bufs, s)
         end

         -- compute the approximate (L-BFGS) inverse Hessian
         -- multiplied by the gradient
         local k = #old_dirs

         -- need to be accessed element-by-element, so don't re-type tensor:
         state.ro = state.ro or torch.Tensor(nCorrection); local ro = state.ro
         for i = 1,k do
            ro[i] = 1 / old_stps[i]:dot(old_dirs[i])
         end

         -- iteration in L-BFGS loop collapsed to use just one buffer
         local q = tmp1  -- reuse tmp1 for the q buffer
         -- need to be accessed element-by-element, so don't re-type tensor:
         state.al = state.al or torch.zeros(nCorrection) local al = state.al

         q:mul(g, -1)  -- -g
         for i = k,1,-1 do
            al[i] = old_dirs[i]:dot(q) * ro[i]
            q:add(-al[i], old_stps[i])
         end

         -- multiply by initial Hessian
         r = d  -- share the same buffer, since we don't need the old d
         r:mul(q, Hdiag)  -- q[1] * Hdiag
         for i = 1,k do
            local be_i = old_stps[i]:dot(r) * ro[i]
            r:add(al[i]-be_i, old_dirs[i])
         end
         -- final direction is in r/d (same object)
      end
      g_old = g_old or g:clone()
      g_old:copy(g)
      f_old = f

      ------------------------------------------------------------
      -- compute step length
      ------------------------------------------------------------
      -- directional derivative
      local gtd = g:dot(d)  -- g * d

      -- check that progress can be made along that direction
      if gtd > -tolX then
         break
      end

      -- reset initial guess for step size
      if state.nIter == 1 then
         tmp1:copy(g):abs()
         t = min(1,1/tmp1:sum()) * learningRate
      else
         t = learningRate
      end

      -- optional line search: user function
      local lsFuncEval = 0
      if lineSearch and type(lineSearch) == 'function' then
         -- perform line search, using user function
         f,g,x,t,lsFuncEval = lineSearch(opfunc,x,t,d,f,g,gtd,lineSearchOpts)
         table.insert(f_hist, f)
      else
         -- no line search, simply move with fixed-step
         x:add(t,d)
         if nIter ~= maxIter then
            -- re-evaluate function only if not in last iteration
            -- the reason we do this: in a stochastic setting,
            -- no use to re-evaluate that function here
            f,g = opfunc(x)
            lsFuncEval = 1
            table.insert(f_hist, f)
         end
      end

      -- update func eval
      currentFuncEval = currentFuncEval + lsFuncEval
      state.funcEval = state.funcEval + lsFuncEval

      ------------------------------------------------------------
      -- check conditions
      ------------------------------------------------------------
      if nIter == maxIter then
         -- no use to run tests
         verbose('reached max number of iterations')
         break
      end

      if currentFuncEval >= maxEval then
         -- max nb of function evals
         verbose('max nb of function evals')
         break
      end

      tmp1:copy(g):abs()
      if tmp1:sum() <= tolFun then
         -- check optimality
         verbose('optimality condition below tolFun')
         break
      end

      tmp1:copy(d):mul(t):abs()
      if tmp1:sum() <= tolX then
         -- step size below tolX
         verbose('step size below tolX')
         break
      end

      if abs(f-f_old) < tolX then
         -- function value changing less than tolX
         verbose('function value changing less than tolX')
         break
      end
   end

   -- save state
   state.old_dirs = old_dirs
   state.old_stps = old_stps
   state.Hdiag = Hdiag
   state.g_old = g_old
   state.f_old = f_old
   state.t = t
   state.d = d

   -- return optimal x, and history of f(x)
   return x,f_hist,currentFuncEval
end
