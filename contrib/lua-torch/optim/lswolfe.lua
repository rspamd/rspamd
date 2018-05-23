--[[ A Line Search satisfying the Wolfe conditions

ARGS:
- `opfunc` : a function (the objective) that takes a single input (X),
         the point of evaluation, and returns f(X) and df/dX
- `x`          : initial point / starting location
- `t`          : initial step size
- `d`          : descent direction
- `f`          : initial function value
- `g`          : gradient at initial location
- `gtd`        : directional derivative at starting location
- `options.c1` : sufficient decrease parameter
- `options.c2` : curvature parameter
- `options.tolX`    : minimum allowable step length
- `options.maxIter` : maximum nb of iterations

RETURN:
- `f`          : function value at x+t*d
- `g`          : gradient value at x+t*d
- `x`          : the next x (=x+t*d)
- `t`          : the step length
- `lsFuncEval` : the number of function evaluations
]]
function optim.lswolfe(opfunc,x,t,d,f,g,gtd,options)
   -- options
   options = options or {}
   local c1 = options.c1 or 1e-4
   local c2 = options.c2 or 0.9
   local tolX = options.tolX or 1e-9
   local maxIter = options.maxIter or 20
   local isverbose = options.verbose or false

   -- some shortcuts
   local abs = torch.abs
   local min = math.min
   local max = math.max

   -- verbose function
   local function verbose(...)
      if isverbose then print('<optim.lswolfe> ', ...) end
   end

   -- evaluate objective and gradient using initial step
   local x_init = x:clone()
   x:add(t,d)
   local f_new,g_new = opfunc(x)
   local lsFuncEval = 1
   local gtd_new = g_new * d

   -- bracket an interval containing a point satisfying the Wolfe
   -- criteria
   local LSiter,t_prev,done = 0,0,false
   local f_prev,g_prev,gtd_prev = f,g:clone(),gtd
   local bracket,bracketFval,bracketGval
   while LSiter < maxIter do
      -- check conditions:
      if (f_new > (f + c1*t*gtd)) or (LSiter > 1 and f_new >= f_prev) then
         bracket = x.new{t_prev,t}
         bracketFval = x.new{f_prev,f_new}
         bracketGval = x.new(2,g_new:size(1))
         bracketGval[1] = g_prev
         bracketGval[2] = g_new
         break

      elseif abs(gtd_new) <= -c2*gtd then
         bracket = x.new{t}
         bracketFval = x.new{f_new}
         bracketGval = x.new(1,g_new:size(1))
         bracketGval[1] = g_new
         done = true
         break

      elseif gtd_new >= 0 then
         bracket = x.new{t_prev,t}
         bracketFval = x.new{f_prev,f_new}
         bracketGval = x.new(2,g_new:size(1))
         bracketGval[1] = g_prev
         bracketGval[2] = g_new
         break

      end

      -- interpolate:
      local tmp = t_prev
      t_prev = t
      local minStep = t + 0.01*(t-tmp)
      local maxStep = t*10
      t = optim.polyinterp(x.new{{tmp,f_prev,gtd_prev},
                                  {t,f_new,gtd_new}},
                           minStep, maxStep)

      -- next step:
      f_prev = f_new
      g_prev = g_new:clone()
      gtd_prev = gtd_new
      x[{}] = x_init
      x:add(t,d)
      f_new,g_new = opfunc(x)
      lsFuncEval = lsFuncEval + 1
      gtd_new = g_new * d
      LSiter = LSiter + 1
   end

   -- reached max nb of iterations?
   if LSiter == maxIter then
      bracket = x.new{0,t}
      bracketFval = x.new{f,f_new}
      bracketGval = x.new(2,g_new:size(1))
      bracketGval[1] = g
      bracketGval[2] = g_new
   end

   -- zoom phase: we now have a point satisfying the criteria, or
   -- a bracket around it. We refine the bracket until we find the
   -- exact point satisfying the criteria
   local insufProgress = false
   local LOposRemoved = 0
   while not done and LSiter < maxIter do
      -- find high and low points in bracket
      local f_LO,LOpos = bracketFval:min(1)
      LOpos = LOpos[1] f_LO = f_LO[1]
      local HIpos = -LOpos+3

      -- compute new trial value
      t = optim.polyinterp(x.new{{bracket[1],bracketFval[1],bracketGval[1]*d},
                                  {bracket[2],bracketFval[2],bracketGval[2]*d}})

      -- test what we are making sufficient progress
      if min(bracket:max()-t,t-bracket:min())/(bracket:max()-bracket:min()) < 0.1 then
         if insufProgress or t>=bracket:max() or t <= bracket:min() then
            if abs(t-bracket:max()) < abs(t-bracket:min()) then
               t = bracket:max()-0.1*(bracket:max()-bracket:min())
            else
               t = bracket:min()+0.1*(bracket:max()-bracket:min())
            end
            insufProgress = false
         else
            insufProgress = true
         end
      else
         insufProgress = false
      end

      -- Evaluate new point
      x[{}] = x_init
      x:add(t,d)
      f_new,g_new = opfunc(x)
      lsFuncEval = lsFuncEval + 1
      gtd_new = g_new * d
      LSiter = LSiter + 1
      if f_new > f + c1*t*gtd or f_new >= f_LO then
         -- Armijo condition not satisfied or not lower than lowest point
         bracket[HIpos] = t
         bracketFval[HIpos] = f_new
         bracketGval[HIpos] = g_new
      else
         if abs(gtd_new) <= - c2*gtd then
            -- Wolfe conditions satisfied
            done = true
         elseif gtd_new*(bracket[HIpos]-bracket[LOpos]) >= 0 then
            -- Old HI becomes new LO
            bracket[HIpos] = bracket[LOpos]
            bracketFval[HIpos] = bracketFval[LOpos]
            bracketGval[HIpos] = bracketGval[LOpos]
         end
         -- New point becomes new LO
         bracket[LOpos] = t
         bracketFval[LOpos] = f_new
         bracketGval[LOpos] = g_new
      end

      -- done?
      if not done and abs((bracket[1]-bracket[2])*gtd_new) < tolX then
         break
      end
   end

   -- be verbose
   if LSiter == maxIter then
      verbose('reached max number of iterations')
   end

   -- return stuff
   local _,LOpos = bracketFval:min(1)
   LOpos = LOpos[1]
   t = bracket[LOpos]
   f_new = bracketFval[LOpos]
   g_new = bracketGval[LOpos]
   x[{}] = x_init
   x:add(t,d)
	return f_new,g_new,x,t,lsFuncEval
end
