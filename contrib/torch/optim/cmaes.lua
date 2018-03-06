require 'torch'
require 'math'

local BestSolution = {}
--[[ An implementation of `CMAES` (Covariance Matrix Adaptation Evolution Strategy),
ported from https://www.lri.fr/~hansen/barecmaes2.html.

Parameters
----------
ARGS:

-    `opfunc` : a function that takes a single input (X), the point of
               evaluation, and returns f(X) and df/dX. Note that df/dX is not used
-    `x` : the initial point
-    `state.sigma`
            float, initial step-size (standard deviation in each
            coordinate)
-    `state.maxEval`
            int, maximal number of function evaluations
-    `state.ftarget`
            float, target function value
-    `state.popsize`
          population size. If this is left empty,
            4 + int(3 * log(|x|)) will be used
-    `state.ftarget`
            stop if fitness < ftarget
-    `state.verb_disp`
            int, display on console every verb_disp iteration, 0 for never

RETURN:
- `x*` : the new `x` vector, at the optimal point
- `f`  : a table of all function values:
       `f[1]` is the value of the function before any optimization and
       `f[#f]` is the final fully optimized value, at `x*`
--]]
function optim.cmaes(opfunc, x, config, state)
   if  (x.triu == nil or x.diag == nil) then
      error('Unsupported Tensor ' .. x:type() .. " please use Float- or DoubleTensor for x")
   end
   -- process input parameters
   local config = config or {}
   local state = state or config
   local xmean = x:clone():view(-1) -- distribution mean, a flattened copy
   local N = xmean:size(1)  -- number of objective variables/problem dimension
   local sigma = state.sigma -- coordinate wise standard deviation (step size)
   local ftarget = state.ftarget -- stop if fitness < ftarget
   local maxEval = tonumber(state.maxEval) or 1e3*N^2
   local objfunc = opfunc
   local verb_disp = state.verb_disp -- display step size
   local min_iterations = state.min_iterations or 1

   local lambda = state.popsize -- population size, offspring number
   -- Strategy parameter setting: Selection
   if state.popsize == nil then
      lambda = 4 + math.floor(3 * math.log(N))
   end

   local mu = lambda / 2  -- number of parents/points for recombination
   local weights = torch.range(0,mu-1):apply(function(i)
       return math.log(mu+0.5) - math.log(i+1)  end) -- recombination weights
   weights:div(weights:sum())  -- normalize recombination weights array
   local mueff = weights:sum()^2 / torch.pow(weights,2):sum()  -- variance-effectiveness of sum w_i x_i
   weights = weights:typeAs(x)

   -- Strategy parameter setting: Adaptation
   local cc = (4 + mueff/N) / (N+4 + 2 * mueff/N)  -- time constant for cumulation for C
   local cs = (mueff + 2) / (N + mueff + 5)  -- t-const for cumulation for sigma control
   local c1 = 2 / ((N + 1.3)^2 + mueff)  -- learning rate for rank-one update of C
   local cmu = math.min(1 - c1, 2 * (mueff - 2 + 1/mueff) / ((N + 2)^2 + mueff))  -- and for rank-mu update
   local damps = 2 * mueff/lambda + 0.3 + cs  -- damping for sigma, usually close to 1

   -- Initialize dynamic (internal) state variables
   local pc = torch.Tensor(N):zero():typeAs(x) -- evolution paths for C
   local ps = torch.Tensor(N):zero():typeAs(x) -- evolution paths for sigma
   local B = torch.eye(N):typeAs(x)   -- B defines the coordinate system
   local D = torch.Tensor(N):fill(1):typeAs(x)  -- diagonal D defines the scaling
   local C = torch.eye(N):typeAs(x)   -- covariance matrix
   if not pcall(function () torch.symeig(C,'V') end) then -- if error occurs trying to use symeig
      error('torch.symeig not available for ' .. x:type() ..
         " please use Float- or DoubleTensor for x")
   end
   local candidates = torch.Tensor(lambda,N):typeAs(x)
   local invsqrtC = torch.eye(N):typeAs(x)  -- C^-1/2
   local eigeneval = 0      -- tracking the update of B and D
   local counteval = 0
   local f_hist = {[1]=opfunc(x)}  -- for bookkeeping output and termination
   local fitvals = torch.Tensor(lambda)-- fitness values
   local best = BestSolution.new(nil,nil,counteval)
   local iteration = 0 -- iteration of the optimize loop


   local function ask()
      --[[return a list of lambda candidate solutions according to
       m + sig * Normal(0,C) = m + sig * B * D * Normal(0,I)
       --]]
      -- Eigendecomposition: first update B, D and invsqrtC from C
      -- postpone in case to achieve O(N^2)
      if counteval - eigeneval > lambda/(c1+cmu)/C:size(1)/10 then
         eigeneval = counteval
         C = torch.triu(C) + torch.triu(C,1):t() -- enforce symmetry
         D, B = torch.symeig(C,'V') -- eigen decomposition, B==normalized eigenvectors, O(N^3)
         D = torch.sqrt(D)  -- D contains standard deviations now
         invsqrtC = (B * torch.diag(torch.pow(D,-1)) * B:t())
      end
      for k=1,lambda do --repeat lambda times
         local z = D:clone():normal(0,1):cmul(D)
         candidates[{k,{}}] = torch.add(xmean, (B * z) * sigma)
      end

      return candidates
   end


   local function tell(arx)
      --[[update the evolution paths and the distribution parameters m,
      sigma, and C within CMA-ES.

      Parameters
      ----------
            `arx`
                  a list of solutions, presumably from `ask()`
            `fitvals`
                  the corresponding objective function values --]]
      -- bookkeeping, preparation
      counteval = counteval + lambda  -- slightly artificial to do here
      local xold = xmean:clone()

      -- Sort by fitness and compute weighted mean into xmean
      local arindex = nil --sorted indices
      fitvals, arindex = torch.sort(fitvals)
      arx = arx:index(1, arindex[{{1, mu}}]) -- sorted candidate solutions

      table.insert(f_hist, fitvals[1]) --append best fitness to history
      best:update(arx[1], fitvals[1], counteval)

      xmean:zero()
      xmean:addmv(arx:t(), weights) --dot product

      -- Cumulation: update evolution paths
      local y = xmean - xold
      local z = invsqrtC * y -- == C^(-1/2) * (xnew - xold)

      local c = (cs * (2-cs) * mueff)^0.5 / sigma
      ps = ps - ps * cs + z * c -- exponential decay on ps
      local hsig = (torch.sum(torch.pow(ps,2)) /
         (1-(1-cs)^(2*counteval/lambda)) / N  < 2 + 4./(N+1))
      hsig = hsig and 1.0 or 0.0 --use binary numbers

      c = (cc * (2-cc) * mueff)^0.5 / sigma
      pc = pc - pc * cc + y * c * hsig -- exponential decay on pc

      -- Adapt covariance matrix C
      local c1a = c1 - (1-hsig^2) * c1 * cc * (2-cc)
      -- for a minor adjustment to the variance loss by hsig
      for i=1,N do
         for j=1,N do
            local r = torch.range(1,mu)
            r:apply(function(k)
               return weights[k] * (arx[k][i]-xold[i]) * (arx[k][j]-xold[j]) end)
            local Cmuij = torch.sum(r) / sigma^2  -- rank-mu update
            C[i][j] = C[i][j] + ((-c1a - cmu) * C[i][j] +
                  c1 * pc[i]*pc[j] + cmu * Cmuij)
            end
         end

         -- Adapt step-size sigma with factor <= exp(0.6) \approx 1.82
         sigma = sigma * math.exp(math.min(0.6,
               (cs / damps) * (torch.sum(torch.pow(ps,2))/N - 1)/2))
   end

   local function stop()
      --[[return satisfied termination conditions in a table like
      {'termination reason':value, ...}, for example {'tolfun':1e-12},
      or the empty table {}--]]
      local res = {}
      if counteval > 0 then
         if counteval >= maxEval then
            res['evals'] = maxEval
         end
         if ftarget ~= nil and fitvals:nElement() > 0 and fitvals[1] <= ftarget then
            res['ftarget'] = ftarget
         end
         if torch.max(D) > 1e7 * torch.min(D) then
            res['condition'] = 1e7
         end
         if fitvals:nElement() > 1 and fitvals[fitvals:nElement()] - fitvals[1] < 1e-12 then
            res['tolfun'] = 1e-12
         end
         if sigma * torch.max(D) < 1e-11 then
            -- remark: max(D) >= max(diag(C))^0.5
            res['tolx'] = 1e-11
         end
      end
      return res
   end

   local function disp(verb_modulo)
      --[[display some iteration info--]]
      if verb_disp == 0 then
         return nil
      end
      local iteration = counteval / lambda

      if iteration == 1 or iteration % (10*verb_modulo) == 0 then
         print('evals:\t ax-ratio max(std)   f-value')
      end
      if iteration <= 2 or iteration % verb_modulo == 0 then
         local max_std = math.sqrt(torch.max(torch.diag(C)))
         print(tostring(counteval).. ': ' ..
            string.format(' %6.1f %8.1e ', torch.max(D) / torch.min(D), sigma * max_std)
            .. tostring(fitvals[1]))
      end

      return nil
   end

   while next(stop()) == nil or iteration < min_iterations do
      iteration = iteration + 1

      local X = ask() -- deliver candidate solutions
      for i=1, lambda do
         -- put candidate tensor back in input shape and evaluate in opfunc
         local candidate = X[i]:viewAs(x)
         fitvals[i] = objfunc(candidate)
      end

      tell(X)
      disp(verb_disp)
   end

   local bestmu, f, c = best:get()
   if verb_disp > 0 then
      for k, v in pairs(stop()) do
         print('termination by', k, '=', v)
      end
      print('best f-value =', f)
      print('solution = ')
      print(bestmu)
      print('best found at iteration: ', c/lambda, ' , total iterations: ', iteration)
   end
   table.insert(f_hist, f)

   return bestmu, f_hist, counteval
end



BestSolution.__index = BestSolution
function BestSolution.new(x, f, evals)
   local self = setmetatable({}, BestSolution)
   self.x = x
   self.f = f
   self.evals = evals
   return self
end

function BestSolution.update(self, arx, arf, evals)
   --[[initialize the best solution with `x`, `f`, and `evals`.
      Better solutions have smaller `f`-values.--]]
   if self.f == nil or arf < self.f then
      self.x = arx:clone()
      self.f = arf
      self.evals = evals
   end
   return self
end

function BestSolution.get(self)
   return self.x, self.f, self.evals
end
