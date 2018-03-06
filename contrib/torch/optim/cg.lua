--[[

This cg implementation is a rewrite of minimize.m written by Carl
E. Rasmussen. It is supposed to produce exactly same results (give
or take numerical accuracy due to some changed order of
operations). You can compare the result on rosenbrock with minimize.m.
http://www.gatsby.ucl.ac.uk/~edward/code/minimize/example.html

    [x fx c] = minimize([0 0]', 'rosenbrock', -25)

Note that we limit the number of function evaluations only, it seems much
more important in practical use.

ARGS:

- `opfunc` : a function that takes a single input, the point of evaluation.
- `x`      : the initial point
- `state` : a table of parameters and temporary allocations.
- `state.maxEval`     : max number of function evaluations
- `state.maxIter`     : max number of iterations
- `state.df[0,1,2,3]` : if you pass torch.Tensor they will be used for temp storage
- `state.[s,x0]`      : if you pass torch.Tensor they will be used for temp storage

RETURN:

- `x*` : the new x vector, at the optimal point
- `f`  : a table of all function values where
     `f[1]` is the value of the function before any optimization and
     `f[#f]` is the final fully optimized value, at x*

(Koray Kavukcuoglu, 2012)
--]]
function optim.cg(opfunc, x, config, state)
   -- parameters
   local config = config or {}
   local state = state or config
   local rho  = config.rho or 0.01
   local sig  = config.sig or 0.5
   local int  = config.int or 0.1
   local ext  = config.ext or 3.0
   local maxIter  = config.maxIter or 20
   local ratio = config.ratio or 100
   local maxEval = config.maxEval or maxIter*1.25
   local red = 1

   local verbose = config.verbose or 0

   local i = 0
   local ls_failed = 0
   local fx  = {}

   -- we need three points for the interpolation/extrapolation stuff
   local z1,z2,z3 = 0,0,0
   local d1,d2,d3 = 0,0,0
   local f1,f2,f3 = 0,0,0

   local df1 = state.df1 or x.new()
   local df2 = state.df2 or x.new()
   local df3 = state.df3 or x.new()
   local tdf

   df1:resizeAs(x)
   df2:resizeAs(x)
   df3:resizeAs(x)

   -- search direction
   local s = state.s or x.new()
   s:resizeAs(x)

   -- we need a temp storage for X
   local x0 = state.x0 or x.new()
   local f0 = 0
   local df0 = state.df0 or x.new()
   x0:resizeAs(x)
   df0:resizeAs(x)

   -- evaluate at initial point
   f1,tdf = opfunc(x)
   fx[#fx+1] = f1
   df1:copy(tdf)
   i=i+1

   -- initial search direction
   s:copy(df1):mul(-1)

   d1 = -s:dot(s )         -- slope
   z1 = red/(1-d1)         -- initial step

   while i < math.abs(maxEval) do

      x0:copy(x)
      f0 = f1
      df0:copy(df1)

      x:add(z1,s)
      f2,tdf = opfunc(x)
      df2:copy(tdf)
      i=i+1
      d2 = df2:dot(s)
      f3,d3,z3 = f1,d1,-z1   -- init point 3 equal to point 1
      local m = math.min(maxIter,maxEval-i)
      local success = 0
      local limit = -1

      while true do
         while (f2 > f1+z1*rho*d1 or d2 > -sig*d1) and m > 0 do
            limit = z1
            if f2 > f1 then
               z2 = z3 - (0.5*d3*z3*z3)/(d3*z3+f2-f3)
            else
               local A = 6*(f2-f3)/z3+3*(d2+d3)
               local B = 3*(f3-f2)-z3*(d3+2*d2)
               z2 = (math.sqrt(B*B-A*d2*z3*z3)-B)/A
            end
            if z2 ~= z2 or z2 == math.huge or z2 == -math.huge then
               z2 = z3/2;
            end
            z2 = math.max(math.min(z2, int*z3),(1-int)*z3);
            z1 = z1 + z2;
            x:add(z2,s)
            f2,tdf = opfunc(x)
            df2:copy(tdf)
            i=i+1
            m = m - 1
            d2 = df2:dot(s)
            z3 = z3-z2;
         end
         if f2 > f1+z1*rho*d1 or d2 > -sig*d1 then
            break
         elseif d2 > sig*d1 then
            success = 1;
            break;
         elseif m == 0 then
            break;
         end
         local A = 6*(f2-f3)/z3+3*(d2+d3);
         local B = 3*(f3-f2)-z3*(d3+2*d2);
         z2 = -d2*z3*z3/(B+math.sqrt(B*B-A*d2*z3*z3))

         if z2 ~= z2 or z2 == math.huge or z2 == -math.huge or z2 < 0 then
            if limit < -0.5 then
               z2 = z1 * (ext -1)
            else
               z2 = (limit-z1)/2
            end
         elseif (limit > -0.5) and (z2+z1) > limit then
            z2 = (limit-z1)/2
         elseif limit < -0.5 and (z2+z1) > z1*ext then
            z2 = z1*(ext-1)
         elseif z2 < -z3*int then
            z2 = -z3*int
         elseif limit > -0.5 and z2 < (limit-z1)*(1-int) then
            z2 = (limit-z1)*(1-int)
         end
         f3=f2; d3=d2; z3=-z2;
         z1 = z1+z2;
         x:add(z2,s)

         f2,tdf = opfunc(x)
         df2:copy(tdf)
         i=i+1
         m = m - 1
         d2 = df2:dot(s)
      end
      if success == 1 then
         f1 = f2
         fx[#fx+1] = f1;
         local ss = (df2:dot(df2)-df2:dot(df1)) / df1:dot(df1)
         s:mul(ss)
         s:add(-1,df2)
         local tmp = df1:clone()
         df1:copy(df2)
         df2:copy(tmp)
         d2 = df1:dot(s)
         if d2> 0 then
            s:copy(df1)
            s:mul(-1)
            d2 = -s:dot(s)
         end

         z1 = z1 * math.min(ratio, d1/(d2-1e-320))
         d1 = d2
         ls_failed = 0
      else
         x:copy(x0)
         f1 = f0
         df1:copy(df0)
         if ls_failed or i>maxEval then
            break
         end
         local tmp = df1:clone()
         df1:copy(df2)
         df2:copy(tmp)
         s:copy(df1)
         s:mul(-1)
         d1 = -s:dot(s)
         z1 = 1/(1-d1)
         ls_failed = 1
      end
   end
   state.df0 = df0
   state.df1 = df1
   state.df2 = df2
   state.df3 = df3
   state.x0 = x0
   state.s = s
   return x,fx,i
end
