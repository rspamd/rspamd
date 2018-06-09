--[[ An implementation of `DE` (Differential Evolution),

ARGS:

    -`opfunc` : a function that takes a single input (X), the point of
    evaluation, and returns f(X) and df/dX. Note that df/dX is not used
    -`x` : 		the initial point
    -`state.popsize`: 			population size. If this is left empty, 10*d will be used
    -`state.scaleFactor`: 		float, usually between 0.4 and 1
    -`state.crossoverRate`:		float, usually between 0.1 and 0.9
    -`state.maxEval`:			int, maximal number of function evaluations

RETURN:
    - `x*` : the new `x` vector, at the optimal point
    - `f`  : a table of all function values:
    `f[1]` is the value of the function before any optimization and
    `f[#f]` is the final fully optimized value, at `x*`
]]

require 'torch'

function optim.de(opfunc, x, config, state)
    -- process input parameters
    local config = config or {}
    local state = state
    local popsize = config.popsize			-- population size
    local scaleFactor = config.scaleFactor	 	-- scale factor
    local crossoverRate = config.crossoverRate	-- crossover rate
    local maxFEs = tonumber(config.maxFEs)		-- maximal number of function evaluations
    local maxRegion = config.maxRegion	        -- upper bound of search region
    local minRegion = config.minRegion		-- lower bound of search region
    local xmean = x:clone():view(-1) 		-- distribution mean, a flattened copy
    local D = xmean:size(1)  			-- number of objective variables/problem dimension

    if config.popsize == nil then
	popsize = 10 * D
    end
    if config.maxRegion == nil then
	maxRegion = 30
    end
    if config.minRegion == nil then
	minRegion = -30
    end

    -- Initialize population
    local fx = x.new(maxFEs)
    local pop = x.new(popsize, D)
    local children = x.new(popsize, D)
    local fitness = x.new(popsize)
    local children_fitness = x.new(popsize)
    local fes = 1	-- number of function evaluations
    local best_fitness
    local best_solution = x.new(D)

    -- Initialize population and evaluate the its fitness value
    local gen = torch.Generator()
    torch.manualSeed(gen, 1)

    pop:uniform(gen, minRegion, maxRegion)
    for i = 1, popsize do
	fitness[i] = opfunc(pop[i])
	fx[fes] = fitness[i]
	fes = fes + 1
    end

    -- Find the best solution
    local index
    best_fitness, index = fitness:max(1)
    best_fitness = best_fitness[1]
    index = index[1]
    best_solution:copy(pop[index])

    -- Main loop
    while fes < maxFEs do
	local  r1, r2
	for i = 1, popsize do
	    repeat
		r1 = torch.random(gen, 1, popsize)
	    until(r1 ~= i)
	    repeat
		r2 = torch.random(gen, 1, popsize)
	    until(r2 ~= r1 and r2 ~= i)

	    local jrand = torch.random(gen, 1, D)
	    for j = 1, D do
		if torch.uniform(gen, 0, 1) < crossoverRate or i == jrand then
		    children[i][j] = best_solution[j] + scaleFactor * (pop[r1][j] - pop[r2][j])
		else
		    children[i][j] = pop[i][j]
		end
	    end
	    children_fitness[i] = opfunc(children[i])
	    fx[fes] = children_fitness[i]
	    fes = fes + 1
	end

	for i = 1, popsize do
	    if children_fitness[i] <= fitness[i] then
		pop[i]:copy(children[i])
		fitness[i] = children_fitness[i]
		if fitness[i] < best_fitness then
		    best_fitness = fitness[i]
		    best_solution:copy(children[i])
		end
	    end
	end
    end
    return best_solution, fx
end
