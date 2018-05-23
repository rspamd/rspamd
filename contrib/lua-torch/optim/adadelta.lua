--[[ ADADELTA implementation for SGD http://arxiv.org/abs/1212.5701

ARGS:
- `opfunc` : a function that takes a single input (X), the point of
            evaluation, and returns f(X) and df/dX
- `x` : the initial point
- `config` : a table of hyper-parameters
- `config.rho` : interpolation parameter
- `config.eps` : for numerical stability
- `config.weightDecay` : weight decay
- `state` : a table describing the state of the optimizer; after each
         call the state is modified
- `state.paramVariance` : vector of temporal variances of parameters
- `state.accDelta` : vector of accummulated delta of gradients
RETURN:
- `x` : the new x vector
- `f(x)` : the function, evaluated before the update
]]
function optim.adadelta(opfunc, x, config, state)
    -- (0) get/update state
    if config == nil and state == nil then
        print('no state table, ADADELTA initializing')
    end
    local config = config or {}
    local state = state or config
    local rho = config.rho or 0.9
    local eps = config.eps or 1e-6
    local wd = config.weightDecay or 0
    state.evalCounter = state.evalCounter or 0
    -- (1) evaluate f(x) and df/dx
    local fx,dfdx = opfunc(x)

    -- (2) weight decay
    if wd ~= 0 then
      dfdx:add(wd, x)
    end

    -- (3) parameter update
    if not state.paramVariance then
        state.paramVariance = torch.Tensor():typeAs(x):resizeAs(dfdx):zero()
        state.paramStd = torch.Tensor():typeAs(x):resizeAs(dfdx):zero()
        state.delta = torch.Tensor():typeAs(x):resizeAs(dfdx):zero()
        state.accDelta = torch.Tensor():typeAs(x):resizeAs(dfdx):zero()
    end
    state.paramVariance:mul(rho):addcmul(1-rho,dfdx,dfdx)
    state.paramStd:resizeAs(state.paramVariance):copy(state.paramVariance):add(eps):sqrt()
    state.delta:resizeAs(state.paramVariance):copy(state.accDelta):add(eps):sqrt():cdiv(state.paramStd):cmul(dfdx)
    x:add(-1, state.delta)
    state.accDelta:mul(rho):addcmul(1-rho, state.delta, state.delta)
    -- (4) update evaluation counter
    state.evalCounter = state.evalCounter + 1

    -- return x*, f(x) before optimization
    return x,{fx}
end
