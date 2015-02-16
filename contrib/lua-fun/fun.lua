---
--- Lua Fun - a high-performance functional programming library for LuaJIT
---
--- Copyright (c) 2013 Roman Tsisyk <roman@tsisyk.com>
---
--- Distributed under the MIT/X11 License. See COPYING.md for more details.
---

--------------------------------------------------------------------------------
-- Tools
--------------------------------------------------------------------------------

local return_if_not_empty = function(state_x, ...)
    if state_x == nil then
        return nil
    end
    return ...
end

local call_if_not_empty = function(fun, state_x, ...)
    if state_x == nil then
        return nil
    end
    return state_x, fun(...)
end

local function deepcopy(orig) -- used by cycle()
    local orig_type = type(orig)
    local copy
    if orig_type == 'table' then
        copy = {}
        for orig_key, orig_value in next, orig, nil do
            copy[deepcopy(orig_key)] = deepcopy(orig_value)
        end
    else
        copy = orig
    end
    return copy
end

--------------------------------------------------------------------------------
-- Basic Functions
--------------------------------------------------------------------------------

local nil_gen = function(_param, _state)
    return nil
end

local string_gen = function(param, state)
    local state = state + 1
    if state > #param then
        return nil
    end
    local r = string.sub(param, state, state)
    return state, r
end

local pairs_gen = pairs({ a = 0 }) -- get the generating function from pairs
local map_gen = function(tab, key)
    local value
    local key, value = pairs_gen(tab, key)
    return key, key, value
end

local iter = function(obj, param, state)
    assert(obj ~= nil, "invalid iterator")
    if (type(obj) == "function") then
        return obj, param, state
    elseif (type(obj) == "table" or type(obj) == "userdata") then
        if #obj > 0 then
            return ipairs(obj)
        else
            return map_gen, obj, nil
        end
    elseif (type(obj) == "string") then
        if #obj == 0 then
            return nil_gen, nil, nil
        end
        return string_gen, obj, 0
    end
    error(string.format('object %s of type "%s" is not iterable',
          obj, type(obj)))
end

local iter_tab = function(obj)
    if type(obj) == "function" then
       return obj, nil, nil
    elseif type(obj) == "table" and type(obj[1]) == "function" then
        return obj[1], obj[2], obj[3]
    else
        return iter(obj)
    end
end

local each = function(fun, gen, param, state)
    local gen_x, param_x, state_x = iter(gen, param, state)
    repeat
        state_x = call_if_not_empty(fun, gen_x(param_x, state_x))
    until state_x == nil
end

--------------------------------------------------------------------------------
-- Generators
--------------------------------------------------------------------------------

local range_gen = function(param, state)
    local stop, step = param[1], param[2]
    local state = state + step
    if state >= stop then
        return nil
    end
    return state, state
end

local range_rev_gen = function(param, state)
    local stop, step = param[1], param[2]
    local state = state + step
    if state <= stop then
        return nil
    end
    return state, state
end

local range = function(start, stop, step)
    if step == nil then
        step = 1
        if stop == nil then
            stop = start
            start = 0
        end
    end

    assert(type(start) == "number", "start must be a number")
    assert(type(stop) == "number", "stop must be a number")
    assert(type(step) == "number", "step must be a number")
    assert(step ~= 0, "step must not be zero")

    if (step > 0) then
        return range_gen, {stop, step}, start - step
    elseif (step < 0) then
        return range_rev_gen, {stop, step}, start - step
    end
end

local duplicate_table_gen = function(param_x, state_x)
    return state_x + 1, unpack(param_x)
end

local duplicate_fun_gen = function(param_x, state_x)
    return state_x + 1, param_x(state_x)
end

local duplicate_gen = function(param_x, state_x)
    return state_x + 1, param_x
end

local duplicate = function(...)
    if select('#', ...) <= 1 then
        return duplicate_gen, select(1, ...), 0
    else
        return duplicate_table_gen, {...}, 0 
    end
end

local tabulate = function(fun)
    assert(type(fun) == "function")
    return duplicate_fun_gen, fun, 0
end

local zeros = function()
    return duplicate_gen, 0, 0
end

local ones = function()
    return duplicate_gen, 1, 0
end

local rands_gen = function(param_x, _state_x)
    return 0, math.random(param_x[1], param_x[2])
end

local rands_nil_gen = function(_param_x, _state_x)
    return 0, math.random()
end

local rands = function(n, m)
    if n == nil and m == nil then
        return rands_nil_gen, 0, 0
    end
    assert(type(n) == "number", "invalid first arg to rands")
    if m == nil then
        m = n
        n = 0
    else
        assert(type(m) == "number", "invalid second arg to rands")
    end
    assert(n < m, "empty interval")
    return rands_gen, {n, m - 1}, 0
end

--------------------------------------------------------------------------------
-- Slicing
--------------------------------------------------------------------------------

local nth = function(n, gen, param, state)
    assert(n > 0, "invalid first argument to nth")
    local gen_x, param_x, state_x = iter(gen, param, state)
    -- An optimization for arrays and strings
    if gen_x == ipairs then
        return param_x[n]
    elseif gen_x == string_gen then
        if n < #param_x then
            return string.sub(param_x, n, n)
        else
            return nil
        end
    end
    for i=1,n-1,1 do
        state_x = gen_x(param_x, state_x)
        if state_x == nil then
            return nil
        end
    end
    return return_if_not_empty(gen_x(param_x, state_x))
end

local head_call = function(state, ...)
    if state == nil then
        error("head: iterator is empty")
    end
    return ...
end

local head = function(gen, param, state)
    local gen_x, param_x, state_x = iter(gen, param, state)
    return head_call(gen_x(param_x, state_x))
end

local tail = function(gen, param, state)
    local gen_x, param_x, state_x = iter(gen, param, state)
    state_x = gen_x(param_x, state_x)
    if state_x == nil then
        return nil_gen, nil, nil
    end
    return gen_x, param_x, state_x
end

local take_n_gen_x = function(i, state_x, ...)
    if state_x == nil then
        return nil
    end
    return {i, state_x}, ...
end

local take_n_gen = function(param, state)
    local n, gen_x, param_x = param[1], param[2], param[3]
    local i, state_x = state[1], state[2]
    if i >= n then
        return nil
    end
    return take_n_gen_x(i + 1, gen_x(param_x, state_x))
end

local take_n = function(n, gen, param, state)
    assert(n >= 0, "invalid first argument to take_n")
    local gen_x, param_x, state_x = iter(gen, param, state)
    return take_n_gen, {n, gen, param}, {0, state}
end

local take_while_gen_x = function(fun, state_x, ...)
    if state_x == nil or not fun(...) then
        return nil
    end
    return state_x, ...
end

local take_while_gen = function(param, state_x)
    local fun, gen_x, param_x = param[1], param[2], param[3]
    return take_while_gen_x(fun, gen_x(param_x, state_x))
end

local take_while = function(fun, gen, param, state)
    assert(type(fun) == "function", "invalid first argument to take_while")
    local gen_x, param_x, state_x = iter(gen, param, state)
    return take_while_gen, {fun, gen, param}, state
end

local take = function(n_or_fun, gen, param, state)
    if type(n_or_fun) == "number" then
        return take_n(n_or_fun, gen, param, state)
    else 
        return take_while(n_or_fun, gen, param, state)
    end
end

local drop_n = function(n, gen, param, state)
    assert(n >= 0, "invalid first argument to drop_n")
    local gen_x, param_x, state_x = iter(gen, param, state)
    for i=1,n,1 do
        state_x = gen_x(param_x, state_x)
        if state_x == nil then
            return nil_gen, nil, nil
        end
    end
    return gen_x, param_x, state_x
end

local drop_while_x = function(fun, state_x, ...)
    if state_x == nil or not fun(...) then
        return state_x, false
    end
    return state_x, true, ...
end

local drop_while = function(fun, gen, param, state)
    assert(type(fun) == "function", "invalid first argument to drop_while")
    local gen_x, param_x, state_x = iter(gen, param, state)
    local cont, state_x_prev
    repeat
        state_x_prev = deepcopy(state_x)
        state_x, cont = drop_while_x(fun, gen_x(param_x, state_x))
    until not cont
    if state_x == nil then
        return nil_gen, nil, nil
    end
    return gen_x, param_x, state_x_prev
end

local drop = function(n_or_fun, gen, param, state)
    if type(n_or_fun) == "number" then
        return drop_n(n_or_fun, gen, param, state)
    else 
        return drop_while(n_or_fun, gen, param, state)
    end
end

local split = function(n_or_fun, gen, param, state)
    return {take(n_or_fun, gen, param, state)},
           {drop(n_or_fun, gen, param, state)}
end

--------------------------------------------------------------------------------
-- Indexing
--------------------------------------------------------------------------------

local index = function(x, gen, param, state) 
    local i = 1
    for _k, r in iter(gen, param, state) do
        if r == x then
            return i
        end
        i = i + 1
    end
    return nil
end

local indexes_gen = function(param, state)
    local x, gen_x, param_x = param[1], param[2], param[3]
    local i, state_x = state[1], state[2]
    local r
    while true do
        state_x, r = gen_x(param_x, state_x)
        if state_x == nil then
            return nil
        end
        i = i + 1
        if r == x then
            return {i, state_x}, i
        end
    end
end

local indexes = function(x, gen, param, state)
    local gen_x, param_x, state_x = iter(gen, param, state)
    return indexes_gen, {x, gen_x, param_x}, {0, state_x}
end

-- TODO: undocumented
local find = function(fun, gen, param, state)
    local gen_x, param_x, state_x = filter(fun, gen, param, state)
    return return_if_not_empty(gen_x(param_x, state_x))
end

--------------------------------------------------------------------------------
-- Filtering
--------------------------------------------------------------------------------

local filter1_gen = function(fun, gen_x, param_x, state_x, a)
    while true do
        if state_x == nil or fun(a) then break; end
        state_x, a = gen_x(param_x, state_x)
    end
    return state_x, a
end

-- call each other
local filterm_gen
local filterm_gen_shrink = function(fun, gen_x, param_x, state_x)
    return filterm_gen(fun, gen_x, param_x, gen_x(param_x, state_x))
end

filterm_gen = function(fun, gen_x, param_x, state_x, ...)
    if state_x == nil then
        return nil
    end
    if fun(...) then
        return state_x, ...
    end
    return filterm_gen_shrink(fun, gen_x, param_x, state_x)
end

local filter_detect = function(fun, gen_x, param_x, state_x, ...)
    if select('#', ...) < 2 then
        return filter1_gen(fun, gen_x, param_x, state_x, ...)
    else
        return filterm_gen(fun, gen_x, param_x, state_x, ...)
    end
end

local filter_gen = function(param, state_x)
    local fun, gen_x, param_x = param[1], param[2], param[3]
    return filter_detect(fun, gen_x, param_x, gen_x(param_x, state_x))
end

local filter = function(fun, gen, param, state)
    local gen_x, param_x, state_x = iter(gen, param, state)
    return filter_gen, {fun, gen_x, param_x}, state_x
end

local grep = function(fun_or_regexp, gen, param, state)
    local fun = fun_or_regexp
    if type(fun_or_regexp) == "string" then
        fun = function(x) return string.find(x, fun_or_regexp) ~= nil end
    end
    return filter(fun, gen, param, state)
end

local partition = function(fun, gen, param, state)
    local neg_fun = function(...)
        return not fun(...)
    end
    local gen_x, param_x, state_x = iter(gen, param, state)
    return {filter(fun, gen_x, param_x, state_x)},
           {filter(neg_fun, gen_x, param_x, state_x)}
end

--------------------------------------------------------------------------------
-- Reducing
--------------------------------------------------------------------------------

local foldl_call = function(fun, start, state, ...)
    if state == nil then
        return nil, start
    end
    return state, fun(start, ...)
end

local foldl = function(fun, start, gen, param, state)
    local gen_x, param_x, state_x = iter(gen, param, state)
    while true do
        state_x, start = foldl_call(fun, start, gen_x(param_x, state_x))
        if state_x == nil then
            break;
        end
    end
    return start
end

local length = function(gen, param, state)
    local gen, param, state = iter(gen, param, state)
    if gen == ipairs or gen == string_gen then
        return #param
    end
    local len = 0
    repeat
        state = gen(param, state)
        len = len + 1
    until state == nil
    return len - 1
end

local is_null = function(gen, param, state)
    local gen_x, param_x, state_x = iter(gen, param, state)
    return gen_x(param_x, deepcopy(state_x)) == nil
end

local is_prefix_of = function(iter_x, iter_y)
    local gen_x, param_x, state_x = iter_tab(iter_x)
    local gen_y, param_y, state_y = iter_tab(iter_y)

    local r_x, r_y
    for i=1,10,1 do
        state_x, r_x = gen_x(param_x, state_x)
        state_y, r_y = gen_y(param_y, state_y)
        if state_x == nil then
            return true
        end
        if state_y == nil or r_x ~= r_y then
            return false
        end
    end
end

local all = function(fun, gen, param, state)
    local gen_x, param_x, state_x = iter(gen, param, state)
    local r
    repeat
        state_x, r = call_if_not_empty(fun, gen_x(param_x, state_x))
    until state_x == nil or not r
    return state_x == nil
end

local any = function(fun, gen, param, state)
    local gen_x, param_x, state_x = iter(gen, param, state)
    local r
    repeat
        state_x, r = call_if_not_empty(fun, gen_x(param_x, state_x))
    until state_x == nil or r
    return not not r
end

local sum = function(gen, param, state)
    local gen, param, state = iter(gen, param, state)
    local s = 0
    local r = 0
    repeat
        s = s + r
        state, r = gen(param, state)
    until state == nil
    return s
end

local product = function(gen, param, state)
    local gen, param, state = iter(gen, param, state)
    local p = 1
    local r = 1
    repeat
        p = p * r
        state, r = gen(param, state)
    until state == nil
    return p
end

local min_cmp = function(m, n)
    if n < m then return n else return m end
end

local max_cmp = function(m, n)
    if n > m then return n else return m end
end

local min = function(gen, param, state)
    local gen, param, state = iter(gen, param, state)
    local state, m = gen(param, state)
    if state == nil then
        error("min: iterator is empty")
    end

    local cmp
    if type(m) == "number" then
        -- An optimization: use math.min for numbers
        cmp = math.min
    else
        cmp = min_cmp
    end

    for _, r in gen, param, state do
        m = cmp(m, r)
    end
    return m
end

local min_by = function(cmp, gen, param, state)
    local gen_x, param_x, state_x = iter(gen, param, state)
    local state_x, m = gen_x(param_x, state_x)
    if state_x == nil then
        error("min: iterator is empty")
    end

    for _, r in gen_x, param_x, state_x do
        m = cmp(m, r)
    end
    return m
end

local max = function(gen, param, state)
    local gen_x, param_x, state_x = iter(gen, param, state)
    local state_x, m = gen_x(param_x, state_x)
    if state_x == nil then
        error("max: iterator is empty")
    end

    local cmp
    if type(m) == "number" then
        -- An optimization: use math.max for numbers
        cmp = math.max
    else
        cmp = max_cmp
    end

    for _, r in gen_x, param_x, state_x do
        m = cmp(m, r)
    end
    return m
end

local max_by = function(cmp, gen, param, state)
    local gen_x, param_x, state_x = iter(gen, param, state)
    local state_x, m = gen_x(param_x, state_x)
    if state_x == nil then
        error("max: iterator is empty")
    end

    for _, r in gen_x, param_x, state_x do
        m = cmp(m, r)
    end
    return m
end

local totable = function(gen, param, state)
    local gen_x, param_x, state_x = iter(gen, param, state)
    local tab, key, val = {}
    while true do
        state_x, val = gen_x(param_x, state_x)
        if state_x == nil then
            break
        end
        table.insert(tab, val)
    end
    return tab
end

local tomap = function(gen, param, state)
    local gen_x, param_x, state_x = iter(gen, param, state)
    local tab, key, val = {}
    while true do
        state_x, key, val = gen_x(param_x, state_x)
        if state_x == nil then
            break
        end
        tab[key] = val
    end
    return tab
end

--------------------------------------------------------------------------------
-- Transformations
--------------------------------------------------------------------------------

local map_gen = function(param, state)
    local gen_x, param_x, fun = param[1], param[2], param[3]
    return call_if_not_empty(fun, gen_x(param_x, state))
end

local map = function(fun, gen, param, state)
    local gen_x, param_x, state_x = iter(gen, param, state)
    return map_gen, {gen_x, param_x, fun}, state_x
end

local enumerate_gen_call = function(state, i, state_x, ...)
    if state_x == nil then
        return nil
    end
    return {i + 1, state_x}, i, ...
end

local enumerate_gen = function(param, state)
    local gen_x, param_x = param[1], param[2]
    local i, state_x = state[1], state[2]
    return enumerate_gen_call(state, i, gen_x(param_x, state_x))
end

local enumerate = function(gen, param, state)
    local gen_x, param_x, state_x = iter(gen, param, state)
    return enumerate_gen, {gen_x, param_x}, {0, state_x}
end

local intersperse_call = function(i, state_x, ...)
    if state_x == nil then
        return nil
    end
    return {i + 1, state_x}, ...
end

local intersperse_gen = function(param, state)
    local x, gen_x, param_x = param[1], param[2], param[3]
    local i, state_x = state[1], state[2]
    if i % 2 == 1 then
        return {i + 1, state_x}, x
    else
        return intersperse_call(i, gen_x(param_x, state_x))
    end
end

-- TODO: interperse must not add x to the tail
local intersperse = function(x, gen, param, state)
    local gen_x, param_x, state_x = iter(gen, param, state)
    return intersperse_gen, {x, gen_x, param_x}, {0, state_x}
end

--------------------------------------------------------------------------------
-- Compositions
--------------------------------------------------------------------------------

local function zip_gen_r(param, state, state_new, ...)
    if #state_new == #param / 2 then
        return state_new, ...
    end

    local i = #state_new + 1
    local gen_x, param_x = param[2 * i - 1], param[2 * i]
    local state_x, r = gen_x(param_x, state[i])
    -- print('i', i, 'state_x', state_x, 'r', r)
    if state_x == nil then
        return nil
    end
    table.insert(state_new, state_x)
    return zip_gen_r(param, state, state_new, r, ...)
end

local zip_gen = function(param, state)
    return zip_gen_r(param, state, {})
end

local zip = function(...)
    local n = select('#', ...)
    if n == 0 then
        return nil_gen, nil, nil
    end
    local param = { [2 * n] = 0 }
    local state = { [n] = 0 }

    local i, gen_x, param_x, state_x
    for i=1,n,1 do
        local elem = select(n - i + 1, ...)
        gen_x, param_x, state_x = iter_tab(elem)
        param[2 * i - 1] = gen_x
        param[2 * i] = param_x
        state[i] = state_x
    end

    return zip_gen, param, state
end

local cycle_gen_call = function(param, state_x, ...)
    if state_x == nil then
        local gen_x, param_x, state_x0 = param[1], param[2], param[3]
        return gen_x(param_x, deepcopy(state_x0))
    end
    return state_x, ...
end

local cycle_gen = function(param, state_x)
    local gen_x, param_x, state_x0 = param[1], param[2], param[3]
    return cycle_gen_call(param, gen_x(param_x, state_x))
end

local cycle = function(gen, param, state)
    local gen_x, param_x, state_x = iter(gen, param, state)
    return cycle_gen, {gen_x, param_x, state_x}, deepcopy(state_x)
end

-- call each other
local chain_gen_r1
local chain_gen_r2 = function(param, state, state_x, ...)
    if state_x == nil then
        local i = state[1]
        i = i + 1
        if i > #param / 3 then
            return nil
        end
        local state_x = param[3 * i]
        return chain_gen_r1(param, {i, state_x})
    end
    return {state[1], state_x}, ...
end

chain_gen_r1 = function(param, state)
    local i, state_x = state[1], state[2]
    local gen_x, param_x = param[3 * i - 2], param[3 * i - 1]
    return chain_gen_r2(param, state, gen_x(param_x, state[2]))
end

local chain = function(...)
    local n = select('#', ...)
    if n == 0 then
        return nil_gen, nil, nil
    end

    local param = { [3 * n] = 0 }
    local i, gen_x, param_x, state_x
    for i=1,n,1 do
        local elem = select(i, ...)
        gen_x, param_x, state_x = iter_tab(elem)
        param[3 * i - 2] = gen_x
        param[3 * i - 1] = param_x
        param[3 * i] = state_x
    end

    return chain_gen_r1, param, {1, param[3]}
end

--------------------------------------------------------------------------------
-- Operators
--------------------------------------------------------------------------------

operator = {
    ----------------------------------------------------------------------------
    -- Comparison operators
    ----------------------------------------------------------------------------
    lt  = function(a, b) return a < b end,
    le  = function(a, b) return a <= b end,
    eq  = function(a, b) return a == b end,
    ne  = function(a, b) return a ~= b end,
    ge  = function(a, b) return a >= b end,
    gt  = function(a, b) return a > b end,

    ----------------------------------------------------------------------------
    -- Arithmetic operators
    ----------------------------------------------------------------------------
    add = function(a, b) return a + b end,
    div = function(a, b) return a / b end,
    floordiv = function(a, b) return math.floor(a/b) end,
    intdiv = function(a, b)
        local q = a / b
        if a >= 0 then return math.floor(q) else return math.ceil(q) end
    end,
    mod = function(a, b) return a % b end,
    mul = function(a, b) return a * b end,
    neq = function(a) return -a end,
    unm = function(a) return -a end, -- an alias
    pow = function(a, b) return a ^ b end,
    sub = function(a, b) return a - b end,
    truediv = function(a, b) return a / b end,

    ----------------------------------------------------------------------------
    -- String operators
    ----------------------------------------------------------------------------
    concat = function(a, b) return a..b end,
    len = function(a) return #a end,
    length = function(a) return #a end, -- an alias

    ----------------------------------------------------------------------------
    -- Logical operators
    ----------------------------------------------------------------------------
    land = function(a, b) return a and b end,
    lor = function(a, b) return a or b end,
    lnot = function(a) return not a end,
    truth = function(a) return not not a end,
}

--------------------------------------------------------------------------------
-- module definitions
--------------------------------------------------------------------------------

local exports = {
    ----------------------------------------------------------------------------
    -- Basic
    ----------------------------------------------------------------------------
    iter = iter,
    each = each,
    for_each = each, -- an alias
    foreach = each, -- an alias

    ----------------------------------------------------------------------------
    -- Generators
    ----------------------------------------------------------------------------
    range = range,
    duplicate = duplicate,
    xrepeat = duplicate, -- an alias
    replicate = duplicate, -- an alias
    tabulate = tabulate,
    ones = ones,
    zeros = zeros,
    rands = rands,

    ----------------------------------------------------------------------------
    -- Slicing
    ----------------------------------------------------------------------------
    nth = nth,
    head = head,
    car = head, -- an alias
    tail = tail,
    cdr = tail, -- an alias
    take_n = take_n,
    take_while = take_while,
    take = take,
    drop_n = drop_n,
    drop_while = drop_while,
    drop = drop,
    split = split,
    split_at = split, -- an alias
    span = split, -- an alias

    ----------------------------------------------------------------------------
    -- Indexing
    ----------------------------------------------------------------------------
    index = index,
    index_of = index, -- an alias
    elem_index = index, -- an alias
    indexes = indexes,
    indices = indexes, -- an alias
    elem_indexes = indexes, -- an alias
    elem_indices = indexes, -- an alias
    find = find,

    ----------------------------------------------------------------------------
    -- Filtering
    ----------------------------------------------------------------------------
    filter = filter,
    remove_if = filter, -- an alias
    grep = grep,
    partition = partition,

    ----------------------------------------------------------------------------
    -- Reducing
    ----------------------------------------------------------------------------
    foldl = foldl,
    reduce = foldl, -- an alias
    length = length,
    is_null = is_null,
    is_prefix_of = is_prefix_of,
    all = all,
    every = all, -- an alias
    any = any,
    some = any, -- an alias
    sum = sum,
    product = product,
    min = min,
    minimum = min, -- an alias
    min_by = min_by,
    minimum_by = min_by, -- an alias
    max = max,
    maximum = max, -- an alias
    max_by = max_by,
    maximum_by = max_by, -- an alias
    totable = totable,
    tomap = tomap,

    ----------------------------------------------------------------------------
    -- Transformations
    ----------------------------------------------------------------------------
    map = map,
    enumerate = enumerate,
    intersperse = intersperse,

    ----------------------------------------------------------------------------
    -- Compositions
    ----------------------------------------------------------------------------
    zip = zip,
    cycle = cycle,
    chain = chain,

    ----------------------------------------------------------------------------
    -- Operators
    ----------------------------------------------------------------------------
    operator = operator,
    op = operator -- an alias
}

-- a special syntax sugar to export all functions to the global table
setmetatable(exports, {
    __call = function(t)
        for k, v in pairs(t) do _G[k] = v end
    end,
})

return exports
