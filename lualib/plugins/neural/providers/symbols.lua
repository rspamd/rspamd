-- Symbols provider: wraps legacy symbols+metatokens vectorization

local neural_common = require "plugins/neural"

neural_common.register_provider('symbols', {
  collect = function(task, ctx)
    local vec = neural_common.result_to_vector(task, ctx.profile)
    return vec, { name = 'symbols', type = 'symbols', dim = #vec, weight = ctx.weight or 1.0 }
  end,
  collect_async = function(task, ctx, cont)
    local vec = neural_common.result_to_vector(task, ctx.profile)
    cont(vec, { name = 'symbols', type = 'symbols', dim = #vec, weight = ctx.weight or 1.0 })
  end
})
