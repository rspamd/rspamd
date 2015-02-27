local json = require 'dkjson'

return function(options, busted)
  local handler = require 'busted.outputHandlers.base'(busted)

  handler.suiteEnd = function()
    print(json.encode({
      pendings = handler.pendings,
      successes = handler.successes,
      failures = handler.failures,
      errors = handler.errors,
      duration = handler.getDuration()
    }))

    return nil, true
  end

  busted.subscribe({ 'suite', 'end' }, handler.suiteEnd)

  return handler
end
