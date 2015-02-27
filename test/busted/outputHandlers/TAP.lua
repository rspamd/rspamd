local pretty = require 'pl.pretty'

return function(options, busted)
  local handler = require 'busted.outputHandlers.base'(busted)

  handler.suiteEnd = function()
    local total = handler.successesCount + handler.errorsCount + handler.failuresCount
    print('1..' .. total)

    local success = 'ok %u - %s'
    local failure = 'not ' .. success
    local counter = 0

    for i,t in pairs(handler.successes) do
      counter = counter + 1
      print(success:format(counter, t.name))
    end

    local showFailure = function(t)
      counter = counter + 1
      local message = t.message
      local trace = t.trace or {}

      if message == nil then
        message = 'Nil error'
      elseif type(message) ~= 'string' then
        message = pretty.write(message)
      end

      print(failure:format(counter, t.name))
      print('# ' .. t.element.trace.short_src .. ' @ ' .. t.element.trace.currentline)
      print('# Failure message: ' .. message:gsub('\n', '\n# '))
      if options.verbose and trace.traceback then
        print('# ' .. trace.traceback:gsub('^\n', '', 1):gsub('\n', '\n# '))
      end
    end

    for i,t in pairs(handler.errors) do
      showFailure(t)
    end
    for i,t in pairs(handler.failures) do
      showFailure(t)
    end

    return nil, true
  end

  busted.subscribe({ 'suite', 'end' }, handler.suiteEnd)

  return handler
end
