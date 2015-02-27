return function(busted)
  local handler = {
    successes = {},
    successesCount = 0,
    pendings = {},
    pendingsCount = 0,
    failures = {},
    failuresCount = 0,
    errors = {},
    errorsCount = 0,
    inProgress = {}
  }

  handler.cancelOnPending = function(element, parent, status)
    return not ((element.descriptor == 'pending' or status == 'pending') and handler.options.suppressPending)
  end

  handler.subscribe = function(handler, options)
    require('busted.languages.en')
    handler.options = options

    if options.language ~= 'en' then
      require('busted.languages.' .. options.language)
    end

    busted.subscribe({ 'suite', 'reinitialize' }, handler.baseSuiteRepeat, { priority = 1 })
    busted.subscribe({ 'suite', 'start' }, handler.baseSuiteStart, { priority = 1 })
    busted.subscribe({ 'suite', 'end' }, handler.baseSuiteEnd, { priority = 1 })
    busted.subscribe({ 'test', 'start' }, handler.baseTestStart, { priority = 1, predicate = handler.cancelOnPending })
    busted.subscribe({ 'test', 'end' }, handler.baseTestEnd, { priority = 1, predicate = handler.cancelOnPending })
    busted.subscribe({ 'pending' }, handler.basePending, { priority = 1, predicate = handler.cancelOnPending })
    busted.subscribe({ 'failure', 'it' }, handler.baseTestFailure, { priority = 1 })
    busted.subscribe({ 'error', 'it' }, handler.baseTestError, { priority = 1 })
    busted.subscribe({ 'failure' }, handler.baseError, { priority = 1 })
    busted.subscribe({ 'error' }, handler.baseError, { priority = 1 })
  end

  handler.getFullName = function(context)
    local parent = busted.context.parent(context)
    local names = { (context.name or context.descriptor) }

    while parent and (parent.name or parent.descriptor) and
          parent.descriptor ~= 'file' do

      table.insert(names, 1, parent.name or parent.descriptor)
      parent = busted.context.parent(parent)
    end

    return table.concat(names, ' ')
  end

  handler.format = function(element, parent, message, debug, isError)
    local formatted = {
      trace = debug or element.trace,
      element = element,
      name = handler.getFullName(element),
      message = message,
      isError = isError
    }
    formatted.element.trace = element.trace or debug

    return formatted
  end

  handler.getDuration = function()
    if not handler.endTime or not handler.startTime then
      return 0
    end

    return handler.endTime - handler.startTime
  end

  handler.baseSuiteStart = function()
    handler.startTime = os.clock()
    return nil, true
  end

  handler.baseSuiteRepeat = function()
    handler.successes = {}
    handler.successesCount = 0
    handler.pendings = {}
    handler.pendingsCount = 0
    handler.failures = {}
    handler.failuresCount = 0
    handler.errors = {}
    handler.errorsCount = 0
    handler.inProgress = {}

    return nil, true
  end

  handler.baseSuiteEnd = function()
    handler.endTime = os.clock()
    return nil, true
  end

  handler.baseTestStart = function(element, parent)
    handler.inProgress[tostring(element)] = {}
    return nil, true
  end

  handler.baseTestEnd = function(element, parent, status, debug)
    local isError
    local insertTable

    if status == 'success' then
      insertTable = handler.successes
      handler.successesCount = handler.successesCount + 1
    elseif status == 'pending' then
      insertTable = handler.pendings
      handler.pendingsCount = handler.pendingsCount + 1
    elseif status == 'failure' then
      insertTable = handler.failures
      -- failure count already incremented in error handler
    elseif status == 'error' then
      -- error count already incremented in error handler
      insertTable = handler.errors
      isError = true
    end

    local formatted = handler.format(element, parent, element.message, debug, isError)

    local id = tostring(element)
    if handler.inProgress[id] then
      for k, v in pairs(handler.inProgress[id]) do
        formatted[k] = v
      end

      handler.inProgress[id] = nil
    end

    table.insert(insertTable, formatted)

    return nil, true
  end

  local function saveInProgress(element, message, debug)
    local id = tostring(element)
    handler.inProgress[id].message = message
    handler.inProgress[id].trace = debug
  end

  local function saveError(element, parent, message, debug)
    if parent.randomseed then
      message = 'Random Seed: ' .. parent.randomseed .. '\n' .. message
    end
    saveInProgress(element, message, debug)
  end

  handler.basePending = function(element, parent, message, debug)
    saveInProgress(element, message, debug)
    return nil, true
  end

  handler.baseTestFailure = function(element, parent, message, debug)
    handler.failuresCount = handler.failuresCount + 1
    saveError(element, parent, message, debug)
    return nil, true
  end

  handler.baseTestError = function(element, parent, message, debug)
    handler.errorsCount = handler.errorsCount + 1
    saveError(element, parent, message, debug)
    return nil, true
  end

  handler.baseError = function(element, parent, message, debug)
    if element.descriptor ~= 'it' then
      handler.errorsCount = handler.errorsCount + 1
      table.insert(handler.errors, handler.format(element, parent, message, debug, true))
    end

    return nil, true
  end

  return handler
end
