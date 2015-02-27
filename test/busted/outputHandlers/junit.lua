local xml = require 'pl.xml'
local socket = require("socket")
local string = require("string")

return function(options, busted)
  local handler = require 'busted.outputHandlers.base'(busted)
  local top = {
    start_time = socket.gettime(),
    xml_doc = xml.new('testsuites', {
      tests = 0,
      errors = 0,
      failures = 0,
      skip = 0,
    })
  }
  local stack = {}
  local testStartTime

  handler.suiteStart = function(count, total)
    local suite = {
      start_time = socket.gettime(),
      xml_doc = xml.new('testsuite', {
        name = 'Run ' .. count .. ' of ' .. total,
        tests = 0,
        errors = 0,
        failures = 0,
        skip = 0,
        timestamp = os.date('!%Y-%m-%dT%T'),
      })
    }
    top.xml_doc:add_direct_child(suite.xml_doc)
    table.insert(stack, top)
    top = suite

    return nil, true
  end

  local function elapsed(start_time)
    return string.format("%.2f", (socket.gettime() - start_time))
  end

  handler.suiteEnd = function(count, total)
    local suite = top
    suite.xml_doc.attr.time = elapsed(suite.start_time)

    top = table.remove(stack)
    top.xml_doc.attr.tests = top.xml_doc.attr.tests + suite.xml_doc.attr.tests
    top.xml_doc.attr.errors = top.xml_doc.attr.errors + suite.xml_doc.attr.errors
    top.xml_doc.attr.failures = top.xml_doc.attr.failures + suite.xml_doc.attr.failures
    top.xml_doc.attr.skip = top.xml_doc.attr.skip + suite.xml_doc.attr.skip

    return nil, true
  end

  handler.exit = function()
    top.xml_doc.attr.time = elapsed(top.start_time)
    print(xml.tostring(top.xml_doc, '', '\t', nil, false))

    return nil, true
  end

  local function testStatus(element, parent, message, status, trace)
    local testcase_node = xml.new('testcase', {
      classname = element.trace.short_src .. ':' .. element.trace.currentline,
      name = handler.getFullName(element),
      time = elapsed(testStartTime)
    })
    top.xml_doc:add_direct_child(testcase_node)

    if status ~= 'success' then
      testcase_node:addtag(status)
      if message then testcase_node:text(message) end
      if trace and trace.traceback then testcase_node:text(trace.traceback) end
      testcase_node:up()
    end
  end

  handler.testStart = function(element, parent)
    testStartTime = socket.gettime()

    return nil, true
  end

  handler.testEnd = function(element, parent, status)
    top.xml_doc.attr.tests = top.xml_doc.attr.tests + 1

    if status == 'success' then
      testStatus(element, parent, nil, 'success')
    elseif status == 'pending' then
      top.xml_doc.attr.skip = top.xml_doc.attr.skip + 1
      local formatted = handler.pendings[#handler.pendings]
      local trace = element.trace ~= formatted.trace and formatted.trace
      testStatus(element, parent, formatted.message, 'skipped', trace)
    end

    return nil, true
  end

  handler.failureTest = function(element, parent, message, trace)
    top.xml_doc.attr.failures = top.xml_doc.attr.failures + 1
    testStatus(element, parent, message, 'failure', trace)
    return nil, true
  end

  handler.errorTest = function(element, parent, message, trace)
    top.xml_doc.attr.errors = top.xml_doc.attr.errors + 1
    testStatus(element, parent, message, 'error', trace)
    return nil, true
  end

  handler.error = function(element, parent, message, trace)
    if element.descriptor ~= 'it' then
      top.xml_doc.attr.errors = top.xml_doc.attr.errors + 1
      top.xml_doc:addtag('error')
      top.xml_doc:text(message)
      if trace and trace.traceback then
        top.xml_doc:text(trace.traceback)
      end
      top.xml_doc:up()
    end

    return nil, true
  end

  busted.subscribe({ 'exit' }, handler.exit)
  busted.subscribe({ 'suite', 'start' }, handler.suiteStart)
  busted.subscribe({ 'suite', 'end' }, handler.suiteEnd)
  busted.subscribe({ 'test', 'start' }, handler.testStart, { predicate = handler.cancelOnPending })
  busted.subscribe({ 'test', 'end' }, handler.testEnd, { predicate = handler.cancelOnPending })
  busted.subscribe({ 'error', 'it' }, handler.errorTest)
  busted.subscribe({ 'failure', 'it' }, handler.failureTest)
  busted.subscribe({ 'error' }, handler.error)
  busted.subscribe({ 'failure' }, handler.error)

  return handler
end
