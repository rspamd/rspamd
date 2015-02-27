-- Busted command-line runner

local path = require 'pl.path'
local term = require 'term'
local utils = require 'busted.utils'
local loaded = false

return function(options)
  if loaded then return else loaded = true end

  local opt = options or {}
  local isBatch = opt.batch
  local cli = require 'cliargs'
  local busted = require 'busted.core'()

  local configLoader = require 'busted.modules.configuration_loader'()
  local helperLoader = require 'busted.modules.helper_loader'()
  local outputHandlerLoader = require 'busted.modules.output_handler_loader'()

  local luacov = require 'busted.modules.luacov'()

  local osexit = require 'busted.compatibility'.osexit

  require 'busted'(busted)

  -- Default cli arg values
  local defaultOutput = term.isatty(io.stdout) and 'utfTerminal' or 'plainTerminal'
  local defaultLoaders = 'lua,moonscript'
  local defaultPattern = '_spec'
  local defaultSeed = 'os.time()'
  local lpathprefix = './src/?.lua;./src/?/?.lua;./src/?/init.lua'
  local cpathprefix = path.is_windows and './csrc/?.dll;./csrc/?/?.dll;' or './csrc/?.so;./csrc/?/?.so;'

  local level = 2
  local info = debug.getinfo(level, 'Sf')
  local source = info.source
  local fileName = source:sub(1,1) == '@' and source:sub(2) or source

  local cliArgsParsed = {}

  local function processOption(key, value, altkey, opt)
    if altkey then cliArgsParsed[altkey] = value end
    cliArgsParsed[key] = value
    return true
  end

  local function processNumber(key, value, altkey, opt)
    local number = tonumber(value)
    if not number then
      return nil, 'argument to ' .. opt:gsub('=.*', '') .. ' must be a number'
    end
    if altkey then cliArgsParsed[altkey] = number end
    cliArgsParsed[key] = number
    return true
  end

  local function processVersion()
    -- Return early if asked for the version
    print(busted.version)
    osexit(0, true)
  end

  -- Load up the command-line interface options
  cli:set_name(path.basename(fileName))
  cli:add_flag('--version', 'prints the program version and exits', processVersion)

  if isBatch then
    cli:optarg('ROOT', 'test script file/folder. Folders will be traversed for any file that matches the --pattern option.', 'spec', 1)

    cli:add_option('-p, --pattern=PATTERN', 'only run test files matching the Lua pattern', defaultPattern, processOption)
  end

  cli:add_option('-o, --output=LIBRARY', 'output library to load', defaultOutput, processOption)
  cli:add_option('-d, --cwd=cwd', 'path to current working directory', './', processOption)
  cli:add_option('-t, --tags=TAGS', 'only run tests with these #tags', nil, processOption)
  cli:add_option('--exclude-tags=TAGS', 'do not run tests with these #tags, takes precedence over --tags', nil, processOption)
  cli:add_option('--filter=PATTERN', 'only run test names matching the Lua pattern', nil, processOption)
  cli:add_option('--filter-out=PATTERN', 'do not run test names matching the Lua pattern, takes precedence over --filter', nil, processOption)
  cli:add_option('-m, --lpath=PATH', 'optional path to be prefixed to the Lua module search path', lpathprefix, processOption)
  cli:add_option('--cpath=PATH', 'optional path to be prefixed to the Lua C module search path', cpathprefix, processOption)
  cli:add_option('-r, --run=RUN', 'config to run from .busted file', nil, processOption)
  cli:add_option('--repeat=COUNT', 'run the tests repeatedly', '1', processNumber)
  cli:add_option('--seed=SEED', 'random seed value to use for shuffling test order', defaultSeed, processNumber)
  cli:add_option('--lang=LANG', 'language for error messages', 'en', processOption)
  cli:add_option('--loaders=NAME', 'test file loaders', defaultLoaders, processOption)
  cli:add_option('--helper=PATH', 'A helper script that is run before tests', nil, processOption)

  cli:add_option('-Xoutput OPTION', 'pass `OPTION` as an option to the output handler. If `OPTION` contains commas, it is split into multiple options at the commas.', nil, processOption)
  cli:add_option('-Xhelper OPTION', 'pass `OPTION` as an option to the helper script. If `OPTION` contains commas, it is split into multiple options at the commas.', nil, processOption)

  cli:add_flag('-c, --coverage', 'do code coverage analysis (requires `LuaCov` to be installed)', processOption)
  cli:add_flag('-v, --verbose', 'verbose output of errors', processOption)
  cli:add_flag('-s, --enable-sound', 'executes `say` command if available', processOption)
  cli:add_flag('-l, --list', 'list the names of all tests instead of running them', processOption)
  cli:add_flag('--no-keep-going', 'quit after first error or failure', processOption)
  cli:add_flag('--no-recursive', 'do not recurse into subdirectories', processOption)
  cli:add_flag('--shuffle', 'randomize file and test order, takes precedence over --sort (--shuffle-test and --shuffle-files)', processOption)
  cli:add_flag('--shuffle-files', 'randomize file execution order, takes precedence over --sort-files', processOption)
  cli:add_flag('--shuffle-tests', 'randomize test order within a file, takes precedence over --sort-tests', processOption)
  cli:add_flag('--sort', 'sort file and test order (--sort-tests and --sort-files)', processOption)
  cli:add_flag('--sort-files', 'sort file execution order', processOption)
  cli:add_flag('--sort-tests', 'sort test order within a file', processOption)
  cli:add_flag('--suppress-pending', 'suppress `pending` test output', processOption)
  cli:add_flag('--defer-print', 'defer print to when test suite is complete', processOption)

  -- Parse the cli arguments
  local cliArgs = cli:parse(arg)
  if not cliArgs then
    osexit(1, true)
  end

  -- Load current working directory
  local fpath = utils.normpath(cliArgs.cwd)

  -- Load busted config file if available
  local configFile = { }
  local bustedConfigFilePath = utils.normpath(path.join(fpath, '.busted'))
  local bustedConfigFile = pcall(function() configFile = loadfile(bustedConfigFilePath)() end)
  if bustedConfigFile then
    local config, err = configLoader(configFile, cliArgsParsed, cliArgs)
    if err then
      print('Error: ' .. err)
      osexit(1, true)
    else
      cliArgs = config
    end
  end

  local tags = {}
  local excludeTags = {}

  if cliArgs.tags and cliArgs.tags ~= '' then
    tags = utils.split(cliArgs.tags, ',')
  end

  if cliArgs['exclude-tags'] and cliArgs['exclude-tags'] ~= '' then
    excludeTags = utils.split(cliArgs['exclude-tags'], ',')
  end

  -- If coverage arg is passed in, load LuaCovsupport
  if cliArgs.coverage then
    luacov()
  end

  -- Add additional package paths based on lpath and cpath cliArgs
  if #cliArgs.lpath > 0 then
    lpathprefix = cliArgs.lpath
    lpathprefix = lpathprefix:gsub('^%.([/%\\])', fpath .. '%1')
    lpathprefix = lpathprefix:gsub(';%.([/%\\])', ';' .. fpath .. '%1')
    package.path = (lpathprefix .. ';' .. package.path):gsub(';;',';')
  end

  if #cliArgs.cpath > 0 then
    cpathprefix = cliArgs.cpath
    cpathprefix = cpathprefix:gsub('^%.([/%\\])', fpath .. '%1')
    cpathprefix = cpathprefix:gsub(';%.([/%\\])', ';' .. fpath .. '%1')
    package.cpath = (cpathprefix .. ';' .. package.cpath):gsub(';;',';')
  end

  local loaders = {}
  if #cliArgs.loaders > 0 then
    string.gsub(cliArgs.loaders, '([^,]+)', function(c) loaders[#loaders+1] = c end)
  end

  -- We report an error if the same tag appears in both `options.tags`
  -- and `options.excluded_tags` because it does not make sense for the
  -- user to tell Busted to include and exclude the same tests at the
  -- same time.
  for _, excluded in pairs(excludeTags) do
    for _, included in pairs(tags) do
      if excluded == included then
        print('Error: Cannot use --tags and --exclude-tags for the same tags')
        osexit(1, true)
      end
    end
  end

  -- watch for test errors
  local failures = 0
  local errors = 0
  local quitOnError = cliArgs['no-keep-going']

  busted.subscribe({ 'error', 'output' }, function(element, parent, message)
    print('Error: Cannot load output library: ' .. element.name .. '\n' .. message)
    return nil, true
  end)

  busted.subscribe({ 'error', 'helper' }, function(element, parent, message)
    print('Error: Cannot load helper script: ' .. element.name .. '\n' .. message)
    return nil, true
  end)

  busted.subscribe({ 'error' }, function(element, parent, message)
    errors = errors + 1
    busted.skipAll = quitOnError
    return nil, true
  end)

  busted.subscribe({ 'failure' }, function(element, parent, message)
    if element.descriptor == 'it' then
      failures = failures + 1
    else
      errors = errors + 1
    end
    busted.skipAll = quitOnError
    return nil, true
  end)

  -- Set up output handler to listen to events
  local outputHandlerOptions = {
    verbose = cliArgs.verbose,
    suppressPending = cliArgs['suppress-pending'],
    language = cliArgs.lang,
    deferPrint = cliArgs['defer-print'],
    arguments = utils.split(cliArgs.Xoutput or '', ',') or {}
  }

  local opath = utils.normpath(path.join(fpath, cliArgs.output))
  local outputHandler = outputHandlerLoader(cliArgs.output, opath, outputHandlerOptions, busted, defaultOutput)
  outputHandler:subscribe(outputHandlerOptions)

  if cliArgs['enable-sound'] then
    require 'busted.outputHandlers.sound'(outputHandlerOptions, busted)
  end

  -- Set up randomization options
  busted.sort = cliArgs['sort-tests'] or cliArgs.sort
  busted.randomize = cliArgs['shuffle-tests'] or cliArgs.shuffle
  busted.randomseed = tonumber(cliArgs.seed) or os.time()

  local getFullName = function(name)
    local parent = busted.context.get()
    local names = { name }

    while parent and (parent.name or parent.descriptor) and
          parent.descriptor ~= 'file' do
      table.insert(names, 1, parent.name or parent.descriptor)
      parent = busted.context.parent(parent)
    end

    return table.concat(names, ' ')
  end

  local hasTag = function(name, tag)
    local found = name:find('#' .. tag)
    return (found ~= nil)
  end

  local filterExcludeTags = function(name)
    for i, tag in pairs(excludeTags) do
      if hasTag(name, tag) then
        return nil, false
      end
    end
    return nil, true
  end

  local filterTags = function(name)
    local fullname = getFullName(name)
    for i, tag in pairs(tags) do
      if hasTag(fullname, tag) then
        return nil, true
      end
    end
    return nil, (#tags == 0)
  end

  local filterOutNames = function(name)
    local found = (getFullName(name):find(cliArgs['filter-out']) ~= nil)
    return nil, not found
  end

  local filterNames = function(name)
    local found = (getFullName(name):find(cliArgs.filter) ~= nil)
    return nil, found
  end

  local printNameOnly = function(name, fn, trace)
    local fullname = getFullName(name)
    if trace and trace.what == 'Lua' then
      print(trace.short_src .. ':' .. trace.currentline .. ': ' .. fullname)
    else
      print(fullname)
    end
    return nil, false
  end

  local ignoreAll = function()
    return nil, false
  end

  local skipOnError = function()
    return nil, (failures == 0 and errors == 0)
  end

  local applyFilter = function(descriptors, name, fn)
    if cliArgs[name] and cliArgs[name] ~= '' then
      for _, descriptor in ipairs(descriptors) do
        busted.subscribe({ 'register', descriptor }, fn, { priority = 1 })
      end
    end
  end

  if cliArgs.list then
    busted.subscribe({ 'suite', 'start' }, ignoreAll, { priority = 1 })
    busted.subscribe({ 'suite', 'end' }, ignoreAll, { priority = 1 })
    applyFilter({ 'setup', 'teardown', 'before_each', 'after_each' }, 'list', ignoreAll)
    applyFilter({ 'it', 'pending' }, 'list', printNameOnly)
  end

  applyFilter({ 'setup', 'teardown', 'before_each', 'after_each' }, 'no-keep-going', skipOnError)
  applyFilter({ 'file', 'describe', 'it', 'pending' }, 'no-keep-going', skipOnError)

  -- The following filters are applied in reverse order
  applyFilter({ 'it', 'pending' }            , 'filter'      , filterNames      )
  applyFilter({ 'describe', 'it', 'pending' }, 'filter-out'  , filterOutNames   )
  applyFilter({ 'it', 'pending' }            , 'tags'        , filterTags       )
  applyFilter({ 'describe', 'it', 'pending' }, 'exclude-tags', filterExcludeTags)

  -- Set up helper script
  if cliArgs.helper and cliArgs.helper ~= '' then
    local helperOptions = {
      verbose = cliArgs.verbose,
      language = cliArgs.lang,
      arguments = utils.split(cliArgs.Xhelper or '', ',') or {}
    }

    local hpath = utils.normpath(path.join(fpath, cliArgs.helper))
    helperLoader(cliArgs.helper, hpath, helperOptions, busted)
  end

  -- Set up test loader options
  local testFileLoaderOptions = {
    verbose = cliArgs.verbose,
    sort = cliArgs['sort-files'] or cliArgs.sort,
    shuffle = cliArgs['shuffle-files'] or cliArgs.shuffle,
    recursive = not cliArgs['no-recursive'],
    seed = busted.randomseed
  }

  -- Load test directory
  local rootFile = cliArgs.ROOT and utils.normpath(path.join(fpath, cliArgs.ROOT)) or fileName
  local pattern = cliArgs.pattern
  local testFileLoader = require 'busted.modules.test_file_loader'(busted, loaders, testFileLoaderOptions)
  local fileList = testFileLoader(rootFile, pattern)

  if not cliArgs.ROOT then
    local ctx = busted.context.get()
    local file = busted.context.children(ctx)[1]
    getmetatable(file.run).__call = info.func
  end

  busted.subscribe({'suite', 'reinitialize'}, function()
    local oldctx = busted.context.get()
    local children = busted.context.children(oldctx)

    busted.context.clear()
    local ctx = busted.context.get()
    for k, v in pairs(oldctx) do
      ctx[k] = v
    end

    for _, child in pairs(children) do
      for descriptor, _ in pairs(busted.executors) do
        child[descriptor] = nil
      end
      busted.context.attach(child)
    end

    busted.randomseed = tonumber(cliArgs.seed) or os.time()

    return nil, true
  end)

  local runs = tonumber(cliArgs['repeat']) or 1
  for i = 1, runs do
    if i > 1 then
      busted.publish({ 'suite', 'reinitialize' })
    end

    busted.publish({ 'suite', 'start' }, i, runs)
    busted.execute()
    busted.publish({ 'suite', 'end' }, i, runs)

    if quitOnError and (failures > 0 or errors > 0) then
      break
    end
  end

  busted.publish({ 'exit' })

  local exit = 0
  if failures > 0 or errors > 0 then
    exit = failures + errors
    if exit > 255 then
      exit = 255
    end
  end
  osexit(exit, true)
end
