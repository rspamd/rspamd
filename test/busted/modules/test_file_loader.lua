local s = require 'say'

return function(busted, loaders, options)
  local path = require 'pl.path'
  local dir = require 'pl.dir'
  local tablex = require 'pl.tablex'
  local shuffle = require 'busted.utils'.shuffle
  local fileLoaders = {}

  for _, v in pairs(loaders) do
    local loader = require('busted.modules.files.'..v)
    fileLoaders[#fileLoaders+1] = loader
  end

  local getTestFiles = function(rootFile, pattern)
    local fileList

    if path.isfile(rootFile) then
      fileList = { rootFile }
    elseif path.isdir(rootFile) then
      local getfiles = options.recursive and dir.getallfiles or dir.getfiles
      fileList = getfiles(rootFile)

      fileList = tablex.filter(fileList, function(filename)
        return path.basename(filename):find(pattern)
      end)

      fileList = tablex.filter(fileList, function(filename)
        if path.is_windows then
          return not filename:find('%\\%.%w+.%w+')
        else
          return not filename:find('/%.%w+.%w+')
        end
      end)
    else
      fileList = {}
    end

    return fileList
  end

  -- runs a testfile, loading its tests
  local loadTestFile = function(busted, filename)
    for _, v in pairs(fileLoaders) do
      if v.match(busted, filename) then
        return v.load(busted, filename)
      end
    end
  end

  local loadTestFiles = function(rootFile, pattern, loaders)
    local fileList = getTestFiles(rootFile, pattern)

    if options.shuffle then
      shuffle(fileList, options.seed)
    elseif options.sort then
      table.sort(fileList)
    end

    for i, fileName in ipairs(fileList) do
      local testFile, getTrace, rewriteMessage = loadTestFile(busted, fileName, loaders)

      if testFile then
        local file = setmetatable({
          getTrace = getTrace,
          rewriteMessage = rewriteMessage
        }, {
          __call = testFile
        })

        busted.executors.file(fileName, file)
      end
    end

    if #fileList == 0 then
      busted.publish({ 'error' }, {}, nil, s('output.no_test_files_match'):format(pattern), {})
    end

    return fileList
  end

  return loadTestFiles, loadTestFile, getTestFiles
end

