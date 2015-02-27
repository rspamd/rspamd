local utils = require 'busted.utils'
local hasMoon, moonscript = pcall(require, 'moonscript')

return function()
  local loadHelper = function(helper, hpath, options, busted)
    local success, err = pcall(function()
      arg = options.arguments
      if helper:match('%.lua$') then
        dofile(utils.normpath(hpath))
      elseif hasMoon and helper:match('%.moon$') then
        moonscript.dofile(utils.normpath(hpath))
      else
        require(helper)
      end
    end)

    if not success then
      busted.publish({ 'error', 'helper' }, { descriptor = 'helper', name = helper }, nil, err, {})
    end
  end

  return loadHelper
end
