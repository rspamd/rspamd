return function()
  local tablex = require 'pl.tablex'

  -- Function to load the .busted configuration file if available
  local loadBustedConfigurationFile = function(configFile, config, defaults)
    if type(configFile) ~= 'table' then
      return config, '.busted file does not return a table.'
    end

    local defaults = defaults or {}
    local run = config.run or defaults.run

    if run and run ~= '' then
      local runConfig = configFile[run]

      if type(runConfig) == 'table' then
        config = tablex.merge(runConfig, config, true)
      else
        return config, 'Task `' .. run .. '` not found, or not a table.'
      end
    end

    if type(configFile.default) == 'table' then
      config = tablex.merge(configFile.default, config, true)
    end

    config = tablex.merge(defaults, config, true)

    return config
  end

  return loadBustedConfigurationFile
end

