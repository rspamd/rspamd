--[[ Logger: a simple class to log symbols during training,
        and automate plot generation

Example:
    logger = optim.Logger('somefile.log')    -- file to save stuff

    for i = 1,N do                           -- log some symbols during
        train_error = ...                     -- training/testing
        test_error = ...
        logger:add{['training error'] = train_error,
            ['test error'] = test_error}
    end

    logger:style{['training error'] = '-',   -- define styles for plots
                 ['test error'] = '-'}
    logger:plot()                            -- and plot

---- OR ---

    logger = optim.Logger('somefile.log')    -- file to save stuff
    logger:setNames{'training error', 'test error'}

    for i = 1,N do                           -- log some symbols during
       train_error = ...                     -- training/testing
       test_error = ...
       logger:add{train_error, test_error}
    end

    logger:style{'-', '-'}                   -- define styles for plots
    logger:plot()                            -- and plot

-----------

    logger:setlogscale(true)                 -- enable logscale on Y-axis
    logger:plot()                            -- and plot
]]
require 'xlua'
local Logger = torch.class('optim.Logger')

function Logger:__init(filename, timestamp)
   if filename then
      self.name = filename
      os.execute('mkdir ' .. (sys.uname() ~= 'windows' and '-p ' or '') .. ' "' .. paths.dirname(filename) .. '"')
      if timestamp then
         -- append timestamp to create unique log file
         filename = filename .. '-'..os.date("%Y_%m_%d_%X")
      end
      self.file = io.open(filename,'w')
      self.epsfile = self.name .. '.eps'
   else
      self.file = io.stdout
      self.name = 'stdout'
      print('<Logger> warning: no path provided, logging to std out')
   end
   self.empty = true
   self.symbols = {}
   self.styles = {}
   self.names = {}
   self.idx = {}
   self.figure = nil
   self.showPlot = true
   self.plotRawCmd = nil
   self.defaultStyle = '+'
   self.logscale = false
end

function Logger:setNames(names)
   self.names = names
   self.empty = false
   self.nsymbols = #names
   for k,key in pairs(names) do
      self.file:write(key .. '\t')
      self.symbols[k] = {}
      self.styles[k] = {self.defaultStyle}
      self.idx[key] = k
   end
   self.file:write('\n')
   self.file:flush()
   return self
end

function Logger:add(symbols)
   -- (1) first time ? print symbols' names on first row
   if self.empty then
      self.empty = false
      self.nsymbols = #symbols
      for k,val in pairs(symbols) do
         self.file:write(k .. '\t')
         self.symbols[k] = {}
         self.styles[k] = {self.defaultStyle}
         self.names[k] = k
      end
      self.idx = self.names
      self.file:write('\n')
   end
   -- (2) print all symbols on one row
   for k,val in pairs(symbols) do
      if type(val) == 'number' then
         self.file:write(string.format('%11.4e',val) .. '\t')
      elseif type(val) == 'string' then
         self.file:write(val .. '\t')
      else
         xlua.error('can only log numbers and strings', 'Logger')
      end
   end
   self.file:write('\n')
   self.file:flush()
   -- (3) save symbols in internal table
   for k,val in pairs(symbols) do
      table.insert(self.symbols[k], val)
   end
end

function Logger:style(symbols)
   for name,style in pairs(symbols) do
      if type(style) == 'string' then
         self.styles[name] = {style}
      elseif type(style) == 'table' then
         self.styles[name] = style
      else
         xlua.error('style should be a string or a table of strings','Logger')
      end
   end
   return self
end

function Logger:setlogscale(state)
   self.logscale = state
end

function Logger:display(state)
   self.showPlot = state
end

function Logger:plot(...)
   if not xlua.require('gnuplot') then
      if not self.warned then
         print('<Logger> warning: cannot plot with this version of Torch')
         self.warned = true
      end
      return
   end
   local plotit = false
   local plots = {}
   local plotsymbol =
      function(name,list)
         if #list > 1 then
            local nelts = #list
            local plot_y = torch.Tensor(nelts)
            for i = 1,nelts do
               plot_y[i] = list[i]
            end
            for _,style in ipairs(self.styles[name]) do
               table.insert(plots, {self.names[name], plot_y, style})
            end
            plotit = true
         end
      end
   local args = {...}
   if not args[1] then -- plot all symbols
      for name,list in pairs(self.symbols) do
         plotsymbol(name,list)
      end
   else -- plot given symbols
      for _,name in ipairs(args) do
         plotsymbol(self.idx[name], self.symbols[self.idx[name]])
      end
   end
   if plotit then
      if self.showPlot then
         self.figure = gnuplot.figure(self.figure)
         if self.logscale then gnuplot.logscale('on') end
         gnuplot.plot(plots)
         if self.plotRawCmd then gnuplot.raw(self.plotRawCmd) end
         gnuplot.grid('on')
         gnuplot.title('<Logger::' .. self.name .. '>')
      end
      if self.epsfile then
         os.execute('rm -f "' .. self.epsfile .. '"')
         local epsfig = gnuplot.epsfigure(self.epsfile)
         if self.logscale then gnuplot.logscale('on') end
         gnuplot.plot(plots)
         if self.plotRawCmd then gnuplot.raw(self.plotRawCmd) end
         gnuplot.grid('on')
         gnuplot.title('<Logger::' .. self.name .. '>')
         gnuplot.plotflush()
         gnuplot.close(epsfig)
      end
   end
end
