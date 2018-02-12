-- Combine tests

require './lib'
require './data'

setup()

local old_setup = setup
local old_teardown = teardown

local empty_function = function() end
setup = empty_function
teardown = empty_function

dofile('mt1.lua')
dofile('mt2.lua')
dofile('mt3.lua')
dofile('mt4.lua')

old_teardown()
