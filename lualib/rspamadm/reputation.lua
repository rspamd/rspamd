local argparse = require 'argparse'
local reputation = require 'reputation'

local parser = argparse()
        :name "reputation"
        :description "Manage reputation top lists"
        :help_description_margin(32)
        :command_target('command')
        :require_command(true)

local watch_lists = parser:command 'watch_lists'
                          :description 'Watch reputation top lists.'



local convert_rbl = parser:command 'convert_rbl'
                          :description 'Convert these lists to RBL'




local function watch_lists_handler(args)

end

local function convert_rbl_handler(args)

end


local command_handlers = {
    watch_lists = watch_lists_handler,
    convert_rbl = convert_rbl_handler,
}

local function handler(args)
    local cmd_opts = parser:parse(args)

    local f = command_handlers[cmd_opts.command]
    if not f then
        parser:error(string.format("command isn't implemented: %s",
                cmd_opts.command))
    end
    f(cmd_opts)
end


return {
    name = 'reputation',
    aliases = { 'reputation' },
    handler = handler,
    description = parser._description
}