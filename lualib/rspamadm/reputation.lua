local argparse = require 'argparse'
local lua_util = require 'lua_util'
local lua_redis = require 'lua_redis'
local rspamd_task = require 'rspamd_task'

local parser = argparse()
        :name "reputation"
        :description "Manage reputation top lists"
        :help_description_margin(32)
        :command_target('command')
        :require_command(true)

local watch_lists = parser:command 'watch_lists'
                          :description 'Watch reputation top lists.'



local convert_rbl = parser:command 'convert_rbl'
                          :description 'Convert top lists to RBL'

local neg_top_name = 'neg_top' -- Key for top negative scores
local pos_top_name = 'pos_top' -- Key for top positive scores
local redis_params
local reputation_settings
local redis_attrs = {
    config = rspamd_config,
    ev_base = rspamadm_ev_base,
    session = rspamadm_session,
    log_obj = rspamd_config,
    resolver = rspamadm_dns_resolver,
}

local function watch_lists_handler(args)
    local pos_top = lua_redis.request(redis_params, redis_attrs,
            { 'ZRANGE', pos_top_name, 0, -1, 'WITSCORES' })
    print("Top list of positive scores: %s", pos_top)

    local neg_top = lua_redis.request(redis_params, redis_attrs,
            { 'ZRANGE', neg_top_name, 0, -1, 'WITSCORES' })
    print("Top list of negative scores: %s", neg_top)

end

local function convert_rbl_handler(args)

end


local command_handlers = {
    watch_lists = watch_lists_handler,
    convert_rbl = convert_rbl_handler,
}

local function handler(args)
    reputation_settings = rspamd_config:get_all_opt('reputation')
    redis_params = lua_redis.parse_redis_server('reputation')

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