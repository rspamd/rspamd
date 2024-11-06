local argparse = require 'argparse'
local lua_redis = require 'lua_redis'
local rspamd_logger = require 'rspamd_logger'

local parser = argparse()
        :name "reputation"
        :description "Manage reputation top lists"
        :help_description_margin(32)
        :command_target('command')
        :require_command(true)

parser:option "-c --config"
      :description "Path to config file"
      :argname("<cfg>")
      :default(rspamd_paths["CONFDIR"] .. "/" .. "rspamd.conf")

local watch_lists = parser:command 'watch_lists'
                          :description 'Watch reputation top lists.'

watch_lists:option "-k --key"
           :description "Key to watch its top lists"
           :argname ("<key>")


local _ = parser:command 'convert_rbl'
                          :description 'Convert top lists to RBL'

local neg_top_name = 'RR_neg_top' -- Key for top negative scores
local pos_top_name = 'RR_pos_top' -- Key for top positive scores
local redis_params

local redis_attrs = {
    config = rspamd_config,
    ev_base = rspamadm_ev_base,
    session = rspamadm_session,
    log_obj = rspamd_config,
    resolver = rspamadm_dns_resolver,
}

local function watch_lists_handler(args)
    local pos_top = lua_redis.request(redis_params, redis_attrs,
            { 'ZRANGE', args['key'] .. pos_top_name, 0, -1, 'WITHSCORES' })
    print("Top list of positive scores: %s", pos_top)

    local neg_top = lua_redis.request(redis_params, redis_attrs,
            { 'ZRANGE', args['key'] .. neg_top_name, 0, -1, 'WITHSCORES' })
    for _, score in ipairs(neg_top) do
        score = 0 - score
    end
    print("Top list of negative scores: %s", neg_top)

end

local function convert_rbl_handler(args)
    local opts = rspamd_config:get_all_opt('rbl')
    if not (opts and type(opts) == 'table') then
        rspamd_logger.infox(rspamd_config, 'Module is unconfigured')
        return
    end
end


local command_handlers = {
    watch_lists = watch_lists_handler,
    convert_rbl = convert_rbl_handler,
}

local function handler(args)
    local cmd_opts = parser:parse(args)

    redis_params = lua_redis.parse_redis_server('redis')
    if not redis_params then
        rspamd_logger.errx('Redis is not configured, exiting')
        os.exit(1)
    end

    lua_redis.connect(redis_params, redis_attrs)

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