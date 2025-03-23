local argparse = require "argparse"
local rspamd_http = require "rspamd_http"
local rspamd_logger = require "rspamd_logger"

local parser = argparse()
    :name 'rspamadm ready'
    :description 'Check whether Rspamd is ready'
    :help_description_margin(30)
    :command_target('command')
    :require_command(true)

parser:option '-t --timeout'
      :description 'Maximum wait time before reporting an error'
      :argname('timeout')
      :default(5)

parser:option '-i --interval'
      :description 'Interval between two checks'
      :argname('interval')
      :default(1)

parser:option '-u --url'
      :description 'URL to check'
      :argname('url')
      :default("http://localhost:11334/ready")

parser:flag '--ssl-verify'
      :description 'Disable SSL verification'
      :argname('ssl_verify')
      :default(false)

parser:flag '-v --verbose'
      :description 'Give verbose output'
      :argname('verbose')
      :default(false)

local function log_and_print(level, verbose,fmt,...)
    rspamd_logger[level](fmt, ...)
    if verbose and level ~="errx" then
        print(string.format(fmt, ...))
    end
end

local stop_polling = false

local function try_again(url, ssl_verify, verbose)
    rspamd_http.request({
        method = 'GET',
        ev_base = rspamadm_ev_base,
        resolver = rspamadm_dns_resolver,
        session = rspamadm_session,
        config = rspamd_config,
        url = url,
        no_ssl_verify = not ssl_verify,
        callback = function(err, code, body, headers)
            if err then
                log_and_print("warnx", verbose,"HTTP request failed: %s", err)
                stop_polling = false
            else
                if(code == 200) then
                    if body then
                        log_and_print("infox",verbose,"Rspamd is ready!")
                        stop_polling = true
                    else
                        log_and_print("warnx",verbose,"No response recieved!")
                        stop_polling = false
                    end
                else
                    log_and_print("warnx",verbose, "Response from controller: %s",body)
                    stop_polling = false
                end
            end
        end
    })
end

local function check_ready_interval(interval, timeout, url, ssl_verify,verbose)
    local start_time = os.time()

    rspamd_config:add_periodic(rspamadm_ev_base, interval, function(cfg, ev_base)
        local elapsed = os.time() - start_time
        if elapsed >= timeout then
            log_and_print("infox",verbose,"Rspamd did not respond within %s seconds!", timeout)
            os.exit(1)
        elseif stop_polling then
            os.exit(0)
        end

        try_again(url, ssl_verify,verbose)

        return true
    end)
end

local function handler(args)
    local cmd_opts = parser:parse(args)
    local timeout = tonumber(cmd_opts.timeout)
    local interval = tonumber(cmd_opts.interval)
    local url = cmd_opts.url
    local ssl_verify = cmd_opts.ssl_verify
    local verbose = cmd_opts.verbose

    check_ready_interval(interval, timeout, url, ssl_verify,verbose)
    rspamadm_ev_base:loop()
end

return {
    handler = handler,
    description = parser._description,
    name = 'ready'
}