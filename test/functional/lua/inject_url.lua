local rspamd_url = require('rspamd_url')
local lua_util = require('lua_util')

local N = 'ibject_url'

local function task_inject_cb (task)
    local url_text = 'http://example.com?redir=http://another.com'
    lua_util.debugm(N, task, 'URL: %s', url_text)
    lua_util.debugm(N, task, 'TYPE: %s', type(url_text))
    local url = rspamd_url:create(url_text, task:get_mempool())
    task:inject_url(url)
    return true
end

rspamd_config:register_symbol({
    name = 'TEST_INJECT_URL',
    score = 1.0,
    callback = task_inject_cb
})
