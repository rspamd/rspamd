local url = require('rspamd_url')

local function task_inject_cb (task)
    local url_text = 'http://example.com?redir=https://another.com'
    local url_to_inject = url.create(task:get_mempool(), url_text)
    task:inject_url(url_to_inject)
    -- 3 urls: 1 from the scanned ics.eml (SUMMARY: http://test.com), 1 injected
    -- (example.com), and 1 extracted from the injected URL's query by the
    -- bounded query scan inject_url runs (another.com from ?redir=...).
    if #(task:get_urls()) == 3 then
        return true
    end
    return false
end

rspamd_config:register_symbol({
    name = 'TEST_INJECT_URL',
    score = 1.0,
    callback = task_inject_cb
})
