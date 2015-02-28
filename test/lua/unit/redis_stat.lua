
    
context("Redis statistics unit tests", function()
  local task = require("rspamd_task")
  local ffi = require("ffi")
  ffi.cdef[[
  struct rspamd_statfile_config {
    const char *symbol;
    const char *label;
    void *opts;
    int is_spam;
    const char *backend;
    void *data;
  };
  unsigned long rspamd_redis_expand_object(const char *pattern,
    struct rspamd_statfile_config *stcf,
    struct rspamd_task *task,
    char **target);
  struct rspamd_task * rspamd_task_new(struct rspamd_worker *worker);
  ]]

  test("Substitute redis values", function()
    local cases = {
      {"%s%l", "symbollabel"},
      {"%s%%", "symbol%"},
      {"%s%u", "symbol"},
      {"%s%W", "symbolW"}
    }
    local stcf = ffi.new("struct rspamd_statfile_config", 
      {symbol="symbol",label="label"})
    local t = ffi.C.rspamd_task_new(nil)
    for _,c in ipairs(cases) do
      local pbuf = ffi.new 'char *[1]'
      local sz = ffi.C.rspamd_redis_expand_object(c[1], stcf, t, pbuf)
      local s = ffi.string(pbuf[0])
      assert_equal(s, c[2])
    end
  end)
end)