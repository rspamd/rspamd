-- Simple kann test (xor function vs 2 layer MLP)

context("Kann test", function()
  local kann = require "rspamd_kann"
  local k
  local inputs = {
    {0, 0},
    {0, 1},
    {1, 0},
    {1, 1}
  }

  local outputs = {
    {0},
    {1},
    {1},
    {0}
  }

  local t = kann.layer.input(2)
  t = kann.transform.relu(t)
  t = kann.transform.tanh(kann.layer.dense(t, 2));
  t = kann.layer.cost(t, 1, kann.cost.mse)
  k = kann.new.kann(t)

  local iters = 500
  local niter = k:train1(inputs, outputs, {
    lr = 0.01,
    max_epoch = iters,
    mini_size = 80,
  })

  local ser = k:save()
  k = kann.load(ser)

  for i,inp in ipairs(inputs) do
    test(string.format("Check XOR MLP %s ^ %s == %s", inp[1], inp[2], outputs[i][1]),
        function()
          local res = math.floor(k:apply1(inp)[1] + 0.5)
          assert_equal(outputs[i][1], res,
              tostring(outputs[i][1]) .. " but test returned " .. tostring(res))
        end)
  end

  -- Round-trip through a file using the documented single-table form
  -- (rspamd_kann.load is a module function, so the options table is arg 1)
  test("Save and load a model via {filename = ...}", function()
    local fname = os.tmpname()
    assert_true(k:save({filename = fname}))
    local loaded = kann.load({filename = fname})
    os.remove(fname)
    assert_not_nil(loaded, "load({filename = ...}) returned nil")

    for i,inp in ipairs(inputs) do
      local res = math.floor(loaded:apply1(inp)[1] + 0.5)
      assert_equal(outputs[i][1], res,
          tostring(outputs[i][1]) .. " but test returned " .. tostring(res))
    end
  end)


end)