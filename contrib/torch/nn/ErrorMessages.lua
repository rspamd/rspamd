
local mt = {
  __index = function(table, key)
    error("nn."..key.." is only supported for Float or Double Tensors.")
  end
}

local tensors = {
  torch.ByteTensor,
  torch.CharTensor,
  torch.ShortTensor,
  torch.IntTensor,
  torch.LongTensor,
}

for _, t in ipairs(tensors) do
  t.nn = {}
  setmetatable(t.nn, mt)
end
