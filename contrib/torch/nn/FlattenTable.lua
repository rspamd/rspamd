local FlattenTable, parent = torch.class('nn.FlattenTable', 'nn.Module')

function FlattenTable:__init()
  parent.__init(self)

  self.output = {}
  self.input_map = {}
  self.gradInput = {}
end

-- Recursive function to flatten a table (output is a table)
local function flatten(output, input)
  local input_map  -- has the same structure as input, but stores the
                   -- indices to the corresponding output
  if type(input) == 'table' then
    input_map = {}
    -- forward DFS order
    for i = 1, #input do
      input_map[#input_map+1] = flatten(output, input[i])
    end
  else
    input_map = #output + 1
    output[input_map] = input  -- append the tensor
  end
  return input_map
end

-- Recursive function to check if we need to rebuild the output table
local function checkMapping(output, input, input_map)
  if input_map == nil or output == nil or input == nil then
    return false
  end
  if type(input) == 'table' then
    if type(input_map) ~= 'table' then
      return false
    end
    if #input ~= #input_map then
      return false
    end
    -- forward DFS order
    for i = 1, #input do
       local ok = checkMapping(output, input[i], input_map[i])
       if not ok then
          return false
       end
    end
    return true
  else
    if type(input_map) ~= 'number' then
      return false
    end
    return output[input_map] == input
  end
end

-- During BPROP we have to build a gradInput with the same shape as the
-- input.  This is a recursive function to build up a gradInput
local function inverseFlatten(gradOutput, input_map)
  if type(input_map) == 'table' then
    local gradInput = {}
    for i = 1, #input_map do
      gradInput[#gradInput + 1] = inverseFlatten(gradOutput, input_map[i])
    end
    return gradInput
  else
    return gradOutput[input_map]
  end
end

function FlattenTable:updateOutput(input)
  assert(type(input) == 'table', 'input must be a table')
  -- to avoid updating rebuilding the flattened table every updateOutput call
  -- we will do a DFS pass over the existing output table and the inputs to
  -- see if it needs to be rebuilt.
  if not checkMapping(self.output, input, self.input_map) then
    self.output = {}
    self.input_map = flatten(self.output, input)
  end
  return self.output
end

function FlattenTable:updateGradInput(input, gradOutput)
  assert(type(input) == 'table', 'input must be a table')
  assert(type(input) == 'table', 'gradOutput must be a table')
  -- If the input changes between the updateOutput and updateGradInput call,
  -- then we may have to rebuild the input_map!  However, let's assume that
  -- the input_map is valid and that forward has already been called.

  -- However, we should check that the gradInput is valid:
  if not checkMapping(gradOutput, self.gradInput, self.input_map) then
    self.gradInput = inverseFlatten(gradOutput, self.input_map)
  end

  return self.gradInput
end

function FlattenTable:type(type, tensorCache)
  -- This function just stores references so we don't need to do any type
  -- conversions.  Just force the tables to be empty.
  self:clearState()
end

function FlattenTable:clearState()
  self.input_map = {}
  return parent.clearState(self)
end
