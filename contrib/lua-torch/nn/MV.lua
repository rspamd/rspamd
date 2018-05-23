--[[ Module to perform matrix vector multiplication on two minibatch inputs,
producing a minibatch.
]]

local MV, parent = torch.class('nn.MV', 'nn.Module')

-- Backward compatibility
local unpack = unpack or table.unpack

function MV:__init(trans)
  parent.__init(self)

  self.trans = trans or false
  assert(type(self.trans) == 'boolean', "argument must be a boolean, matrix transpose before multiplication")

  self.gradInput = {torch.Tensor(), torch.Tensor()}
end

function MV:updateOutput(input)
  assert(#input == 2, 'input must be a pair of minibatch matrices')
  local M, v = unpack(input)
  assert(M:nDimension() == 2 or M:nDimension() == 3, 'input matrix must be 2D or 3D')
  assert(v:nDimension() == 1 or v:nDimension() == 2, 'input vector must be 1D or 2D')

  if M:nDimension() == 2 then
    assert(v:nDimension() == 1, 'vector must be 1D')

    if self.trans then M = M:transpose(1,2) end
    assert(M:size(2) == v:size(1), 'matrix row count and vector length do not match')

    self.output:resize(M:size(1))
    self.output:mv(M, v)
  else
    assert(v:nDimension() == 2, 'vector must be 2D (batch dimension)')
    assert(M:size(1) == v:size(1), 'inputs must contain the same number of minibatches')

    if self.trans then M = M:transpose(2,3) end
    assert(M:size(3) == v:size(2), 'matrix row count and vector length do not match')

    self.output:resize(M:size(1), M:size(2), 1)
    self.output:bmm(M, v:view(v:size(1), v:size(2), 1)):resize(M:size(1), M:size(2))
  end

  return self.output
end

function MV:updateGradInput(input, gradOutput)
  assert(#input == 2, 'input must be a pair of tensors')
  local M, v = unpack(input)
  self.gradInput[1]:resizeAs(M)
  self.gradInput[2]:resizeAs(v)

  assert(gradOutput:nDimension() == 1 or gradOutput:nDimension() == 2, 'arguments must be a 1D or 2D Tensor')

  if gradOutput:nDimension() == 2 then
    assert(M:nDimension() == 3, 'matrix must must be 3D (batched)')
    assert(v:nDimension() == 2, 'vector must be 2D (batched)')
    local bdim = M:size(1)
    local odim = M:size(2)
    local idim = M:size(3)

    if self.trans then
      self.gradInput[1]:bmm(v:view(bdim, odim, 1), gradOutput:view(bdim, 1, idim))
      self.gradInput[2]:view(bdim, odim, 1):bmm(M, gradOutput:view(bdim, idim, 1))
    else
      self.gradInput[1]:bmm(gradOutput:view(bdim, odim, 1), v:view(bdim, 1, idim))
      self.gradInput[2]:view(bdim, idim, 1):bmm(M:transpose(2,3), gradOutput:view(bdim, odim, 1))
    end
  else
    assert(M:nDimension() == 2, 'matrix must be 2D')
    assert(v:nDimension() == 1, 'vector must be 1D')

    if self.trans then
      self.gradInput[1]:ger(v, gradOutput)
      self.gradInput[2] = M * gradOutput
    else
      self.gradInput[1]:ger(gradOutput, v)
      self.gradInput[2] = M:t() * gradOutput
    end
  end
  return self.gradInput
end
