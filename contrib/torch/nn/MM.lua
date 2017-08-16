--[[ Module to perform matrix multiplication on two minibatch inputs,
     producing a minibatch.
]]

local MM, parent = torch.class('nn.MM', 'nn.Module')

--[[ The constructor takes two optional arguments, specifying whether or not transpose
     any of the input matrices before perfoming the multiplication.
]]
function MM:__init(transA, transB)
  parent.__init(self)

  self.transA = transA or false
  self.transB = transB or false

  self.gradInput = {torch.Tensor(), torch.Tensor()}
end

function MM:updateOutput(input)
  assert(#input == 2, 'input must be a pair of minibatch matrices')
  local a, b = table.unpack(input)
  assert(a:nDimension() == 2 or a:nDimension() == 3, 'input tensors must be 2D or 3D')

  if a:nDimension() == 2 then
    assert(b:nDimension() == 2, 'second input tensor must be 2D')

    if self.transA then a = a:t() end
    if self.transB then b = b:t() end
    assert(a:size(2) == b:size(1), 'matrix sizes do not match')

    self.output:resize(a:size(1), b:size(2))
    self.output:mm(a, b)
  else
    assert(b:nDimension() == 3, 'second input tensor must be 3D')
    assert(a:size(1) == b:size(1), 'inputs must contain the same number of minibatches')

    if self.transA then a = a:transpose(2, 3) end
    if self.transB then b = b:transpose(2, 3) end
    assert(a:size(3) == b:size(2), 'matrix sizes do not match')

    self.output:resize(a:size(1), a:size(2), b:size(3))
    self.output:bmm(a, b)
  end

  return self.output
end

function MM:updateGradInput(input, gradOutput)
  self.gradInput[1] = self.gradInput[1] or input[1].new()
  self.gradInput[2] = self.gradInput[2] or input[2].new()

  assert(#input == 2, 'input must be a pair of tensors')
  local a, b = table.unpack(input)
  self.gradInput[1]:resizeAs(a)
  self.gradInput[2]:resizeAs(b)

  assert(gradOutput:nDimension() == 2 or gradOutput:nDimension() == 3, 'arguments must be a 2D or 3D Tensor')

  local h_dim, w_dim, f
  if gradOutput:nDimension() == 2 then
    assert(a:nDimension() == 2, 'first input tensor must be 2D')
    assert(b:nDimension() == 2, 'second input tensor must be 2D')

    h_dim, w_dim = 1, 2
    f = "mm"
  else
    assert(a:nDimension() == 3, 'first input tensor must be 3D')
    assert(b:nDimension() == 3, 'second input tensor must be 3D')

    h_dim, w_dim = 2, 3
    f = "bmm"
  end

  if self.transA == self.transB then
    a = a:transpose(h_dim, w_dim)
    b = b:transpose(h_dim, w_dim)
  end

  if self.transA then
    self.gradInput[1][f](self.gradInput[1], b, gradOutput:transpose(h_dim, w_dim))
  else
    self.gradInput[1][f](self.gradInput[1], gradOutput, b)
  end

  if self.transB then
    self.gradInput[2][f](self.gradInput[2], gradOutput:transpose(h_dim, w_dim), a)
  else
    self.gradInput[2][f](self.gradInput[2], a, gradOutput)
  end

  return self.gradInput
end
