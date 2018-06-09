-- nn.DFD: Decision Forest Discretizer
-- Takes a dense input and outputs a sparse output.
-- Each node in the forest is its own feature.
-- When a node is traversed, its commensurate feature takes on a value of 1.
-- For all non-traversed nodes, the feature is 0.
local DFD, parent = torch.class("nn.DFD", "nn.Module")

-- TODO: add :type, as the default will convert the long tensors
function DFD:__init(df, onlyLastNode)
   parent.__init(self)
   if torch.type(df) == 'table' then
      self:reconstructFromInfo(df)
   else
      assert(torch.type(df) == 'dt.DecisionForest')

      self.rootIds = torch.LongTensor()
      -- nodeId of left and right child nodes
      self.leftChild = torch.LongTensor()
      self.rightChild = torch.LongTensor()
      -- index and value of the feature that splits this node
      self.splitFeatureId = torch.LongTensor()
      self.splitFeatureValue = torch.Tensor()
      -- initialize state given df
      self:convertForest2Tensors(df)
      self:clearState()
   end
   self.onlyLastNode = onlyLastNode
   self.nTrees = self.rootIds:size(1)
end

-- converts a DecisionForest to efficient tensor representation
function DFD:convertForest2Tensors(df)
   self.rootIds:resize(#df.trees)

   -- nodeId will map to featureId
   local nodeId = 0
   -- sets nodeIds of all subnodes
   -- and measures the maximum depth over all trees
   local function recursiveTree(node, depth)
      depth = (depth or 0) + 1
      local rdepth = depth
      nodeId = nodeId + 1
      node._nodeId = nodeId

      if node.leftChild then
         rdepth = math.max(rdepth, recursiveTree(node.leftChild, depth))
      end
      if node.rightChild then
         rdepth = math.max(rdepth, recursiveTree(node.rightChild, depth))
      end
      return rdepth
   end

   -- sum over trees of max depth
   self.depth = 0
   for i,tree in ipairs(df.trees) do
      assert(torch.isTypeOf(tree.root, 'dt.CartNode'))
      self.depth = self.depth + recursiveTree(tree.root)
   end
   -- remove roots from depth
   self.depth = self.depth - self.rootIds:size(1)

   -- total number of nodes in all trees
   self.nNode = nodeId

   -- nodeId of left and right child nodes
   self.leftChild:resize(self.nNode):fill(-1)
   self.rightChild:resize(self.nNode):fill(-1)
   -- index and value of the feature that splits this node
   self.splitFeatureId:resize(self.nNode):fill(-1)
   self.splitFeatureValue:resize(self.nNode):fill(-1)

   -- aggregates CartNode attributes to an efficient tensor representation
   local function recursiveTree2(node)
      local nodeId = assert(node._nodeId)
      assert(self.splitFeatureId[nodeId] == -1)

      if node.leftChild then
         self.leftChild[nodeId] = assert(node.leftChild._nodeId)
         recursiveTree2(node.leftChild)
      else
      	 self.leftChild[nodeId] = 0
      end

      if node.rightChild then
         self.rightChild[nodeId] = assert(node.rightChild._nodeId)
         recursiveTree2(node.rightChild)
      else
      	 self.rightChild[nodeId] = 0
      end

      -- each node splits the dataset on a feature id-value pair
      self.splitFeatureId[nodeId] = assert(node.splitFeatureId)
      self.splitFeatureValue[nodeId] = assert(node.splitFeatureValue)
   end

   for i,tree in ipairs(df.trees) do
      self.rootIds[i] = assert(tree.root._nodeId)
      recursiveTree2(tree.root)
   end

   assert(self.leftChild:min() >= 0)
   assert(self.rightChild:min() >= 0)
end

-- input is a batchsize x inputsize tensor
function DFD:updateOutput(input)
   assert(torch.isTensor(input))
   assert(input:dim() == 2)
   input = input:contiguous()

   local batchsize, inputsize = input:size(1), input:size(2)
   local size = self.onlyLastNode and self.nTree or self.depth

   -- each sample's output keys is resized to maxdepth, which is the maximum size that it can take on
   self.outputkeys = self.outputkeys or torch.LongTensor()
   self.outputkeys:resize(batchsize, size)
   -- values are 1
   self.outputvalues = self.outputvalues or input.new()
   self.outputvalues:resize(batchsize, size):fill(1)

   self.output = input.nn.DFD_computeOutput(self.outputkeys, self.outputvalues, self.rootIds, self.leftChild, self.rightChild, self.splitFeatureId, self.splitFeatureValue, input, self.onlyLastNode)
   return self.output
end

function DFD:type(type, tensorCache)
   if type then
      local info = self:getReconstructionInfo()
      for k, v in pairs(info) do
         if torch.type(v) ~= 'torch.LongTensor' then
            info[k] = nil
         end
      end
      parent.type(self, type, tensorCache)
      self:reconstructFromInfo(info)
      return self
   else
      return parent.type(self)
   end
end

function DFD:updateGradInput()
   error"Not Implemented"
end

function DFD:clearState()
   self.output = {{},{}}
   self.taskbuffer = {}
   self.outputkeys = nil
   self.outputvalues = nil
   self._range = nil
   self._indices = nil
   self._mask = nil
end

function DFD:reconstructFromInfo(DFDinfo)
   for k,v in pairs(DFDinfo) do
      self[k] = v
   end
   assert(self.leftChild:nDimension() == 1)
   assert(self.rightChild:nDimension() == 1)
   assert(self.leftChild:size(1) == self.nNode)
   assert(self.rightChild:size(1) == self.nNode)
   assert(self.leftChild:min() >= 0)
   assert(self.rightChild:min() >= 0)
   assert(self.splitFeatureId:nDimension() == 1)
   assert(self.splitFeatureValue:nDimension() == 1)
   assert(self.splitFeatureId:size(1) == self.splitFeatureValue:size(1))
end

function DFD:getReconstructionInfo()
   local DFDinfo = {
      nNode = self.nNode,
      rootIds = self.rootIds,
      leftChild = self.leftChild,
      rightChild = self.rightChild,
      splitFeatureId = self.splitFeatureId,
      splitFeatureValue = self.splitFeatureValue,
      depth = self.depth
   }
   return DFDinfo
end
