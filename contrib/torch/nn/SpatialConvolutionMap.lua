local SpatialConvolutionMap, parent = torch.class('nn.SpatialConvolutionMap', 'nn.Module')

nn.tables = nn.tables or {}

function nn.tables.full(nin, nout)
   local ft = torch.Tensor(nin*nout,2)
   local p = 1
   for j=1,nout do
      for i=1,nin do
	 ft[p][1] = i
	 ft[p][2] = j
	 p = p + 1
      end
   end
   return ft
end

function nn.tables.oneToOne(nfeat)
   local ft = torch.Tensor(nfeat,2)
   for i=1,nfeat do
      ft[i][1] = i
      ft[i][2] = i
   end
   return ft
end

function nn.tables.random(nin, nout, nto)
   local nker = nto * nout
   local tbl = torch.Tensor(nker, 2)
   local fi = torch.randperm(nin)
   local frcntr = 1
   local nfi = math.floor(nin/nto) -- number of distinct nto chunks
   local totbl = tbl:select(2,2)
   local frtbl = tbl:select(2,1)
   local fitbl = fi:narrow(1, 1, (nfi * nto)) -- part of fi that covers distinct chunks
   local ufrtbl= frtbl:unfold(1, nto, nto)
   local utotbl= totbl:unfold(1, nto, nto)
   local ufitbl= fitbl:unfold(1, nto, nto)

   -- start filling frtbl
   for i=1,nout do -- fro each unit in target map
      ufrtbl:select(1,i):copy(ufitbl:select(1,frcntr))
      frcntr = frcntr + 1
      if frcntr-1 ==  nfi then -- reset fi
	 fi:copy(torch.randperm(nin))
	 frcntr = 1
      end
   end
   for tocntr=1,utotbl:size(1) do
      utotbl:select(1,tocntr):fill(tocntr)
   end
   return tbl
end

function SpatialConvolutionMap:__init(conMatrix, kW, kH, dW, dH)
   parent.__init(self)

   dW = dW or 1
   dH = dH or 1

   self.kW = kW
   self.kH = kH
   self.dW = dW
   self.dH = dH
   self.connTable = conMatrix
   self.nInputPlane = self.connTable:select(2,1):max()
   self.nOutputPlane = self.connTable:select(2,2):max()
   self.weight = torch.Tensor(self.connTable:size(1), kH, kW)
   self.bias = torch.Tensor(self.nOutputPlane)
   self.gradWeight = torch.Tensor(self.connTable:size(1), kH, kW)
   self.gradBias = torch.Tensor(self.nOutputPlane)

   self:reset()
end

function SpatialConvolutionMap:reset(stdv)
   if stdv then
      stdv = stdv * math.sqrt(3)
      if nn.oldSeed then
         self.weight:apply(function()
            return torch.uniform(-stdv, stdv)
         end)
         self.bias:apply(function()
            return torch.uniform(-stdv, stdv)
         end)
      else
         self.weight:uniform(-stdv, stdv)
         self.bias:uniform(-stdv, stdv)
      end
   else
      local ninp = torch.Tensor(self.nOutputPlane):zero()
      for i=1,self.connTable:size(1) do ninp[self.connTable[i][2]] =  ninp[self.connTable[i][2]]+1 end
      for k=1,self.connTable:size(1) do
         stdv = 1/math.sqrt(self.kW*self.kH*ninp[self.connTable[k][2]])
         if nn.oldSeed then
            self.weight:select(1,k):apply(function() return torch.uniform(-stdv,stdv) end)
         else
            self.weight:select(1,k):uniform(-stdv,stdv)
         end
      end
      for k=1,self.bias:size(1) do
         stdv = 1/math.sqrt(self.kW*self.kH*ninp[k])
         self.bias[k] = torch.uniform(-stdv,stdv)
      end
   end
end

function SpatialConvolutionMap:updateOutput(input)
   input.THNN.SpatialConvolutionMap_updateOutput(
      input:cdata(),
      self.output:cdata(),
      self.weight:cdata(),
      self.bias:cdata(),
      self.connTable:cdata(),
      self.nInputPlane,
      self.nOutputPlane,
      self.dW, self.dH
   )
   return self.output
end

function SpatialConvolutionMap:updateGradInput(input, gradOutput)
   input.THNN.SpatialConvolutionMap_updateGradInput(
      input:cdata(),
      gradOutput:cdata(),
      self.gradInput:cdata(),
      self.weight:cdata(),
      self.bias:cdata(),
      self.connTable:cdata(),
      self.nInputPlane,
      self.nOutputPlane,
      self.dW, self.dH
   )
   return self.gradInput
end

function SpatialConvolutionMap:accGradParameters(input, gradOutput, scale)
   input.THNN.SpatialConvolutionMap_accGradParameters(
      input:cdata(),
      gradOutput:cdata(),
      self.gradWeight:cdata(),
      self.gradBias:cdata(),
      self.connTable:cdata(),
      self.nInputPlane,
      self.nOutputPlane,
      self.dW, self.dH,
      scale or 1
   )
end

function SpatialConvolutionMap:decayParameters(decay)
   self.weight:add(-decay, self.weight)
   self.bias:add(-decay, self.bias)
end
