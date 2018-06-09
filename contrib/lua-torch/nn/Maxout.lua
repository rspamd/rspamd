-- Reference: http://jmlr.org/proceedings/papers/v28/goodfellow13.pdf

local Maxout, parent = torch.class('nn.Maxout', 'nn.Sequential')

function Maxout:__init(inputSize, outputSize, maxoutNumber, preprocess)
   parent.__init(self)
   self:add(nn.Linear(inputSize, outputSize * maxoutNumber))
   self:add(nn.View(maxoutNumber, outputSize):setNumInputDims(1))
   if preprocess then
      self:add(preprocess)
   end
   self:add(nn.Max(1, 2))
end
