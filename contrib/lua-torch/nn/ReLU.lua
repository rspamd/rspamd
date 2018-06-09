local ReLU, Parent = torch.class('nn.ReLU', 'nn.Threshold')

function ReLU:__init(p)
   Parent.__init(self,0,0,p)
end
