local Clamp, Parent = torch.class('nn.Clamp', 'nn.HardTanh')

function Clamp:__init(min_value, max_value)
   Parent.__init(self, min_value, max_value)
end
