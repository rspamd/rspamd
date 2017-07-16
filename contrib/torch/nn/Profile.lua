local ProfileModule, parent = torch.class("nn.Profile", "nn.Decorator")

function ProfileModule:__init(module, print_interval, name)
   parent.__init(self, module)
   self.print_interval = print_interval or 100
   self.name = name or torch.type(module)
   self.module = module
   self.numFwds = 0
   self.numBwds = 0
   self.summedFwdTime = 0
   self.summedBwdTime = 0
   self.timer = torch.Timer()
end

function ProfileModule:updateOutput(input)
   self.timer:reset()
   self.output = self.module:updateOutput(input)
   self.summedFwdTime = self.summedFwdTime + self.timer:time().real
   self.numFwds = self.numFwds + 1
   if self.numFwds % self.print_interval == 0 then
      print (string.format('%s took %.3f seconds for %d forward passes',
         self.name, self.summedFwdTime, self.print_interval))
      self.numFwds = 0
      self.summedFwdTime = 0
   end
   return self.output
end

function ProfileModule:updateGradInput(input, gradOutput)
   self.timer:reset()
   self.gradInput = self.module:updateGradInput(input, gradOutput)
   self.summedBwdTime = self.summedBwdTime + self.timer:time().real
   self.numBwds = self.numBwds + 1
   if self.numBwds % self.print_interval == 0 then
      print (string.format('%s took %.3f seconds for %d backward passes',
         self.name, self.summedBwdTime, self.print_interval))
      self.numBwds = 0
      self.summedBwdTime = 0
   end
   return self.gradInput
end

local function makeTorchTimerSerializable()
   -- The Timer object part of this class needs to be serializable
   -- so that the layer can be saved, cloned, etc. We add a dummy
   -- serialization of torch.Timer that just creates a new instance at read
   local timerMetatable = getmetatable(torch.Timer())
   timerMetatable['__factory'] = torch.Timer
   timerMetatable['write'] = function(object, file) end
   timerMetatable['read'] = function(object, file, versionNumber)
      return object
   end
end

makeTorchTimerSerializable()
