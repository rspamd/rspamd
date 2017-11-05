local dt = require "decisiontree._env"

-- Utility to simplify construction of a pool of daemon threads with which to execute tasks in parallel.
local WorkPool = torch.class("dt.WorkPool", dt)

function WorkPool:__init(nThread)
   self.nThread = nThread or 16
   assert(torch.type(self.nThread) == 'number')
   assert(self.nThread > 0)

   self:initialize()
end

function WorkPool:initialize()
   local ipc = require 'libipc'
   self.queuename = os.tmpname()
   self.queue = ipc.workqueue(self.queuename)
   self.queues = {}
   for i=1,self.nThread do
      self.queues[i] = ipc.workqueue(self.queuename.."/"..i)
   end

   -- spawn thread workers
   ipc.map(self.nThread, function(queuename, nThread, myId)
      assert(nThread)
      assert(myId)
      local ipc = require 'libipc'

      -- Open the queue by name (the main thread already created it)
      local mainqueue = ipc.workqueue(queuename)
      local workqueue = ipc.workqueue(queuename.."/"..myId)

      local taskname, args

      local store = {}
      local queue = mainqueue

      repeat
         local msg = queue:read()
         assert(torch.type(msg) == 'table')
         taskname, task = unpack(msg)
         if taskname == nil then
            break
         elseif torch.type(taskname) ~= 'string' then
            error("Expecting taskname string. Got "..torch.type(taskname))
         elseif taskname == 'storeKeyValue' then
            assert(torch.type(task) == 'table')
            assert(queue == workqueue)
            store[task.key] = task.value
            queue:write({taskname})
         elseif taskname == 'storeKeysValues' then
            assert(torch.type(task) == 'table')
            assert(queue == workqueue)
            for key,value in pairs(task) do
               store[key] = value
            end
            queue:write({taskname})
         elseif taskname == 'require' then
            assert(torch.type(task) == 'table')
            assert(torch.type(task.libname) == 'string')
            assert(torch.type(task.varname) == 'string')
            _G[task.varname] = require(task.libname)
            assert(queue == workqueue)
            queue:write({taskname})
         elseif taskname == 'storeReset' then
            store = {}
            mainqueue:write({taskname})
         elseif taskname == 'echo' then
            mainqueue:write({taskname, task})
         elseif taskname == 'readWorkerQueue' then
            queue = workqueue
         elseif taskname == 'readMainQueue' then
            queue = mainqueue
         elseif taskname == 'execute' then
            if torch.type(task) == 'table' then
               assert(task.func and task.args)
               queue:write({taskname, task.func(store, task.args, myId)})
            else
               assert(torch.type(task) == 'function')
               queue:write({taskname, task(store, myId)})
            end
         else
            error("Unknown taskname: "..taskname)
         end
      until taskname == nil
   end, self.queuename, self.nThread)

end

-- Terminates all daemon threads.
function WorkPool:terminate()
   for i=1,self.nThread do
      self.queue:write({})
   end
end

-- this function is used to update the store of data in each worker thread
function WorkPool:_update(taskname, task, upval)
   assert(torch.type(taskname) == 'string')
   local _ = require 'moses'
   assert(_.contains({'storeKeyValue','storeKeysValues','require','execute'}, taskname))
   assert(torch.type(task) == 'table' or torch.type(task) == 'function')

   -- tell the workers to read their individual queue
   for i=1,self.nThread do
      self.queue:write({'readWorkerQueue'})
   end

   -- write to individual worker queues
   for i=1,self.nThread do
      if upval then
         self.queues[i]:writeup({taskname, task})
      else
         self.queues[i]:write({taskname, task})
      end
   end

   -- TODO use ipc.mutex:barrier(nThread+1)
   -- barrier: make sure that every worker has completed task by reading their queue
   for i=1,self.nThread do
      assert(self.queues[i]:read()[1] == taskname)
   end

   -- finally, tell them to read the main queue
   for i=1,self.nThread do
      self.queues[i]:write({'readMainQueue'})
   end
end

function WorkPool:update(taskname, task)
   return self:_update(taskname, task, false)
end

function WorkPool:updateup(taskname, task)
   return self:_update(taskname, task, true)
end

function WorkPool:write(taskname, task)
   assert(torch.type(taskname) == 'string')
   assert(taskname ~= 'storeKeyValue' or taskname ~= 'storeKeysValues')
   self.queue:write({taskname, task})
end

function WorkPool:writeup(taskname, task)
   assert(torch.type(taskname) == 'string')
   assert(taskname ~= 'storeKeyValue' or taskname ~= 'storeKeysValues')
   self.queue:writeup({taskname, task})
end

function WorkPool:read()
   local res = self.queue:read()
   assert(torch.type(res) == 'table')
   assert(torch.type(res[1] == 'string'))
   return unpack(res)
end

