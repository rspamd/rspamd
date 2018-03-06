
require 'torch'

optim = {}

-- optimizations
require('optim.sgd')
require('optim.cg')
require('optim.asgd')
require('optim.nag')
require('optim.fista')
require('optim.lbfgs')
require('optim.adagrad')
require('optim.rprop')
require('optim.adam')
require('optim.adamax')
require('optim.rmsprop')
require('optim.adadelta')
require('optim.cmaes')
require('optim.de')

-- line search functions
require('optim.lswolfe')

-- helpers
require('optim.polyinterp')
require('optim.checkgrad')

-- tools
require('optim.ConfusionMatrix')
require('optim.Logger')

return optim
