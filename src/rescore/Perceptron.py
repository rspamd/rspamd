import math
import random

from utility import shuffle

class Perceptron:
    
    def __init__(self, symbols_tuple, threshold, n_epoch=5, l_rate=0.01, symbols_type={}):
        self.n_epoch = n_epoch
        self.l_rate = l_rate
        self.symbols_type = symbols_type
        self.symbols_tuple = symbols_tuple
        self.threshold = threshold

        self.weights_ = [0.0] * (len(symbols_tuple) + 1)        


        for i in range(1, len(symbols_tuple)):
            self.weights_[i] = symbols_type[symbols_tuple[i - 1]]
                
        
    def activation(self, x):
        return 1 / (1 + math.exp( -x ))


    def predict(self, row):
        transfer = self.weights_[0]
        
        for i in range(len(row) - 1):
            transfer = transfer + self.weights_[i + 1] * row[i]

        return self.activation(transfer)


    def train(self, X, y):

        best_weights = self.weights_
        best_error = float('inf')
        
        for epoch in range(self.n_epoch):
            squared_sum_error = 0.0

            X, y = shuffle(X, y)
            
            for row, output in zip(X, y):
                prediction = self.predict(row)
                error = output - prediction
                
                delta = prediction * (1 - prediction) * error * self.l_rate / sum(row)
                
                squared_sum_error = error ** 2

                self.weights_[0] = self.weights_[0] + self.l_rate * error

                # TODO 
                if epoch + 1 < self.n_epoch:
                    self.weights_[0] += delta

                for i in range(1, len(self.weights_)):
                    self.weights_[i] += delta

                    org_sym_score = self.symbols_type[self.symbols_tuple[i - 1]]
                    max_change = 5
                    
                    if org_sym_score < 0:
                        self.weights_[i] = min(0, self.weights_[i]) # Prevent HAM symbols score exceeding 0
#                        self.weights_[i] = max(self.score_to_weight(org_sym_score - max_change),
#                                               self.weights_[i])

                    elif org_sym_score > 0:
                        self.weights_[i] = max(0, self.weights_[i]) # Prevent SPAM symbols score dipping below 0
#                        self.weights_[i] = min(self.score_to_weight(org_sym_score + max_change),
#                                               self.weights_[i])

            print 'epoch: {} | error: {}'.format(str(epoch), str(squared_sum_error))
            
            # Pocket the best weights
            if squared_sum_error < best_error:
                best_error = squared_sum_error
                best_weights = self.weights_[:]

        self.weights_ = best_weights


    def score_to_weight(self, s):

        bias = self.weights_[0]

        return -s * bias / float(self.threshold)

    
    def weight_to_score(self, w):

        bias = self.weights_[0]

        return s * -self.threshold / float(bias)
    
        
    def scale_weights(self):

        bias = self.weights_[0]

        scaled_weights = self.weights_

        for i in range(1, len(self.weights_)):
            scaled_weights[i] = round(self.weights_[i] * -self.threshold / float(bias), 2)

        return scaled_weights

    
    def rescore_weights(self, X, y):

        self.train(X, y)

        scaled_weights = self.scale_weights()

        return scaled_weights
    
        
if __name__ == "__main__":


    # TESTING
    
    p = Perceptron()

    X = ['a', 'b', 'c']
    y = [1, 2, 3]

    X, y = p.shuffle(X, y)

    print X
    print y
    
    
