import math

class Perceptron:

    def __init__(self, n_epoch=5, l_rate=0.01):
        self.weights_ = []
        self.n_epoch = n_epoch
        self.l_rate = l_rate


    def activation(self, x):
        return 1 / (1 + math.exp( -x ))


    def predict(self, row):
        transfer = self.weights_[0]
        
        for i in range(len(row) - 1):
            transfer = transfer + self.weights_[i + 1] * row[i]

        return self.activation(transfer)


    def train(self, X, y):

        self.weights_ = [0.0] * (len(X[0]) + 1)

        for epoch in range(self.n_epoch):
            squared_sum_error = 0.0
            for row, output in zip(X, y):
                prediction = self.predict(row)
                error = prediction * (1 - prediction) * (output - prediction)

                #print str(prediction) + " | " + str(output)
                
                squared_sum_error = error ** 2

                self.weights_[0] = self.weights_[0] + self.l_rate * error

                for i in range(len(row)):
                    self.weights_[i + 1] = self.weights_[i + 1] + self.l_rate * error * row[i]


            print "epoch : {} | error : {}".format(str(epoch), str(squared_sum_error))
        

    def scale_weights(self, threshold=10):

        bias = self.weights_[0]

        scaled_weights = self.weights_
        
        for i in range(1, len(self.weights_)):
            scaled_weights[i] = self.weights_[i] * -threshold / bias

        return scaled_weights
        
    def rescore_weights(self, X, y):

        self.train(X, y)

        scaled_weights = self.scale_weights()

        return scaled_weights
    
        
if __name__ == "__main__":

    p = Perceptron()

    print "0: " + str(p.activation(0))
    print "8: " + str(p.activation(8))
    print "10: " + str(p.activation(10))
    print "13: " + str(p.activation(13))
    print "15: " + str(p.activation(15))
    
    
