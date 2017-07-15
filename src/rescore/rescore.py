#!/usr/bin/env python

import argparse
import os

import numpy as np
from Perceptron import Perceptron

from utility import get_all_filenames

def get_dataset_from_logs(logdir):
    '''
    Returns X, y, symbol_set
    X is a list of lists. Each list contains symbols hit by an email
    y is a list of actual email class. Yi = 1 ith email is spam, 0 otherwise
    symbol_set is a list of symbols
    '''
    
    filenames = get_all_filenames(logdir)

    X = []
    y = []
    
    for file in filenames:
        with open(file, 'r') as f:
            for line in f:
                X.append(line.split()[4:])
                y.append(0 if line.split()[1] == "HAM" else 1)

    symbol_set = get_all_symbols(X)

    X, y = make_perceptron_input(X, y, symbol_set)

    X = np.array(X)
    y = np.array(y)
    
    return X, y, symbol_set


def get_all_symbols(dataset):

    symbol_set = set()

    for row in dataset:
        map(lambda x : symbol_set.add(x), row)

    return tuple(symbol_set)


def make_perceptron_input(X, y, symbol_set):
    '''
    Returns a list of lists containing 1s and 0s. 
    X(i, j) = 1 if symbol_set(j) is present in ith log line, 0 otherwise
    '''

    X_new = []

    for row in X:
        X_new.append([1 if symbol in row else 0 for symbol in symbol_set])

    return np.array(X_new), np.array(y)
    

def rescore_weights(X, y, epoch=10, l_rate=0.01):
    '''
    Returns a tuple of (symbol, score) after training perceptron
    '''

    n_samples, n_feaures = X.shape

    perceptron = Perceptron(n_epoch=epoch,l_rate=l_rate)

    weights = perceptron.rescore_weights(X, y)

    return weights


def split_dataset(X, y):
    '''
    Return X_train, y_train, X_test, y_test
    Splits dataset into 70:30 (70 - train, 30 - test)
    '''

    pass
    

def main():

    epoch = 10
    l_rate = 0.01
    
    arg_parser = argparse.ArgumentParser()
    arg_parser.add_argument("-l", "--logdir",
                            help="path to log directory")
    arg_parser.add_argument("-e", "--epoch",
                            help="no of epochs",
                            type=int)
    arg_parser.add_argument("-r", "--lrate",
                            help="Learning rate of perceptron",
                            type=float)
    

    args = arg_parser.parse_args()

    if not args.logdir:
        arg_parser.error('specify log directory')
        return

    if args.epoch:
        epoch = args.epoch

    if args.lrate:
        l_rate = args.lrate

        
    X, y, symbol_set = get_dataset_from_logs(logdir=args.logdir)


    #X_train, y_train, X_test, y_test = split_dataset(X, y)
    
    weights = rescore_weights(X=X,
                              y=y,
                              epoch=epoch,
                              l_rate=l_rate)

    
    for i in range(len(symbol_set)):
        print symbol_set[i] + ": " + str(weights[i + 1])
    
    
if __name__ == "__main__":
    main()
