#!/usr/bin/env python

import argparse
import os

import numpy as np
from sklearn.linear_model import Perceptron

from utility import get_all_filenames

def get_dataset_from_logs(logdir):
    '''
    Returns X, y
    X is a list of lists. Each list contains symbols hit by an email
    y is a list of actual email class. Yi = 1 ith email is spam, 0 otherwise
    '''
    
    filenames = get_all_filenames(logdir)

    X = []
    y = []
    
    for file in filenames:
        with open(file, 'r') as f:
            for line in f:
                X.append(line.split()[3:])
                y.append(0 if line.split()[1] == "HAM" else 1)

    symbol_set = get_all_symbols(X)

    X, y = make_perceptron_input(X, y, symbol_set)

    X = np.array(X)
    y = np.array(y)
    
    return X, y


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

    return np.array(X_new)
    

def rescore_weights(X, y, no_of_iters=1):
    
    n_samples, n_feaures = X.shape

    pass


def main():

    arg_parser = argparse.ArgumentParser()
    arg_parser.add_argument("-l", "--logdir",
                            help="path to log directory")

    args = arg_parser.parse_args()

    if not args.logdir:
        arg_parser.error('specify log directory')
        return
        
    X, y = get_dataset_from_logs(logdir=args.logdir)

    weights = rescore_weights(X, y)
    
    
if __name__ == "__main__":
    main()
