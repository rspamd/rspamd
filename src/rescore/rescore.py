#!/usr/bin/env python

import argparse
import os
import math
import requests
import json

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


def file_exists(filepath):

    return os.path.isfile(filepath)


def get_symbols_type_from_file(filepath):

    cache = {}
    
    with open(filepath, 'r') as f:
        cache = json.load(f)

    return cache


def get_all_symbols_type(address="localhost", port=11334, endpoint="symbols"):

    url = "http://{}:{}/{}".format(address, port, endpoint)

    response = json.loads(requests.get(url).text)

    symbols_type = {}

    for group in response:
        group = group["rules"]
        for rule in group:
            symbols_type[rule['symbol']] = rule['weight']

    return symbols_type


def write_symbols_cache(symbols_type, filepath="symbols_type.cache"):

    with open(filepath, "w") as f:
        json.dump(symbols_type, f)

    return


def get_symbols_type_from_file(filepath):

    symbols_type = {}
    
    with open(filepath, 'r') as f:
        symbols_type = json.load(f)
    
    return symbols_type


def filter_symbols_type(symbols_set, symbols_type):

    filtered_symbols_type = {}

    for symbol in symbols_set:
        filtered_symbols_type[symbol] = 0
        if symbol in symbols_type:
            filtered_symbols_type[symbol] = symbols_type[symbol]
    
    return filtered_symbols_type
    

def get_symbols_type(symbol_set, symbols_type_cache_file="symbols_type.cache"):

    symbols_type = {}
    
    if file_exists(symbols_type_cache_file):
        symbols_type = get_symbols_type_from_file(symbols_type_cache_file)

    else:
        symbols_type = get_all_symbols_type()
        write_symbols_cache(symbols_type)

    symbols_type = filter_symbols_type(symbol_set, symbols_type) # Removes symbols not in symbol set

    return symbols_type


def rescore_weights(X, y, symbols_tuple, symbols_type, threshold, epoch=10, l_rate=0.01):
    '''
    Returns a tuple of (symbol, score) after training perceptron
    '''

    n_samples, n_feaures = X.shape

    perceptron = Perceptron(symbols_tuple=symbols_tuple,
                            n_epoch=epoch,
                            l_rate=l_rate,
                            threshold=threshold,
                            symbols_type=symbols_type)

    weights = perceptron.rescore_weights(X, y)

    return weights
    

def main():

    epoch = 10
    l_rate = 0.01
    threshold = 15
    
    arg_parser = argparse.ArgumentParser()
    arg_parser.add_argument("-l", "--logdir",
                            help="path to log directory")
    arg_parser.add_argument("-e", "--epoch",
                            help="no of epochs",
                            type=int)
    arg_parser.add_argument("-r", "--lrate",
                            help="Learning rate of perceptron",
                            type=float)
    arg_parser.add_argument("-t", "--threshold",
                            help="threshold value",
                            type=float)

    args = arg_parser.parse_args()

    if not args.logdir:
        arg_parser.error('specify log directory')
        return

    if args.epoch:
        epoch = args.epoch

    if args.lrate:
        l_rate = args.lrate

    if args.threshold:
        threshold = args.threshold
        
    X, y, symbol_set = get_dataset_from_logs(logdir=args.logdir)

    symbols_type = get_symbols_type(symbol_set)
    
    new_scores = rescore_weights(X=X,
                                 y=y,
                                 epoch=epoch,
                                 l_rate=l_rate,
                                 threshold=threshold,
                                 symbols_type=symbols_type,
                                 symbols_tuple=symbol_set) [1:] # Ignore bias
 

    print "{:<35} {:<13} {:<10}".format("SYMBOL", "OLD SCORE", "NEW SCORE")

    for i in range(len(symbol_set)):
        print "{:<35} {:<13} {:<10}".format(symbol_set[i], symbols_type[symbol_set[i]], new_scores[i])
    
    
if __name__ == "__main__":
    main()

