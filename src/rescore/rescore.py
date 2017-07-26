#!/usr/bin/env python

# TODO Rename symbol_set -> symbols_set
# TODO Rename symbols_type -> org_symbol_scores

import argparse
import os
import math
import requests
import json
import sys
import time

import numpy as np
from Perceptron import Perceptron

from statistics import get_file_stats
from utility import get_all_filenames, shuffle

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


def rescore_weights(X, y, symbols_tuple, symbols_type, threshold, decay, epoch, l_rate):
    '''
    Returns a tuple of (symbol, score) after training perceptron
    '''

    n_samples, n_feaures = len(X), len(X[0])

    perceptron = Perceptron(symbols_tuple=symbols_tuple,
                            n_epoch=epoch,
                            l_rate=l_rate,
                            threshold=threshold,
                            decay=decay,
                            symbols_type=symbols_type)

    weights = perceptron.rescore_weights(X, y)

    return weights
    

def split_dataset(X, y, percent):
    '''
    Splits dataset into (percent) % and (100 - percent) %
    Returns X1, y1, X2, y2
    '''

    split_index = len(X) * percent / 100

    X1 = X[ : split_index]
    y1 = y[ : split_index]

    X2 = X[split_index + 1 : ]
    y2 = y[split_index + 1 : ]

    return X1, y1, X2, y2


def print_new_scores(output_file, symbol_set, symbols_type, new_scores):

    score_output_format = "{:<35} {:<13} {:<10}"

    print >>output_file, score_output_format.format("SYMBOL", "OLD SCORE", "NEW SCORE")

    for i in range(len(symbol_set)):
        print >>output_file, score_output_format.format(symbol_set[i], symbols_type[symbol_set[i]], new_scores[i])

        
def eval_email_score(record, new_scores):

    score = 0
    
    for i in range(len(record)):
        if record[i] == 1:
            score = score + new_scores[i]

    return score


def make_log_for_stats(X, y, scores):

    logs = []

    for x, y_val in zip(X, y):
        logs.append("dummy_file" + " " +
                    ("HAM" if y_val == 0 else "SPAM") + " " +
                    str(eval_email_score(x, scores)) + " " +
                    "DUMMY_SYM" +
                    "\n")

    return logs


def find_best_spam_threshold(X_cv, y_cv, spam_thresholds, new_scores):

    logs = make_log_for_stats(X_cv, y_cv, new_scores)

    max_accuracy = -1
    max_accuracy_threshold = -1
    ms = 0
    
    for threshold in spam_thresholds:
        stats = get_file_stats(logs, threshold)
        accuracy = stats[-1]
        if(accuracy > max_accuracy):
            max_accuracy = accuracy
            max_accuracy_threshold = threshold
            ms = stats    

    return max_accuracy_threshold


def fscore(stats):

    fp = stats.false_positive_rate * stats.no_of_ham / 100
    fn = stats.false_negative_rate * stats.no_of_spam / 100
    
    f_score = 2 * stats.true_positives / float(2 * stats.true_positives + fp + fn)

    return f_score


def print_stats(X, y, scores, threshold):

    stats = get_file_stats(make_log_for_stats(X, y, scores), threshold)
    f_score = fscore(stats)

    print
    print "Statistics at threshold {}".format(threshold)
    print "Accuracy: {} %".format(str(round(stats.overall_accuracy, 2)))
    print "F score: {}".format(fscore(stats))
    print "False positive rate: {}".format(stats.false_positive_rate)
    print "False negative rate: {}".format(stats.false_negative_rate)
    print
    
    
def main():

    start_time = time.time()
    
    epoch = 100
    l_rate = 0.001
    threshold = 15
    output = sys.stdout
    decay = 1
    
    arg_parser = argparse.ArgumentParser()
    arg_parser.add_argument("-l", "--logdir",
                            help="path to log directory")
    arg_parser.add_argument("-e", "--epoch",
                            help="no of epochs [Default: 100]",
                            type=int)
    arg_parser.add_argument("-r", "--lrate",
                            help="Learning rate of perceptron [Default: 0.001]",
                            type=float)
    arg_parser.add_argument("-t", "--threshold",
                            help="threshold value [Default: 15]",
                            type=float)
    arg_parser.add_argument("-o", "--output",
                            help="Write new scores to file")
    arg_parser.add_argument("-d", "--decay",
                            help="Weight decay [Default: 1]",
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

    if args.output:
        output = open(args.output, 'w')

    if args.decay:
        decay = args.decay
        
    X, y, symbol_set = get_dataset_from_logs(logdir=args.logdir)

    X, y = shuffle(X, y)
    
    symbols_type = get_symbols_type(symbol_set)

    # Split data into 60 : 20 : 20 (Train : Cross-validation : Test)
    X_train, y_train, X_test, y_test = split_dataset(X, y, 60)

    X_cv, y_cv, X_test, y_test = split_dataset(X_test, y_test, 50) 

    old_scores = []
    for sym in symbol_set:
       old_scores.append(symbols_type[sym])

    new_scores = rescore_weights(X=X_train,
                                 y=y_train,
                                 epoch=epoch,
                                 l_rate=l_rate,
                                 decay=decay,
                                 threshold=threshold,
                                 symbols_type=symbols_type,
                                 symbols_tuple=symbol_set)[1:] # excluding bias
 
    total_time = round(time.time() - start_time, 2)

    # Statistics 
    print "\n"
    print "Statistics: "
    print "Time taken: {}s".format(total_time)
    print
    
    # Pre-rescore test stats
    print "Pre-rescore test stats: "
    print_stats(X_test, y_test, old_scores, 5)
    print_stats(X_test, y_test, old_scores, 15)
    
    # Post-rescore test stats
    print
    print "Post-rescore test data stats:"
    print_stats(X_test, y_test, new_scores, args.threshold)
    print_stats(X_test, y_test, new_scores, args.threshold)
    print
    
    print_new_scores(output_file=output,
                     symbol_set=symbol_set,
                     symbols_type=symbols_type,
                     new_scores=new_scores)

    
if __name__ == "__main__":
    main()

