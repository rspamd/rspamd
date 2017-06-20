#!/usr/bin/env python

import argparse
import os

from utility import get_all_filenames

def filter_logs(logdir):
    '''Makes a list of lists. Each list contains symbols hit by an email'''
    
    filenames = get_all_filenames(logdir)
    
    dataset = [open(file, 'r').read().split(' ')[4:] for file in filenames]

    return dataset


def get_symbol_set(dataset):

    symbol_set = set()

    for record in dataset:
        map(lambda x : symbol_set.add(x), record)

    return symbol_set


def main():

    arg_parser = argparse.ArgumentParser()
    arg_parser.add_argument("-l", "--logdir",
                            help="path to log directory")

    args = arg_parser.parse_args()

    if not args.logdir:
        arg_parser.error('specify log directory')
        return
        
    dataset = filter_logs(logdir=args.logdir)
    
    symbol_set = get_symbol_set(dataset)

    
if __name__ == "__main__":
    main()
