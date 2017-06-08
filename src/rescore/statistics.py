#!/usr/bin/env python

import sys
import argparse
from collections import namedtuple, defaultdict

file_stat = namedtuple('FileStat',
                        'no_of_emails \
                        no_of_spam \
                        no_of_ham \
                        spam_percent \
                        ham_percent \
                        spam_dict \
                        ham_dict \
                        symbol_set \
                        false_positive_rate \
                        false_negative_rate')

sym_stat = namedtuple('SymbolStat',
                      'name \
                      overall \
                      spam_percent \
                      ham_percent \
                      so')

def get_symbol_stats(file_stat):

    symbol_stats = []
    
    for symbol in file_stat.symbol_set:

        spam_hits = 0
        ham_hits = 0
        spam_hits = 0
        
        spam_hits = file_stat.spam_dict.get(symbol, 0)
        ham_hits = file_stat.ham_dict.get(symbol, 0)

        total_hits = spam_hits + ham_hits

        name = symbol
        overall = 0
        spam_percent = 0
        ham_percent = 0
        so = 0

        if file_stat.no_of_emails > 0:
            overall = total_hits * 100/ float(file_stat.no_of_emails)
            
        if file_stat.no_of_spam > 0:
            spam_percent = spam_hits * 100 / float(file_stat.no_of_spam)

        if file_stat.no_of_ham > 0:
            ham_percent = ham_hits * 100 / float(file_stat.no_of_ham)
            
        so = spam_percent / float(spam_percent + ham_percent)

        symbol_stats.append(sym_stat(name,
                                     round(overall, 2),
                                     round(spam_percent, 2),
                                     round(ham_percent, 2),
                                     round(so, 2)))

    return symbol_stats        

    
def get_file_stats(logs, spam_threshold):

    no_of_emails = len(logs)
    no_of_spam = 0
    no_of_ham = 0
    spam_dict = defaultdict(int)
    ham_dict = defaultdict(int)
    symbol_set = set()
    ham_percent = 0
    spam_percent = 0
    no_of_fp = 0
    no_of_fn = 0
    false_positive_rate = 0
    false_negative_rate = 0
    
    for line in logs:
        log = line.split()

        if log[1] == 'HAM':
            no_of_ham += 1
            no_of_fp += (1 if float(log[2]) >= spam_threshold else 0)        
        else:
            no_of_spam += 1
            no_of_fn += (1 if float(log[2]) < spam_threshold else 0)

        for symbol in log[3:]:
            symbol_set.add(symbol)

            if log[1] == 'HAM':
                ham_dict[symbol] += 1

            else:
                spam_dict[symbol] += 1
    
    if no_of_ham > 0:
        false_positive_rate = no_of_fp * 100 / float(no_of_ham)

    if no_of_spam > 0:
        false_negative_rate = no_of_fn * 100 / float(no_of_spam)                       

    if no_of_emails > 0:
        spam_percent = no_of_spam * 100 / float(no_of_emails)
        ham_percent = no_of_ham * 100 / float(no_of_emails)
        
    return file_stat(no_of_emails,
                     no_of_spam,
                     no_of_ham,
                     spam_percent,
                     ham_percent,
                     spam_dict,
                     ham_dict,
                     symbol_set,
                     false_positive_rate,
                     false_negative_rate)
            
                             
def write_file_stats(file_stat):

    print "File statistics: "
    print
    print "Number of emails: {}".format(str(file_stat.no_of_emails))
    print "Number of spam: {}".format(str(file_stat.no_of_spam))
    print "Number of ham: {}".format(str(file_stat.no_of_ham))
    print "Spam percentage : {} %".format(
        str(round(file_stat.spam_percent, 2)))
    print "Ham percentage : {} %".format(
        str(round(file_stat.ham_percent, 2)))
    print "False positive rate: {} %".format(
        str(round(file_stat.false_positive_rate, 2)))
    print "False negative rate: {} %".format(
        str(round(file_stat.false_negative_rate, 2)))
    print

    
def write_sym_stats(sym_stats):
    
    sym_width = max(len(max([sym.name for sym in sym_stats], key=len)) + 2, 8)
    overall_width = 9
    spam_width = 8
    ham_width = 7
    so_width = 5
    
    print "Symbol statistics: "
    print 
    print "{} {} {} {} {}".format('SYMBOL'.ljust(sym_width),
                                  'OVERALL'.ljust(overall_width),
                                  'SPAM %'.ljust(spam_width),
                                  'HAM %'.ljust(ham_width),
                                  'S/O'.ljust(so_width))

    for sym in sym_stats:
        print "{} {} {} {} {}".format(sym.name.ljust(sym_width),
                                      str(sym.overall).ljust(overall_width),
                                      str(sym.spam_percent).ljust(spam_width),
                                      str(sym.ham_percent).ljust(ham_width),
                                      str(sym.so).ljust(so_width))

def main():

    arg_parser = argparse.ArgumentParser()

    arg_parser.add_argument('-t',
                            '--threshold',
                            help='spam score threshold',
                            type=int)

    args = arg_parser.parse_args()

    if args.threshold is None:
        arg_parser.error('specify spam score threshold')
        return
    
    logs = sys.stdin.readlines()

    file_stat = get_file_stats(logs, args.threshold)

    sym_stats = get_symbol_stats(file_stat)

    write_file_stats(file_stat)
    write_sym_stats(sym_stats)
    
    
if __name__ == "__main__":
    main()
