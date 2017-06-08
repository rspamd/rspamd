#!/usr/bin/env python

import argparse
import os
import socket
import requests
import json
from os.path import basename
from requests.exceptions import RequestException
from itertools import chain

def get_all_filenames(location):
    ''' Recursively gets a list of  all file names'''
    
    files = []
    
    for root, directories, filenames in os.walk(location):
        for filename in filenames:
            if not filename.startswith('.'):
                files.append(os.path.join(root, filename))

    return files


def get_test_url(host, port):

    endpoint = "symbols"

    return "http://{}:{}/{}".format(host, port, endpoint)


def is_symbol_field(value):

    is_symbol = False
    
    if type(value) == type(dict()):
        if "score" in value:
            is_symbol = True

    return is_symbol


def test_files_from_dir(test_url, location, email_type):

    if email_type not in ['HAM', 'SPAM']:
        # TODO : Handle exception
        raise ValueError("Wrong email_type")
        return
    
    if not os.path.isdir(location):
        print "{} is does not exists or is not a directory.".format(location)
        return

    filenames = get_all_filenames(location) 

    test_results = []

    for filename in filenames:
        with open(filename, 'r') as f:
            try:
                response = requests.post(test_url, data=f)
            except RequestException as err:
                print "Connection error."
                print err
            else:
                metrics = json.loads(response.text)["default"]

                symbols = []
            
                for field in metrics:
                    if is_symbol_field(metrics[field]):
                        symbols.append(field)

                test_results.append('{} {} {} {}'.format(basename(filename),
                                                         email_type,
                                                         metrics['score'],
                                                         ' '.join(symbols)))

    return test_results
                                    

def write_test_results(results, filename):

    with open(filename, 'a') as out:
        out.write('\r\n'.join(results))
        
    
def main():

    rspamd_host = "127.0.0.1"
    rspamd_port = 11333

    output_file = "results.log"
    
    arg_parser = argparse.ArgumentParser()
    arg_parser.add_argument("-a", "--ham", help="path to ham directory")
    arg_parser.add_argument("-s", "--spam", help="path to spam directory")
    arg_parser.add_argument("-o", "--output",
                            help="path to test results output [Default: results.log]")
    arg_parser.add_argument("-i", "--ip",
                            help="ip of rspamd service [Default: 127.0.0.1]")
    arg_parser.add_argument("-p", "--port",
                            help="rspamd service port number [Default: 11333]",
                            type=int)
    
    args = arg_parser.parse_args()

    if not (args.ham or args.spam):
        arg_parser.error("Provide atleast one of spam or ham directory")
        arg_parser.print_help()
        return

    if args.ip:
        rspamd_host = args.ip

    if args.port:
        rspamd_port = args.port

    if args.output:
        output_file = args.output
        
    test_url = get_test_url(rspamd_host, rspamd_port)

    ham_test_results = []
    spam_test_results = []
    
    if args.ham:
        ham_test_results = test_files_from_dir(test_url, args.ham, 'HAM')

    if args.spam:
        spam_test_results = test_files_from_dir(test_url, args.spam, 'SPAM')

    test_results = chain(ham_test_results, spam_test_results)

    write_test_results(test_results, output_file)

        
if __name__ == "__main__":
    main()
