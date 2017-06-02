import argparse
import os
import socket
import requests
import json

def is_rspamd_alive(rspamd_host, rspamd_port):

    result = False
    test_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    
    try:
        test_socket.connect((rspamd_host, rspamd_port))
        result = True
    except:
        pass

    return result


def get_all_filenames(location):

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


def test_files_from_dir(test_url, location, output_file):

    if not os.path.isdir(location):
        print "{} is does not exists or is not a directory.".format(location)
        return

    filenames = get_all_filenames(location) # Recursively get all file names

    for filename in filenames:
        with open(filename, 'r') as f, open(output_file, 'a') as out:
            response = requests.post(test_url, data=f)
            result = json.loads(response.text)["default"]

            symbols = []
            
            for field in result:
                if is_symbol_field(result[field]):
                    symbols.append(field)

            # TODO filter filename
            out.write(filename + ' ' + ' '.join(symbols) + '\r\n')        

            
def main():

    rspamd_host = "127.0.0.1"
    rspamd_port = 11333
    
    arg_parser = argparse.ArgumentParser()
    arg_parser.add_argument("--ham", help="path to ham directory")
    arg_parser.add_argument("--spam", help="path to spam directory")
    arg_parser.add_argument("-i", "--ip",
                            help="ip of rspamd service [Default: 127.0.0.1]")
    arg_parser.add_argument("-p", "--port",
                            help="rspamd service port number [Default: 11333]",
                            type=int)
    arg_parser.add_argument("-s", "--stat-output",
                            help="generate stat file at the specified location")
    
    args = arg_parser.parse_args()

    if not (args.ham or args.spam):
        arg_parser.error("Provide atleast one of spam or ham directory")
        arg_parser.print_help()
        return

    if args.ip:
        rspamd_host = args.ip

    if args.port:
        rspamd_port = args.port
        
    if not is_rspamd_alive(rspamd_host, rspamd_port):
        print "Could not connect to rspamd on {}:{}".format(rspamd_host, rspamd_port)
        return

    test_url = get_test_url(rspamd_host, rspamd_port)
                
    if args.ham:
        test_files_from_dir(test_url, args.ham, 'ham.log')

    if args.spam:
        test_files_from_dir(test_url, args.spam, 'spam.log')

        
if __name__ == "__main__":
    main()
