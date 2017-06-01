import argparse
import os
import socket

def is_rspamd_alive(rspamd_host, rspamd_port):

    result = False
    
    skt = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    
    try:
        skt.connect((rspamd_host, rspamd_port))
        result = True
    except:
        pass

    return result

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
    
    args = arg_parser.parse_args()

    if args.ham is None and args.spam is None:
        print "Provide atleast one of spam directory or ham directory."
        arg_parser.print_help()
        return

    if args.ham is not None:
        if os.path.isdir(args.ham) is False:
            print "ham directory does not exist or is a file."
            return

    if args.spam is not None:
        if os.path.isdir(args.spam) is False:
            print "spam directory does not exist or is a file."
            return

    if args.ip is not None:
        rspamd_host = args.ip

    if args.port is not None:
        rspamd_port = args.port
        
    if is_rspamd_alive(rspamd_host, rspamd_port) is False:
        print "Could not connect to rspamd on {}:{}".format(rspamd_host, rspamd_port)
        return

    

if __name__ == "__main__":
    main()
