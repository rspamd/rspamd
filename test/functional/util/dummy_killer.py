import signal
import os
import atexit

def setup_killer(server, method = None):
    def default_method():
        server.server_close()

    if method is None:
        method = default_method

    def alarm_handler(signum, frame):
        method()

    signal.signal(signal.SIGALRM, alarm_handler)
    signal.signal(signal.SIGTERM, alarm_handler)
    signal.alarm(120)


def write_pid(path):
    with open(path, 'w+') as f:
        f.write(str(os.getpid()))
        f.close()

    def cleanup():
        os.remove(path)

    atexit.register(cleanup)
