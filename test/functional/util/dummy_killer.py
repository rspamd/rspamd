import signal
import os
import atexit
import tempfile

def setup_killer(server, method = None):
    def default_method():
        server.server_close()

    if method is None:
        method = default_method

    def alarm_handler(signum, frame):
        try:
            method()
        finally:
            # Closing the socket here can race with an in-flight
            # serve_forever() select/epoll loop on the same fd, which then
            # busy-spins instead of exiting (the closed fd keeps reporting
            # ready). Force an immediate exit so we never spin.
            os._exit(0)

    signal.signal(signal.SIGALRM, alarm_handler)
    signal.signal(signal.SIGTERM, alarm_handler)
    signal.alarm(120)


def write_pid(path):
    with tempfile.NamedTemporaryFile(mode='w', delete=False) as f:
        f.write(str(os.getpid()))
        f.close()
        os.rename(f.name, path)

    def cleanup():
        os.remove(path)

    atexit.register(cleanup)
