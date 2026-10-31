import errno
from hashlib import sha256
import socket


class Resource:
    def __init__(self, name):
        self.name = name
        self.socket = None

    def __enter__(self):
        self.socket = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
        try:
            self.socket.bind('\0vulnfin-' + sha256(self.name.encode()).hexdigest())
        except OSError as error:
            self.socket.close()
            self.socket = None
            if error.errno == errno.EADDRINUSE:
                raise ValueError('Resource busy: ' + self.name + '; finish or stop the other command') from None
            raise ValueError('Cannot lock ' + self.name + ': ' + str(error)) from None
        return self

    def __exit__(self, *args):
        if self.socket:
            self.socket.close()
