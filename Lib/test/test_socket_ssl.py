# Test just the SSL support in the socket module, in a moderately bogus way.

from test import test_support
import socket

# Optionally test SSL support.  This requires the 'network' resource as given
# on the regrtest command line.
skip_expected = not (test_support.is_resource_enabled('network') and
                     hasattr(socket, "ssl"))

def test_basic():
    test_support.requires('network')

    import urllib

    socket.RAND_status()
    try:
        socket.RAND_egd(1)
    except TypeError:
        pass
    else:
        print "didn't raise TypeError"
    socket.RAND_add("this is a random string", 75.0)

    f = urllib.urlopen('https://sf.net')
    buf = f.read()
    f.close()

def test_rude_shutdown():
    try:
        import threading
    except ImportError:
        return

    # Some random port to connect to.
    PORT = 9934

    listener_gone = threading.Event()

    # `listener` runs in a thread.  It opens a socket listening on PORT, and
    # sits in an accept() until the main thread connects.  Then it rudely
    # closes the socket, and sets Event `listener_gone` to let the main thread
    # know the socket is gone.
    def listener():
        s = socket.socket()
        s.bind(('', PORT))
        s.listen(5)
        s.accept()
        s = None # reclaim the socket object, which also closes it
        listener_gone.set()

    def connector():
        s = socket.socket()
        s.connect(('localhost', PORT))
        listener_gone.wait()
        try:
            ssl_sock = socket.ssl(s)
        except socket.sslerror:
            pass
        else:
            raise test_support.TestFailed(
                      'connecting to closed SSL socket should have failed')

    t = threading.Thread(target=listener)
    t.start()
    connector()
    t.join()

def test_main():
    if not hasattr(socket, "ssl"):
        raise test_support.TestSkipped("socket module has no ssl support")
    test_rude_shutdown()
    test_basic()

if __name__ == "__main__":
    test_main()
