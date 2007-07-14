import asyncore
import unittest
import select
import os
import socket
import threading
import sys
import time

from test import test_support
from test.test_support import TESTFN, run_unittest, unlink
from StringIO import StringIO

HOST = "127.0.0.1"
PORT = 54322

class dummysocket:
    def __init__(self):
        self.closed = False

    def close(self):
        self.closed = True

    def fileno(self):
        return 42

class dummychannel:
    def __init__(self):
        self.socket = dummysocket()

class exitingdummy:
    def __init__(self):
        pass

    def handle_read_event(self):
        raise asyncore.ExitNow()

    handle_write_event = handle_read_event
    handle_expt_event = handle_read_event

class crashingdummy:
    def __init__(self):
        self.error_handled = False

    def handle_read_event(self):
        raise Exception()

    handle_write_event = handle_read_event
    handle_expt_event = handle_read_event

    def handle_error(self):
        self.error_handled = True

# used when testing senders; just collects what it gets until newline is sent
class capture_server(threading.Thread):
    def run(self):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        global PORT
        PORT = test_support.bind_port(sock, HOST, PORT)
        sock.listen(1)
        conn, client = sock.accept()
        self.captured = ""
        while 1:
            data = conn.recv(10)
            if '\n' in data:
                break
            self.captured = self.captured + data

        conn.close()
        sock.close()


class HelperFunctionTests(unittest.TestCase):
    def test_readwriteexc(self):
        # Check exception handling behavior of read, write and _exception

        # check that ExitNow exceptions in the object handler method
        # bubbles all the way up through asyncore read/write/_exception calls
        tr1 = exitingdummy()
        self.assertRaises(asyncore.ExitNow, asyncore.read, tr1)
        self.assertRaises(asyncore.ExitNow, asyncore.write, tr1)
        self.assertRaises(asyncore.ExitNow, asyncore._exception, tr1)

        # check that an exception other than ExitNow in the object handler
        # method causes the handle_error method to get called
        tr2 = crashingdummy()
        asyncore.read(tr2)
        self.assertEqual(tr2.error_handled, True)

        tr2 = crashingdummy()
        asyncore.write(tr2)
        self.assertEqual(tr2.error_handled, True)

        tr2 = crashingdummy()
        asyncore._exception(tr2)
        self.assertEqual(tr2.error_handled, True)

    def test_readwrite(self):
        # Check that correct methods are called by readwrite()

        class testobj:
            def __init__(self):
                self.read = False
                self.write = False
                self.expt = False

            def handle_read_event(self):
                self.read = True

            def handle_write_event(self):
                self.write = True

            def handle_expt_event(self):
                self.expt = True

            def handle_error(self):
                self.error_handled = True

        for flag in (select.POLLIN, select.POLLPRI):
            tobj = testobj()
            self.assertEqual(tobj.read, False)
            asyncore.readwrite(tobj, flag)
            self.assertEqual(tobj.read, True)

            # check that ExitNow exceptions in the object handler method
            # bubbles all the way up through asyncore readwrite call
            tr1 = exitingdummy()
            self.assertRaises(asyncore.ExitNow, asyncore.readwrite, tr1, flag)

            # check that an exception other than ExitNow in the object handler
            # method causes the handle_error method to get called
            tr2 = crashingdummy()
            asyncore.readwrite(tr2, flag)
            self.assertEqual(tr2.error_handled, True)

        tobj = testobj()
        self.assertEqual(tobj.write, False)
        asyncore.readwrite(tobj, select.POLLOUT)
        self.assertEqual(tobj.write, True)

        # check that ExitNow exceptions in the object handler method
        # bubbles all the way up through asyncore readwrite call
        tr1 = exitingdummy()
        self.assertRaises(asyncore.ExitNow, asyncore.readwrite, tr1,
                          select.POLLOUT)

        # check that an exception other than ExitNow in the object handler
        # method causes the handle_error method to get called
        tr2 = crashingdummy()
        asyncore.readwrite(tr2, select.POLLOUT)
        self.assertEqual(tr2.error_handled, True)

        for flag in (select.POLLERR, select.POLLHUP, select.POLLNVAL):
            tobj = testobj()
            self.assertEqual(tobj.expt, False)
            asyncore.readwrite(tobj, flag)
            self.assertEqual(tobj.expt, True)

            # check that ExitNow exceptions in the object handler method
            # bubbles all the way up through asyncore readwrite calls
            tr1 = exitingdummy()
            self.assertRaises(asyncore.ExitNow, asyncore.readwrite, tr1, flag)

            # check that an exception other than ExitNow in the object handler
            # method causes the handle_error method to get called
            tr2 = crashingdummy()
            asyncore.readwrite(tr2, flag)
            self.assertEqual(tr2.error_handled, True)

    def test_closeall(self):
        self.closeall_check(False)

    def test_closeall_default(self):
        self.closeall_check(True)

    def closeall_check(self, usedefault):
        # Check that close_all() closes everything in a given map

        l = []
        testmap = {}
        for i in range(10):
            c = dummychannel()
            l.append(c)
            self.assertEqual(c.socket.closed, False)
            testmap[i] = c

        if usedefault:
            socketmap = asyncore.socket_map
            try:
                asyncore.socket_map = testmap
                asyncore.close_all()
            finally:
                testmap, asyncore.socket_map = asyncore.socket_map, socketmap
        else:
            asyncore.close_all(testmap)

        self.assertEqual(len(testmap), 0)

        for c in l:
            self.assertEqual(c.socket.closed, True)

    def test_compact_traceback(self):
        try:
            raise Exception("I don't like spam!")
        except:
            real_t, real_v, real_tb = sys.exc_info()
            r = asyncore.compact_traceback()
        else:
            self.fail("Expected exception")

        (f, function, line), t, v, info = r
        self.assertEqual(os.path.split(f)[-1], 'test_asyncore.py')
        self.assertEqual(function, 'test_compact_traceback')
        self.assertEqual(t, real_t)
        self.assertEqual(v, real_v)
        self.assertEqual(info, '[%s|%s|%s]' % (f, function, line))


class DispatcherTests(unittest.TestCase):
    def test_basic(self):
        d = asyncore.dispatcher()
        self.assertEqual(d.readable(), True)
        self.assertEqual(d.writable(), True)

    def test_repr(self):
        d = asyncore.dispatcher()
        self.assertEqual(repr(d), '<asyncore.dispatcher at %#x>' % id(d))

    def test_log(self):
        d = asyncore.dispatcher()

        # capture output of dispatcher.log() (to stderr)
        fp = StringIO()
        stderr = sys.stderr
        l1 = "Lovely spam! Wonderful spam!"
        l2 = "I don't like spam!"
        try:
            sys.stderr = fp
            d.log(l1)
            d.log(l2)
        finally:
            sys.stderr = stderr

        lines = fp.getvalue().splitlines()
        self.assertEquals(lines, ['log: %s' % l1, 'log: %s' % l2])

    def test_log_info(self):
        d = asyncore.dispatcher()

        # capture output of dispatcher.log_info() (to stdout via print)
        fp = StringIO()
        stdout = sys.stdout
        l1 = "Have you got anything without spam?"
        l2 = "Why can't she have egg bacon spam and sausage?"
        l3 = "THAT'S got spam in it!"
        try:
            sys.stdout = fp
            d.log_info(l1, 'EGGS')
            d.log_info(l2)
            d.log_info(l3, 'SPAM')
        finally:
            sys.stdout = stdout

        lines = fp.getvalue().splitlines()
        expected = ['EGGS: %s' % l1, 'info: %s' % l2, 'SPAM: %s' % l3]
        self.assertEquals(lines, expected)

    def test_unhandled(self):
        d = asyncore.dispatcher()

        # capture output of dispatcher.log_info() (to stdout via print)
        fp = StringIO()
        stdout = sys.stdout
        try:
            sys.stdout = fp
            d.handle_expt()
            d.handle_read()
            d.handle_write()
            d.handle_connect()
            d.handle_accept()
        finally:
            sys.stdout = stdout

        lines = fp.getvalue().splitlines()
        expected = ['warning: unhandled exception',
                    'warning: unhandled read event',
                    'warning: unhandled write event',
                    'warning: unhandled connect event',
                    'warning: unhandled accept event']
        self.assertEquals(lines, expected)



class dispatcherwithsend_noread(asyncore.dispatcher_with_send):
    def readable(self):
        return False

    def handle_connect(self):
        pass

class DispatcherWithSendTests(unittest.TestCase):
    usepoll = False

    def test_send(self):
        s = capture_server()
        s.start()
        time.sleep(1) # Give server time to initialize

        data = "Suppose there isn't a 16-ton weight?"*100
        d = dispatcherwithsend_noread()
        d.create_socket(socket.AF_INET, socket.SOCK_STREAM)
        d.connect((HOST, PORT))
        d.send(data)
        d.send('\n')

        while d.out_buffer:
            asyncore.poll()

        s.stopit = True
        s.join()

        self.assertEqual(s.captured, data)


class DispatcherWithSendTests_UsePoll(DispatcherWithSendTests):
    usepoll = True

if hasattr(asyncore, 'file_wrapper'):
    class FileWrapperTest(unittest.TestCase):
        def setUp(self):
            self.d = "It's not dead, it's sleeping!"
            file(TESTFN, 'w').write(self.d)

        def tearDown(self):
            unlink(TESTFN)

        def test_recv(self):
            fd = os.open(TESTFN, os.O_RDONLY)
            w = asyncore.file_wrapper(fd)

            self.assertEqual(w.fd, fd)
            self.assertEqual(w.fileno(), fd)
            self.assertEqual(w.recv(13), "It's not dead")
            self.assertEqual(w.read(6), ", it's")
            w.close()
            self.assertRaises(OSError, w.read, 1)

        def test_send(self):
            d1 = "Come again?"
            d2 = "I want to buy some cheese."
            fd = os.open(TESTFN, os.O_WRONLY | os.O_APPEND)
            w = asyncore.file_wrapper(fd)

            w.write(d1)
            w.send(d2)
            w.close()
            self.assertEqual(file(TESTFN).read(), self.d + d1 + d2)


def test_main():
    tests = [HelperFunctionTests, DispatcherTests, DispatcherWithSendTests,
             DispatcherWithSendTests_UsePoll]
    if hasattr(asyncore, 'file_wrapper'):
        tests.append(FileWrapperTest)

    run_unittest(*tests)

if __name__ == "__main__":
    test_main()
