#!/home/bernie/src/python23/dist/src/python

import unittest

import time
import socket

class creationTestCase(unittest.TestCase):
    """Test Case for socket.gettimeout() and socket.settimeout()"""
    def setUp(self):
        self.__s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    def tearDown(self):
        self.__s.close()

    def testObjectCreation(self):
        "Test Socket creation"
        self.assertEqual(self.__s.gettimeout(), None, 
            "Timeout socket not default to disable (None)")

    def testFloatReturnValue(self):
        "Test return value of getter/setter"
        self.__s.settimeout(7.345)
        self.assertEqual(self.__s.gettimeout(), 7.345, 
            "settimeout() and gettimeout() return different result")

        self.__s.settimeout(3)
        self.assertEqual(self.__s.gettimeout(), 3, 
            "settimeout() and gettimeout() return different result")

    def testReturnType(self):
        "Test return type of getter/setter"
        self.__s.settimeout(1)
        self.assertEqual(type(self.__s.gettimeout()), type(1.0),
            "return type of gettimeout() is not FloatType")

        self.__s.settimeout(3.9)
        self.assertEqual(type(self.__s.gettimeout()), type(1.0),
            "return type of gettimeout() is not FloatType")


class timeoutTestCase(unittest.TestCase):
    """Test Case for socket.socket() timeout functions"""
    def setUp(self):
        self.__s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.__addr_remote = ('www.google.com', 80)
        self.__addr_local  = ('127.0.0.1', 25339)

    def tearDown(self):
        self.__s.close()

    def testConnectTimeout(self):
        "Test connect() timeout"
        _timeout = 0.02
        self.__s.settimeout(_timeout)

        _t1 = time.time()
        self.failUnlessRaises(socket.error, self.__s.connect,
                self.__addr_remote)
        _t2 = time.time()

        _delta = abs(_t1 - _t2)
        self.assert_(_delta < _timeout + 0.5,
                "timeout (%f) is 0.5 seconds more than required (%f)"
                %(_delta, _timeout))

    def testRecvTimeout(self):
        "Test recv() timeout"
        _timeout = 0.02
        self.__s.connect(self.__addr_remote)
        self.__s.settimeout(_timeout)

        _t1 = time.time()
        self.failUnlessRaises(socket.error, self.__s.recv, 1024)
        _t2 = time.time()

        _delta = abs(_t1 - _t2)
        self.assert_(_delta < _timeout + 0.5,
                "timeout (%f) is 0.5 seconds more than required (%f)" 
                %(_delta, _timeout))

    def testAcceptTimeout(self):
        "Test accept() timeout()"
        _timeout = 2
        self.__s.settimeout(_timeout)
        self.__s.bind(self.__addr_local)
        self.__s.listen(5)

        _t1 = time.time()
        self.failUnlessRaises(socket.error, self.__s.accept)
        _t2 = time.time()

        _delta = abs(_t1 - _t2)
        self.assert_(_delta < _timeout + 0.5,
                "timeout (%f) is 0.5 seconds more than required (%f)" 
                %(_delta, _timeout))

    def testRecvfromTimeout(self):
        "Test recvfrom() timeout()"
        _timeout = 2
        self.__s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.__s.settimeout(_timeout)
        self.__s.bind(self.__addr_local)

        _t1 = time.time()
        self.failUnlessRaises(socket.error, self.__s.recvfrom, 8192)
        _t2 = time.time()

        _delta = abs(_t1 - _t2)
        self.assert_(_delta < _timeout + 0.5,
                "timeout (%f) is 0.5 seconds more than required (%f)" 
                %(_delta, _timeout))

    def testSend(self):
        "Test send() timeout"
        # couldn't figure out how to test it
        pass

    def testSendto(self):
        "Test sendto() timeout"
        # couldn't figure out how to test it
        pass

    def testSendall(self):
        "Test sendall() timeout"
        # couldn't figure out how to test it
        pass


def suite():
    suite = unittest.TestSuite()

    return suite

if __name__ == "__main__":
    unittest.main()
