import pickle
import unittest
from cStringIO import StringIO

from test import test_support

from test.pickletester import AbstractPickleTests
from test.pickletester import TempAbstractPickleTests as XXXTemp
from test.pickletester import AbstractPickleModuleTests
from test.pickletester import AbstractPersistentPicklerTests

class PickleTests(AbstractPickleTests, AbstractPickleModuleTests, XXXTemp):

    def setUp(self):
        self.dumps = pickle.dumps
        self.loads = pickle.loads

    module = pickle
    error = KeyError

class PicklerTests(AbstractPickleTests):

    error = KeyError

    def dumps(self, arg, proto=0):
        f = StringIO()
        p = pickle.Pickler(f, proto)
        p.dump(arg)
        f.seek(0)
        return f.read()

    def loads(self, buf):
        f = StringIO(buf)
        u = pickle.Unpickler(f)
        return u.load()

class PersPicklerTests(AbstractPersistentPicklerTests):

    def dumps(self, arg, proto=0):
        class PersPickler(pickle.Pickler):
            def persistent_id(subself, obj):
                return self.persistent_id(obj)
        f = StringIO()
        p = PersPickler(f, proto)
        p.dump(arg)
        f.seek(0)
        return f.read()

    def loads(self, buf):
        class PersUnpickler(pickle.Unpickler):
            def persistent_load(subself, obj):
                return self.persistent_load(obj)
        f = StringIO(buf)
        u = PersUnpickler(f)
        return u.load()

def test_main():
    loader = unittest.TestLoader()
    suite = unittest.TestSuite()
    suite.addTest(loader.loadTestsFromTestCase(PickleTests))
    suite.addTest(loader.loadTestsFromTestCase(PicklerTests))
    suite.addTest(loader.loadTestsFromTestCase(PersPicklerTests))
    test_support.run_suite(suite)

if __name__ == "__main__":
    test_main()
