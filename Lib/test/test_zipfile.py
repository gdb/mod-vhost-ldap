# We can test part of the module without zlib.
try:
    import zlib
except ImportError:
    zlib = None

import zipfile, os, unittest, sys, shutil, struct

from StringIO import StringIO
from tempfile import TemporaryFile
from random import randint, random

import test.test_support as support
from test.test_support import TESTFN, run_unittest

TESTFN2 = TESTFN + "2"
FIXEDTEST_SIZE = 10

class TestsWithSourceFile(unittest.TestCase):
    def setUp(self):
        self.line_gen = ("Zipfile test line %d. random float: %f" % (i, random())
                          for i in xrange(FIXEDTEST_SIZE))
        self.data = '\n'.join(self.line_gen) + '\n'

        # Make a source file with some lines
        fp = open(TESTFN, "wb")
        fp.write(self.data)
        fp.close()

    def makeTestArchive(self, f, compression):
        # Create the ZIP archive
        zipfp = zipfile.ZipFile(f, "w", compression)
        zipfp.write(TESTFN, "another"+os.extsep+"name")
        zipfp.write(TESTFN, TESTFN)
        zipfp.writestr("strfile", self.data)
        zipfp.close()

    def zipTest(self, f, compression):
        self.makeTestArchive(f, compression)

        # Read the ZIP archive
        zipfp = zipfile.ZipFile(f, "r", compression)
        self.assertEqual(zipfp.read(TESTFN), self.data)
        self.assertEqual(zipfp.read("another"+os.extsep+"name"), self.data)
        self.assertEqual(zipfp.read("strfile"), self.data)

        # Print the ZIP directory
        fp = StringIO()
        stdout = sys.stdout
        try:
            sys.stdout = fp

            zipfp.printdir()
        finally:
            sys.stdout = stdout

        directory = fp.getvalue()
        lines = directory.splitlines()
        self.assertEquals(len(lines), 4) # Number of files + header

        self.assert_('File Name' in lines[0])
        self.assert_('Modified' in lines[0])
        self.assert_('Size' in lines[0])

        fn, date, time, size = lines[1].split()
        self.assertEquals(fn, 'another.name')
        # XXX: timestamp is not tested
        self.assertEquals(size, str(len(self.data)))

        # Check the namelist
        names = zipfp.namelist()
        self.assertEquals(len(names), 3)
        self.assert_(TESTFN in names)
        self.assert_("another"+os.extsep+"name" in names)
        self.assert_("strfile" in names)

        # Check infolist
        infos = zipfp.infolist()
        names = [ i.filename for i in infos ]
        self.assertEquals(len(names), 3)
        self.assert_(TESTFN in names)
        self.assert_("another"+os.extsep+"name" in names)
        self.assert_("strfile" in names)
        for i in infos:
            self.assertEquals(i.file_size, len(self.data))

        # check getinfo
        for nm in (TESTFN, "another"+os.extsep+"name", "strfile"):
            info = zipfp.getinfo(nm)
            self.assertEquals(info.filename, nm)
            self.assertEquals(info.file_size, len(self.data))

        # Check that testzip doesn't raise an exception
        zipfp.testzip()
        zipfp.close()

    def testStored(self):
        for f in (TESTFN2, TemporaryFile(), StringIO()):
            self.zipTest(f, zipfile.ZIP_STORED)

    def zipOpenTest(self, f, compression):
        self.makeTestArchive(f, compression)

        # Read the ZIP archive
        zipfp = zipfile.ZipFile(f, "r", compression)
        zipdata1 = []
        zipopen1 = zipfp.open(TESTFN)
        while 1:
            read_data = zipopen1.read(256)
            if not read_data:
                break
            zipdata1.append(read_data)

        zipdata2 = []
        zipopen2 = zipfp.open("another"+os.extsep+"name")
        while 1:
            read_data = zipopen2.read(256)
            if not read_data:
                break
            zipdata2.append(read_data)

        self.assertEqual(''.join(zipdata1), self.data)
        self.assertEqual(''.join(zipdata2), self.data)
        zipfp.close()

    def testOpenStored(self):
        for f in (TESTFN2, TemporaryFile(), StringIO()):
            self.zipOpenTest(f, zipfile.ZIP_STORED)

    def zipRandomOpenTest(self, f, compression):
        self.makeTestArchive(f, compression)

        # Read the ZIP archive
        zipfp = zipfile.ZipFile(f, "r", compression)
        zipdata1 = []
        zipopen1 = zipfp.open(TESTFN)
        while 1:
            read_data = zipopen1.read(randint(1, 1024))
            if not read_data:
                break
            zipdata1.append(read_data)

        self.assertEqual(''.join(zipdata1), self.data)
        zipfp.close()

    def testRandomOpenStored(self):
        for f in (TESTFN2, TemporaryFile(), StringIO()):
            self.zipRandomOpenTest(f, zipfile.ZIP_STORED)

    def zipReadlineTest(self, f, compression):
        self.makeTestArchive(f, compression)

        # Read the ZIP archive
        zipfp = zipfile.ZipFile(f, "r")
        zipopen = zipfp.open(TESTFN)
        for line in self.line_gen:
            linedata = zipopen.readline()
            self.assertEqual(linedata, line + '\n')

        zipfp.close()

    def zipReadlinesTest(self, f, compression):
        self.makeTestArchive(f, compression)

        # Read the ZIP archive
        zipfp = zipfile.ZipFile(f, "r")
        ziplines = zipfp.open(TESTFN).readlines()
        for line, zipline in zip(self.line_gen, ziplines):
            self.assertEqual(zipline, line + '\n')

        zipfp.close()

    def zipIterlinesTest(self, f, compression):
        self.makeTestArchive(f, compression)

        # Read the ZIP archive
        zipfp = zipfile.ZipFile(f, "r")
        for line, zipline in zip(self.line_gen, zipfp.open(TESTFN)):
            self.assertEqual(zipline, line + '\n')

        zipfp.close()

    def testReadlineStored(self):
        for f in (TESTFN2, TemporaryFile(), StringIO()):
            self.zipReadlineTest(f, zipfile.ZIP_STORED)

    def testReadlinesStored(self):
        for f in (TESTFN2, TemporaryFile(), StringIO()):
            self.zipReadlinesTest(f, zipfile.ZIP_STORED)

    def testIterlinesStored(self):
        for f in (TESTFN2, TemporaryFile(), StringIO()):
            self.zipIterlinesTest(f, zipfile.ZIP_STORED)

    if zlib:
        def testDeflated(self):
            for f in (TESTFN2, TemporaryFile(), StringIO()):
                self.zipTest(f, zipfile.ZIP_DEFLATED)

        def testOpenDeflated(self):
            for f in (TESTFN2, TemporaryFile(), StringIO()):
                self.zipOpenTest(f, zipfile.ZIP_DEFLATED)

        def testRandomOpenDeflated(self):
            for f in (TESTFN2, TemporaryFile(), StringIO()):
                self.zipRandomOpenTest(f, zipfile.ZIP_DEFLATED)

        def testReadlineDeflated(self):
            for f in (TESTFN2, TemporaryFile(), StringIO()):
                self.zipReadlineTest(f, zipfile.ZIP_DEFLATED)

        def testReadlinesDeflated(self):
            for f in (TESTFN2, TemporaryFile(), StringIO()):
                self.zipReadlinesTest(f, zipfile.ZIP_DEFLATED)

        def testIterlinesDeflated(self):
            for f in (TESTFN2, TemporaryFile(), StringIO()):
                self.zipIterlinesTest(f, zipfile.ZIP_DEFLATED)

        def testLowCompression(self):
            # Checks for cases where compressed data is larger than original
            # Create the ZIP archive
            zipfp = zipfile.ZipFile(TESTFN2, "w", zipfile.ZIP_DEFLATED)
            zipfp.writestr("strfile", '12')
            zipfp.close()

            # Get an open object for strfile
            zipfp = zipfile.ZipFile(TESTFN2, "r", zipfile.ZIP_DEFLATED)
            openobj = zipfp.open("strfile")
            self.assertEqual(openobj.read(1), '1')
            self.assertEqual(openobj.read(1), '2')

    def testAbsoluteArcnames(self):
        zipfp = zipfile.ZipFile(TESTFN2, "w", zipfile.ZIP_STORED)
        zipfp.write(TESTFN, "/absolute")
        zipfp.close()

        zipfp = zipfile.ZipFile(TESTFN2, "r", zipfile.ZIP_STORED)
        self.assertEqual(zipfp.namelist(), ["absolute"])
        zipfp.close()

    def tearDown(self):
        os.remove(TESTFN)
        os.remove(TESTFN2)

class TestZip64InSmallFiles(unittest.TestCase):
    # These tests test the ZIP64 functionality without using large files,
    # see test_zipfile64 for proper tests.

    def setUp(self):
        self._limit = zipfile.ZIP64_LIMIT
        zipfile.ZIP64_LIMIT = 5

        line_gen = ("Test of zipfile line %d." % i for i in range(0, FIXEDTEST_SIZE))
        self.data = '\n'.join(line_gen)

        # Make a source file with some lines
        fp = open(TESTFN, "wb")
        fp.write(self.data)
        fp.close()

    def largeFileExceptionTest(self, f, compression):
        zipfp = zipfile.ZipFile(f, "w", compression)
        self.assertRaises(zipfile.LargeZipFile,
                zipfp.write, TESTFN, "another"+os.extsep+"name")
        zipfp.close()

    def largeFileExceptionTest2(self, f, compression):
        zipfp = zipfile.ZipFile(f, "w", compression)
        self.assertRaises(zipfile.LargeZipFile,
                zipfp.writestr, "another"+os.extsep+"name", self.data)
        zipfp.close()

    def testLargeFileException(self):
        for f in (TESTFN2, TemporaryFile(), StringIO()):
            self.largeFileExceptionTest(f, zipfile.ZIP_STORED)
            self.largeFileExceptionTest2(f, zipfile.ZIP_STORED)

    def zipTest(self, f, compression):
        # Create the ZIP archive
        zipfp = zipfile.ZipFile(f, "w", compression, allowZip64=True)
        zipfp.write(TESTFN, "another"+os.extsep+"name")
        zipfp.write(TESTFN, TESTFN)
        zipfp.writestr("strfile", self.data)
        zipfp.close()

        # Read the ZIP archive
        zipfp = zipfile.ZipFile(f, "r", compression)
        self.assertEqual(zipfp.read(TESTFN), self.data)
        self.assertEqual(zipfp.read("another"+os.extsep+"name"), self.data)
        self.assertEqual(zipfp.read("strfile"), self.data)

        # Print the ZIP directory
        fp = StringIO()
        stdout = sys.stdout
        try:
            sys.stdout = fp

            zipfp.printdir()
        finally:
            sys.stdout = stdout

        directory = fp.getvalue()
        lines = directory.splitlines()
        self.assertEquals(len(lines), 4) # Number of files + header

        self.assert_('File Name' in lines[0])
        self.assert_('Modified' in lines[0])
        self.assert_('Size' in lines[0])

        fn, date, time, size = lines[1].split()
        self.assertEquals(fn, 'another.name')
        # XXX: timestamp is not tested
        self.assertEquals(size, str(len(self.data)))

        # Check the namelist
        names = zipfp.namelist()
        self.assertEquals(len(names), 3)
        self.assert_(TESTFN in names)
        self.assert_("another"+os.extsep+"name" in names)
        self.assert_("strfile" in names)

        # Check infolist
        infos = zipfp.infolist()
        names = [ i.filename for i in infos ]
        self.assertEquals(len(names), 3)
        self.assert_(TESTFN in names)
        self.assert_("another"+os.extsep+"name" in names)
        self.assert_("strfile" in names)
        for i in infos:
            self.assertEquals(i.file_size, len(self.data))

        # check getinfo
        for nm in (TESTFN, "another"+os.extsep+"name", "strfile"):
            info = zipfp.getinfo(nm)
            self.assertEquals(info.filename, nm)
            self.assertEquals(info.file_size, len(self.data))

        # Check that testzip doesn't raise an exception
        zipfp.testzip()


        zipfp.close()

    def testStored(self):
        for f in (TESTFN2, TemporaryFile(), StringIO()):
            self.zipTest(f, zipfile.ZIP_STORED)


    if zlib:
        def testDeflated(self):
            for f in (TESTFN2, TemporaryFile(), StringIO()):
                self.zipTest(f, zipfile.ZIP_DEFLATED)

    def testAbsoluteArcnames(self):
        zipfp = zipfile.ZipFile(TESTFN2, "w", zipfile.ZIP_STORED, allowZip64=True)
        zipfp.write(TESTFN, "/absolute")
        zipfp.close()

        zipfp = zipfile.ZipFile(TESTFN2, "r", zipfile.ZIP_STORED)
        self.assertEqual(zipfp.namelist(), ["absolute"])
        zipfp.close()


    def tearDown(self):
        zipfile.ZIP64_LIMIT = self._limit
        os.remove(TESTFN)
        os.remove(TESTFN2)

class PyZipFileTests(unittest.TestCase):
    def testWritePyfile(self):
        zipfp  = zipfile.PyZipFile(TemporaryFile(), "w")
        fn = __file__
        if fn.endswith('.pyc') or fn.endswith('.pyo'):
            fn = fn[:-1]

        zipfp.writepy(fn)

        bn = os.path.basename(fn)
        self.assert_(bn not in zipfp.namelist())
        self.assert_(bn + 'o' in zipfp.namelist() or bn + 'c' in zipfp.namelist())
        zipfp.close()


        zipfp  = zipfile.PyZipFile(TemporaryFile(), "w")
        fn = __file__
        if fn.endswith('.pyc') or fn.endswith('.pyo'):
            fn = fn[:-1]

        zipfp.writepy(fn, "testpackage")

        bn = "%s/%s"%("testpackage", os.path.basename(fn))
        self.assert_(bn not in zipfp.namelist())
        self.assert_(bn + 'o' in zipfp.namelist() or bn + 'c' in zipfp.namelist())
        zipfp.close()

    def testWritePythonPackage(self):
        import email
        packagedir = os.path.dirname(email.__file__)

        zipfp  = zipfile.PyZipFile(TemporaryFile(), "w")
        zipfp.writepy(packagedir)

        # Check for a couple of modules at different levels of the hieararchy
        names = zipfp.namelist()
        self.assert_('email/__init__.pyo' in names or 'email/__init__.pyc' in names)
        self.assert_('email/mime/text.pyo' in names or 'email/mime/text.pyc' in names)

    def testWritePythonDirectory(self):
        os.mkdir(TESTFN2)
        try:
            fp = open(os.path.join(TESTFN2, "mod1.py"), "w")
            fp.write("print 42\n")
            fp.close()

            fp = open(os.path.join(TESTFN2, "mod2.py"), "w")
            fp.write("print 42 * 42\n")
            fp.close()

            fp = open(os.path.join(TESTFN2, "mod2.txt"), "w")
            fp.write("bla bla bla\n")
            fp.close()

            zipfp  = zipfile.PyZipFile(TemporaryFile(), "w")
            zipfp.writepy(TESTFN2)

            names = zipfp.namelist()
            self.assert_('mod1.pyc' in names or 'mod1.pyo' in names)
            self.assert_('mod2.pyc' in names or 'mod2.pyo' in names)
            self.assert_('mod2.txt' not in names)

        finally:
            shutil.rmtree(TESTFN2)



class OtherTests(unittest.TestCase):
    def testCreateNonExistentFileForAppend(self):
        if os.path.exists(TESTFN):
            os.unlink(TESTFN)

        filename = 'testfile.txt'
        content = 'hello, world. this is some content.'

        try:
            zf = zipfile.ZipFile(TESTFN, 'a')
            zf.writestr(filename, content)
            zf.close()
        except IOError, (errno, errmsg):
            self.fail('Could not append data to a non-existent zip file.')

        self.assert_(os.path.exists(TESTFN))

        zf = zipfile.ZipFile(TESTFN, 'r')
        self.assertEqual(zf.read(filename), content)
        zf.close()

    def testCloseErroneousFile(self):
        # This test checks that the ZipFile constructor closes the file object
        # it opens if there's an error in the file.  If it doesn't, the traceback
        # holds a reference to the ZipFile object and, indirectly, the file object.
        # On Windows, this causes the os.unlink() call to fail because the
        # underlying file is still open.  This is SF bug #412214.
        #
        fp = open(TESTFN, "w")
        fp.write("this is not a legal zip file\n")
        fp.close()
        try:
            zf = zipfile.ZipFile(TESTFN)
        except zipfile.BadZipfile:
            pass

    def testIsZipErroneousFile(self):
        # This test checks that the is_zipfile function correctly identifies
        # a file that is not a zip file
        fp = open(TESTFN, "w")
        fp.write("this is not a legal zip file\n")
        fp.close()
        chk = zipfile.is_zipfile(TESTFN)
        self.assert_(chk is False)

    def testIsZipValidFile(self):
        # This test checks that the is_zipfile function correctly identifies
        # a file that is a zip file
        zipf = zipfile.ZipFile(TESTFN, mode="w")
        zipf.writestr("foo.txt", "O, for a Muse of Fire!")
        zipf.close()
        chk = zipfile.is_zipfile(TESTFN)
        self.assert_(chk is True)

    def testNonExistentFileRaisesIOError(self):
        # make sure we don't raise an AttributeError when a partially-constructed
        # ZipFile instance is finalized; this tests for regression on SF tracker
        # bug #403871.

        # The bug we're testing for caused an AttributeError to be raised
        # when a ZipFile instance was created for a file that did not
        # exist; the .fp member was not initialized but was needed by the
        # __del__() method.  Since the AttributeError is in the __del__(),
        # it is ignored, but the user should be sufficiently annoyed by
        # the message on the output that regression will be noticed
        # quickly.
        self.assertRaises(IOError, zipfile.ZipFile, TESTFN)

    def testClosedZipRaisesRuntimeError(self):
        # Verify that testzip() doesn't swallow inappropriate exceptions.
        data = StringIO()
        zipf = zipfile.ZipFile(data, mode="w")
        zipf.writestr("foo.txt", "O, for a Muse of Fire!")
        zipf.close()

        # This is correct; calling .read on a closed ZipFile should throw
        # a RuntimeError, and so should calling .testzip.  An earlier
        # version of .testzip would swallow this exception (and any other)
        # and report that the first file in the archive was corrupt.
        self.assertRaises(RuntimeError, zipf.testzip)

    def tearDown(self):
        support.unlink(TESTFN)
        support.unlink(TESTFN2)

class DecryptionTests(unittest.TestCase):
    # This test checks that ZIP decryption works. Since the library does not
    # support encryption at the moment, we use a pre-generated encrypted
    # ZIP file

    data = (
    'PK\x03\x04\x14\x00\x01\x00\x00\x00n\x92i.#y\xef?&\x00\x00\x00\x1a\x00'
    '\x00\x00\x08\x00\x00\x00test.txt\xfa\x10\xa0gly|\xfa-\xc5\xc0=\xf9y'
    '\x18\xe0\xa8r\xb3Z}Lg\xbc\xae\xf9|\x9b\x19\xe4\x8b\xba\xbb)\x8c\xb0\xdbl'
    'PK\x01\x02\x14\x00\x14\x00\x01\x00\x00\x00n\x92i.#y\xef?&\x00\x00\x00'
    '\x1a\x00\x00\x00\x08\x00\x00\x00\x00\x00\x00\x00\x01\x00 \x00\xb6\x81'
    '\x00\x00\x00\x00test.txtPK\x05\x06\x00\x00\x00\x00\x01\x00\x01\x006\x00'
    '\x00\x00L\x00\x00\x00\x00\x00' )

    plain = 'zipfile.py encryption test'

    def setUp(self):
        fp = open(TESTFN, "wb")
        fp.write(self.data)
        fp.close()
        self.zip = zipfile.ZipFile(TESTFN, "r")

    def tearDown(self):
        self.zip.close()
        os.unlink(TESTFN)

    def testNoPassword(self):
        # Reading the encrypted file without password
        # must generate a RunTime exception
        self.assertRaises(RuntimeError, self.zip.read, "test.txt")

    def testBadPassword(self):
        self.zip.setpassword("perl")
        self.assertRaises(RuntimeError, self.zip.read, "test.txt")

    def testGoodPassword(self):
        self.zip.setpassword("python")
        self.assertEquals(self.zip.read("test.txt"), self.plain)


class TestsWithRandomBinaryFiles(unittest.TestCase):
    def setUp(self):
        datacount = randint(16, 64)*1024 + randint(1, 1024)
        self.data = ''.join((struct.pack('<f', random()*randint(-1000, 1000)) for i in xrange(datacount)))

        # Make a source file with some lines
        fp = open(TESTFN, "wb")
        fp.write(self.data)
        fp.close()

    def tearDown(self):
        support.unlink(TESTFN)
        support.unlink(TESTFN2)

    def makeTestArchive(self, f, compression):
        # Create the ZIP archive
        zipfp = zipfile.ZipFile(f, "w", compression)
        zipfp.write(TESTFN, "another"+os.extsep+"name")
        zipfp.write(TESTFN, TESTFN)
        zipfp.close()

    def zipTest(self, f, compression):
        self.makeTestArchive(f, compression)

        # Read the ZIP archive
        zipfp = zipfile.ZipFile(f, "r", compression)
        testdata = zipfp.read(TESTFN)
        self.assertEqual(len(testdata), len(self.data))
        self.assertEqual(testdata, self.data)
        self.assertEqual(zipfp.read("another"+os.extsep+"name"), self.data)
        zipfp.close()

    def testStored(self):
        for f in (TESTFN2, TemporaryFile(), StringIO()):
            self.zipTest(f, zipfile.ZIP_STORED)

    def zipOpenTest(self, f, compression):
        self.makeTestArchive(f, compression)

        # Read the ZIP archive
        zipfp = zipfile.ZipFile(f, "r", compression)
        zipdata1 = []
        zipopen1 = zipfp.open(TESTFN)
        while 1:
            read_data = zipopen1.read(256)
            if not read_data:
                break
            zipdata1.append(read_data)

        zipdata2 = []
        zipopen2 = zipfp.open("another"+os.extsep+"name")
        while 1:
            read_data = zipopen2.read(256)
            if not read_data:
                break
            zipdata2.append(read_data)

        testdata1 = ''.join(zipdata1)
        self.assertEqual(len(testdata1), len(self.data))
        self.assertEqual(testdata1, self.data)

        testdata2 = ''.join(zipdata2)
        self.assertEqual(len(testdata1), len(self.data))
        self.assertEqual(testdata1, self.data)
        zipfp.close()

    def testOpenStored(self):
        for f in (TESTFN2, TemporaryFile(), StringIO()):
            self.zipOpenTest(f, zipfile.ZIP_STORED)

    def zipRandomOpenTest(self, f, compression):
        self.makeTestArchive(f, compression)

        # Read the ZIP archive
        zipfp = zipfile.ZipFile(f, "r", compression)
        zipdata1 = []
        zipopen1 = zipfp.open(TESTFN)
        while 1:
            read_data = zipopen1.read(randint(1, 1024))
            if not read_data:
                break
            zipdata1.append(read_data)

        testdata = ''.join(zipdata1)
        self.assertEqual(len(testdata), len(self.data))
        self.assertEqual(testdata, self.data)
        zipfp.close()

    def testRandomOpenStored(self):
        for f in (TESTFN2, TemporaryFile(), StringIO()):
            self.zipRandomOpenTest(f, zipfile.ZIP_STORED)

class TestsWithMultipleOpens(unittest.TestCase):
    def setUp(self):
        # Create the ZIP archive
        zipfp = zipfile.ZipFile(TESTFN2, "w", zipfile.ZIP_DEFLATED)
        zipfp.writestr('ones', '1'*FIXEDTEST_SIZE)
        zipfp.writestr('twos', '2'*FIXEDTEST_SIZE)
        zipfp.close()

    def testSameFile(self):
        # Verify that (when the ZipFile is in control of creating file objects)
        # multiple open() calls can be made without interfering with each other.
        zipf = zipfile.ZipFile(TESTFN2, mode="r")
        zopen1 = zipf.open('ones')
        zopen2 = zipf.open('ones')
        data1 = zopen1.read(500)
        data2 = zopen2.read(500)
        data1 += zopen1.read(500)
        data2 += zopen2.read(500)
        self.assertEqual(data1, data2)
        zipf.close()

    def testDifferentFile(self):
        # Verify that (when the ZipFile is in control of creating file objects)
        # multiple open() calls can be made without interfering with each other.
        zipf = zipfile.ZipFile(TESTFN2, mode="r")
        zopen1 = zipf.open('ones')
        zopen2 = zipf.open('twos')
        data1 = zopen1.read(500)
        data2 = zopen2.read(500)
        data1 += zopen1.read(500)
        data2 += zopen2.read(500)
        self.assertEqual(data1, '1'*FIXEDTEST_SIZE)
        self.assertEqual(data2, '2'*FIXEDTEST_SIZE)
        zipf.close()

    def testInterleaved(self):
        # Verify that (when the ZipFile is in control of creating file objects)
        # multiple open() calls can be made without interfering with each other.
        zipf = zipfile.ZipFile(TESTFN2, mode="r")
        zopen1 = zipf.open('ones')
        data1 = zopen1.read(500)
        zopen2 = zipf.open('twos')
        data2 = zopen2.read(500)
        data1 += zopen1.read(500)
        data2 += zopen2.read(500)
        self.assertEqual(data1, '1'*FIXEDTEST_SIZE)
        self.assertEqual(data2, '2'*FIXEDTEST_SIZE)
        zipf.close()

    def tearDown(self):
        os.remove(TESTFN2)


class UniversalNewlineTests(unittest.TestCase):
    def setUp(self):
        self.line_gen = ["Test of zipfile line %d." % i for i in xrange(FIXEDTEST_SIZE)]
        self.seps = ('\r', '\r\n', '\n')
        self.arcdata, self.arcfiles = {}, {}
        for n, s in enumerate(self.seps):
            self.arcdata[s] = s.join(self.line_gen) + s
            self.arcfiles[s] = '%s-%d' % (TESTFN, n)
            file(self.arcfiles[s], "wb").write(self.arcdata[s])

    def makeTestArchive(self, f, compression):
        # Create the ZIP archive
        zipfp = zipfile.ZipFile(f, "w", compression)
        for fn in self.arcfiles.values():
            zipfp.write(fn, fn)
        zipfp.close()

    def readTest(self, f, compression):
        self.makeTestArchive(f, compression)

        # Read the ZIP archive
        zipfp = zipfile.ZipFile(f, "r")
        for sep, fn in self.arcfiles.items():
            zipdata = zipfp.open(fn, "rU").read()
            self.assertEqual(self.arcdata[sep], zipdata)

        zipfp.close()

    def readlineTest(self, f, compression):
        self.makeTestArchive(f, compression)

        # Read the ZIP archive
        zipfp = zipfile.ZipFile(f, "r")
        for sep, fn in self.arcfiles.items():
            zipopen = zipfp.open(fn, "rU")
            for line in self.line_gen:
                linedata = zipopen.readline()
                self.assertEqual(linedata, line + '\n')

        zipfp.close()

    def readlinesTest(self, f, compression):
        self.makeTestArchive(f, compression)

        # Read the ZIP archive
        zipfp = zipfile.ZipFile(f, "r")
        for sep, fn in self.arcfiles.items():
            ziplines = zipfp.open(fn, "rU").readlines()
            for line, zipline in zip(self.line_gen, ziplines):
                self.assertEqual(zipline, line + '\n')

        zipfp.close()

    def iterlinesTest(self, f, compression):
        self.makeTestArchive(f, compression)

        # Read the ZIP archive
        zipfp = zipfile.ZipFile(f, "r")
        for sep, fn in self.arcfiles.items():
            for line, zipline in zip(self.line_gen, zipfp.open(fn, "rU")):
                self.assertEqual(zipline, line + '\n')

        zipfp.close()

    def testReadStored(self):
        for f in (TESTFN2, TemporaryFile(), StringIO()):
            self.readTest(f, zipfile.ZIP_STORED)

    def testReadlineStored(self):
        for f in (TESTFN2, TemporaryFile(), StringIO()):
            self.readlineTest(f, zipfile.ZIP_STORED)

    def testReadlinesStored(self):
        for f in (TESTFN2, TemporaryFile(), StringIO()):
            self.readlinesTest(f, zipfile.ZIP_STORED)

    def testIterlinesStored(self):
        for f in (TESTFN2, TemporaryFile(), StringIO()):
            self.iterlinesTest(f, zipfile.ZIP_STORED)

    if zlib:
        def testReadDeflated(self):
            for f in (TESTFN2, TemporaryFile(), StringIO()):
                self.readTest(f, zipfile.ZIP_DEFLATED)

        def testReadlineDeflated(self):
            for f in (TESTFN2, TemporaryFile(), StringIO()):
                self.readlineTest(f, zipfile.ZIP_DEFLATED)

        def testReadlinesDeflated(self):
            for f in (TESTFN2, TemporaryFile(), StringIO()):
                self.readlinesTest(f, zipfile.ZIP_DEFLATED)

        def testIterlinesDeflated(self):
            for f in (TESTFN2, TemporaryFile(), StringIO()):
                self.iterlinesTest(f, zipfile.ZIP_DEFLATED)

    def tearDown(self):
        for sep, fn in self.arcfiles.items():
            os.remove(fn)
        support.unlink(TESTFN)
        support.unlink(TESTFN2)


def test_main():
    run_unittest(TestsWithSourceFile, TestZip64InSmallFiles, OtherTests,
                 PyZipFileTests, DecryptionTests, TestsWithMultipleOpens,
                 UniversalNewlineTests, TestsWithRandomBinaryFiles)

if __name__ == "__main__":
    test_main()
