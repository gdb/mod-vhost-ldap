"""
Tests for uu module.
Nick Mathewson
"""

from test_support import verify, TestFailed, verbose, TESTFN
import sys, os
import uu
from StringIO import StringIO

teststr = "The smooth-scaled python crept over the sleeping dog\n"
expected = """\
M5&AE('-M;V]T:\"US8V%L960@<'ET:&]N(&-R97!T(&]V97(@=&AE('-L965P
(:6YG(&1O9PH """
encoded1 = "begin 666 t1\n"+expected+"\n \nend\n"
if verbose:
    print '1. encode file->file'
inp = StringIO(teststr)
out = StringIO()
uu.encode(inp, out, "t1")
verify(out.getvalue() == encoded1)
inp = StringIO(teststr)
out = StringIO()
uu.encode(inp, out, "t1", 0644)
verify(out.getvalue() == "begin 644 t1\n"+expected+"\n \nend\n")

if verbose:
    print '2. decode file->file'
inp = StringIO(encoded1)
out = StringIO()
uu.decode(inp, out)
verify(out.getvalue() == teststr)
inp = StringIO("""UUencoded files may contain many lines,
                  even some that have 'begin' in them.\n"""+encoded1)
out = StringIO()
uu.decode(inp, out)
verify(out.getvalue() == teststr)

stdinsave = sys.stdin
stdoutsave = sys.stdout
try:
    if verbose:
        print '3. encode stdin->stdout'
    sys.stdin = StringIO(teststr)
    sys.stdout = StringIO()
    uu.encode("-", "-", "t1", 0666)
    verify(sys.stdout.getvalue() == encoded1)
    if verbose:
        print >>stdoutsave, '4. decode stdin->stdout'
    sys.stdin = StringIO(encoded1)
    sys.stdout = StringIO()
    uu.decode("-", "-")
    verify(sys.stdout.getvalue() == teststr)
finally:
    sys.stdin = stdinsave
    sys.stdout = stdoutsave

if verbose:
    print '5. encode file->file'
tmpIn  = TESTFN + "i"
tmpOut = TESTFN + "o"
try:
    fin = open(tmpIn, 'w')
    fin.write(teststr)
    fin.close()

    fin = open(tmpIn, 'r')
    fout = open(tmpOut, 'w')
    uu.encode(fin, fout, tmpIn, mode=0644)
    fin.close()
    fout.close()

    fout = open(tmpOut, 'r')
    s = fout.read()
    fout.close()
    verify(s == 'begin 644 ' + tmpIn + '\n' + expected + '\n \nend\n')

    os.unlink(tmpIn)
    if verbose:
        print '6. decode file-> file'
    uu.decode(tmpOut)
    fin = open(tmpIn, 'r')
    s = fin.read()
    fin.close()
    verify(s == teststr)
    # XXX is there an xp way to verify the mode?

finally:
    try:
        fin.close()
    except:
        pass
    try:
        fout.close()
    except:
        pass
    try:
        os.unlink(tmpIn)
    except:
        pass
    try:
        os.unlink(tmpOut)
    except:
        pass

if verbose:
    print '7. error: truncated input'
inp = StringIO("begin 644 t1\n"+expected)
out = StringIO()
try:
    uu.decode(inp, out)
    raise TestFailed("No exception thrown")
except uu.Error, e:
    verify(str(e) == 'Truncated input file')

if verbose:
    print '8. error: missing begin'
inp = StringIO("")
out = StringIO()
try:
    uu.decode(inp, out)
    raise TestFailed("No exception thrown")
except uu.Error, e:
    verify(str(e) == 'No valid begin line found in input file')
