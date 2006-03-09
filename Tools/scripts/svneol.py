#! /usr/bin/env python

"""
SVN helper script.

Try to set the svn:eol-style property to "native" on every .py and .txt file
in the directory tree rooted at the current directory.

Files with the svn:eol-style property already set (to anything) are skipped.

svn will itself refuse to set this property on a file that's not under SVN
control, or that has a binary mime-type property set.  This script inherits
that behavior, and passes on whatever warning message the failing "svn
propset" command produces.

In the Python project, it's safe to invoke this script from the root of
a checkout.

No output is produced for files that are ignored.  For a file that gets
svn:eol-style set, output looks like:

    property 'svn:eol-style' set on 'Lib\ctypes\__init__.py'

For a file not under version control:

    svn: warning: 'patch-finalizer.txt' is not under version control

and for a file with a binary mime-type property:

    svn: File 'Lib\test\test_pep263.py' has binary mime type property

TODO:  This is slow, and especially on Windows, because it invokes a new svn
command-line operation for every .py and .txt file.
"""

import os

for root, dirs, files in os.walk('.'):
    if '.svn' in dirs:
        dirs.remove('.svn')
    for fn in files:
        if fn.endswith('.py') or fn.endswith('.txt'):
            path = os.path.join(root, fn)
            p = os.popen('svn proplist "%s"' % path)
            guts = p.read()
            p.close()
            if 'eol-style' not in guts:
                os.system('svn propset svn:eol-style native "%s"' % path)
