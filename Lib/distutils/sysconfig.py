"""Provide access to Python's configuration information.  The specific names
defined in the module depend heavily on the platform and configuration.

Written by:   Fred L. Drake, Jr.
Email:        <fdrake@acm.org>
Initial date: 17-Dec-1998
"""

__version__ = "$Revision$"

import os
import re
import string
import sys

prefix = os.path.normpath (sys.prefix)
exec_prefix = os.path.normpath (sys.exec_prefix)


def get_config_h_filename():
    """Return full pathname of installed config.h file."""
    if os.name == "nt":
        return os.path.join(exec_prefix, "include", "config.h")
    else:
        return os.path.join(exec_prefix,
                            "include", "python" + sys.version[:3],
                            "config.h")

def get_makefile_filename():
    """Return full pathname of installed Makefile from the Python build."""
    return os.path.join(exec_prefix,
                        "lib", "python" + sys.version[:3],
                        "config", "Makefile")

def parse_config_h(fp, g=None):
    """Parse a config.h-style file.  A dictionary containing name/value
    pairs is returned.  If an optional dictionary is passed in as the second
    argument, it is used instead of a new dictionary.
    """
    if g is None:
        g = {}
    define_rx = re.compile("#define ([A-Z][A-Z0-9_]+) (.*)\n")
    undef_rx = re.compile("/[*] #undef ([A-Z][A-Z0-9_]+) [*]/\n")
    #
    while 1:
        line = fp.readline()
        if not line:
            break
        m = define_rx.match(line)
        if m:
            n, v = m.group(1, 2)
            try: v = string.atoi(v)
            except ValueError: pass
            g[n] = v
        else:
            m = undef_rx.match(line)
            if m:
                g[m.group(1)] = 0
    return g

def parse_makefile(fp, g=None):
    """Parse a Makefile-style file.  A dictionary containing name/value
    pairs is returned.  If an optional dictionary is passed in as the second
    argument, it is used instead of a new dictionary.
    """
    if g is None:
        g = {}
    variable_rx = re.compile("([a-zA-Z][a-zA-Z0-9_]+)\s*=\s*(.*)\n")
    done = {}
    notdone = {}
    #
    while 1:
        line = fp.readline()
        if not line:
            break
        m = variable_rx.match(line)
        if m:
            n, v = m.group(1, 2)
            v = string.strip(v)
            if "$" in v:
                notdone[n] = v
            else:
                try: v = string.atoi(v)
                except ValueError: pass
                done[n] = v

    # do variable interpolation here
    findvar1_rx = re.compile(r"\$\(([A-Za-z][A-Za-z0-9_]*)\)")
    findvar2_rx = re.compile(r"\${([A-Za-z][A-Za-z0-9_]*)}")
    while notdone:
        for name in notdone.keys():
            value = notdone[name]
            m = findvar1_rx.search(value)
            if not m:
                m = findvar2_rx.search(value)
            if m:
                n = m.group(1)
                if done.has_key(n):
                    after = value[m.end():]
                    value = value[:m.start()] + done[n] + after
                    if "$" in after:
                        notdone[name] = value
                    else:
                        try: value = string.atoi(value)
                        except ValueError: pass
                        done[name] = string.strip(value)
                        del notdone[name]
                elif notdone.has_key(n):
                    # get it on a subsequent round
                    pass
                else:
                    done[n] = ""
                    after = value[m.end():]
                    value = value[:m.start()] + after
                    if "$" in after:
                        notdone[name] = value
                    else:
                        try: value = string.atoi(value)
                        except ValueError: pass
                        done[name] = string.strip(value)
                        del notdone[name]
            else:
                # bogus variable reference; just drop it since we can't deal
                del notdone[name]

    # save the results in the global dictionary
    g.update(done)
    return g


def _init_posix():
    """Initialize the module as appropriate for POSIX systems."""
    g = globals()
    # load the installed config.h:
    parse_config_h(open(get_config_h_filename()), g)
    # load the installed Makefile:
    parse_makefile(open(get_makefile_filename()), g)


def _init_nt():
    """Initialize the module as appropriate for NT"""
    g = globals()
    # load config.h, though I don't know how useful this is
    parse_config_h(open(get_config_h_filename()), g)
    # set basic install directories
    g['LIBDEST'] = os.path.join(exec_prefix, "Lib")
    g['BINLIBDEST'] = os.path.join(exec_prefix, "Lib")

    # XXX hmmm.. a normal install puts include files here
    g['INCLUDEPY'] = os.path.join(prefix, 'include')

    g['SO'] = '.pyd'
    g['exec_prefix'] = exec_prefix


def _init_mac():
    """Initialize the module as appropriate for Macintosh systems"""
    g = globals()
    # load the installed config.h (what if not installed? - still need to
    # be able to install packages which don't require compilation)
    parse_config_h(open(
            os.path.join(sys.exec_prefix, "Mac", "Include", "config.h")), g)
    # set basic install directories
    g['LIBDEST']=os.path.join(sys.exec_prefix, "Lib")
    g['BINLIBDEST']= os.path.join(sys.exec_prefix, "Mac", "Plugins")

    # XXX hmmm.. a normal install puts include files here
    g['INCLUDEPY'] = os.path.join (sys.prefix, 'Include' )

    g['SO'] = '.ppc.slb'
    g['exec_prefix'] = sys.exec_prefix
    print sys.prefix
    g['install_lib'] = os.path.join(sys.exec_prefix, "Lib")
    g['install_platlib'] = os.path.join(sys.exec_prefix, "Mac", "Lib")


try:
    exec "_init_" + os.name
except NameError:
    # not needed for this platform
    pass
else:
    exec "_init_%s()" % os.name


del _init_posix
del _init_nt
del _init_mac
