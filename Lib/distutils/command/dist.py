"""distutils.command.dist

Implements the Distutils 'dist' command (create a source distribution)."""

# created 1999/09/22, Greg Ward

__rcsid__ = "$Id$"

import sys, os, string, re
import fnmatch
from types import *
from glob import glob
from distutils.core import Command
from distutils.text_file import TextFile


# Possible modes of operation:
#   - require an explicit manifest that lists every single file (presumably
#     along with a way to auto-generate the manifest)
#   - require an explicit manifest, but allow it to have globs or
#     filename patterns of some kind (and also have auto-generation)
#   - allow an explict manifest, but automatically augment it at runtime
#     with the source files mentioned in 'packages', 'py_modules', and
#     'ext_modules' (and any other such things that might come along)

# I'm liking the third way.  Possible gotchas:
#   - redundant specification: 'packages' includes 'foo' and manifest
#     includes 'foo/*.py'
#   - obvious conflict: 'packages' includes 'foo' and manifest
#     includes '! foo/*.py' (can't imagine why you'd want this)
#   - subtle conflict:  'packages' includes 'foo' and manifest
#     includes '! foo/bar.py' (this could well be desired: eg. exclude
#     an experimental module from distribution)

# Syntax for the manifest file:
#   - if a line is just a Unix-style glob by itself, it's a "simple include
#     pattern": go find all files that match and add them to the list
#     of files
#   - if a line is a glob preceded by "!", then it's a "simple exclude
#     pattern": go over the current list of files and exclude any that
#     match the glob pattern
#   - if a line consists of a directory name followed by zero or more
#     glob patterns, then we'll recursively explore that directory tree
#     - the glob patterns can be include (no punctuation) or exclude
#       (prefixed by "!", no space)
#     - if no patterns given or the first pattern is not an include pattern,
#       then assume "*" -- ie. find everything (and then start applying
#       the rest of the patterns)
#     - the patterns are given in order of increasing precedence, ie.
#       the *last* one to match a given file applies to it
# 
# example (ignoring auto-augmentation!):
#   distutils/*.py
#   distutils/command/*.py
#   ! distutils/bleeding_edge.py
#   examples/*.py
#   examples/README
# 
# smarter way (that *will* include distutils/command/bleeding_edge.py!)
#   distutils *.py
#   ! distutils/bleeding_edge.py
#   examples !*~ !*.py[co]     (same as: examples * !*~ !*.py[co])
#   test test_* *.txt !*~ !*.py[co]
#   README
#   setup.py
#
# The actual Distutils manifest (don't need to mention source files,
# README, setup.py -- they're automatically distributed!):
#   examples !*~ !*.py[co]
#   test !*~ !*.py[co]

# The algorithm that will make it work:
#   files = stuff from 'packages', 'py_modules', 'ext_modules',
#     plus README, setup.py, ... ?
#   foreach pattern in manifest file:
#     if simple-include-pattern:         # "distutils/*.py"
#       files.append (glob (pattern))
#     elif simple-exclude-pattern:       # "! distutils/foo*"
#       xfiles = glob (pattern)
#       remove all xfiles from files
#     elif recursive-pattern:            # "examples" (just a directory name)
#       patterns = rest-of-words-on-line
#       dir_files = list of all files under dir
#       if patterns:
#         if patterns[0] is an exclude-pattern:
#           insert "*" at patterns[0]
#         for file in dir_files:
#           for dpattern in reverse (patterns):
#             if file matches dpattern:
#               if dpattern is an include-pattern:
#                 files.append (file)
#               else:
#                 nothing, don't include it
#               next file
#       else:
#         files.extend (dir_files)    # ie. accept all of them


# Anyways, this is all implemented below -- BUT it is largely untested; I
# know it works for the simple case of distributing the Distutils, but
# haven't tried it on more complicated examples.  Undoubtedly doing so will
# reveal bugs and cause delays, so I'm waiting until after I've released
# Distutils 0.1.


# Other things we need to look for in creating a source distribution:
#   - make sure there's a README
#   - make sure the distribution meta-info is supplied and non-empty
#     (*must* have name, version, ((author and author_email) or
#     (maintainer and maintainer_email)), url
#
# Frills:
#   - make sure the setup script is called "setup.py"
#   - make sure the README refers to "setup.py" (ie. has a line matching
#     /^\s*python\s+setup\.py/)

# A crazy idea that conflicts with having/requiring 'version' in setup.py:
#   - make sure there's a version number in the "main file" (main file
#     is __init__.py of first package, or the first module if no packages,
#     or the first extension module if no pure Python modules)
#   - XXX how do we look for __version__ in an extension module?
#   - XXX do we import and look for __version__? or just scan source for
#     /^__version__\s*=\s*"[^"]+"/ ?
#   - what about 'version_from' as an alternative to 'version' -- then
#     we know just where to search for the version -- no guessing about
#     what the "main file" is



class Dist (Command):

    options = [('formats=', 'f',
                "formats for source distribution (tar, ztar, gztar, or zip)"),
               ('manifest=', 'm',
                "name of manifest file"),
               ('list-only', 'l',
                "just list files that would be distributed"),
              ]

    default_format = { 'posix': 'gztar',
                       'nt': 'zip' }

    exclude_re = re.compile (r'\s*!\s*(\S+)') # for manifest lines


    def set_default_options (self):
        self.formats = None
        self.manifest = None
        self.list_only = 0


    def set_final_options (self):
        if self.formats is None:
            try:
                self.formats = [self.default_format[os.name]]
            except KeyError:
                raise DistutilsPlatformError, \
                      "don't know how to build source distributions on " + \
                      "%s platform" % os.name
        elif type (self.formats) is StringType:
            self.formats = string.split (self.formats, ',')

        if self.manifest is None:
            self.manifest = "MANIFEST"


    def run (self):

        self.check_metadata ()

        self.files = []
        self.find_defaults ()
        self.read_manifest ()

        if self.list_only:
            for f in self.files:
                print f

        else:
            self.make_distribution ()


    def check_metadata (self):

        dist = self.distribution

        missing = []
        for attr in ('name', 'version', 'url'):
            if not (hasattr (dist, attr) and getattr (dist, attr)):
                missing.append (attr)

        if missing:
            self.warn ("missing required meta-data: " +
                       string.join (missing, ", "))

        if dist.author:
            if not dist.author_email:
                self.warn ("missing meta-data: if 'author' supplied, " +
                           "'author_email' must be supplied too")
        elif dist.maintainer:
            if not dist.maintainer_email:
                self.warn ("missing meta-data: if 'maintainer' supplied, " +
                           "'maintainer_email' must be supplied too")
        else:
            self.warn ("missing meta-data: either author (and author_email) " +
                       "or maintainer (and maintainer_email) " +
                       "must be supplied")

    # check_metadata ()


    def find_defaults (self):

        standards = ['README', 'setup.py']
        for fn in standards:
            if os.path.exists (fn):
                self.files.append (fn)
            else:
                self.warn ("standard file %s not found" % fn)

        optional = ['test/test*.py']
        for pattern in optional:
            files = filter (os.path.isfile, glob (pattern))
            if files:
                self.files.extend (files)

        if self.distribution.packages or self.distribution.py_modules:
            build_py = self.find_peer ('build_py')
            build_py.ensure_ready ()
            self.files.extend (build_py.get_source_files ())

        if self.distribution.ext_modules:
            build_ext = self.find_peer ('build_ext')
            build_ext.ensure_ready ()
            self.files.extend (build_ext.get_source_files ())



    def open_manifest (self, filename):
        return TextFile (filename,
                         strip_comments=1,
                         skip_blanks=1,
                         join_lines=1,
                         lstrip_ws=1,
                         rstrip_ws=1,
                         collapse_ws=1)


    def search_dir (self, dir, patterns):

        allfiles = findall (dir)
        if patterns:
            if patterns[0][0] == "!":   # starts with an exclude spec?
                patterns.insert (0, "*")# then accept anything that isn't
                                        # explicitly excluded

            act_patterns = []           # "action-patterns": (include,regexp)
                                        # tuples where include is a boolean
            for pattern in patterns:
                if pattern[0] == '!':
                    act_patterns.append \
                        ((0, re.compile (fnmatch.translate (pattern[1:]))))
                else:
                    act_patterns.append \
                        ((1, re.compile (fnmatch.translate (pattern))))
            act_patterns.reverse()


            files = []
            for file in allfiles:
                for (include,regexp) in act_patterns:
                    if regexp.match (file):
                        if include:
                            files.append (file)
                        break           # continue to next file
        else:
            files = allfiles

        return files

    # search_dir ()


    def exclude_files (self, pattern):

        regexp = re.compile (fnmatch.translate (pattern))
        for i in range (len (self.files)-1, -1, -1):
            if regexp.match (self.files[i]):
                del self.files[i]


    def read_manifest (self):

        # self.files had better already be defined (and hold the
        # "automatically found" files -- Python modules and extensions,
        # README, setup script, ...)
        assert self.files is not None

        manifest = self.open_manifest (self.manifest)
        while 1:

            pattern = manifest.readline()
            if pattern is None:            # end of file
                break

            # Cases:
            #   1) simple-include: "*.py", "foo/*.py", "doc/*.html", "FAQ"
            #   2) simple-exclude: same, prefaced by !
            #   3) recursive: multi-word line, first word a directory

            exclude = self.exclude_re.match (pattern)
            if exclude:
                pattern = exclude.group (1)

            words = string.split (pattern)
            assert words                # must have something!
            if os.name != 'posix':
                words[0] = apply (os.path.join, string.split (words[0], '/'))

            # First word is a directory, possibly with include/exclude
            # patterns making up the rest of the line: it's a recursive
            # pattern
            if os.path.isdir (words[0]):
                if exclude:
                    file.warn ("exclude (!) doesn't apply to " +
                               "whole directory trees")
                    continue

                dir_files = self.search_dir (words[0], words[1:])
                self.files.extend (dir_files)

            # Multiple words in pattern: that's a no-no unless the first
            # word is a directory name
            elif len (words) > 1:
                file.warn ("can't have multiple words unless first word " +
                           "('%s') is a directory name" % words[0])
                continue

            # Single word, no bang: it's a "simple include pattern"
            elif not exclude:
                matches = filter (os.path.isfile, glob (pattern))
                if matches:
                    self.files.extend (matches)
                else:
                    manifest.warn ("no matches for '%s' found" % pattern)


            # Single word prefixed with a bang: it's a "simple exclude pattern"
            else:
                if self.exclude_files (pattern) == 0:
                    file.warn ("no files excluded by '%s'" % pattern)

            # if/elif/.../else on 'pattern'

        # loop over lines of 'manifest'

    # read_manifest ()


    def make_release_tree (self, base_dir, files):

        # XXX this is Unix-specific

        # First get the list of directories to create
        need_dir = {}
        for file in files:
            need_dir[os.path.join (base_dir, os.path.dirname (file))] = 1
        need_dirs = need_dir.keys()
        need_dirs.sort()

        # Now create them
        for dir in need_dirs:
            self.mkpath (dir)

        # And walk over the list of files, making a hard link for
        # each one that doesn't already exist in its corresponding
        # location under 'base_dir'
    
        self.announce ("making hard links in %s..." % base_dir)
        for file in files:
            dest = os.path.join (base_dir, file)
            if not os.path.exists (dest):
                self.execute (os.link, (file, dest),
                              "linking %s -> %s" % (file, dest))
    # make_release_tree ()


    def make_tarball (self, base_dir):

        # XXX GNU tar 1.13 has a nifty option to add a prefix directory.
        # It's pretty new, though, so we certainly can't require it -- but
        # it would be nice to take advantage of it to skip the "create a
        # tree of hardlinks" step!

        # But I am a lazy bastard, so I require GNU tar anyways.

        archive_name = base_dir + ".tar.gz"
        self.spawn (["tar", "-czf", archive_name, base_dir])


    def make_zipfile (self, base_dir):

        # This assumes the Unix 'zip' utility -- it could be easily recast
        # to use pkzip (or whatever the command-line zip creation utility
        # on Redmond's archaic CP/M knockoff is nowadays), but I'll let
        # someone who can actually test it do that.

        self.spawn (["zip", "-r", base_dir + ".zip", base_dir])


    def make_distribution (self):

        # Don't warn about missing meta-data here -- should be done
        # elsewhere.
        name = self.distribution.name or "UNKNOWN"
        version = self.distribution.version

        if version:
            base_dir = "%s-%s" % (name, version)
        else:
            base_dir = name

        # Remove any files that match "base_dir" from the fileset -- we
        # don't want to go distributing the distribution inside itself!
        self.exclude_files (base_dir + "*")
 
        self.make_release_tree (base_dir, self.files)
        if 'gztar' in self.formats:
            self.make_tarball (base_dir)
        if 'zip' in self.formats:
            self.make_zipfile (base_dir)

# class Dist


# ----------------------------------------------------------------------
# Utility functions

def findall (dir = os.curdir):
    """Find all files under 'dir' and return the sorted list of full
       filenames (relative to 'dir')."""

    list = []
    stack = [dir]
    pop = stack.pop
    push = stack.append

    while stack:
        dir = pop()
        names = os.listdir (dir)

        for name in names:
            fullname = os.path.join (dir, name)
            list.append (fullname)
            if os.path.isdir (fullname) and not os.path.islink(fullname):
                push (fullname)

    list.sort()
    return list





# ======================================================================
# Here follows some extensive mental masturbation about how to
# make the manifest file and search algorithm even more complex.
# I think this is all gratuitous, really.

# Hmm, something extra: want to apply an exclude pattern over a whole
# subtree without necessarily having to explicitly include files from it,
# ie. it should apply after gathering files by other means (simple
# include pattern)
#   . !*~ !*.bak !#*#
# and we also want to prune at certain directories:
#   . !RCS !CVS
# which again should apply globally.
#
# possible solution:
#   - exclude pattern in a directory applies to all files found under that
#     directory
#   - subdirectories that match an exclude pattern will be pruned
#   - hmmm, to be consistent, subdirectories that match an include
#     pattern should be recursively included
#   - and this should apply to "simple" patterns too
#
# thus:
#
#     examples/
#
# means get everything in examples/ and all subdirs;
#
#     examples/ !*~ !#*# !*.py[co]
#
# means get everything under examples/ except files matching those three globs;
#
#     ./ !RCS !CVS
#
# means get everything under current dir, but prune RCS/CVS directories;
#
#     ./ !*~ !#*# !*.py[co] !RCS !CVS
#     ! build/
#     ! experimental/
#
# means get everything under the distribution directory except the usual
# excludes at all levels; exclude "build" and "experimental" under the
# distribution dir only.
#
# Do the former examples still work?
#
#     distutils/ *.py
#     ! distutils/bleeding_edge.py
#
# means all .py files recursively found under distutils, except for the one
# explicitly named.
#
#     distutils/ *.py !bleeding_edge.py
#
# means the same, except bleeding_edge.py will be excluded wherever it's
# found -- thus this can exclude up to one file per directory under
# distutils.
#
#     distutils/*.py
#     ! distutils/bleeding_edge.py
#
# gets exactly distutils/*.py, minus the one explicitly mentioned exclude, and
#
#     distutils/*.py
#     distutils/ !bleeding_edge.py
#
# coincidentally does the same, but only because there can only be one file
# that matches the exclude pattern.  Oh, we'd still like
#
#     distutils *.py !bleeding*.py
#     distutils/bleeding_ledge.py
#
# to include distutils/bleeding_ledge.py -- i.e. it should override the
# earlier exclude pattern by virtue of appearing later in the manifest.  Does
# this conflict with the above requirements, ie. that "!RCS" and "!*~" should
# apply everywhere?  Hmm, I think it doesn't have to, as long as we're smart
# about it.  Consequence:
#
#     . !RCS !CVS
#     distutils *
#
# will go ahead and include RCS and CVS files under distutils, but
#
#     distutils *
#     . !RCS !CVS
#
# will do the right thing.  Hmmm.  I think that's OK, and an inevitable
# consequence of the ability to override exclusions.

# OK, new crack at the search algorithm.
#
#   for pattern in manifest:
#     if dir-pattern:             # ie. first word is a directory (incl. "."!)
#       dir = first word on line
#       patterns = rest of line
#       if patterns:
#         for dpattern in patterns:
#           if exclude-pattern:
#             remove from files anything matching dpattern (including pruning
#             subtrees rooted at directories that match dpattern)
#           else:
#             files.append (recursive_glob (dir, dpattern))
#       else:
#         files.append (recursive_glob (dir, '*')
#
#     elif include-pattern:       # it's a "simple include pattern"
#       files.append (glob (pattern))
#
#     else:                    # it's a "simple exclude pattern"
#       remove from files anything matching pattern

# The two removal algorithms might be a bit tricky:
#
#   "remove simple exclude pattern":
#     for f in files:
#       if f matches pattern:
#         delete it
# 
#   "remove recursive exclude pattern":
#     for f in files:
#
#       t = tail (f)
#       while t:
#         if t matches pattern:
#           delete current file
#           continue
#         t = tail (t)
#
# Well, that was an interesting mental exercise.  I'm not completely
# convinced it will work, nor am I convinced this level of complexity
# is necessary.  If you want to exclude RCS or CVS directories, just
# don't bloody include them!


