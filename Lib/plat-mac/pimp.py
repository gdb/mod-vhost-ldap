"""Package Install Manager for Python.

This is currently a MacOSX-only strawman implementation. 
Motto: "He may be shabby, but he gets you what you need" :-) 

Tools to allow easy installation of packages. The idea is that there is
an online XML database per (platform, python-version) containing packages
known to work with that combination. This module contains tools for getting
and parsing the database, testing whether packages are installed, computing
dependencies and installing packages.

There is a minimal main program that works as a command line tool, but the
intention is that the end user will use this through a GUI.
"""
import sys
import os
import urllib
import urlparse
import plistlib
import distutils.util
import distutils.sysconfig
import md5

__all__ = ["PimpPreferences", "PimpDatabase", "PimpPackage", "main"]

_scriptExc_NotInstalled = "pimp._scriptExc_NotInstalled"
_scriptExc_OldInstalled = "pimp._scriptExc_OldInstalled"
_scriptExc_BadInstalled = "pimp._scriptExc_BadInstalled"

NO_EXECUTE=0

PIMP_VERSION="0.1"

# Flavors:
# source: setup-based package
# binary: tar (or other) archive created with setup.py bdist.
DEFAULT_FLAVORORDER=['source', 'binary']
DEFAULT_DOWNLOADDIR='/tmp'
DEFAULT_BUILDDIR='/tmp'
DEFAULT_INSTALLDIR=distutils.sysconfig.get_python_lib()
DEFAULT_PIMPDATABASE="http://www.cwi.nl/~jack/pimp/pimp-%s.plist" % distutils.util.get_platform()

ARCHIVE_FORMATS = [
	(".tar.Z", "zcat \"%s\" | tar -xf -"),
	(".taz", "zcat \"%s\" | tar -xf -"),
	(".tar.gz", "zcat \"%s\" | tar -xf -"),
	(".tgz", "zcat \"%s\" | tar -xf -"),
	(".tar.bz", "bzcat \"%s\" | tar -xf -"),
	(".zip", "unzip \"%s\""),
]

class MyURLopener(urllib.FancyURLopener):
	"""Like FancyURLOpener, but we do want to get errors as exceptions."""
	def http_error_default(self, url, fp, errcode, errmsg, headers):
		urllib.URLopener.http_error_default(self, url, fp, errcode, errmsg, headers)

class PimpPreferences:
	"""Container for per-user preferences, such as the database to use
	and where to install packages."""
	
	def __init__(self, 
			flavorOrder=None,
			downloadDir=None,
			buildDir=None,
			installDir=None,
			pimpDatabase=None):
		if not flavorOrder:
			flavorOrder = DEFAULT_FLAVORORDER
		if not downloadDir:
			downloadDir = DEFAULT_DOWNLOADDIR
		if not buildDir:
			buildDir = DEFAULT_BUILDDIR
		if not installDir:
			installDir = DEFAULT_INSTALLDIR
		if not pimpDatabase:
			pimpDatabase = DEFAULT_PIMPDATABASE
		self.flavorOrder = flavorOrder
		self.downloadDir = downloadDir
		self.buildDir = buildDir
		self.installDir = installDir
		self.pimpDatabase = pimpDatabase
		
	def check(self):
		"""Check that the preferences make sense: directories exist and are
		writable, the install directory is on sys.path, etc."""
		
		rv = ""
		RWX_OK = os.R_OK|os.W_OK|os.X_OK
		if not os.path.exists(self.downloadDir):
			rv += "Warning: Download directory \"%s\" does not exist\n" % self.downloadDir
		elif not os.access(self.downloadDir, RWX_OK):
			rv += "Warning: Download directory \"%s\" is not writable or not readable\n" % self.downloadDir
		if not os.path.exists(self.buildDir):
			rv += "Warning: Build directory \"%s\" does not exist\n" % self.buildDir
		elif not os.access(self.buildDir, RWX_OK):
			rv += "Warning: Build directory \"%s\" is not writable or not readable\n" % self.buildDir
		if not os.path.exists(self.installDir):
			rv += "Warning: Install directory \"%s\" does not exist\n" % self.installDir
		elif not os.access(self.installDir, RWX_OK):
			rv += "Warning: Install directory \"%s\" is not writable or not readable\n" % self.installDir
		else:
			installDir = os.path.realpath(self.installDir)
			for p in sys.path:
				try:
					realpath = os.path.realpath(p)
				except:
					pass
				if installDir == realpath:
					break
			else:
				rv += "Warning: Install directory \"%s\" is not on sys.path\n" % self.installDir
		return rv			
		
	def compareFlavors(self, left, right):
		"""Compare two flavor strings. This is part of your preferences
		because whether the user prefers installing from source or binary is."""
		if left in self.flavorOrder:
			if right in self.flavorOrder:
				return cmp(self.flavorOrder.index(left), self.flavorOrder.index(right))
			return -1
		if right in self.flavorOrder:
			return 1
		return cmp(left, right)
		
class PimpDatabase:
	"""Class representing a pimp database. It can actually contain
	information from multiple databases through inclusion, but the
	toplevel database is considered the master, as its maintainer is
	"responsible" for the contents."""
	
	def __init__(self, prefs):
		self._packages = []
		self.preferences = prefs
		self._urllist = []
		self._version = ""
		self._maintainer = ""
		self._description = ""
		
	def close(self):
		"""Clean up"""
		self._packages = []
		self.preferences = None
		
	def appendURL(self, url, included=0):
		"""Append packages from the database with the given URL.
		Only the first database should specify included=0, so the
		global information (maintainer, description) get stored."""
		
		if url in self._urllist:
			return
		self._urllist.append(url)
		fp = MyURLopener().open(url).fp
		dict = plistlib.Plist.fromFile(fp)
		# Test here for Pimp version, etc
		if not included:
			self._version = dict.get('Version', '0.1')
			if self._version != PIMP_VERSION:
				sys.stderr.write("Warning: database version %s does not match %s\n" 
					% (self._version, PIMP_VERSION))
			self._maintainer = dict.get('Maintainer', '')
			self._description = dict.get('Description', '')
		self._appendPackages(dict['Packages'])
		others = dict.get('Include', [])
		for url in others:
			self.appendURL(url, included=1)
		
	def _appendPackages(self, packages):
		"""Given a list of dictionaries containing package
		descriptions create the PimpPackage objects and append them
		to our internal storage."""
		
		for p in packages:
			p = dict(p)
			flavor = p.get('Flavor')
			if flavor == 'source':
				pkg = PimpPackage_source(self, p)
			elif flavor == 'binary':
				pkg = PimpPackage_binary(self, p)
			else:
				pkg = PimpPackage(self, dict(p))
			self._packages.append(pkg)
			
	def list(self):
		"""Return a list of all PimpPackage objects in the database."""
		
		return self._packages
		
	def listnames(self):
		"""Return a list of names of all packages in the database."""
		
		rv = []
		for pkg in self._packages:
			rv.append(pkg.fullname())
		rv.sort()
		return rv
		
	def dump(self, pathOrFile):
		"""Dump the contents of the database to an XML .plist file.
		
		The file can be passed as either a file object or a pathname.
		All data, including included databases, is dumped."""
		
		packages = []
		for pkg in self._packages:
			packages.append(pkg.dump())
		dict = {
			'Version': self._version,
			'Maintainer': self._maintainer,
			'Description': self._description,
			'Packages': packages
			}
		plist = plistlib.Plist(**dict)
		plist.write(pathOrFile)
		
	def find(self, ident):
		"""Find a package. The package can be specified by name
		or as a dictionary with name, version and flavor entries.
		
		Only name is obligatory. If there are multiple matches the
		best one (higher version number, flavors ordered according to
		users' preference) is returned."""
		
		if type(ident) == str:
			# Remove ( and ) for pseudo-packages
			if ident[0] == '(' and ident[-1] == ')':
				ident = ident[1:-1]
			# Split into name-version-flavor
			fields = ident.split('-')
			if len(fields) < 1 or len(fields) > 3:
				return None
			name = fields[0]
			if len(fields) > 1:
				version = fields[1]
			else:
				version = None
			if len(fields) > 2:
				flavor = fields[2]
			else:
				flavor = None
		else:
			name = ident['Name']
			version = ident.get('Version')
			flavor = ident.get('Flavor')
		found = None
		for p in self._packages:
			if name == p.name() and \
					(not version or version == p.version()) and \
					(not flavor or flavor == p.flavor()):
				if not found or found < p:
					found = p
		return found
		
ALLOWED_KEYS = [
	"Name",
	"Version",
	"Flavor",
	"Description",
	"Home-page",
	"Download-URL",
	"Install-test",
	"Install-command",
	"Pre-install-command",
	"Post-install-command",
	"Prerequisites",
	"MD5Sum"
]

class PimpPackage:
	"""Class representing a single package."""
	
	def __init__(self, db, dict):
		self._db = db
		name = dict["Name"]
		for k in dict.keys():
			if not k in ALLOWED_KEYS:
				sys.stderr.write("Warning: %s: unknown key %s\n" % (name, k))
		self._dict = dict
	
	def __getitem__(self, key):
		return self._dict[key]
		
	def name(self): return self._dict['Name']
	def version(self): return self._dict['Version']
	def flavor(self): return self._dict['Flavor']
	def description(self): return self._dict['Description']
	def homepage(self): return self._dict.get('Home-page')
	def downloadURL(self): return self._dict['Download-URL']
	
	def fullname(self):
		"""Return the full name "name-version-flavor" of a package.
		
		If the package is a pseudo-package, something that cannot be
		installed through pimp, return the name in (parentheses)."""
		
		rv = self._dict['Name']
		if self._dict.has_key('Version'):
			rv = rv + '-%s' % self._dict['Version']
		if self._dict.has_key('Flavor'):
			rv = rv + '-%s' % self._dict['Flavor']
		if not self._dict.get('Download-URL'):
			# Pseudo-package, show in parentheses
			rv = '(%s)' % rv
		return rv
	
	def dump(self):
		"""Return a dict object containing the information on the package."""
		return self._dict
		
	def __cmp__(self, other):
		"""Compare two packages, where the "better" package sorts lower."""
		
		if not isinstance(other, PimpPackage):
			return cmp(id(self), id(other))
		if self.name() != other.name():
			return cmp(self.name(), other.name())
		if self.version() != other.version():
			return -cmp(self.version(), other.version())
		return self._db.preferences.compareFlavors(self.flavor(), other.flavor())
		
	def installed(self):
		"""Test wheter the package is installed.
		
		Returns two values: a status indicator which is one of
		"yes", "no", "old" (an older version is installed) or "bad"
		(something went wrong during the install test) and a human
		readable string which may contain more details."""
		
		namespace = {
			"NotInstalled": _scriptExc_NotInstalled,
			"OldInstalled": _scriptExc_OldInstalled,
			"BadInstalled": _scriptExc_BadInstalled,
			"os": os,
			"sys": sys,
			}
		installTest = self._dict['Install-test'].strip() + '\n'
		try:
			exec installTest in namespace
		except ImportError, arg:
			return "no", str(arg)
		except _scriptExc_NotInstalled, arg:
			return "no", str(arg)
		except _scriptExc_OldInstalled, arg:
			return "old", str(arg)
		except _scriptExc_BadInstalled, arg:
			return "bad", str(arg)
		except:
			sys.stderr.write("-------------------------------------\n")
			sys.stderr.write("---- %s: install test got exception\n" % self.fullname())
			sys.stderr.write("---- source:\n")
			sys.stderr.write(installTest)
			sys.stderr.write("---- exception:\n")
			import traceback
			traceback.print_exc(file=sys.stderr)
			if self._db._maintainer:
				sys.stderr.write("---- Please copy this and mail to %s\n" % self._db._maintainer)
			sys.stderr.write("-------------------------------------\n")
			return "bad", "Package install test got exception"
		return "yes", ""
		
	def prerequisites(self):
		"""Return a list of prerequisites for this package.
		
		The list contains 2-tuples, of which the first item is either
		a PimpPackage object or None, and the second is a descriptive
		string. The first item can be None if this package depends on
		something that isn't pimp-installable, in which case the descriptive
		string should tell the user what to do."""
		
		rv = []
		if not self._dict.get('Download-URL'):
			return [(None, 
				"%s: This package needs to be installed manually (no Download-URL field)" %
					self.fullname())]
		if not self._dict.get('Prerequisites'):
			return []
		for item in self._dict['Prerequisites']:
			if type(item) == str:
				pkg = None
				descr = str(item)
			else:
				name = item['Name']
				if item.has_key('Version'):
					name = name + '-' + item['Version']
				if item.has_key('Flavor'):
					name = name + '-' + item['Flavor']
				pkg = self._db.find(name)
				if not pkg:
					descr = "Requires unknown %s"%name
				else:
					descr = pkg.description()
			rv.append((pkg, descr))
		return rv
			
	def _cmd(self, output, dir, *cmditems):
		"""Internal routine to run a shell command in a given directory."""
		
		cmd = ("cd \"%s\"; " % dir) + " ".join(cmditems)
		if output:
			output.write("+ %s\n" % cmd)
		if NO_EXECUTE:
			return 0
		dummy, fp = os.popen4(cmd, "r")
		dummy.close()
		while 1:
			line = fp.readline()
			if not line:
				break
			if output:
				output.write(line)
		rv = fp.close()
		return rv
		
	def downloadPackageOnly(self, output=None):
		"""Download a single package, if needed.
		
		An MD5 signature is used to determine whether download is needed,
		and to test that we actually downloaded what we expected.
		If output is given it is a file-like object that will receive a log
		of what happens.
		
		If anything unforeseen happened the method returns an error message
		string.
		"""
		
		scheme, loc, path, query, frag = urlparse.urlsplit(self._dict['Download-URL'])
		path = urllib.url2pathname(path)
		filename = os.path.split(path)[1]
		self.archiveFilename = os.path.join(self._db.preferences.downloadDir, filename)			
		if not self._archiveOK():
			if scheme == 'manual':
				return "Please download package manually and save as %s" % self.archiveFilename
			if self._cmd(output, self._db.preferences.downloadDir,
					"curl",
					"--output", self.archiveFilename,
					self._dict['Download-URL']):
				return "download command failed"
		if not os.path.exists(self.archiveFilename) and not NO_EXECUTE:
			return "archive not found after download"
		if not self._archiveOK():
			return "archive does not have correct MD5 checksum"
			
	def _archiveOK(self):
		"""Test an archive. It should exist and the MD5 checksum should be correct."""
		
		if not os.path.exists(self.archiveFilename):
			return 0
		if not self._dict.get('MD5Sum'):
			sys.stderr.write("Warning: no MD5Sum for %s\n" % self.fullname())
			return 1
		data = open(self.archiveFilename, 'rb').read()
		checksum = md5.new(data).hexdigest()
		return checksum == self._dict['MD5Sum']
			
	def unpackPackageOnly(self, output=None):
		"""Unpack a downloaded package archive."""
		
		filename = os.path.split(self.archiveFilename)[1]
		for ext, cmd in ARCHIVE_FORMATS:
			if filename[-len(ext):] == ext:
				break
		else:
			return "unknown extension for archive file: %s" % filename
		self.basename = filename[:-len(ext)]
		cmd = cmd % self.archiveFilename
		if self._cmd(output, self._db.preferences.buildDir, cmd):
			return "unpack command failed"
			
	def installPackageOnly(self, output=None):
		"""Default install method, to be overridden by subclasses"""
		return "%s: This package needs to be installed manually (no support for flavor=\"%s\")" \
			% (self.fullname(), self._dict.get(flavor, ""))
			
	def installSinglePackage(self, output=None):
		"""Download, unpack and install a single package.
		
		If output is given it should be a file-like object and it
		will receive a log of what happened."""
		
		if not self._dict['Download-URL']:
			return "%s: This package needs to be installed manually (no Download-URL field)" % _fmtpackagename(self)
		msg = self.downloadPackageOnly(output)
		if msg:
			return "%s: download: %s" % (self.fullname(), msg)
			
		msg = self.unpackPackageOnly(output)
		if msg:
			return "%s: unpack: %s" % (self.fullname(), msg)
			
		return self.installPackageOnly(output)
		
	def beforeInstall(self):
		"""Bookkeeping before installation: remember what we have in site-packages"""
		self._old_contents = os.listdir(self._db.preferences.installDir)
		
	def afterInstall(self):
		"""Bookkeeping after installation: interpret any new .pth files that have
		appeared"""
				
		new_contents = os.listdir(self._db.preferences.installDir)
		for fn in new_contents:
			if fn in self._old_contents:
				continue
			if fn[-4:] != '.pth':
				continue
			fullname = os.path.join(self._db.preferences.installDir, fn)
			f = open(fullname)
			for line in f.readlines():
				if not line:
					continue
				if line[0] == '#':
					continue
				if line[:6] == 'import':
					exec line
					continue
				if line[-1] == '\n':
					line = line[:-1]
				if not os.path.isabs(line):
					line = os.path.join(self._db.preferences.installDir, line)
				line = os.path.realpath(line)
				if not line in sys.path:
					sys.path.append(line)			

class PimpPackage_binary(PimpPackage):

	def unpackPackageOnly(self, output=None):
		"""We don't unpack binary packages until installing"""
		pass
			
	def installPackageOnly(self, output=None):
		"""Install a single source package.
		
		If output is given it should be a file-like object and it
		will receive a log of what happened."""
		print 'PimpPackage_binary installPackageOnly'
					
		msgs = []
		if self._dict.has_key('Pre-install-command'):
			msg.append("%s: Pre-install-command ignored" % self.fullname())
		if self._dict.has_key('Install-command'):
			msgs.append("%s: Install-command ignored" % self.fullname())
		if self._dict.has_key('Post-install-command'):
			msgs.append("%s: Post-install-command ignored" % self.fullname())
					
		self.beforeInstall()

		# Install by unpacking
		filename = os.path.split(self.archiveFilename)[1]
		for ext, cmd in ARCHIVE_FORMATS:
			if filename[-len(ext):] == ext:
				break
		else:
			return "unknown extension for archive file: %s" % filename
		
		# Extract the files in the root folder.
		cmd = cmd % self.archiveFilename
		if self._cmd(output, "/", cmd):
			return "unpack command failed"
		
		self.afterInstall()
		
		if self._dict.has_key('Post-install-command'):
			if self._cmd(output, self._buildDirname, self._dict['Post-install-command']):
				return "post-install %s: running \"%s\" failed" % \
					(self.fullname(), self._dict['Post-install-command'])
		return None
		
	
class PimpPackage_source(PimpPackage):

	def unpackPackageOnly(self, output=None):
		"""Unpack a source package and check that setup.py exists"""
		PimpPackage.unpackPackageOnly(self, output)
		# Test that a setup script has been create
		self._buildDirname = os.path.join(self._db.preferences.buildDir, self.basename)
		setupname = os.path.join(self._buildDirname, "setup.py")
		if not os.path.exists(setupname) and not NO_EXECUTE:
			return "no setup.py found after unpack of archive"

	def installPackageOnly(self, output=None):
		"""Install a single source package.
		
		If output is given it should be a file-like object and it
		will receive a log of what happened."""
					
		if self._dict.has_key('Pre-install-command'):
			if self._cmd(output, self._buildDirname, self._dict['Pre-install-command']):
				return "pre-install %s: running \"%s\" failed" % \
					(self.fullname(), self._dict['Pre-install-command'])
					
		self.beforeInstall()
		installcmd = self._dict.get('Install-command')
		if not installcmd:
			installcmd = '"%s" setup.py install' % sys.executable
		if self._cmd(output, self._buildDirname, installcmd):
			return "install %s: running \"%s\" failed" % self.fullname()
		
		self.afterInstall()
		
		if self._dict.has_key('Post-install-command'):
			if self._cmd(output, self._buildDirname, self._dict['Post-install-command']):
				return "post-install %s: running \"%s\" failed" % \
					(self.fullname(), self._dict['Post-install-command'])
		return None
		
	
class PimpInstaller:
	"""Installer engine: computes dependencies and installs
	packages in the right order."""
	
	def __init__(self, db):
		self._todo = []
		self._db = db
		self._curtodo = []
		self._curmessages = []
		
	def __contains__(self, package):
		return package in self._todo
		
	def _addPackages(self, packages):
		for package in packages:
			if not package in self._todo:
				self._todo.insert(0, package)
			
	def _prepareInstall(self, package, force=0, recursive=1):
		"""Internal routine, recursive engine for prepareInstall.
		
		Test whether the package is installed and (if not installed
		or if force==1) prepend it to the temporary todo list and
		call ourselves recursively on all prerequisites."""
		
		if not force:
			status, message = package.installed()
			if status == "yes":
				return 
		if package in self._todo or package in self._curtodo:
			return
		self._curtodo.insert(0, package)
		if not recursive:
			return
		prereqs = package.prerequisites()
		for pkg, descr in prereqs:
			if pkg:
				self._prepareInstall(pkg, force, recursive)
			else:
				self._curmessages.append("Requires: %s" % descr)
				
	def prepareInstall(self, package, force=0, recursive=1):
		"""Prepare installation of a package.
		
		If the package is already installed and force is false nothing
		is done. If recursive is true prerequisites are installed first.
		
		Returns a list of packages (to be passed to install) and a list
		of messages of any problems encountered.
		"""
		
		self._curtodo = []
		self._curmessages = []
		self._prepareInstall(package, force, recursive)
		rv = self._curtodo, self._curmessages
		self._curtodo = []
		self._curmessages = []
		return rv
		
	def install(self, packages, output):
		"""Install a list of packages."""
		
		self._addPackages(packages)
		status = []
		for pkg in self._todo:
			msg = pkg.installSinglePackage(output)
			if msg:
				status.append(msg)
		return status
		
		
	
def _run(mode, verbose, force, args):
	"""Engine for the main program"""
	
	prefs = PimpPreferences()
	prefs.check()
	db = PimpDatabase(prefs)
	db.appendURL(prefs.pimpDatabase)
	
	if mode == 'dump':
		db.dump(sys.stdout)
	elif mode =='list':
		if not args:
			args = db.listnames()
		print "%-20.20s\t%s" % ("Package", "Description")
		print
		for pkgname in args:
			pkg = db.find(pkgname)
			if pkg:
				description = pkg.description()
				pkgname = pkg.fullname()
			else:
				description = 'Error: no such package'
			print "%-20.20s\t%s" % (pkgname, description)
			if verbose:
				print "\tHome page:\t", pkg.homepage()
				print "\tDownload URL:\t", pkg.downloadURL()
	elif mode =='status':
		if not args:
			args = db.listnames()
			print "%-20.20s\t%s\t%s" % ("Package", "Installed", "Message")
			print
		for pkgname in args:
			pkg = db.find(pkgname)
			if pkg:
				status, msg = pkg.installed()
				pkgname = pkg.fullname()
			else:
				status = 'error'
				msg = 'No such package'
			print "%-20.20s\t%-9.9s\t%s" % (pkgname, status, msg)
			if verbose and status == "no":
				prereq = pkg.prerequisites()
				for pkg, msg in prereq:
					if not pkg:
						pkg = ''
					else:
						pkg = pkg.fullname()
					print "%-20.20s\tRequirement: %s %s" % ("", pkg, msg)
	elif mode == 'install':
		if not args:
			print 'Please specify packages to install'
			sys.exit(1)
		inst = PimpInstaller(db)
		for pkgname in args:
			pkg = db.find(pkgname)
			if not pkg:
				print '%s: No such package' % pkgname
				continue
			list, messages = inst.prepareInstall(pkg, force)
			if messages and not force:
				print "%s: Not installed:" % pkgname
				for m in messages:
					print "\t", m
			else:
				if verbose:
					output = sys.stdout
				else:
					output = None
				messages = inst.install(list, output)
				if messages:
					print "%s: Not installed:" % pkgname
					for m in messages:
						print "\t", m

def main():
	"""Minimal commandline tool to drive pimp."""
	
	import getopt
	def _help():
		print "Usage: pimp [-v] -s [package ...]  List installed status"
		print "       pimp [-v] -l [package ...]  Show package information"
		print "       pimp [-vf] -i package ...   Install packages"
		print "       pimp -d                     Dump database to stdout"
		print "Options:"
		print "       -v  Verbose"
		print "       -f  Force installation"
		sys.exit(1)
		
	try:
		opts, args = getopt.getopt(sys.argv[1:], "slifvd")
	except getopt.Error:
		_help()
	if not opts and not args:
		_help()
	mode = None
	force = 0
	verbose = 0
	for o, a in opts:
		if o == '-s':
			if mode:
				_help()
			mode = 'status'
		if o == '-l':
			if mode:
				_help()
			mode = 'list'
		if o == '-d':
			if mode:
				_help()
			mode = 'dump'
		if o == '-i':
			mode = 'install'
		if o == '-f':
			force = 1
		if o == '-v':
			verbose = 1
	if not mode:
		_help()
	_run(mode, verbose, force, args)
				
if __name__ == '__main__':
	main()
	
	