#! /ufs/guido/bin/sgi/python

# Mirror a remote ftp subtree into a local directory tree.
# Basic usage: ftpmirror [options] host remotedir localdir
#
# XXX To do:
# - handle symbolic links
# - back up .mirrorinfo before overwriting
# - use pickles for .mirrorinfo?

import os
import sys
import time
import getopt
import string
import ftplib
from fnmatch import fnmatch

usage_msg = """
usage: ftpmirror [-v] [-q] [-i] [-m] [-n] [-r] [-s pat]
                 [-l username [-p passwd [-a account]]]
		 hostname [remotedir [localdir]]
-v: verbose
-q: quiet
-i: interactive mode
-m: macintosh server (NCSA telnet 2.4) (implies -n -s '*.o')
-n: don't log in
-r: remove files no longer pertinent
-l username [-p passwd [-a account]]: login info (default anonymous ftp)
-s pat: skip files matching pattern
hostname: remote host
remotedir: remote directory (default initial)
localdir: local directory (default current)
"""
def usage(*args):
	sys.stdout = sys.stderr
	for msg in args: print msg
	print usage_msg
	sys.exit(2)

verbose = 1 # 0 for -q, 2 for -v
interactive = 0
mac = 0
rmok = 0
nologin = 0
skippats = ['.', '..', '.mirrorinfo']

def main():
	global verbose, interactive, mac, rmok, nologin
	try:
		opts, args = getopt.getopt(sys.argv[1:], 'a:bil:mnp:qrs:v')
	except getopt.error, msg:
		usage(msg)
	login = ''
	passwd = ''
	account = ''
	for o, a in opts:
		if o == '-l': login = a
		if o == '-p': passwd = a
		if o == '-a': account = a
		if o == '-v': verbose = verbose + 1
		if o == '-q': verbose = 0
		if o == '-i': interactive = 1
		if o == '-m': mac = 1; nologin = 1; skippats.append('*.o')
		if o == '-n': nologin = 1
		if o == '-r': rmok = 1
		if o == '-s': skippats.append(a)
	if not args: usage('hostname missing')
	host = args[0]
	remotedir = ''
	localdir = ''
	if args[1:]:
		remotedir = args[1]
		if args[2:]:
			localdir = args[2]
			if args[3:]: usage('too many arguments')
	#
	f = ftplib.FTP()
	if verbose: print 'Connecting to %s...' % host
	f.connect(host)
	if not nologin:
		if verbose:
			print 'Logging in as %s...' % (login or 'anonymous')
		f.login(login, passwd, account)
	if verbose: print 'OK.'
	pwd = f.pwd()
	if verbose > 1: print 'PWD =', `pwd`
	if remotedir:
		if verbose > 1: print 'cwd(%s)' % `remotedir`
		f.cwd(remotedir)
		if verbose > 1: print 'OK.'
		pwd = f.pwd()
		if verbose > 1: print 'PWD =', `pwd`
	#
	mirrorsubdir(f, localdir)

def mirrorsubdir(f, localdir):
	pwd = f.pwd()
	if localdir and not os.path.isdir(localdir):
		if verbose: print 'Creating local directory', localdir
		makedir(localdir)
	infofilename = os.path.join(localdir, '.mirrorinfo')
	try:
		text = open(infofilename, 'r').read()
	except IOError, msg:
		text = '{}'
	try:
		info = eval(text)
	except (SyntaxError, NameError):
		print 'Bad mirror info in %s' % infofilename
		info = {}
	subdirs = []
	listing = []
	if verbose: print 'Listing remote directory %s...' % pwd
	f.retrlines('LIST', listing.append)
	for line in listing:
		if verbose > 1: print '-->', `line`
		if mac:
			# Mac listing has just filenames;
			# trailing / means subdirectory
			filename = string.strip(line)
			mode = '-'
			if filename[-1:] == '/':
				filename = filename[:-1]
				mode = 'd'
			infostuff = ''
		else:
			# Parse, assuming a UNIX listing
			words = string.split(line)
			if len(words) < 6:
				if verbose > 1: print 'Skipping short line'
				continue
			if words[-2] == '->':
				if verbose > 1:
					print 'Skipping symbolic link %s -> %s' % \
						  (words[-3], words[-1])
				continue
			filename = words[-1]
			infostuff = words[-5:-1]
			mode = words[0]
		skip = 0
		for pat in skippats:
			if fnmatch(filename, pat):
				if verbose > 1:
					print 'Skip pattern', pat,
					print 'matches', filename
				skip = 1
				break
		if skip:
			continue
		if mode[0] == 'd':
			if verbose > 1:
				print 'Remembering subdirectory', filename
			subdirs.append(filename)
			continue
		if info.has_key(filename) and info[filename] == infostuff:
			if verbose > 1:
				print 'Already have this version of', filename
			continue
		fullname = os.path.join(localdir, filename)
		if interactive:
			doit = askabout('file', filename, pwd)
			if not doit:
				if not info.has_key(filename):
					info[filename] = 'Not retrieved'
				continue
		try:
			os.unlink(fullname)
		except os.error:
			pass
		try:
			fp = open(fullname, 'w')
		except IOError, msg:
			print "Can't create %s: %s" % (fullname, str(msg))
			continue
		if verbose:
			print 'Retrieving %s from %s as %s...' % \
				  (filename, pwd, fullname)
		if verbose:
			fp1 = LoggingFile(fp, 1024, sys.stdout)
		else:
			fp1 = fp
		t0 = time.time()
		try:
			f.retrbinary('RETR ' + filename, fp1.write, 8*1024)
		except ftplib.error_perm, msg:
			print msg
		t1 = time.time()
		bytes = fp.tell()
		fp.close()
		if fp1 != fp:
			fp1.close()
		info[filename] = infostuff
		writedict(info, infofilename)
		if verbose:
			dt = t1 - t0
			kbytes = bytes / 1024.0
			print int(round(kbytes)),
			print 'Kbytes in',
			print int(round(dt)),
			print 'seconds',
			if t1 > t0:
				print '(~%d Kbytes/sec)' % \
					  int(round(kbytes/dt),)
			print
	#
	# Remove local files that are no longer in the remote directory
	if not localdir: names = os.listdir(os.curdir)
	else: names = os.listdir(localdir)
	for name in names:
		if name[0] == '.' or info.has_key(name) or name in subdirs:
			continue
		fullname = os.path.join(localdir, name)
		if not rmok:
			if verbose:
				print 'Local file', fullname,
				print 'is no longer pertinent'
			continue
		if verbose: print 'Removing local file', fullname
		try:
			os.unlink(fullname)
		except os.error, msg:
			print "Can't remove local file %s: %s" % \
				  (fullname, str(msg))
	#
	# Recursively mirror subdirectories
	for subdir in subdirs:
		if interactive:
			doit = askabout('subdirectory', subdir, pwd)
			if not doit: continue
		if verbose: print 'Processing subdirectory', subdir
		localsubdir = os.path.join(localdir, subdir)
		pwd = f.pwd()
		if verbose > 1:
			print 'Remote directory now:', pwd
			print 'Remote cwd', subdir
		try:
			f.cwd(subdir)
		except ftplib.error_perm, msg:
			print "Can't chdir to", subdir, ":", msg
		else:
			if verbose: print 'Mirroring as', localsubdir
			mirrorsubdir(f, localsubdir)
			if verbose > 1: print 'Remote cwd ..'
			f.cwd('..')
		newpwd = f.pwd()
		if newpwd != pwd:
			print 'Ended up in wrong directory after cd + cd ..'
			print 'Giving up now.'
			break
		else:
			if verbose > 1: print 'OK.'

# Wrapper around a file for writing to write a hash sign every block.
class LoggingFile:
	def __init__(self, fp, blocksize, outfp):
		self.fp = fp
		self.bytes = 0
		self.hashes = 0
		self.blocksize = blocksize
		self.outfp = outfp
	def write(self, data):
		self.bytes = self.bytes + len(data)
		hashes = int(self.bytes) / self.blocksize
		while hashes > self.hashes:
			self.outfp.write('#')
			self.outfp.flush()
			self.hashes = self.hashes + 1
		self.fp.write(data)
	def close(self):
		self.outfp.write('\n')

# Ask permission to download a file.
def askabout(filetype, filename, pwd):
	prompt = 'Retrieve %s %s from %s ? [ny] ' % (filetype, filename, pwd)
	while 1:
		reply = string.lower(string.strip(raw_input(prompt)))
		if reply in ['y', 'ye', 'yes']:
			return 1
		if reply in ['', 'n', 'no', 'nop', 'nope']:
			return 0
		print 'Please answer yes or no.'

# Create a directory if it doesn't exist.  Recursively create the
# parent directory as well if needed.
def makedir(pathname):
	if os.path.isdir(pathname):
		return
	dirname = os.path.dirname(pathname)
	if dirname: makedir(dirname)
	os.mkdir(pathname, 0777)

# Write a dictionary to a file in a way that can be read back using
# rval() but is still somewhat readable (i.e. not a single long line).
def writedict(dict, filename):
	fp = open(filename, 'w')
	fp.write('{\n')
	for key, value in dict.items():
		fp.write('%s: %s,\n' % (`key`, `value`))
	fp.write('}\n')
	fp.close()

main()
