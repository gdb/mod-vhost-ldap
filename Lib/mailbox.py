#
# A class to hand a unix-style or mmdf-style mailboxes
#
# Jack Jansen, CWI, March 1994.
#
import rfc822
import os
import regex

class _Mailbox:
	def __init__(self, fp):
		self.fp = fp
		self.seekp = 0

	def seek(self, pos, whence=0):
		if whence==1:		# Relative to current position
			self.pos = self.pos + pos
		if whence==2:		# Relative to file's end
			self.pos = self.stop + pos
		else:			# Default - absolute position
			self.pos = self.start + pos

	def next(self):
		while 1:
			self.fp.seek(self.seekp)
			try:
				self._search_start()
			except EOFError:
				self.seekp = self.fp.tell()
				return None
			start = self.fp.tell()
			self._search_end()
			self.seekp = stop = self.fp.tell()
			if start <> stop:
				break
		return rfc822.Message(_Subfile(self.fp, start, stop))

class _Subfile:
	def __init__(self, fp, start, stop):
		self.fp = fp
		self.start = start
		self.stop = stop
		self.pos = self.start

	def read(self, length = None):
		if self.pos >= self.stop:
			return ''
		if length is None:
			length = self.stop - self.pos
		self.fp.seek(self.pos)
		self.pos = self.pos + length
		return self.fp.read(length)

	def readline(self, length = None):
		if self.pos >= self.stop:
			return ''
		if length is None:
			length = self.stop - self.pos
		self.fp.seek(self.pos)
		data = self.fp.readline(length)
		if len(data) < length:
			length = len(data)
		self.pos = self.pos + length
		return data

	def tell(self):
		return self.pos - self.start

	def seek(self, pos, whence=0):
	        if whence == 0:
		    self.pos = self.start + pos
		elif whence == 1:
		    self.pos = self.pos + pos
		elif whence == 2:
		    self.pos = self.stop + pos

	def close(self):
		pass

class UnixMailbox(_Mailbox):
	def _search_start(self):
		while 1:
			line = self.fp.readline()
			if not line:
				raise EOFError
			if line[:5] == 'From ':
				return

	def _search_end(self):
		while 1:
			pos = self.fp.tell()
			line = self.fp.readline()
			if not line:
				return
			if line[:5] == 'From ':
				self.fp.seek(pos)
				return

class MmdfMailbox(_Mailbox):
	def _search_start(self):
		while 1:
			line = self.fp.readline()
			if not line:
				raise EOFError
			if line[:5] == '\001\001\001\001\n':
				return

	def _search_end(self):
		while 1:
			pos = self.fp.tell()
			line = self.fp.readline()
			if not line:
				return
			if line == '\001\001\001\001\n':
				self.fp.seek(pos)
				return

class MHMailbox:
    def __init__(self, dirname):
	pat = regex.compile('^[0-9][0-9]*$')
	self.dirname = dirname
	files = os.listdir(self.dirname)
	self.boxes = []
	for f in files:
	    if pat.match(f) == len(f):
		self.boxes.append(f)

    def next(self):
	if not self.boxes:
	    return None
	fn = self.boxes[0]
	del self.boxes[0]
	fp = open(os.path.join(self.dirname, fn))
	return rfc822.Message(fp)
	    
    
if __name__ == '__main__':
	import posix
	import time
	import sys
	import string
##	mbox = '/usr/mail/'+posix.environ['USER']
##	fp = open(mbox, 'r')
##	mb = UnixMailbox(fp)

	mbox = posix.environ['HOME']+'/Mail/inbox'
	mb = MHMailbox(mbox)
	
	msgs = []
	while 1:
		msg = mb.next()
		if not msg:
			break
		msgs.append(msg)
	if len(sys.argv) > 1:
		num = string.atoi(sys.argv[1])
		print 'Message %d body:'%num
		msg = msgs[num-1]
		msg.rewindbody()
		sys.stdout.write(msg.fp.read())
		sys.exit(0)
	print 'Mailbox',mbox,'has',len(msgs),'messages:'
	for msg in msgs:
		f = msg.getheader('from')
		s = msg.getheader('subject')
		d = (msg.getheader('date'))
		print '%20.20s   %18.18s   %-30.30s'%(f, d[5:], s)
		
