# RFC-822 message manipulation class.
#
# XXX This is only a very rough sketch of a full RFC-822 parser;
# in particular the tokenizing of addresses does not adhere to all the
# quoting rules.
#
# Directions for use:
#
# To create a Message object: first open a file, e.g.:
#   fp = open(file, 'r')
# (or use any other legal way of getting an open file object, e.g. use
# sys.stdin or call os.popen()).
# Then pass the open file object to the Message() constructor:
#   m = Message(fp)
#
# To get the text of a particular header there are several methods:
#   str = m.getheader(name)
#   str = m.getrawheader(name)
# where name is the name of the header, e.g. 'Subject'.
# The difference is that getheader() strips the leading and trailing
# whitespace, while getrawheader() doesn't.  Both functions retain
# embedded whitespace (including newlines) exactly as they are
# specified in the header, and leave the case of the text unchanged.
#
# For addresses and address lists there are functions
#   realname, mailaddress = m.getaddr(name) and
#   list = m.getaddrlist(name)
# where the latter returns a list of (realname, mailaddr) tuples.
#
# There is also a method
#   time = m.getdate(name)
# which parses a Date-like field and returns a time-compatible tuple,
# i.e. a tuple such as returned by time.localtime() or accepted by
# time.mktime().
#
# See the class definition for lower level access methods.
#
# There are also some utility functions here.


import re
import string
import time


_blanklines = ('\r\n', '\n')		# Optimization for islast()


class Message:

	# Initialize the class instance and read the headers.
	
	def __init__(self, fp, seekable = 1):
		self.fp = fp
		self.seekable = seekable
		self.startofheaders = None
		self.startofbody = None
		#
		if self.seekable:
			try:
				self.startofheaders = self.fp.tell()
			except IOError:
				self.seekable = 0
		#
		self.readheaders()
		#
		if self.seekable:
			try:
				self.startofbody = self.fp.tell()
			except IOError:
				self.seekable = 0


	# Rewind the file to the start of the body (if seekable).

	def rewindbody(self):
		if not self.seekable:
			raise IOError, "unseekable file"
		self.fp.seek(self.startofbody)


	# Read header lines up to the entirely blank line that
	# terminates them.  The (normally blank) line that ends the
	# headers is skipped, but not included in the returned list.
	# If a non-header line ends the headers, (which is an error),
	# an attempt is made to backspace over it; it is never
	# included in the returned list.
	#
	# The variable self.status is set to the empty string if all
	# went well, otherwise it is an error message.
	# The variable self.headers is a completely uninterpreted list
	# of lines contained in the header (so printing them will
	# reproduce the header exactly as it appears in the file).

	def readheaders(self):
		self.dict = {}
		self.unixfrom = ''
		self.headers = list = []
		self.status = ''
		headerseen = ""
		firstline = 1
		while 1:
			line = self.fp.readline()
			if not line:
				self.status = 'EOF in headers'
				break
			# Skip unix From name time lines
			if firstline and line[:5] == 'From ':
				self.unixfrom = self.unixfrom + line
			        continue
			firstline = 0
			if self.islast(line):
				break
			elif headerseen and line[0] in ' \t':
				# It's a continuation line.
				list.append(line)
				x = (self.dict[headerseen] + "\n " +
				     string.strip(line))
				self.dict[headerseen] = string.strip(x)
			elif ':' in line:
				# It's a header line.
				list.append(line)
				i = string.find(line, ':')
				headerseen = string.lower(line[:i])
				self.dict[headerseen] = string.strip(
					line[i+1:])
			else:
				# It's not a header line; stop here.
				if not headerseen:
					self.status = 'No headers'
				else:
					self.status = 'Bad header'
				# Try to undo the read.
				if self.seekable:
					self.fp.seek(-len(line), 1)
				else:
					self.status = \
						self.status + '; bad seek'
				break


	# Method to determine whether a line is a legal end of
	# RFC-822 headers.  You may override this method if your
	# application wants to bend the rules, e.g. to strip trailing
	# whitespace, or to recognise MH template separators
	# ('--------').  For convenience (e.g. for code reading from
	# sockets) a line consisting of \r\n also matches.

	def islast(self, line):
		return line in _blanklines


	# Look through the list of headers and find all lines matching
	# a given header name (and their continuation lines).
	# A list of the lines is returned, without interpretation.
	# If the header does not occur, an empty list is returned.
	# If the header occurs multiple times, all occurrences are
	# returned.  Case is not important in the header name.

	def getallmatchingheaders(self, name):
		name = string.lower(name) + ':'
		n = len(name)
		list = []
		hit = 0
		for line in self.headers:
			if string.lower(line[:n]) == name:
				hit = 1
			elif line[:1] not in string.whitespace:
				hit = 0
			if hit:
				list.append(line)
		return list


	# Similar, but return only the first matching header (and its
	# continuation lines).

	def getfirstmatchingheader(self, name):
		name = string.lower(name) + ':'
		n = len(name)
		list = []
		hit = 0
		for line in self.headers:
			if hit:
				if line[:1] not in string.whitespace:
					break
			elif string.lower(line[:n]) == name:
				hit = 1
			if hit:
				list.append(line)
		return list


	# A higher-level interface to getfirstmatchingheader().
	# Return a string containing the literal text of the header
	# but with the keyword stripped.  All leading, trailing and
	# embedded whitespace is kept in the string, however.
	# Return None if the header does not occur.

	def getrawheader(self, name):
		list = self.getfirstmatchingheader(name)
		if not list:
			return None
		list[0] = list[0][len(name) + 1:]
		return string.joinfields(list, '')


	# The normal interface: return a stripped version of the
	# header value with a name, or None if it doesn't exist.  This
	# uses the dictionary version which finds the *last* such
	# header.

	def getheader(self, name):
		try:
			return self.dict[string.lower(name)]
		except KeyError:
			return None


	# Retrieve a single address from a header as a tuple, e.g.
	# ('Guido van Rossum', 'guido@cwi.nl').

	def getaddr(self, name):
		try:
			data = self[name]
		except KeyError:
			return None, None
		return parseaddr(data)

	# Retrieve a list of addresses from a header, where each
	# address is a tuple as returned by getaddr().

	def getaddrlist(self, name):
		# XXX This function is not really correct.  The split
		# on ',' might fail in the case of commas within
		# quoted strings.
		try:
			data = self[name]
		except KeyError:
			return []
		data = string.splitfields(data, ',')
		for i in range(len(data)):
			data[i] = parseaddr(data[i])
		return data

	# Retrieve a date field from a header as a tuple compatible
	# with time.mktime().

	def getdate(self, name):
		try:
			data = self[name]
		except KeyError:
			return None
		return parsedate(data)

	# Retrieve a date field from a header as a 10-tuple.  
	# The first 9 elements make up a tuple compatible
	# with time.mktime(), and the 10th is the offset
	# of the poster's time zone from GMT/UTC.

	def getdate_tz(self, name):
		try:
			data = self[name]
		except KeyError:
			return None
		return parsedate_tz(data)


	# Access as a dictionary (only finds *last* header of each type):

	def __len__(self):
		return len(self.dict)

	def __getitem__(self, name):
		return self.dict[string.lower(name)]

	def has_key(self, name):
		return self.dict.has_key(string.lower(name))

	def keys(self):
		return self.dict.keys()

	def values(self):
		return self.dict.values()

	def items(self):
		return self.dict.items()



# Utility functions
# -----------------

# XXX Should fix these to be really conformant.
# XXX The inverses of the parse functions may also be useful.


# Remove quotes from a string.

def unquote(str):
	if len(str) > 1:
		if str[0] == '"' and str[-1:] == '"':
			return str[1:-1]
		if str[0] == '<' and str[-1:] == '>':
			return str[1:-1]
	return str


# Parse an address into (name, address) tuple
# (By Sjoerd Mullender)

error = 'parseaddr.error'

specials = re.compile(r'[][()<>,.;:@\" \000-\037\177-\377]')

def quote(str):
	return '"%s"' % string.join(
	    string.split(
		string.join(
		    string.split(str, '\\'),
		    '\\\\'),
		'"'),
	    '\\"')

def parseaddr(address):
	token = []			# the current token
	tokens = []			# the list of tokens
	backslash = 0
	dquote = 0
	was_quoted = 0
	space = 0
	paren = 0
	for c in address:
		if backslash:
			token.append(c)
			backslash = 0
		if c == '\\':
			backslash = 1
			was_quoted = 1
			continue
		if dquote:
			if c == '"':
				dquote = 0
			else:
				token.append(c)
			continue
		if c == '"':
			dquote = 1
			was_quoted = 1
			continue
		if paren:
			if c == '(':
				paren = paren + 1
			elif c == ')':
				paren = paren - 1
				if paren == 0:
					token = string.join(token, '')
					tokens.append((2, token))
					token = []
					continue
			token.append(c)
			continue
		if c == '(':
			paren = 1
			token = string.join(token, '')
			tokens.append((was_quoted, token))
			was_quoted = 0
			token = []
			continue
		if c in string.whitespace:
			space = 1
			continue
		if c in '<>@,;:.[]':
			token = string.join(token, '')
			tokens.append((was_quoted, token))
			was_quoted = 0
			token = []
			tokens.append((0, c))
			space = 0
			continue
		if space:
			token = string.join(token, '')
			tokens.append((was_quoted, token))
			was_quoted = 0
			token = []
			space = 0
		token.append(c)
	token = string.join(token, '')
	tokens.append((was_quoted, token))
	if (0, '<') in tokens:
		name = []
		addr = []
		cur = name
		for token in tokens:
			if token[1] == '':
				continue
			if token == (0, '<'):
				if addr:
					raise error, 'syntax error'
				cur = addr
			elif token == (0, '>'):
				if cur is not addr:
					raise error, 'syntax error'
				cur = name
			elif token[0] == 2:
				if cur is name:
					name.append('(' + token[1] + ')')
				else:
					name.append(token[1])
			elif token[0] == 1 and cur is addr:
				if specials.search(token[1]):
					cur.append(quote(token[1]))
				else:
					cur.append(token[1])
			else:
				cur.append(token[1])
	else:
		name = []
		addr = []
		for token in tokens:
			if token[1] == '':
				continue
			if token[0] == 2:
				name.append(token[1])
			elif token[0] == 1:
				if specials.search(token[1]):
					addr.append(quote(token[1]))
				else:
					addr.append(token[1])
			else:
				addr.append(token[1])
	return string.join(name, ' '), string.join(addr, '')


# Parse a date field

_monthnames = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul',
	  'Aug', 'Sep', 'Oct', 'Nov', 'Dec']
_daynames = ['Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat', 'Sun']

# The timezone table does not include the military time zones defined
# in RFC822, other than Z.  According to RFC1123, the description in
# RFC822 gets the signs wrong, so we can't rely on any such time
# zones.  RFC1123 recommends that numeric timezone indicators be used
# instead of timezone names.

_timezones = {'UT':0, 'UTC':0, 'GMT':0, 'Z':0, 
	      'AST': -400, 'ADT': -300,  # Atlantic standard
	      'EST': -500, 'EDT': -400,  # Eastern
	      'CST': -600, 'CDT':-500,   # Centreal
	      'MST':-700, 'MDT':-600,    # Mountain
	      'PST':-800, 'PDT':-700     # Pacific
	     }    

def parsedate_tz(data):
	data = string.split(data)
	if data[0][-1] == ',' or data[0] in _daynames:
		# There's a dayname here. Skip it
		del data[0]
	if len(data) == 3: # RFC 850 date, deprecated
		stuff = string.split(data[0], '-')
		if len(stuff) == 3:
			data = stuff + data[1:]
	if len(data) == 4:
		s = data[3]
		i = string.find(s, '+')
		if i > 0:
			data[3:] = [s[:i], s[i+1:]]
		else:
			data.append('') # Dummy tz
	if len(data) < 5:
		return None
	data = data[:5]
	[dd, mm, yy, tm, tz] = data
	if not mm in _monthnames:
		dd, mm, yy, tm, tz = mm, dd, tm, yy, tz
		if not mm in _monthnames:
			return None
	mm = _monthnames.index(mm)+1
	tm = string.splitfields(tm, ':')
	if len(tm) == 2:
		[thh, tmm] = tm
		tss = '0'
	else:
		[thh, tmm, tss] = tm
	try:
		yy = string.atoi(yy)
		dd = string.atoi(dd)
		thh = string.atoi(thh)
		tmm = string.atoi(tmm)
		tss = string.atoi(tss)
	except string.atoi_error:
		return None
	tzoffset=0
	tz=string.upper(tz)
	if _timezones.has_key(tz):
		tzoffset=_timezones[tz]
	else:
		try: 
			tzoffset=string.atoi(tz)
		except string.atoi_error: 
			pass
	# Convert a timezone offset into seconds ; -0500 -> -18000
	if tzoffset<0: tzsign=-1
	else: tzsign=1
	tzoffset=tzoffset*tzsign
	tzoffset = tzsign * ( (tzoffset/100)*3600 + (tzoffset % 100)*60)
	tuple = (yy, mm, dd, thh, tmm, tss, 0, 0, 0, tzoffset)
	return tuple

def parsedate(data):
	t=parsedate_tz(data)
	if type(t)==type( () ):
		return t[:9]
	else: return t    

def mktime_tz(data):
	"""Turn a 10-tuple as returned by parsedate_tz() into a UTC timestamp.

	Minor glitch: this first interprets the first 8 elements as a
	local time and then compensates for the timezone difference;
	this may yield a slight error around daylight savings time
	switch dates.  Not enough to worry about for common use.

	"""
	t = time.mktime(data[:8] + (0,))
	return t + data[9] - time.timezone

# When used as script, run a small test program.
# The first command line argument must be a filename containing one
# message in RFC-822 format.

if __name__ == '__main__':
	import sys, os
	file = os.path.join(os.environ['HOME'], 'Mail/inbox/1')
	if sys.argv[1:]: file = sys.argv[1]
	f = open(file, 'r')
	m = Message(f)
	print 'From:', m.getaddr('from')
	print 'To:', m.getaddrlist('to')
	print 'Subject:', m.getheader('subject')
	print 'Date:', m.getheader('date')
	date = m.getdate_tz('date')
	if date:
		print 'ParsedDate:', time.asctime(date[:-1]),
		hhmmss = date[-1]
		hhmm, ss = divmod(hhmmss, 60)
		hh, mm = divmod(hhmm, 60)
		print "%+03d%02d" % (hh, mm),
		if ss: print ".%02d" % ss,
		print
	else:
		print 'ParsedDate:', None
	m.rewindbody()
	n = 0
	while f.readline():
		n = n + 1
	print 'Lines:', n
	print '-'*70
	print 'len =', len(m)
	if m.has_key('Date'): print 'Date =', m['Date']
	if m.has_key('X-Nonsense'): pass
	print 'keys =', m.keys()
	print 'values =', m.values()
	print 'items =', m.items()
