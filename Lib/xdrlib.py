"""Implements (a subset of) Sun XDR -- eXternal Data Representation.

See: RFC 1014

This module will conditionally use the _xdrmodule.so module to get
support for those representations we can't do much with from Python.

"""

import struct
from types import LongType

# workaround Python 1.4b2 bug
import sys
sys.path[0] = '.'

# use C layer XDR libraries for some data types if available
try:
    import _xdr
except ImportError:
    _xdr = None

# this test is done to see if machine representation is the same as
# network representation.  if so, we can use module struct for packing
# some data types
__USE_MACHINE_REP = (struct.pack('l', 1) == '\0\0\0\1')

# exceptions
class Error:
    """Exception class for this module. Use:

    except xdrlib.Error, var:
        # var has the Error instance for the exception

    Public ivars:
        msg -- contains the message

    """
    def __init__(self, msg):
	self.msg = msg
    def __repr__(self):
	return repr(self.msg)
    def __str__(self):
	return str(self.msg)


class ConversionError(Error):
    pass



class Packer:
    """Pack various data representations into a buffer."""

    def __init__(self):
	self.reset()

    def reset(self):
	self.__buf = ''

    def get_buffer(self):
	return self.__buf
    # backwards compatibility
    get_buf = get_buffer

    def pack_uint(self, x):
	self.__buf = self.__buf + \
		     (chr(int(x>>24 & 0xff)) + chr(int(x>>16 & 0xff)) + \
		      chr(int(x>>8 & 0xff)) + chr(int(x & 0xff)))
    if __USE_MACHINE_REP:
	def pack_uint(self, x):
	    if type(x) == LongType:
		x = int((x + 0x80000000L) % 0x100000000L - 0x80000000L)
	    self.__buf = self.__buf + struct.pack('l', x)

    pack_int = pack_uint
    pack_enum = pack_int

    def pack_bool(self, x):
	if x: self.__buf = self.__buf + '\0\0\0\1'
	else: self.__buf = self.__buf + '\0\0\0\0'

    def pack_uhyper(self, x):
	self.pack_uint(int(x>>32 & 0xffffffff))
	self.pack_uint(int(x & 0xffffffff))

    pack_hyper = pack_uhyper

    def pack_float(self, x):
	raise ConversionError('Not supported')
    def pack_double(self, x):
	raise ConversionError('Not supported')
    # get these from the C layer if available
    if _xdr:
	def pack_float(self, x):
	    try: self.__buf = self.__buf + _xdr.pack_float(x)
	    except _xdr.error, msg:
		raise ConversionError(msg)
	def pack_double(self, x):
	    try: self.__buf = self.__buf + _xdr.pack_double(x)
	    except _xdr.error, msg:
		raise ConversionError(msg)

    def pack_fstring(self, n, s):
	if n < 0:
	    raise ValueError, 'fstring size must be nonnegative'
	n = ((n+3)/4)*4
	data = s[:n]
	data = data + (n - len(data)) * '\0'
	self.__buf = self.__buf + data

    pack_fopaque = pack_fstring

    def pack_string(self, s):
	n = len(s)
	self.pack_uint(n)
	self.pack_fstring(n, s)

    pack_opaque = pack_string
    pack_bytes = pack_string

    def pack_list(self, list, pack_item):
	for item in list:
	    self.pack_uint(1)
	    pack_item(item)
	self.pack_uint(0)

    def pack_farray(self, n, list, pack_item):
	if len(list) <> n:
	    raise ValueError, 'wrong array size'
	for item in list:
	    pack_item(item)

    def pack_array(self, list, pack_item):
	n = len(list)
	self.pack_uint(n)
	self.pack_farray(n, list, pack_item)



class Unpacker:
    """Unpacks various data representations from the given buffer."""

    def __init__(self, data):
	self.reset(data)

    def reset(self, data):
	self.__buf = data
	self.__pos = 0

    def get_position(self):
	return self.__pos

    def set_position(self, position):
	self.__pos = position

    def done(self):
	if self.__pos < len(self.__buf):
	    raise Error('unextracted data remains')

    def unpack_uint(self):
	i = self.__pos
	self.__pos = j = i+4
	data = self.__buf[i:j]
	if len(data) < 4:
	    raise EOFError
	x = long(ord(data[0]))<<24 | ord(data[1])<<16 | \
	    ord(data[2])<<8 | ord(data[3])
	# Return a Python long only if the value is not representable
	# as a nonnegative Python int
	if x < 0x80000000L:
	    x = int(x)
	return x
    if __USE_MACHINE_REP:
	def unpack_uint(self):
	    i = self.__pos
	    self.__pos = j = i+4
	    data = self.__buf[i:j]
	    if len(data) < 4:
		raise EOFError
	    return struct.unpack('l', data)[0]

    def unpack_int(self):
	x = self.unpack_uint()
	if x >= 0x80000000L:
	    x = x - 0x100000000L
	return int(x)

    unpack_enum = unpack_int
    unpack_bool = unpack_int

    def unpack_uhyper(self):
	hi = self.unpack_uint()
	lo = self.unpack_uint()
	return long(hi)<<32 | lo

    def unpack_hyper(self):
	x = self.unpack_uhyper()
	if x >= 0x8000000000000000L:
	    x = x - 0x10000000000000000L
	return x

    def unpack_float(self):
	raise ConversionError('Not supported')
    def unpack_double(self):
	raise ConversionError('Not supported')
    # get these from the C layer if available
    if _xdr:
	def unpack_float(self):
	    i = self.__pos
	    self.__pos = j = i+4
	    data = self.__buf[i:j]
	    if len(data) < 4:
		raise EOFError
	    try: return _xdr.unpack_float(data)
	    except _xdr.error, msg:
		raise ConversionError(msg)

	def unpack_double(self):
	    i = self.__pos
	    self.__pos = j = i+8
	    data = self.__buf[i:j]
	    if len(data) < 8:
		raise EOFError
	    try: return _xdr.unpack_double(data)
	    except _xdr.error, msg:
		raise ConversionError(msg)

    def unpack_fstring(self, n):
	if n < 0:
	    raise ValueError, 'fstring size must be nonnegative'
	i = self.__pos
	j = i + (n+3)/4*4
	if j > len(self.__buf):
	    raise EOFError
	self.__pos = j
	return self.__buf[i:i+n]

    unpack_fopaque = unpack_fstring

    def unpack_string(self):
	n = self.unpack_uint()
	return self.unpack_fstring(n)

    unpack_opaque = unpack_string
    unpack_bytes = unpack_string

    def unpack_list(self, unpack_item):
	list = []
	while 1:
	    x = self.unpack_uint()
	    if x == 0: break
	    if x <> 1:
		raise ConversionError('0 or 1 expected, got ' + `x`)
	    item = unpack_item()
	    list.append(item)
	return list

    def unpack_farray(self, n, unpack_item):
	list = []
	for i in range(n):
	    list.append(unpack_item())
	return list

    def unpack_array(self, unpack_item):
	n = self.unpack_uint()
	return self.unpack_farray(n, unpack_item)


# test suite
def __test():
    p = Packer()
    packtest = [
	(p.pack_uint,    (9,)),
	(p.pack_bool,    (None,)),
	(p.pack_bool,    ('hello',)),
	(p.pack_uhyper,  (45L,)),
	(p.pack_float,   (1.9,)),
	(p.pack_double,  (1.9,)),
	(p.pack_string,  ('hello world',)),
	(p.pack_list,    (range(5), p.pack_uint)),
	(p.pack_array,   (['what', 'is', 'hapnin', 'doctor'], p.pack_string)),
	]
    succeedlist = [1] * len(packtest)
    count = 0
    for method, args in packtest:
	print 'pack test', count,
	try:
	    apply(method, args)
	    print 'succeeded'
	except ConversionError, var:
	    print 'ConversionError:', var.msg
	    succeedlist[count] = 0
	count = count + 1
    data = p.get_buffer()
    # now verify
    up = Unpacker(data)
    unpacktest = [
	(up.unpack_uint,   (), lambda x: x == 9),
	(up.unpack_bool,   (), lambda x: not x),
	(up.unpack_bool,   (), lambda x: x),
	(up.unpack_uhyper, (), lambda x: x == 45L),
	(up.unpack_float,  (), lambda x: 1.89 < x < 1.91),
	(up.unpack_double, (), lambda x: 1.89 < x < 1.91),
	(up.unpack_string, (), lambda x: x == 'hello world'),
	(up.unpack_list,   (up.unpack_uint,), lambda x: x == range(5)),
	(up.unpack_array,  (up.unpack_string,),
	 lambda x: x == ['what', 'is', 'hapnin', 'doctor']),
	]
    count = 0
    for method, args, pred in unpacktest:
	print 'unpack test', count,
	try:
	    if succeedlist[count]:
		x = apply(method, args)
		print pred(x) and 'succeeded' or 'failed', ':', x
	    else:
		print 'skipping'
	except ConversionError, var:
	    print 'ConversionError:', var.msg
	count = count + 1

if __name__ == '__main__':
    __test()
