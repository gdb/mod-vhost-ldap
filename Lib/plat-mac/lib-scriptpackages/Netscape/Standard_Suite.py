"""Suite Standard Suite: Common terms for most applications
Level 1, version 1

Generated from /Volumes/Moes/Applications (Mac OS 9)/Netscape Communicator\xe2\x84\xa2 Folder/Netscape Communicator\xe2\x84\xa2
AETE/AEUT resource version 1/0, language 0, script 0
"""

import aetools
import MacOS

_code = 'CoRe'

from StdSuites.Standard_Suite import *
class Standard_Suite_Events(Standard_Suite_Events):

	def close(self, _object, _attributes={}, **_arguments):
		"""close: Close an object
		Required argument: the objects to close
		Keyword argument _attributes: AppleEvent attribute dictionary
		"""
		_code = 'core'
		_subcode = 'clos'

		if _arguments: raise TypeError, 'No optional args expected'
		_arguments['----'] = _object


		_reply, _arguments, _attributes = self.send(_code, _subcode,
				_arguments, _attributes)
		if _arguments.get('errn', 0):
			raise aetools.Error, aetools.decodeerror(_arguments)
		# XXXX Optionally decode result
		if _arguments.has_key('----'):
			return _arguments['----']

	def data_size(self, _object, _attributes={}, **_arguments):
		"""data size: Return the size in bytes of an object
		Required argument: the object whose data size is to be returned
		Keyword argument _attributes: AppleEvent attribute dictionary
		Returns: the size of the object in bytes
		"""
		_code = 'core'
		_subcode = 'dsiz'

		if _arguments: raise TypeError, 'No optional args expected'
		_arguments['----'] = _object


		_reply, _arguments, _attributes = self.send(_code, _subcode,
				_arguments, _attributes)
		if _arguments.get('errn', 0):
			raise aetools.Error, aetools.decodeerror(_arguments)
		# XXXX Optionally decode result
		if _arguments.has_key('----'):
			return _arguments['----']

	def get(self, _object, _attributes={}, **_arguments):
		"""get: Get the data for an object
		Required argument: the object whose data is to be returned
		Keyword argument _attributes: AppleEvent attribute dictionary
		Returns: The data from the object
		"""
		_code = 'core'
		_subcode = 'getd'

		if _arguments: raise TypeError, 'No optional args expected'
		_arguments['----'] = _object


		_reply, _arguments, _attributes = self.send(_code, _subcode,
				_arguments, _attributes)
		if _arguments.get('errn', 0):
			raise aetools.Error, aetools.decodeerror(_arguments)
		# XXXX Optionally decode result
		if _arguments.has_key('----'):
			return _arguments['----']

	_argmap_set = {
		'to' : 'data',
	}

	def set(self, _object, _attributes={}, **_arguments):
		"""set: Set an object\xd5s data
		Required argument: the object to change
		Keyword argument to: the new value
		Keyword argument _attributes: AppleEvent attribute dictionary
		"""
		_code = 'core'
		_subcode = 'setd'

		aetools.keysubst(_arguments, self._argmap_set)
		_arguments['----'] = _object


		_reply, _arguments, _attributes = self.send(_code, _subcode,
				_arguments, _attributes)
		if _arguments.get('errn', 0):
			raise aetools.Error, aetools.decodeerror(_arguments)
		# XXXX Optionally decode result
		if _arguments.has_key('----'):
			return _arguments['----']


class application(aetools.ComponentItem):
	"""application - An application program """
	want = 'capp'
class alert_application(aetools.NProperty):
	"""alert application - Most of the alerts will be sent to this application using yet unspecified AE interface. We need a few alert boxes: alert, confirm and notify. Any ideas on how to design this event? mailto:atotic@netscape.com. I\xd5d like to conform to the standard. """
	which = 'ALAP'
	want = 'type'
class kiosk_mode(aetools.NProperty):
	"""kiosk mode - Kiosk mode leaves very few menus enabled """
	which = 'KOSK'
	want = 'long'
#        element 'cwin' as ['indx', 'name', 'ID  ']

class window(aetools.ComponentItem):
	"""window - A Window """
	want = 'cwin'
class URL(aetools.NProperty):
	"""URL - Current URL """
	which = 'curl'
	want = 'TEXT'
class bounds(aetools.NProperty):
	"""bounds - the boundary rectangle for the window """
	which = 'pbnd'
	want = 'qdrt'
class busy(aetools.NProperty):
	"""busy - Is window loading something right now. 2, window is busy and will reject load requests. 1, window is busy, but will interrupt outstanding loads """
	which = 'busy'
	want = 'long'
class closeable(aetools.NProperty):
	"""closeable - Does the window have a close box? """
	which = 'hclb'
	want = 'bool'
class floating(aetools.NProperty):
	"""floating - Does the window float? """
	which = 'isfl'
	want = 'bool'
class index(aetools.NProperty):
	"""index - the number of the window """
	which = 'pidx'
	want = 'long'
class modal(aetools.NProperty):
	"""modal - Is the window modal? """
	which = 'pmod'
	want = 'bool'
class name(aetools.NProperty):
	"""name - the title of the window """
	which = 'pnam'
	want = 'itxt'
class position(aetools.NProperty):
	"""position - upper left coordinates of window """
	which = 'ppos'
	want = 'QDpt'
class resizable(aetools.NProperty):
	"""resizable - Is the window resizable? """
	which = 'prsz'
	want = 'bool'
class titled(aetools.NProperty):
	"""titled - Does the window have a title bar? """
	which = 'ptit'
	want = 'bool'
class unique_ID(aetools.NProperty):
	"""unique ID - Window\xd5s unique ID (a bridge between WWW! suite window id\xd5s and standard AE windows) """
	which = 'wiid'
	want = 'long'
class visible(aetools.NProperty):
	"""visible - is the window visible? """
	which = 'pvis'
	want = 'bool'
class zoomable(aetools.NProperty):
	"""zoomable - Is the window zoomable? """
	which = 'iszm'
	want = 'bool'
class zoomed(aetools.NProperty):
	"""zoomed - Is the window zoomed? """
	which = 'pzum'
	want = 'bool'
application._superclassnames = []
application._privpropdict = {
	'alert_application' : alert_application,
	'kiosk_mode' : kiosk_mode,
}
application._privelemdict = {
	'window' : window,
}
window._superclassnames = []
window._privpropdict = {
	'URL' : URL,
	'bounds' : bounds,
	'busy' : busy,
	'closeable' : closeable,
	'floating' : floating,
	'index' : index,
	'modal' : modal,
	'name' : name,
	'position' : position,
	'resizable' : resizable,
	'titled' : titled,
	'unique_ID' : unique_ID,
	'visible' : visible,
	'zoomable' : zoomable,
	'zoomed' : zoomed,
}
window._privelemdict = {
}

#
# Indices of types declared in this module
#
_classdeclarations = {
	'capp' : application,
	'cwin' : window,
}

_propdeclarations = {
	'ALAP' : alert_application,
	'KOSK' : kiosk_mode,
	'busy' : busy,
	'curl' : URL,
	'hclb' : closeable,
	'isfl' : floating,
	'iszm' : zoomable,
	'pbnd' : bounds,
	'pidx' : index,
	'pmod' : modal,
	'pnam' : name,
	'ppos' : position,
	'prsz' : resizable,
	'ptit' : titled,
	'pvis' : visible,
	'pzum' : zoomed,
	'wiid' : unique_ID,
}

_compdeclarations = {
}

_enumdeclarations = {
}
