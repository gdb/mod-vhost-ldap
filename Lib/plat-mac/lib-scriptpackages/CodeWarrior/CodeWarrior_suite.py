"""Suite CodeWarrior suite: Terms for scripting the CodeWarrior IDE
Level 0, version 0

Generated from /Volumes/Moes/Applications (Mac OS 9)/Metrowerks CodeWarrior 7.0/Metrowerks CodeWarrior/CodeWarrior IDE 4.2.6
AETE/AEUT resource version 1/0, language 0, script 0
"""

import aetools
import MacOS

_code = 'CWIE'

class CodeWarrior_suite_Events:

	_argmap_add = {
		'new' : 'kocl',
		'with_data' : 'data',
		'to_targets' : 'TTGT',
		'to_group' : 'TGRP',
	}

	def add(self, _object, _attributes={}, **_arguments):
		"""add: add elements to a project or target
		Required argument: an AE object reference
		Keyword argument new: the class of the new element or elements to add
		Keyword argument with_data: the initial data for the element or elements
		Keyword argument to_targets: the targets to which the new element or elements will be added
		Keyword argument to_group: the group to which the new element or elements will be added
		Keyword argument _attributes: AppleEvent attribute dictionary
		"""
		_code = 'CWIE'
		_subcode = 'ADDF'

		aetools.keysubst(_arguments, self._argmap_add)
		_arguments['----'] = _object


		_reply, _arguments, _attributes = self.send(_code, _subcode,
				_arguments, _attributes)
		if _arguments.get('errn', 0):
			raise aetools.Error, aetools.decodeerror(_arguments)
		# XXXX Optionally decode result
		if _arguments.has_key('----'):
			return _arguments['----']

	def build(self, _no_object=None, _attributes={}, **_arguments):
		"""build: build a project or target (equivalent of the Make menu command)
		Keyword argument _attributes: AppleEvent attribute dictionary
		"""
		_code = 'CWIE'
		_subcode = 'MAKE'

		if _arguments: raise TypeError, 'No optional args expected'
		if _no_object != None: raise TypeError, 'No direct arg expected'


		_reply, _arguments, _attributes = self.send(_code, _subcode,
				_arguments, _attributes)
		if _arguments.get('errn', 0):
			raise aetools.Error, aetools.decodeerror(_arguments)
		# XXXX Optionally decode result
		if _arguments.has_key('----'):
			return _arguments['----']

	def check(self, _object=None, _attributes={}, **_arguments):
		"""check: check the syntax of a file in a project or target
		Required argument: the file or files to be checked
		Keyword argument _attributes: AppleEvent attribute dictionary
		"""
		_code = 'CWIE'
		_subcode = 'CHEK'

		if _arguments: raise TypeError, 'No optional args expected'
		_arguments['----'] = _object


		_reply, _arguments, _attributes = self.send(_code, _subcode,
				_arguments, _attributes)
		if _arguments.get('errn', 0):
			raise aetools.Error, aetools.decodeerror(_arguments)
		# XXXX Optionally decode result
		if _arguments.has_key('----'):
			return _arguments['----']

	def compile_file(self, _object=None, _attributes={}, **_arguments):
		"""compile file: compile a file in a project or target
		Required argument: the file or files to be compiled
		Keyword argument _attributes: AppleEvent attribute dictionary
		"""
		_code = 'CWIE'
		_subcode = 'COMP'

		if _arguments: raise TypeError, 'No optional args expected'
		_arguments['----'] = _object


		_reply, _arguments, _attributes = self.send(_code, _subcode,
				_arguments, _attributes)
		if _arguments.get('errn', 0):
			raise aetools.Error, aetools.decodeerror(_arguments)
		# XXXX Optionally decode result
		if _arguments.has_key('----'):
			return _arguments['----']

	def disassemble_file(self, _object=None, _attributes={}, **_arguments):
		"""disassemble file: disassemble a file in a project or target
		Required argument: the file or files to be disassembled
		Keyword argument _attributes: AppleEvent attribute dictionary
		"""
		_code = 'CWIE'
		_subcode = 'DASM'

		if _arguments: raise TypeError, 'No optional args expected'
		_arguments['----'] = _object


		_reply, _arguments, _attributes = self.send(_code, _subcode,
				_arguments, _attributes)
		if _arguments.get('errn', 0):
			raise aetools.Error, aetools.decodeerror(_arguments)
		# XXXX Optionally decode result
		if _arguments.has_key('----'):
			return _arguments['----']

	_argmap_export = {
		'in_' : 'kfil',
	}

	def export(self, _no_object=None, _attributes={}, **_arguments):
		"""export: Export the project file as an XML file
		Keyword argument in_: the XML file in which to export the project
		Keyword argument _attributes: AppleEvent attribute dictionary
		"""
		_code = 'CWIE'
		_subcode = 'EXPT'

		aetools.keysubst(_arguments, self._argmap_export)
		if _no_object != None: raise TypeError, 'No direct arg expected'


		_reply, _arguments, _attributes = self.send(_code, _subcode,
				_arguments, _attributes)
		if _arguments.get('errn', 0):
			raise aetools.Error, aetools.decodeerror(_arguments)
		# XXXX Optionally decode result
		if _arguments.has_key('----'):
			return _arguments['----']

	def remove_object_code(self, _no_object=None, _attributes={}, **_arguments):
		"""remove object code: remove object code from a project or target
		Keyword argument _attributes: AppleEvent attribute dictionary
		"""
		_code = 'CWIE'
		_subcode = 'RMOB'

		if _arguments: raise TypeError, 'No optional args expected'
		if _no_object != None: raise TypeError, 'No direct arg expected'


		_reply, _arguments, _attributes = self.send(_code, _subcode,
				_arguments, _attributes)
		if _arguments.get('errn', 0):
			raise aetools.Error, aetools.decodeerror(_arguments)
		# XXXX Optionally decode result
		if _arguments.has_key('----'):
			return _arguments['----']

	def remove_target_files(self, _object, _attributes={}, **_arguments):
		"""remove target files: remove files from a target
		Required argument: an AE object reference
		Keyword argument _attributes: AppleEvent attribute dictionary
		"""
		_code = 'CWIE'
		_subcode = 'RMFL'

		if _arguments: raise TypeError, 'No optional args expected'
		_arguments['----'] = _object


		_reply, _arguments, _attributes = self.send(_code, _subcode,
				_arguments, _attributes)
		if _arguments.get('errn', 0):
			raise aetools.Error, aetools.decodeerror(_arguments)
		# XXXX Optionally decode result
		if _arguments.has_key('----'):
			return _arguments['----']

	def run_target(self, _no_object=None, _attributes={}, **_arguments):
		"""run target: run a project or target
		Keyword argument _attributes: AppleEvent attribute dictionary
		"""
		_code = 'CWIE'
		_subcode = 'RUN '

		if _arguments: raise TypeError, 'No optional args expected'
		if _no_object != None: raise TypeError, 'No direct arg expected'


		_reply, _arguments, _attributes = self.send(_code, _subcode,
				_arguments, _attributes)
		if _arguments.get('errn', 0):
			raise aetools.Error, aetools.decodeerror(_arguments)
		# XXXX Optionally decode result
		if _arguments.has_key('----'):
			return _arguments['----']

	def touch_file(self, _object=None, _attributes={}, **_arguments):
		"""touch file: touch a file in a project or target for compilation
		Required argument: the file or files to be touched
		Keyword argument _attributes: AppleEvent attribute dictionary
		"""
		_code = 'CWIE'
		_subcode = 'TOCH'

		if _arguments: raise TypeError, 'No optional args expected'
		_arguments['----'] = _object


		_reply, _arguments, _attributes = self.send(_code, _subcode,
				_arguments, _attributes)
		if _arguments.get('errn', 0):
			raise aetools.Error, aetools.decodeerror(_arguments)
		# XXXX Optionally decode result
		if _arguments.has_key('----'):
			return _arguments['----']

	def update(self, _no_object=None, _attributes={}, **_arguments):
		"""update: bring a project or target up to date
		Keyword argument _attributes: AppleEvent attribute dictionary
		"""
		_code = 'CWIE'
		_subcode = 'UP2D'

		if _arguments: raise TypeError, 'No optional args expected'
		if _no_object != None: raise TypeError, 'No direct arg expected'


		_reply, _arguments, _attributes = self.send(_code, _subcode,
				_arguments, _attributes)
		if _arguments.get('errn', 0):
			raise aetools.Error, aetools.decodeerror(_arguments)
		# XXXX Optionally decode result
		if _arguments.has_key('----'):
			return _arguments['----']


class ToolServer_worksheet(aetools.ComponentItem):
	"""ToolServer worksheet - a ToolServer worksheet """
	want = 'TOOL'
class inherits(aetools.NProperty):
	"""inherits - all properties and elements of the given class are inherited by this class. """
	which = 'c@#^'
	want = 'TXTD'

ToolServer_worksheets = ToolServer_worksheet

class build_progress_document(aetools.ComponentItem):
	"""build progress document - a build progress document """
	want = 'PRGS'

build_progress_documents = build_progress_document

class catalog_document(aetools.ComponentItem):
	"""catalog document - a browser catalog document """
	want = 'CTLG'

catalog_documents = catalog_document

class class_browser(aetools.ComponentItem):
	"""class browser - a class browser """
	want = 'BROW'

class_browsers = class_browser

class class_hierarchies(aetools.ComponentItem):
	"""class hierarchies - more than one class hierarchy document """
	want = 'HIER'

class_hierarchy = class_hierarchies

class editor_document(aetools.ComponentItem):
	"""editor document - an editor document """
	want = 'EDIT'

editor_documents = editor_document

class file_compare_document(aetools.ComponentItem):
	"""file compare document - a file compare document """
	want = 'COMP'

file_compare_documents = file_compare_document

class message_document(aetools.ComponentItem):
	"""message document - a message document """
	want = 'MSSG'

message_documents = message_document

class project_document(aetools.ComponentItem):
	"""project document - a project document """
	want = 'PRJD'
class current_target(aetools.NProperty):
	"""current target - the current target """
	which = 'CURT'
	want = 'TRGT'
#        element 'TRGT' as ['indx', 'name', 'test', 'rang']

project_documents = project_document

class project_inspector(aetools.ComponentItem):
	"""project inspector - the project inspector """
	want = 'INSP'

project_inspectors = project_inspector

class single_class_browser(aetools.ComponentItem):
	"""single class browser - a single class browser """
	want = '1BRW'

single_class_browsers = single_class_browser

class single_class_hierarchies(aetools.ComponentItem):
	"""single class hierarchies - more than one single class hierarchy document """
	want = '1HIR'

single_class_hierarchy = single_class_hierarchies

class subtarget(aetools.ComponentItem):
	"""subtarget - a target that is prerequisite for another target """
	want = 'SBTG'
class target(aetools.NProperty):
	"""target - the target that is dependent on this subtarget """
	which = 'TrgT'
	want = 'TRGT'
class link_against_output(aetools.NProperty):
	"""link against output - is the output of this subtarget linked into its dependent target? """
	which = 'LNKO'
	want = 'bool'

subtargets = subtarget

class symbol_browser(aetools.ComponentItem):
	"""symbol browser - a symbol browser """
	want = 'SYMB'

symbol_browsers = symbol_browser

class target(aetools.ComponentItem):
	"""target - a target in a project """
	want = 'TRGT'
class name(aetools.NProperty):
	"""name -  """
	which = 'pnam'
	want = 'itxt'
class project_document(aetools.NProperty):
	"""project document - the project document that contains this target """
	which = 'PrjD'
	want = 'PRJD'
#        element 'SRCF' as ['indx', 'test', 'rang']
#        element 'SBTG' as ['indx', 'test', 'rang']

class target_file(aetools.ComponentItem):
	"""target file - a source or header file in a target """
	want = 'SRCF'
class id(aetools.NProperty):
	"""id - the unique ID number of the target file """
	which = 'ID  '
	want = 'long'
class type(aetools.NProperty):
	"""type - the type of source file """
	which = 'FTYP'
	want = 'FTYP'
class location(aetools.NProperty):
	"""location - the location of the target file on disk """
	which = 'FILE'
	want = 'fss '
class path(aetools.NProperty):
	"""path - the path of the source file on disk """
	which = 'Path'
	want = 'itxt'
class linked(aetools.NProperty):
	"""linked - is the source file in the link order of its target? """
	which = 'LINK'
	want = 'bool'
class link_index(aetools.NProperty):
	"""link index - the index of the source file in its target\xd5s link order (-1 if source file is not in link order) """
	which = 'LIDX'
	want = 'long'
class modified_date(aetools.NProperty):
	"""modified date - the date and time this source file was last modified """
	which = 'MODD'
	want = 'ldt '
class compiled_date(aetools.NProperty):
	"""compiled date - the date and this source file was last compiled """
	which = 'CMPD'
	want = 'ldt '
class code_size(aetools.NProperty):
	"""code size - the size of the code (in bytes) produced by compiling this source file """
	which = 'CSZE'
	want = 'long'
class data_size(aetools.NProperty):
	"""data size - the size of the date (in bytes) produced by compiling this source file """
	which = 'DSZE'
	want = 'long'
class debug(aetools.NProperty):
	"""debug - is debugging information generated for this source file? """
	which = 'DBUG'
	want = 'bool'
class weak_link(aetools.NProperty):
	"""weak link - is this shared library linked weakly? """
	which = 'WEAK'
	want = 'bool'
class init_before(aetools.NProperty):
	"""init before - is the \xd4initialize before\xd5 flag set for this shared library? """
	which = 'INIT'
	want = 'bool'
class merge_output(aetools.NProperty):
	"""merge output - is this shared library merged into another code fragment? """
	which = 'MRGE'
	want = 'bool'
class prerequisites(aetools.NProperty):
	"""prerequisites - the source files needed to build this source file """
	which = 'PRER'
	want = 'list'
class dependents(aetools.NProperty):
	"""dependents - the source files that need this source file in order to build """
	which = 'DPND'
	want = 'list'

target_files = target_file

targets = target

class text_document(aetools.ComponentItem):
	"""text document - a document that contains text """
	want = 'TXTD'
class modified(aetools.NProperty):
	"""modified - Has the document been modified since the last save? """
	which = 'imod'
	want = 'bool'
class selection(aetools.NProperty):
	"""selection - the selection visible to the user """
	which = 'sele'
	want = 'csel'
#        element 'cha ' as ['indx', 'rele', 'rang', 'test']
#        element 'cins' as ['rele']
#        element 'clin' as ['indx', 'rang', 'rele']
#        element 'ctxt' as ['rang']

text_documents = text_document
ToolServer_worksheet._superclassnames = ['text_document']
ToolServer_worksheet._privpropdict = {
	'inherits' : inherits,
}
ToolServer_worksheet._privelemdict = {
}
import Standard_Suite
build_progress_document._superclassnames = ['document']
build_progress_document._privpropdict = {
	'inherits' : inherits,
}
build_progress_document._privelemdict = {
}
catalog_document._superclassnames = ['text_document']
catalog_document._privpropdict = {
	'inherits' : inherits,
}
catalog_document._privelemdict = {
}
class_browser._superclassnames = ['text_document']
class_browser._privpropdict = {
	'inherits' : inherits,
}
class_browser._privelemdict = {
}
class_hierarchies._superclassnames = []
class_hierarchies._privpropdict = {
}
class_hierarchies._privelemdict = {
}
editor_document._superclassnames = ['text_document']
editor_document._privpropdict = {
	'inherits' : inherits,
}
editor_document._privelemdict = {
}
file_compare_document._superclassnames = ['text_document']
file_compare_document._privpropdict = {
	'inherits' : inherits,
}
file_compare_document._privelemdict = {
}
message_document._superclassnames = ['text_document']
message_document._privpropdict = {
	'inherits' : inherits,
}
message_document._privelemdict = {
}
project_document._superclassnames = ['document']
project_document._privpropdict = {
	'inherits' : inherits,
	'current_target' : current_target,
}
project_document._privelemdict = {
	'target' : target,
}
project_inspector._superclassnames = ['document']
project_inspector._privpropdict = {
	'inherits' : inherits,
}
project_inspector._privelemdict = {
}
single_class_browser._superclassnames = ['text_document']
single_class_browser._privpropdict = {
	'inherits' : inherits,
}
single_class_browser._privelemdict = {
}
single_class_hierarchies._superclassnames = []
single_class_hierarchies._privpropdict = {
}
single_class_hierarchies._privelemdict = {
}
subtarget._superclassnames = ['target']
subtarget._privpropdict = {
	'inherits' : inherits,
	'target' : target,
	'link_against_output' : link_against_output,
}
subtarget._privelemdict = {
}
symbol_browser._superclassnames = ['text_document']
symbol_browser._privpropdict = {
	'inherits' : inherits,
}
symbol_browser._privelemdict = {
}
target._superclassnames = []
target._privpropdict = {
	'name' : name,
	'project_document' : project_document,
}
target._privelemdict = {
	'target_file' : target_file,
	'subtarget' : subtarget,
}
target_file._superclassnames = []
target_file._privpropdict = {
	'id' : id,
	'type' : type,
	'location' : location,
	'path' : path,
	'linked' : linked,
	'link_index' : link_index,
	'modified_date' : modified_date,
	'compiled_date' : compiled_date,
	'code_size' : code_size,
	'data_size' : data_size,
	'debug' : debug,
	'weak_link' : weak_link,
	'init_before' : init_before,
	'merge_output' : merge_output,
	'prerequisites' : prerequisites,
	'dependents' : dependents,
}
target_file._privelemdict = {
}
text_document._superclassnames = ['document']
text_document._privpropdict = {
	'inherits' : inherits,
	'modified' : modified,
	'selection' : selection,
}
text_document._privelemdict = {
	'character' : Standard_Suite.character,
	'insertion_point' : Standard_Suite.insertion_point,
	'line' : Standard_Suite.line,
	'text' : Standard_Suite.text,
}
_Enum_DKND = {
	'project' : 'PRJD',	# a project document
	'editor_document' : 'EDIT',	# an editor document
	'message' : 'MSSG',	# a message document
	'file_compare' : 'COMP',	# a file compare document
	'catalog_document' : 'CTLG',	# a browser catalog
	'class_browser' : 'BROW',	# a class browser document
	'single_class_browser' : '1BRW',	# a single class browser document
	'symbol_browser' : 'SYMB',	# a symbol browser document
	'class_hierarchy' : 'HIER',	# a class hierarchy document
	'single_class_hierarchy' : '1HIR',	# a single class hierarchy document
	'project_inspector' : 'INSP',	# a project inspector
	'ToolServer_worksheet' : 'TOOL',	# the ToolServer worksheet
	'build_progress_document' : 'PRGS',	# the build progress window
}

_Enum_FTYP = {
	'library_file' : 'LIBF',	# a library file
	'project_file' : 'PRJF',	# a project file
	'resource_file' : 'RESF',	# a resource file
	'text_file' : 'TXTF',	# a text file
	'unknown_file' : 'UNKN',	# unknown file type
}

_Enum_Inte = {
	'never_interact' : 'eNvr',	# never allow user interactions
	'interact_with_self' : 'eInS',	# allow user interaction only when an AppleEvent is sent from within CodeWarrior
	'interact_with_local' : 'eInL',	# allow user interaction when AppleEvents are sent from applications on the same machine (default)
	'interact_with_all' : 'eInA',	# allow user interaction from both local and remote AppleEvents
}

_Enum_PERM = {
	'read_write' : 'RdWr',	# the file is open with read/write permission
	'read_only' : 'Read',	# the file is open with read/only permission
	'checked_out_read_write' : 'CkRW',	# the file is checked out with read/write permission
	'checked_out_read_only' : 'CkRO',	# the file is checked out with read/only permission
	'checked_out_read_modify' : 'CkRM',	# the file is checked out with read/modify permission
	'locked' : 'Lock',	# the file is locked on disk
	'none' : 'LNNO',	# the file is new
}


#
# Indices of types declared in this module
#
_classdeclarations = {
	'1BRW' : single_class_browser,
	'PRJD' : project_document,
	'SYMB' : symbol_browser,
	'EDIT' : editor_document,
	'COMP' : file_compare_document,
	'TOOL' : ToolServer_worksheet,
	'SBTG' : subtarget,
	'MSSG' : message_document,
	'INSP' : project_inspector,
	'TXTD' : text_document,
	'CTLG' : catalog_document,
	'HIER' : class_hierarchies,
	'TRGT' : target,
	'PRGS' : build_progress_document,
	'SRCF' : target_file,
	'BROW' : class_browser,
	'1HIR' : single_class_hierarchies,
}

_propdeclarations = {
	'CURT' : current_target,
	'PrjD' : project_document,
	'MRGE' : merge_output,
	'WEAK' : weak_link,
	'DPND' : dependents,
	'c@#^' : inherits,
	'ID  ' : id,
	'CMPD' : compiled_date,
	'LIDX' : link_index,
	'FILE' : location,
	'Path' : path,
	'LNKO' : link_against_output,
	'imod' : modified,
	'sele' : selection,
	'DSZE' : data_size,
	'INIT' : init_before,
	'MODD' : modified_date,
	'FTYP' : type,
	'TrgT' : target,
	'pnam' : name,
	'LINK' : linked,
	'CSZE' : code_size,
	'DBUG' : debug,
	'PRER' : prerequisites,
}

_compdeclarations = {
}

_enumdeclarations = {
	'Inte' : _Enum_Inte,
	'DKND' : _Enum_DKND,
	'FTYP' : _Enum_FTYP,
	'PERM' : _Enum_PERM,
}
