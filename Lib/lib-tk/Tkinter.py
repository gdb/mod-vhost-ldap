# Tkinter.py -- Tk/Tcl widget wrappers

__version__ = "$Revision$"

try:
	# See if modern _tkinter is present
	import _tkinter
	tkinter = _tkinter # b/w compat
except ImportError:
	# No modern _tkinter -- try oldfashioned tkinter
	import tkinter
	if hasattr(tkinter, "__path__"):
		import sys, os
		# Append standard platform specific directory
		p = tkinter.__path__
		for dir in sys.path:
			if (dir not in p and
			    os.path.basename(dir) == sys.platform):
				p.append(dir)
		del sys, os, p, dir
		from tkinter import tkinter
TclError = tkinter.TclError
from types import *
from Tkconstants import *
import string; _string = string; del string

TkVersion = _string.atof(tkinter.TK_VERSION)
TclVersion = _string.atof(tkinter.TCL_VERSION)

######################################################################
# Since the values of file event masks changed from Tk 4.0 to Tk 4.1,
# they are defined here (and not in Tkconstants):
######################################################################
if TkVersion >= 4.1:
    READABLE = 2
    WRITABLE = 4
    EXCEPTION = 8
else:
    READABLE = 1
    WRITABLE = 2
    EXCEPTION = 4
    
    
def _flatten(tuple):
	res = ()
	for item in tuple:
		if type(item) in (TupleType, ListType):
			res = res + _flatten(item)
		elif item is not None:
			res = res + (item,)
	return res

def _cnfmerge(cnfs):
	if type(cnfs) is DictionaryType:
		return cnfs
	elif type(cnfs) in (NoneType, StringType):
		
		return cnfs
	else:
		cnf = {}
		for c in _flatten(cnfs):
			for k, v in c.items():
				cnf[k] = v
		return cnf

class Event:
	pass

_default_root = None

def _tkerror(err):
	pass

def _exit(code='0'):
	raise SystemExit, code

_varnum = 0
class Variable:
	def __init__(self, master=None):
		global _default_root
		global _varnum
		if master:
			self._tk = master.tk
		else:
			self._tk = _default_root.tk
		self._name = 'PY_VAR' + `_varnum`
		_varnum = _varnum + 1
	def __del__(self):
		self._tk.globalunsetvar(self._name)
	def __str__(self):
		return self._name
	def set(self, value):
		return self._tk.globalsetvar(self._name, value)

class StringVar(Variable):
	def __init__(self, master=None):
		Variable.__init__(self, master)
	def get(self):
		return self._tk.globalgetvar(self._name)

class IntVar(Variable):
	def __init__(self, master=None):
		Variable.__init__(self, master)
	def get(self):
		return self._tk.getint(self._tk.globalgetvar(self._name))

class DoubleVar(Variable):
	def __init__(self, master=None):
		Variable.__init__(self, master)
	def get(self):
		return self._tk.getdouble(self._tk.globalgetvar(self._name))

class BooleanVar(Variable):
	def __init__(self, master=None):
		Variable.__init__(self, master)
	def get(self):
		return self._tk.getboolean(self._tk.globalgetvar(self._name))

def mainloop(n=0):
	_default_root.tk.mainloop(n)

def getint(s):
	return _default_root.tk.getint(s)

def getdouble(s):
	return _default_root.tk.getdouble(s)

def getboolean(s):
	return _default_root.tk.getboolean(s)

class Misc:
	def tk_strictMotif(self, boolean=None):
		return self.tk.getboolean(self.tk.call(
			'set', 'tk_strictMotif', boolean))
	def tk_menuBar(self, *args):
		apply(self.tk.call, ('tk_menuBar', self._w) + args)
	def wait_variable(self, name='PY_VAR'):
		self.tk.call('tkwait', 'variable', name)
	waitvar = wait_variable # XXX b/w compat
	def wait_window(self, window=None):
		if window == None:
			window = self
		self.tk.call('tkwait', 'window', window._w)
	def wait_visibility(self, window=None):
		if window == None:
			window = self
		self.tk.call('tkwait', 'visibility', window._w)
	def setvar(self, name='PY_VAR', value='1'):
		self.tk.setvar(name, value)
	def getvar(self, name='PY_VAR'):
		return self.tk.getvar(name)
	def getint(self, s):
		return self.tk.getint(s)
	def getdouble(self, s):
		return self.tk.getdouble(s)
	def getboolean(self, s):
		return self.tk.getboolean(s)
	def focus_set(self):
		self.tk.call('focus', self._w)
	focus = focus_set # XXX b/w compat?
	def focus_default_set(self):
		self.tk.call('focus', 'default', self._w)
	def focus_default_none(self):
		self.tk.call('focus', 'default', 'none')
	focus_default = focus_default_set
	def focus_none(self):
		self.tk.call('focus', 'none')
	def focus_get(self):
		name = self.tk.call('focus')
		if name == 'none' or not name: return None
		return self._nametowidget(name)
	def tk_focusNext(self):
		name = self.tk.call('tk_focusNext', self._w)
		if not name: return None
		return self._nametowidget(name)
	def tk_focusPrev(self):
		name = self.tk.call('tk_focusPrev', self._w)
		if not name: return None
		return self._nametowidget(name)
	def after(self, ms, func=None, *args):
		if not func:
			# I'd rather use time.sleep(ms*0.001)
			self.tk.call('after', ms)
		else:
			# XXX Disgusting hack to clean up after calling func
			tmp = []
			def callit(func=func, args=args, tk=self.tk, tmp=tmp):
				try:
					apply(func, args)
				finally:
					tk.deletecommand(tmp[0])
			name = self._register(callit)
			tmp.append(name)
			return self.tk.call('after', ms, name)
	def after_idle(self, func, *args):
		return apply(self.after, ('idle', func) + args)
	def after_cancel(self, id):
		self.tk.call('after', 'cancel', id)
	def bell(self, displayof=None):
		if displayof:
			self.tk.call('bell', '-displayof', displayof)
		else:
			self.tk.call('bell', '-displayof', self._w)
	# XXX grab current w/o window argument
	def grab_current(self):
		name = self.tk.call('grab', 'current', self._w)
		if not name: return None
		return self._nametowidget(name)
	def grab_release(self):
		self.tk.call('grab', 'release', self._w)
	def grab_set(self):
		self.tk.call('grab', 'set', self._w)
	def grab_set_global(self):
		self.tk.call('grab', 'set', '-global', self._w)
	def grab_status(self):
		status = self.tk.call('grab', 'status', self._w)
		if status == 'none': status = None
		return status
	def lower(self, belowThis=None):
		self.tk.call('lower', self._w, belowThis)
	def option_add(self, pattern, value, priority = None):
		self.tk.call('option', 'add', pattern, value, priority)
	def option_clear(self):
		self.tk.call('option', 'clear')
	def option_get(self, name, className):
		return self.tk.call('option', 'get', self._w, name, className)
	def option_readfile(self, fileName, priority = None):
		self.tk.call('option', 'readfile', fileName, priority)
	def selection_clear(self):
		self.tk.call('selection', 'clear', self._w)
	def selection_get(self, type=None):
		return self.tk.call('selection', 'get', type)
	def selection_handle(self, func, type=None, format=None):
		name = self._register(func)
		self.tk.call('selection', 'handle', self._w, 
			     name, type, format)
	def selection_own(self, func=None):
		name = self._register(func)
		self.tk.call('selection', 'own', self._w, name)
	def selection_own_get(self):
		return self._nametowidget(self.tk.call('selection', 'own'))
	def send(self, interp, cmd, *args):
		return apply(self.tk.call, ('send', interp, cmd) + args)
	def lower(self, belowThis=None):
		self.tk.call('lift', self._w, belowThis)
	def tkraise(self, aboveThis=None):
		self.tk.call('raise', self._w, aboveThis)
	lift = tkraise
	def colormodel(self, value=None):
		return self.tk.call('tk', 'colormodel', self._w, value)
	def winfo_atom(self, name):
		return self.tk.getint(self.tk.call('winfo', 'atom', name))
	def winfo_atomname(self, id):
		return self.tk.call('winfo', 'atomname', id)
	def winfo_cells(self):
		return self.tk.getint(
			self.tk.call('winfo', 'cells', self._w))
	def winfo_children(self):
		return map(self._nametowidget,
			   self.tk.splitlist(self.tk.call(
				   'winfo', 'children', self._w)))
	def winfo_class(self):
		return self.tk.call('winfo', 'class', self._w)
	def winfo_containing(self, rootX, rootY):
		return self.tk.call('winfo', 'containing', rootX, rootY)
	def winfo_depth(self):
		return self.tk.getint(self.tk.call('winfo', 'depth', self._w))
	def winfo_exists(self):
		return self.tk.getint(
			self.tk.call('winfo', 'exists', self._w))
	def winfo_fpixels(self, number):
		return self.tk.getdouble(self.tk.call(
			'winfo', 'fpixels', self._w, number))
	def winfo_geometry(self):
		return self.tk.call('winfo', 'geometry', self._w)
	def winfo_height(self):
		return self.tk.getint(
			self.tk.call('winfo', 'height', self._w))
	def winfo_id(self):
		return self.tk.getint(
			self.tk.call('winfo', 'id', self._w))
	def winfo_interps(self):
		return self.tk.splitlist(
			self.tk.call('winfo', 'interps'))
	def winfo_ismapped(self):
		return self.tk.getint(
			self.tk.call('winfo', 'ismapped', self._w))
	def winfo_name(self):
		return self.tk.call('winfo', 'name', self._w)
	def winfo_parent(self):
		return self.tk.call('winfo', 'parent', self._w)
	def winfo_pathname(self, id):
		return self.tk.call('winfo', 'pathname', id)
	def winfo_pixels(self, number):
		return self.tk.getint(
			self.tk.call('winfo', 'pixels', self._w, number))
	def winfo_reqheight(self):
		return self.tk.getint(
			self.tk.call('winfo', 'reqheight', self._w))
	def winfo_reqwidth(self):
		return self.tk.getint(
			self.tk.call('winfo', 'reqwidth', self._w))
	def winfo_rgb(self, color):
		return self._getints(
			self.tk.call('winfo', 'rgb', self._w, color))
	def winfo_rootx(self):
		return self.tk.getint(
			self.tk.call('winfo', 'rootx', self._w))
	def winfo_rooty(self):
		return self.tk.getint(
			self.tk.call('winfo', 'rooty', self._w))
	def winfo_screen(self):
		return self.tk.call('winfo', 'screen', self._w)
	def winfo_screencells(self):
		return self.tk.getint(
			self.tk.call('winfo', 'screencells', self._w))
	def winfo_screendepth(self):
		return self.tk.getint(
			self.tk.call('winfo', 'screendepth', self._w))
	def winfo_screenheight(self):
		return self.tk.getint(
			self.tk.call('winfo', 'screenheight', self._w))
	def winfo_screenmmheight(self):
		return self.tk.getint(
			self.tk.call('winfo', 'screenmmheight', self._w))
	def winfo_screenmmwidth(self):
		return self.tk.getint(
			self.tk.call('winfo', 'screenmmwidth', self._w))
	def winfo_screenvisual(self):
		return self.tk.call('winfo', 'screenvisual', self._w)
	def winfo_screenwidth(self):
		return self.tk.getint(
			self.tk.call('winfo', 'screenwidth', self._w))
	def winfo_toplevel(self):
		return self._nametowidget(self.tk.call(
			'winfo', 'toplevel', self._w))
	def winfo_visual(self):
		return self.tk.call('winfo', 'visual', self._w)
	def winfo_vrootheight(self):
		return self.tk.getint(
			self.tk.call('winfo', 'vrootheight', self._w))
	def winfo_vrootwidth(self):
		return self.tk.getint(
			self.tk.call('winfo', 'vrootwidth', self._w))
	def winfo_vrootx(self):
		return self.tk.getint(
			self.tk.call('winfo', 'vrootx', self._w))
	def winfo_vrooty(self):
		return self.tk.getint(
			self.tk.call('winfo', 'vrooty', self._w))
	def winfo_width(self):
		return self.tk.getint(
			self.tk.call('winfo', 'width', self._w))
	def winfo_x(self):
		return self.tk.getint(
			self.tk.call('winfo', 'x', self._w))
	def winfo_y(self):
		return self.tk.getint(
			self.tk.call('winfo', 'y', self._w))
	def update(self):
		self.tk.call('update')
	def update_idletasks(self):
		self.tk.call('update', 'idletasks')
	def bindtags(self, tagList=None):
		if tagList is None:
			return self.tk.splitlist(
				self.tk.call('bindtags', self._w))
		else:
			self.tk.call('bindtags', self._w, tagList)
	def _bind(self, what, sequence, func, add):
		if func:
			cmd = ("%sset _tkinter_break [%s %s]\n"
			       'if {"$_tkinter_break" == "break"} break\n') \
			       % (add and '+' or '',
				  self._register(func, self._substitute),
				  _string.join(self._subst_format))
			apply(self.tk.call, what + (sequence, cmd))
		elif func == '':
			apply(self.tk.call, what + (sequence, func))
		else:
			return apply(self.tk.call, what + (sequence,))
	def bind(self, sequence=None, func=None, add=None):
		return self._bind(('bind', self._w), sequence, func, add)
	def unbind(self, sequence):
		self.tk.call('bind', self._w, sequence, '')
	def bind_all(self, sequence=None, func=None, add=None):
		return self._bind(('bind', 'all'), sequence, func, add)
	def unbind_all(self, sequence):
		self.tk.call('bind', 'all' , sequence, '')
	def bind_class(self, className, sequence=None, func=None, add=None):
		self._bind(('bind', className), sequence, func, add)
	def unbind_class(self, className, sequence):
		self.tk.call('bind', className , sequence, '')
	def mainloop(self, n=0):
		self.tk.mainloop(n)
	def quit(self):
		self.tk.quit()
	def _getints(self, string):
		if not string: return None
		return tuple(map(self.tk.getint, self.tk.splitlist(string)))
	def _getdoubles(self, string):
		if not string: return None
		return tuple(map(self.tk.getdouble, self.tk.splitlist(string)))
	def _getboolean(self, string):
		if string:
			return self.tk.getboolean(string)
	def _options(self, cnf, kw = None):
		if kw:
			cnf = _cnfmerge((cnf, kw))
		else:
			cnf = _cnfmerge(cnf)
		res = ()
		for k, v in cnf.items():
			if k[-1] == '_': k = k[:-1]
			if callable(v):
				v = self._register(v)
			res = res + ('-'+k, v)
		return res
	def _nametowidget(self, name):
		w = self
		if name[0] == '.':
			w = w._root()
			name = name[1:]
		find = _string.find
		while name:
			i = find(name, '.')
			if i >= 0:
				name, tail = name[:i], name[i+1:]
			else:
				tail = ''
			w = w.children[name]
			name = tail
		return w
	def _register(self, func, subst=None):
		f = CallWrapper(func, subst, self).__call__
		name = `id(f)`
		try:
			func = func.im_func
		except AttributeError:
			pass
		try:
			name = name + func.__name__
		except AttributeError:
			pass
		self.tk.createcommand(name, f)
		return name
	register = _register
	def _root(self):
		w = self
		while w.master: w = w.master
		return w
	_subst_format = ('%#', '%b', '%f', '%h', '%k', 
			 '%s', '%t', '%w', '%x', '%y',
			 '%A', '%E', '%K', '%N', '%W', '%T', '%X', '%Y')
	def _substitute(self, *args):
		tk = self.tk
		if len(args) != len(self._subst_format): return args
		nsign, b, f, h, k, s, t, w, x, y, A, E, K, N, W, T, X, Y = args
		# Missing: (a, c, d, m, o, v, B, R)
		e = Event()
		e.serial = tk.getint(nsign)
		e.num = tk.getint(b)
		try: e.focus = tk.getboolean(f)
		except TclError: pass
		e.height = tk.getint(h)
		e.keycode = tk.getint(k)
		# For Visibility events, event state is a string and
		# not an integer:
		try:
			e.state = tk.getint(s)
		except TclError:
			e.state = s
		e.time = tk.getint(t)
		e.width = tk.getint(w)
		e.x = tk.getint(x)
		e.y = tk.getint(y)
		e.char = A
		try: e.send_event = tk.getboolean(E)
		except TclError: pass
		e.keysym = K
		e.keysym_num = tk.getint(N)
		e.type = T
		e.widget = self._nametowidget(W)
		e.x_root = tk.getint(X)
		e.y_root = tk.getint(Y)
		return (e,)
	def _report_exception(self):
		import sys
		exc, val, tb = sys.exc_type, sys.exc_value, sys.exc_traceback
		root = self._root()
		root.report_callback_exception(exc, val, tb)

class CallWrapper:
	def __init__(self, func, subst, widget):
		self.func = func
		self.subst = subst
		self.widget = widget
	def __call__(self, *args):
		try:
			if self.subst:
				args = apply(self.subst, args)
			return apply(self.func, args)
		except SystemExit, msg:
			raise SystemExit, msg
		except:
			self.widget._report_exception()

class Wm:
	def aspect(self, 
		   minNumer=None, minDenom=None, 
		   maxNumer=None, maxDenom=None):
		return self._getints(
			self.tk.call('wm', 'aspect', self._w, 
				     minNumer, minDenom, 
				     maxNumer, maxDenom))
	def client(self, name=None):
		return self.tk.call('wm', 'client', self._w, name)
	def command(self, value=None):
		return self.tk.call('wm', 'command', self._w, value)
	def deiconify(self):
		return self.tk.call('wm', 'deiconify', self._w)
	def focusmodel(self, model=None):
		return self.tk.call('wm', 'focusmodel', self._w, model)
	def frame(self):
		return self.tk.call('wm', 'frame', self._w)
	def geometry(self, newGeometry=None):
		return self.tk.call('wm', 'geometry', self._w, newGeometry)
	def grid(self,
		 baseWidht=None, baseHeight=None, 
		 widthInc=None, heightInc=None):
		return self._getints(self.tk.call(
			'wm', 'grid', self._w,
			baseWidht, baseHeight, widthInc, heightInc))
	def group(self, pathName=None):
		return self.tk.call('wm', 'group', self._w, pathName)
	def iconbitmap(self, bitmap=None):
		return self.tk.call('wm', 'iconbitmap', self._w, bitmap)
	def iconify(self):
		return self.tk.call('wm', 'iconify', self._w)
	def iconmask(self, bitmap=None):
		return self.tk.call('wm', 'iconmask', self._w, bitmap)
	def iconname(self, newName=None):
		return self.tk.call('wm', 'iconname', self._w, newName)
	def iconposition(self, x=None, y=None):
		return self._getints(self.tk.call(
			'wm', 'iconposition', self._w, x, y))
	def iconwindow(self, pathName=None):
		return self.tk.call('wm', 'iconwindow', self._w, pathName)
	def maxsize(self, width=None, height=None):
		return self._getints(self.tk.call(
			'wm', 'maxsize', self._w, width, height))
	def minsize(self, width=None, height=None):
		return self._getints(self.tk.call(
			'wm', 'minsize', self._w, width, height))
	def overrideredirect(self, boolean=None):
		return self._getboolean(self.tk.call(
			'wm', 'overrideredirect', self._w, boolean))
	def positionfrom(self, who=None):
		return self.tk.call('wm', 'positionfrom', self._w, who)
	def protocol(self, name=None, func=None):
	        if callable(func):
			command = self._register(func)
		else:
			command = func
		return self.tk.call(
			'wm', 'protocol', self._w, name, command)
	def resizable(self, width=None, height=None):
		return self.tk.call('wm', 'resizable', self._w, width, height)
	def sizefrom(self, who=None):
		return self.tk.call('wm', 'sizefrom', self._w, who)
	def state(self):
		return self.tk.call('wm', 'state', self._w)
	def title(self, string=None):
		return self.tk.call('wm', 'title', self._w, string)
	def transient(self, master=None):
		return self.tk.call('wm', 'transient', self._w, master)
	def withdraw(self):
		return self.tk.call('wm', 'withdraw', self._w)

class Tk(Misc, Wm):
	_w = '.'
	def __init__(self, screenName=None, baseName=None, className='Tk'):
		global _default_root
		self.master = None
		self.children = {}
		if baseName is None:
			import sys, os
			baseName = os.path.basename(sys.argv[0])
			if baseName[-3:] == '.py': baseName = baseName[:-3]
		self.tk = tkinter.create(screenName, baseName, className)
		try:
			# Disable event scanning except for Command-Period
			import MacOS
			MacOS.EnableAppswitch(0)
		except ImportError:
			pass
		else:
			# Work around nasty MacTk bug
			self.update()
		# Version sanity checks
		tk_version = self.tk.getvar('tk_version')
		if tk_version != tkinter.TK_VERSION:
		    raise RuntimeError, \
		    "tk.h version (%s) doesn't match libtk.a version (%s)" \
		    % (tkinter.TK_VERSION, tk_version)
		tcl_version = self.tk.getvar('tcl_version')
		if tcl_version != tkinter.TCL_VERSION:
		    raise RuntimeError, \
		    "tcl.h version (%s) doesn't match libtcl.a version (%s)" \
		    % (tkinter.TCL_VERSION, tcl_version)
		if TkVersion < 4.0:
			raise RuntimeError, \
			"Tk 4.0 or higher is required; found Tk %s" \
			% str(TkVersion)
		self.tk.createcommand('tkerror', _tkerror)
		self.tk.createcommand('exit', _exit)
		self.readprofile(baseName, className)
		if not _default_root:
			_default_root = self
	def destroy(self):
		for c in self.children.values(): c.destroy()
		self.tk.call('destroy', self._w)
	def __str__(self):
		return self._w
	def readprofile(self, baseName, className):
		import os
		if os.environ.has_key('HOME'): home = os.environ['HOME']
		else: home = os.curdir
		class_tcl = os.path.join(home, '.%s.tcl' % className)
		class_py = os.path.join(home, '.%s.py' % className)
		base_tcl = os.path.join(home, '.%s.tcl' % baseName)
		base_py = os.path.join(home, '.%s.py' % baseName)
		dir = {'self': self}
		exec 'from Tkinter import *' in dir
		if os.path.isfile(class_tcl):
			print 'source', `class_tcl`
			self.tk.call('source', class_tcl)
		if os.path.isfile(class_py):
			print 'execfile', `class_py`
			execfile(class_py, dir)
		if os.path.isfile(base_tcl):
			print 'source', `base_tcl`
			self.tk.call('source', base_tcl)
		if os.path.isfile(base_py):
			print 'execfile', `base_py`
			execfile(base_py, dir)
	def report_callback_exception(self, exc, val, tb):
		import traceback
		print "Exception in Tkinter callback"
		traceback.print_exception(exc, val, tb)

class Pack:
	def config(self, cnf={}, **kw):
		apply(self.tk.call, 
		      ('pack', 'configure', self._w) 
		      + self._options(cnf, kw))
	configure = config
	pack = config
	def __setitem__(self, key, value):
		Pack.config({key: value})
	def forget(self):
		self.tk.call('pack', 'forget', self._w)
	pack_forget = forget
	def info(self):
		words = self.tk.splitlist(
			self.tk.call('pack', 'info', self._w))
		dict = {}
		for i in range(0, len(words), 2):
			key = words[i][1:]
			value = words[i+1]
			if value[:1] == '.':
				value = self._nametowidget(value)
			dict[key] = value
		return dict
	pack_info = info
	_noarg_ = ['_noarg_']
	def propagate(self, flag=_noarg_):
		if flag is Pack._noarg_:
			return self._getboolean(self.tk.call(
				'pack', 'propagate', self._w))
		else:
			self.tk.call('pack', 'propagate', self._w, flag)
	pack_propagate = propagate
	def slaves(self):
		return map(self._nametowidget,
			   self.tk.splitlist(
				   self.tk.call('pack', 'slaves', self._w)))
	pack_slaves = slaves

class Place:
	def config(self, cnf={}, **kw):
		for k in ['in_']:
			if kw.has_key(k):
				kw[k[:-1]] = kw[k]
				del kw[k]
		apply(self.tk.call, 
		      ('place', 'configure', self._w) 
		      + self._options(cnf, kw))
	configure = config
	place = config
	def __setitem__(self, key, value):
		Place.config({key: value})
	def forget(self):
		self.tk.call('place', 'forget', self._w)
	place_forget = forget
	def info(self):
		words = self.tk.splitlist(
			self.tk.call('place', 'info', self._w))
		dict = {}
		for i in range(0, len(words), 2):
			key = words[i][1:]
			value = words[i+1]
			if value[:1] == '.':
				value = self._nametowidget(value)
			dict[key] = value
		return dict
	place_info = info
	def slaves(self):
		return map(self._nametowidget,
			   self.tk.splitlist(
				   self.tk.call(
					   'place', 'slaves', self._w)))
	place_slaves = slaves

class Grid:
	# Thanks to Masazumi Yoshikawa (yosikawa@isi.edu)
	def config(self, cnf={}, **kw):
		apply(self.tk.call, 
		      ('grid', 'configure', self._w) 
		      + self._options(cnf, kw))
	grid = config
	def __setitem__(self, key, value):
		Grid.config({key: value})
	def bbox(self, column, row):
		return self._getints(
			self.tk.call(
				'grid', 'bbox', self._w, column, row)) or None
	grid_bbox = bbox
	def columnconfigure(self, index, cnf={}, **kw):
		if type(cnf) is not DictionaryType and not kw:
			options = self._options({cnf: None})
		else:
			options = self._options(cnf, kw)
		res = apply(self.tk.call, 
			      ('grid', 'columnconfigure', self._w, index) 
			      + options)
		if options == ('-minsize', None):
			return self.tk.getint(res) or None
		elif options == ('-weight', None):
			return self.tk.getdouble(res) or None
	def forget(self):
		self.tk.call('grid', 'forget', self._w)
	grid_forget = forget
	def info(self):
		words = self.tk.splitlist(
			self.tk.call('grid', 'info', self._w))
		dict = {}
		for i in range(0, len(words), 2):
			key = words[i][1:]
			value = words[i+1]
			if value[:1] == '.':
				value = self._nametowidget(value)
			dict[key] = value
		return dict
	grid_info = info
	def location(self, x, y):
		return self._getints(
			self.tk.call(
				'grid', 'location', self._w, x, y)) or None
	_noarg_ = ['_noarg_']
	def propagate(self, flag=_noarg_):
		if flag is Grid._noarg_:
			return self._getboolean(self.tk.call(
				'grid', 'propagate', self._w))
		else:
			self.tk.call('grid', 'propagate', self._w, flag)
	grid_propagate = propagate
	def rowconfigure(self, index, cnf={}, **kw):
		if type(cnf) is not DictionaryType and not kw:
			options = self._options({cnf: None})
		else:
			options = self._options(cnf, kw)
		res = apply(self.tk.call, 
			      ('grid', 'rowconfigure', self._w, index) 
			      + options)
		if options == ('-minsize', None):
			return self.tk.getint(res) or None
		elif options == ('-weight', None):
			return self.tk.getdouble(res) or None
	def size(self):
		return self._getints(
			self.tk.call('grid', 'size', self._w)) or None
	def slaves(self, *args):
		return map(self._nametowidget,
			   self.tk.splitlist(
				   apply(self.tk.call,
					 ('grid', 'slaves', self._w) + args)))
	grid_slaves = slaves

class Widget(Misc, Pack, Place, Grid):
	def _setup(self, master, cnf):
		global _default_root
		if not master:
			if not _default_root:
				_default_root = Tk()
			master = _default_root
		if not _default_root:
			_default_root = master
		self.master = master
		self.tk = master.tk
		if cnf.has_key('name'):
			name = cnf['name']
			del cnf['name']
		else:
			name = `id(self)`
		self._name = name
		if master._w=='.':
			self._w = '.' + name
		else:
			self._w = master._w + '.' + name
		self.children = {}
		if self.master.children.has_key(self._name):
			self.master.children[self._name].destroy()
		self.master.children[self._name] = self
	def __init__(self, master, widgetName, cnf={}, kw={}, extra=()):
		if kw:
			cnf = _cnfmerge((cnf, kw))
		self.widgetName = widgetName
		Widget._setup(self, master, cnf)
		classes = []
		for k in cnf.keys():
			if type(k) is ClassType:
				classes.append((k, cnf[k]))
				del cnf[k]
		apply(self.tk.call,
		      (widgetName, self._w) + extra + self._options(cnf))
		for k, v in classes:
			k.config(self, v)
	def config(self, cnf=None, **kw):
		# XXX ought to generalize this so tag_config etc. can use it
		if kw:
			cnf = _cnfmerge((cnf, kw))
		elif cnf:
			cnf = _cnfmerge(cnf)
		if cnf is None:
			cnf = {}
			for x in self.tk.split(
				self.tk.call(self._w, 'configure')):
				cnf[x[0][1:]] = (x[0][1:],) + x[1:]
			return cnf
		if type(cnf) is StringType:
			x = self.tk.split(self.tk.call(
				self._w, 'configure', '-'+cnf))
			return (x[0][1:],) + x[1:]
		apply(self.tk.call, (self._w, 'configure')
		      + self._options(cnf))
	configure = config
	def cget(self, key):
		return self.tk.call(self._w, 'cget', '-' + key)
	__getitem__ = cget
	def __setitem__(self, key, value):
		Widget.config(self, {key: value})
	def keys(self):
		return map(lambda x: x[0][1:],
			   self.tk.split(self.tk.call(self._w, 'configure')))
	def __str__(self):
		return self._w
	def destroy(self):
		for c in self.children.values(): c.destroy()
		if self.master.children.has_key(self._name):
			del self.master.children[self._name]
		self.tk.call('destroy', self._w)
	def _do(self, name, args=()):
		return apply(self.tk.call, (self._w, name) + args)

class Toplevel(Widget, Wm):
	def __init__(self, master=None, cnf={}, **kw):
		if kw:
			cnf = _cnfmerge((cnf, kw))
		extra = ()
		for wmkey in ['screen', 'class_', 'class', 'visual',
			      'colormap']:
			if cnf.has_key(wmkey):
				val = cnf[wmkey]
				# TBD: a hack needed because some keys
				# are not valid as keyword arguments
				if wmkey[-1] == '_': opt = '-'+wmkey[:-1]
				else: opt = '-'+wmkey
				extra = extra + (opt, val)
				del cnf[wmkey]
		Widget.__init__(self, master, 'toplevel', cnf, {}, extra)
		root = self._root()
		self.iconname(root.iconname())
		self.title(root.title())

class Button(Widget):
	def __init__(self, master=None, cnf={}, **kw):
		Widget.__init__(self, master, 'button', cnf, kw)
	def tkButtonEnter(self, *dummy):
		self.tk.call('tkButtonEnter', self._w)
	def tkButtonLeave(self, *dummy):
		self.tk.call('tkButtonLeave', self._w)
	def tkButtonDown(self, *dummy):
		self.tk.call('tkButtonDown', self._w)
	def tkButtonUp(self, *dummy):
		self.tk.call('tkButtonUp', self._w)
	def tkButtonInvoke(self, *dummy):
		self.tk.call('tkButtonInvoke', self._w)
	def flash(self):
		self.tk.call(self._w, 'flash')
	def invoke(self):
		self.tk.call(self._w, 'invoke')

# Indices:
# XXX I don't like these -- take them away
def AtEnd():
	return 'end'
def AtInsert(*args):
	s = 'insert'
	for a in args:
		if a: s = s + (' ' + a)
	return s
def AtSelFirst():
	return 'sel.first'
def AtSelLast():
	return 'sel.last'
def At(x, y=None):
	if y is None:
		return '@' + `x`		
	else:
		return '@' + `x` + ',' + `y`

class Canvas(Widget):
	def __init__(self, master=None, cnf={}, **kw):
		Widget.__init__(self, master, 'canvas', cnf, kw)
	def addtag(self, *args):
		self._do('addtag', args)
	def addtag_above(self, newtag, tagOrId):
		self.addtag(newtag, 'above', tagOrId)
	def addtag_all(self, newtag):
		self.addtag(newtag, 'all')
	def addtag_below(self, newtag, tagOrId):
		self.addtag(newtag, 'below', tagOrId)
	def addtag_closest(self, newtag, x, y, halo=None, start=None):
		self.addtag(newtag, 'closest', x, y, halo, start)
	def addtag_enclosed(self, newtag, x1, y1, x2, y2):
		self.addtag(newtag, 'enclosed', x1, y1, x2, y2)
	def addtag_overlapping(self, newtag, x1, y1, x2, y2):
		self.addtag(newtag, 'overlapping', x1, y1, x2, y2)
	def addtag_withtag(self, newtag, tagOrId):
		self.addtag(newtag, 'withtag', tagOrId)
	def bbox(self, *args):
		return self._getints(self._do('bbox', args)) or None
	def tag_unbind(self, tagOrId, sequence):
		self.tk.call(self._w, 'bind', tagOrId, sequence, '')
	def tag_bind(self, tagOrId, sequence=None, func=None, add=None):
		return self._bind((self._w, 'bind', tagOrId),
				  sequence, func, add)
	def canvasx(self, screenx, gridspacing=None):
		return self.tk.getdouble(self.tk.call(
			self._w, 'canvasx', screenx, gridspacing))
	def canvasy(self, screeny, gridspacing=None):
		return self.tk.getdouble(self.tk.call(
			self._w, 'canvasy', screeny, gridspacing))
	def coords(self, *args):
		return map(self.tk.getdouble,
                           self.tk.splitlist(self._do('coords', args)))
	def _create(self, itemType, args, kw): # Args: (val, val, ..., cnf={})
		args = _flatten(args)
		cnf = args[-1]
		if type(cnf) in (DictionaryType, TupleType):
			args = args[:-1]
		else:
			cnf = {}
		return self.tk.getint(apply(
			self.tk.call,
			(self._w, 'create', itemType) 
			+ args + self._options(cnf, kw)))
	def create_arc(self, *args, **kw):
		return self._create('arc', args, kw)
	def create_bitmap(self, *args, **kw):
		return self._create('bitmap', args, kw)
	def create_image(self, *args, **kw):
		return self._create('image', args, kw)
	def create_line(self, *args, **kw):
		return self._create('line', args, kw)
	def create_oval(self, *args, **kw):
		return self._create('oval', args, kw)
	def create_polygon(self, *args, **kw):
		return self._create('polygon', args, kw)
	def create_rectangle(self, *args, **kw):
		return self._create('rectangle', args, kw)
	def create_text(self, *args, **kw):
		return self._create('text', args, kw)
	def create_window(self, *args, **kw):
		return self._create('window', args, kw)
	def dchars(self, *args):
		self._do('dchars', args)
	def delete(self, *args):
		self._do('delete', args)
	def dtag(self, *args):
		self._do('dtag', args)
	def find(self, *args):
		return self._getints(self._do('find', args)) or ()
	def find_above(self, tagOrId):
		return self.find('above', tagOrId)
	def find_all(self):
		return self.find('all')
	def find_below(self, tagOrId):
		return self.find('below', tagOrId)
	def find_closest(self, x, y, halo=None, start=None):
		return self.find('closest', x, y, halo, start)
	def find_enclosed(self, x1, y1, x2, y2):
		return self.find('enclosed', x1, y1, x2, y2)
	def find_overlapping(self, x1, y1, x2, y2):
		return self.find('overlapping', x1, y1, x2, y2)
	def find_withtag(self, tagOrId):
		return self.find('withtag', tagOrId)
	def focus(self, *args):
		return self._do('focus', args)
	def gettags(self, *args):
		return self.tk.splitlist(self._do('gettags', args))
	def icursor(self, *args):
		self._do('icursor', args)
	def index(self, *args):
		return self.tk.getint(self._do('index', args))
	def insert(self, *args):
		self._do('insert', args)
	def itemcget(self, tagOrId, option):
		return self._do('itemcget', (tagOrId, '-'+option))
	def itemconfig(self, tagOrId, cnf=None, **kw):
		if cnf is None and not kw:
			cnf = {}
			for x in self.tk.split(
				self._do('itemconfigure', (tagOrId))):
				cnf[x[0][1:]] = (x[0][1:],) + x[1:]
			return cnf
		if type(cnf) == StringType and not kw:
			x = self.tk.split(self._do('itemconfigure',
						   (tagOrId, '-'+cnf,)))
			return (x[0][1:],) + x[1:]
		self._do('itemconfigure', (tagOrId,)
			 + self._options(cnf, kw))
	itemconfigure = itemconfig
	def lower(self, *args):
		self._do('lower', args)
	def move(self, *args):
		self._do('move', args)
	def postscript(self, cnf={}, **kw):
		return self._do('postscript', self._options(cnf, kw))
	def tkraise(self, *args):
		self._do('raise', args)
	lift = tkraise
	def scale(self, *args):
		self._do('scale', args)
	def scan_mark(self, x, y):
		self.tk.call(self._w, 'scan', 'mark', x, y)
	def scan_dragto(self, x, y):
		self.tk.call(self._w, 'scan', 'dragto', x, y)
	def select_adjust(self, tagOrId, index):
		self.tk.call(self._w, 'select', 'adjust', tagOrId, index)
	def select_clear(self):
		self.tk.call(self._w, 'select', 'clear')
	def select_from(self, tagOrId, index):
		self.tk.call(self._w, 'select', 'set', tagOrId, index)
	def select_item(self):
		self.tk.call(self._w, 'select', 'item')
	def select_to(self, tagOrId, index):
		self.tk.call(self._w, 'select', 'to', tagOrId, index)
	def type(self, tagOrId):
		return self.tk.call(self._w, 'type', tagOrId) or None
	def xview(self, *args):
		if not args:
			return self._getdoubles(self.tk.call(self._w, 'xview'))
		apply(self.tk.call, (self._w, 'xview')+args)
	def yview(self, *args):
		if not args:
			return self._getdoubles(self.tk.call(self._w, 'yview'))
		apply(self.tk.call, (self._w, 'yview')+args)

class Checkbutton(Widget):
	def __init__(self, master=None, cnf={}, **kw):
		Widget.__init__(self, master, 'checkbutton', cnf, kw)
	def deselect(self):
		self.tk.call(self._w, 'deselect')
	def flash(self):
		self.tk.call(self._w, 'flash')
	def invoke(self):
		self.tk.call(self._w, 'invoke')
	def select(self):
		self.tk.call(self._w, 'select')
	def toggle(self):
		self.tk.call(self._w, 'toggle')

class Entry(Widget):
	def __init__(self, master=None, cnf={}, **kw):
		Widget.__init__(self, master, 'entry', cnf, kw)
	def delete(self, first, last=None):
		self.tk.call(self._w, 'delete', first, last)
	def get(self):
		return self.tk.call(self._w, 'get')
	def icursor(self, index):
		self.tk.call(self._w, 'icursor', index)
	def index(self, index):
		return self.tk.getint(self.tk.call(
			self._w, 'index', index))
	def insert(self, index, string):
		self.tk.call(self._w, 'insert', index, string)
	def scan_mark(self, x):
		self.tk.call(self._w, 'scan', 'mark', x)
	def scan_dragto(self, x):
		self.tk.call(self._w, 'scan', 'dragto', x)
	def selection_adjust(self, index):
		self.tk.call(self._w, 'selection', 'adjust', index)
	select_adjust = selection_adjust
	def selection_clear(self):
		self.tk.call(self._w, 'selection', 'clear')
	select_clear = selection_clear
	def selection_from(self, index):
		self.tk.call(self._w, 'selection', 'set', index)
	select_from = selection_from
	def selection_present(self):
		return self.tk.getboolean(
			self.tk.call(self._w, 'selection', 'present'))
	select_present = selection_present
	def selection_range(self, start, end):
		self.tk.call(self._w, 'selection', 'range', start, end)
	select_range = selection_range
	def selection_to(self, index):
		self.tk.call(self._w, 'selection', 'to', index)
	select_to = selection_to
	def xview(self, index):
		self.tk.call(self._w, 'xview', index)
	def xview_moveto(self, fraction):
		self.tk.call(self._w, 'xview', 'moveto', fraction)
	def xview_scroll(self, number, what):
		self.tk.call(self._w, 'xview', 'scroll', number, what)

class Frame(Widget):
	def __init__(self, master=None, cnf={}, **kw):
		cnf = _cnfmerge((cnf, kw))
		extra = ()
		if cnf.has_key('class'):
			extra = ('-class', cnf['class'])
			del cnf['class']
		Widget.__init__(self, master, 'frame', cnf, {}, extra)

class Label(Widget):
	def __init__(self, master=None, cnf={}, **kw):
		Widget.__init__(self, master, 'label', cnf, kw)

class Listbox(Widget):
	def __init__(self, master=None, cnf={}, **kw):
		Widget.__init__(self, master, 'listbox', cnf, kw)
	def activate(self, index):
		self.tk.call(self._w, 'activate', index)
	def bbox(self, *args):
		return self._getints(self._do('bbox', args)) or None
	def curselection(self):
		# XXX Ought to apply self._getints()...
		return self.tk.splitlist(self.tk.call(
			self._w, 'curselection'))
	def delete(self, first, last=None):
		self.tk.call(self._w, 'delete', first, last)
	def get(self, first, last=None):
		if last:
			return self.tk.splitlist(self.tk.call(
				self._w, 'get', first, last))
		else:
			return self.tk.call(self._w, 'get', first)
	def insert(self, index, *elements):
		apply(self.tk.call,
		      (self._w, 'insert', index) + elements)
	def nearest(self, y):
		return self.tk.getint(self.tk.call(
			self._w, 'nearest', y))
	def scan_mark(self, x, y):
		self.tk.call(self._w, 'scan', 'mark', x, y)
	def scan_dragto(self, x, y):
		self.tk.call(self._w, 'scan', 'dragto', x, y)
	def see(self, index):
		self.tk.call(self._w, 'see', index)
	def index(self, index):
		i = self.tk.call(self._w, 'index', index)
		if i == 'none': return None
		return self.tk.getint(i)
	def select_adjust(self, index):
		self.tk.call(self._w, 'select', 'adjust', index)
	def select_anchor(self, index):
		self.tk.call(self._w, 'selection', 'anchor', index)
	def select_clear(self, first, last=None):
		self.tk.call(self._w,
			     'selection', 'clear', first, last)
	def select_includes(self, index):
		return self.tk.getboolean(self.tk.call(
			self._w, 'selection', 'includes', index))
	def select_set(self, first, last=None):
		self.tk.call(self._w, 'selection', 'set', first, last)
	def size(self):
		return self.tk.getint(self.tk.call(self._w, 'size'))
	def xview(self, *what):
		if not what:
			return self._getdoubles(self.tk.call(self._w, 'xview'))
		apply(self.tk.call, (self._w, 'xview')+what)
	def yview(self, *what):
		if not what:
			return self._getdoubles(self.tk.call(self._w, 'yview'))
		apply(self.tk.call, (self._w, 'yview')+what)

class Menu(Widget):
	def __init__(self, master=None, cnf={}, **kw):
		Widget.__init__(self, master, 'menu', cnf, kw)
	def tk_bindForTraversal(self):
		self.tk.call('tk_bindForTraversal', self._w)
	def tk_mbPost(self):
		self.tk.call('tk_mbPost', self._w)
	def tk_mbUnpost(self):
		self.tk.call('tk_mbUnpost')
	def tk_traverseToMenu(self, char):
		self.tk.call('tk_traverseToMenu', self._w, char)
	def tk_traverseWithinMenu(self, char):
		self.tk.call('tk_traverseWithinMenu', self._w, char)
	def tk_getMenuButtons(self):
		return self.tk.call('tk_getMenuButtons', self._w)
	def tk_nextMenu(self, count):
		self.tk.call('tk_nextMenu', count)
	def tk_nextMenuEntry(self, count):
		self.tk.call('tk_nextMenuEntry', count)
	def tk_invokeMenu(self):
		self.tk.call('tk_invokeMenu', self._w)
	def tk_firstMenu(self):
		self.tk.call('tk_firstMenu', self._w)
	def tk_mbButtonDown(self):
		self.tk.call('tk_mbButtonDown', self._w)
	def tk_popup(self, x, y, entry=""):
		self.tk.call('tk_popup', self._w, x, y, entry)
	def activate(self, index):
		self.tk.call(self._w, 'activate', index)
	def add(self, itemType, cnf={}, **kw):
		apply(self.tk.call, (self._w, 'add', itemType) 
		      + self._options(cnf, kw))
	def add_cascade(self, cnf={}, **kw):
		self.add('cascade', cnf or kw)
	def add_checkbutton(self, cnf={}, **kw):
		self.add('checkbutton', cnf or kw)
	def add_command(self, cnf={}, **kw):
		self.add('command', cnf or kw)
	def add_radiobutton(self, cnf={}, **kw):
		self.add('radiobutton', cnf or kw)
	def add_separator(self, cnf={}, **kw):
		self.add('separator', cnf or kw)
	def delete(self, index1, index2=None):
		self.tk.call(self._w, 'delete', index1, index2)
	def entryconfig(self, index, cnf=None, **kw):
		if cnf is None and not kw:
			cnf = {}
			for x in self.tk.split(apply(self.tk.call,
			    (self._w, 'entryconfigure', index))):
				cnf[x[0][1:]] = (x[0][1:],) + x[1:]
			return cnf
		if type(cnf) == StringType and not kw:
			x = self.tk.split(apply(self.tk.call,
			    (self._w, 'entryconfigure', index, '-'+cnf)))
			return (x[0][1:],) + x[1:]
		apply(self.tk.call, (self._w, 'entryconfigure', index)
		      + self._options(cnf, kw))
	entryconfigure = entryconfig
	def index(self, index):
		i = self.tk.call(self._w, 'index', index)
		if i == 'none': return None
		return self.tk.getint(i)
	def invoke(self, index):
		return self.tk.call(self._w, 'invoke', index)
	def post(self, x, y):
		self.tk.call(self._w, 'post', x, y)
	def unpost(self):
		self.tk.call(self._w, 'unpost')
	def yposition(self, index):
		return self.tk.getint(self.tk.call(
			self._w, 'yposition', index))

class Menubutton(Widget):
	def __init__(self, master=None, cnf={}, **kw):
		Widget.__init__(self, master, 'menubutton', cnf, kw)

class Message(Widget):
	def __init__(self, master=None, cnf={}, **kw):
		Widget.__init__(self, master, 'message', cnf, kw)

class Radiobutton(Widget):
	def __init__(self, master=None, cnf={}, **kw):
		Widget.__init__(self, master, 'radiobutton', cnf, kw)
	def deselect(self):
		self.tk.call(self._w, 'deselect')
	def flash(self):
		self.tk.call(self._w, 'flash')
	def invoke(self):
		self.tk.call(self._w, 'invoke')
	def select(self):
		self.tk.call(self._w, 'select')

class Scale(Widget):
	def __init__(self, master=None, cnf={}, **kw):
		Widget.__init__(self, master, 'scale', cnf, kw)
	def get(self):
		return self.tk.getint(self.tk.call(self._w, 'get'))
	def set(self, value):
		self.tk.call(self._w, 'set', value)

class Scrollbar(Widget):
	def __init__(self, master=None, cnf={}, **kw):
		Widget.__init__(self, master, 'scrollbar', cnf, kw)
	def activate(self, index):
		self.tk.call(self._w, 'activate', index)
	def delta(self, deltax, deltay):
		return self.getdouble(self.tk.call(
			self._w, 'delta', deltax, deltay))
	def fraction(self, x, y):
		return self.getdouble(self.tk.call(
			self._w, 'fraction', x, y))
	def identify(self, x, y):
		return self.tk.call(self._w, 'identify', x, y)
	def get(self):
		return self._getdoubles(self.tk.call(self._w, 'get'))
	def set(self, *args):
		apply(self.tk.call, (self._w, 'set')+args)

class Text(Widget):
	def __init__(self, master=None, cnf={}, **kw):
		Widget.__init__(self, master, 'text', cnf, kw)
		self.bind('<Delete>', self.bspace)
	def bbox(self, *args):
		return self._getints(self._do('bbox', args)) or None
	def bspace(self, *args):
		self.delete('insert')
	def tk_textSelectTo(self, index):
		self.tk.call('tk_textSelectTo', self._w, index)
	def tk_textBackspace(self):
		self.tk.call('tk_textBackspace', self._w)
	def tk_textIndexCloser(self, a, b, c):
		self.tk.call('tk_textIndexCloser', self._w, a, b, c)
	def tk_textResetAnchor(self, index):
		self.tk.call('tk_textResetAnchor', self._w, index)
	def compare(self, index1, op, index2):
		return self.tk.getboolean(self.tk.call(
			self._w, 'compare', index1, op, index2))
	def debug(self, boolean=None):
		return self.tk.getboolean(self.tk.call(
			self._w, 'debug', boolean))
	def delete(self, index1, index2=None):
		self.tk.call(self._w, 'delete', index1, index2)
	def dlineinfo(self, index):
		return self._getints(self.tk.call(self._w, 'dlineinfo', index))
	def get(self, index1, index2=None):
		return self.tk.call(self._w, 'get', index1, index2)
	def index(self, index):
		return self.tk.call(self._w, 'index', index)
	def insert(self, index, chars, *args):
		apply(self.tk.call, (self._w, 'insert', index, chars)+args)
	def mark_gravity(self, markName, direction=None):
		return apply(self.tk.call,
			     (self._w, 'mark', 'gravity', markName, direction))
	def mark_names(self):
		return self.tk.splitlist(self.tk.call(
			self._w, 'mark', 'names'))
	def mark_set(self, markName, index):
		self.tk.call(self._w, 'mark', 'set', markName, index)
	def mark_unset(self, *markNames):
		apply(self.tk.call, (self._w, 'mark', 'unset') + markNames)
	def scan_mark(self, x, y):
		self.tk.call(self._w, 'scan', 'mark', x, y)
	def scan_dragto(self, x, y):
		self.tk.call(self._w, 'scan', 'dragto', x, y)
	def search(self, pattern, index, stopindex=None,
		   forwards=None, backwards=None, exact=None,
		   regexp=None, nocase=None, count=None):
		args = [self._w, 'search']
		if forwards: args.append('-forwards')
		if backwards: args.append('-backwards')
		if exact: args.append('-exact')
		if regexp: args.append('-regexp')
		if nocase: args.append('-nocase')
		if count: args.append('-count'); args.append(count)
		if pattern[0] == '-': args.append('--')
		args.append(pattern)
		args.append(index)
		if stopindex: args.append(stopindex)
		return apply(self.tk.call, tuple(args))
	def see(self, index):
		self.tk.call(self._w, 'see', index)
	def tag_add(self, tagName, index1, index2=None):
		self.tk.call(
			self._w, 'tag', 'add', tagName, index1, index2)
	def tag_unbind(self, tagName, sequence):
		self.tk.call(self._w, 'tag', 'bind', tagName, sequence, '')
	def tag_bind(self, tagName, sequence, func, add=None):
		return self._bind((self._w, 'tag', 'bind', tagName),
				  sequence, func, add)
	def tag_cget(self, tagName, option):
		return self.tk.call(self._w, 'tag', 'cget', tagName, option)
	def tag_config(self, tagName, cnf={}, **kw):
		if type(cnf) == StringType:
			x = self.tk.split(self.tk.call(
				self._w, 'tag', 'configure', tagName, '-'+cnf))
			return (x[0][1:],) + x[1:]
		apply(self.tk.call, 
		      (self._w, 'tag', 'configure', tagName)
		      + self._options(cnf, kw))
	tag_configure = tag_config
	def tag_delete(self, *tagNames):
		apply(self.tk.call, (self._w, 'tag', 'delete') + tagNames)
	def tag_lower(self, tagName, belowThis=None):
		self.tk.call(self._w, 'tag', 'lower', tagName, belowThis)
	def tag_names(self, index=None):
		return self.tk.splitlist(
			self.tk.call(self._w, 'tag', 'names', index))
	def tag_nextrange(self, tagName, index1, index2=None):
		return self.tk.splitlist(self.tk.call(
			self._w, 'tag', 'nextrange', tagName, index1, index2))
	def tag_raise(self, tagName, aboveThis=None):
		self.tk.call(
			self._w, 'tag', 'raise', tagName, aboveThis)
	def tag_ranges(self, tagName):
		return self.tk.splitlist(self.tk.call(
			self._w, 'tag', 'ranges', tagName))
	def tag_remove(self, tagName, index1, index2=None):
		self.tk.call(
			self._w, 'tag', 'remove', tagName, index1, index2)
	def window_cget(self, index, option):
		return self.tk.call(self._w, 'window', 'cget', index, option)
	def window_config(self, index, cnf={}, **kw):
		if type(cnf) == StringType:
			x = self.tk.split(self.tk.call(
				self._w, 'window', 'configure',
				index, '-'+cnf))
			return (x[0][1:],) + x[1:]
		apply(self.tk.call, 
		      (self._w, 'window', 'configure', index)
		      + self._options(cnf, kw))
	window_configure = window_config
	def window_create(self, index, cnf={}, **kw):
		apply(self.tk.call, 
		      (self._w, 'window', 'create', index)
		      + self._options(cnf, kw))
	def window_names(self):
		return self.tk.splitlist(
			self.tk.call(self._w, 'window', 'names'))
	def xview(self, *what):
		if not what:
			return self._getdoubles(self.tk.call(self._w, 'xview'))
		apply(self.tk.call, (self._w, 'xview')+what)
	def yview(self, *what):
		if not what:
			return self._getdoubles(self.tk.call(self._w, 'yview'))
		apply(self.tk.call, (self._w, 'yview')+what)
	def yview_pickplace(self, *what):
		apply(self.tk.call, (self._w, 'yview', '-pickplace')+what)

class OptionMenu(Widget):
	def __init__(self, master, variable, value, *values):
		self.widgetName = 'tk_optionMenu'
		Widget._setup(self, master, {})
		self.menuname = apply(
			self.tk.call,
			(self.widgetName, self._w, variable, value) + values)

class Image:
	def __init__(self, imgtype, name=None, cnf={}, **kw):
		self.name = None
		master = _default_root
		if not master: raise RuntimeError, 'Too early to create image'
		self.tk = master.tk
		if not name: name = `id(self)`
		if kw and cnf: cnf = _cnfmerge((cnf, kw))
		elif kw: cnf = kw
		options = ()
		for k, v in cnf.items():
			if callable(v):
				v = self._register(v)
			options = options + ('-'+k, v)
		apply(self.tk.call,
		      ('image', 'create', imgtype, name,) + options)
		self.name = name
	def __str__(self): return self.name
	def __del__(self):
		if self.name:
			self.tk.call('image', 'delete', self.name)
	def __setitem__(self, key, value):
		self.tk.call(self.name, 'configure', '-'+key, value)
	def __getitem__(self, key):
		return self.tk.call(self.name, 'configure', '-'+key)
	def height(self):
		return self.tk.getint(
			self.tk.call('image', 'height', self.name))
	def type(self):
		return self.tk.call('image', 'type', self.name)
	def width(self):
		return self.tk.getint(
			self.tk.call('image', 'width', self.name))

class PhotoImage(Image):
	def __init__(self, name=None, cnf={}, **kw):
		apply(Image.__init__, (self, 'photo', name, cnf), kw)
	def blank(self):
		self.tk.call(self.name, 'blank')
	def cget(self, option):
		return self.tk.call(self.name, 'cget', '-' + option)
	# XXX config
	def __getitem__(self, key):
		return self.tk.call(self.name, 'cget', '-' + key)
	def copy(self):
		destImage = PhotoImage()
		self.tk.call(destImage, 'copy', self.name)
		return destImage
	def zoom(self,x,y=''):
		destImage = PhotoImage()
		if y=='': y=x
		self.tk.call(destImage, 'copy', self.name, '-zoom',x,y)
		return destImage
	def subsample(self,x,y=''):
		destImage = PhotoImage()
		if y=='': y=x
		self.tk.call(destImage, 'copy', self.name, '-subsample',x,y)
		return destImage
	def get(self, x, y):
		return self.tk.call(self.name, 'get', x, y)
	def put(self, data, to=None):
		args = (self.name, 'put', data)
		if to:
			args = args + to
		apply(self.tk.call, args)
	# XXX read
	def write(self, filename, format=None, from_coords=None):
		args = (self.name, 'write', filename)
		if format:
			args = args + ('-format', format)
		if from_coords:
			args = args + ('-from',) + tuple(from_coords)
		apply(self.tk.call, args)

class BitmapImage(Image):
	def __init__(self, name=None, cnf={}, **kw):
		apply(Image.__init__, (self, 'bitmap', name, cnf), kw)

def image_names(): return _default_root.tk.call('image', 'names')
def image_types(): return _default_root.tk.call('image', 'types')

######################################################################
# Extensions:

class Studbutton(Button):
	def __init__(self, master=None, cnf={}, **kw):
		Widget.__init__(self, master, 'studbutton', cnf, kw)
		self.bind('<Any-Enter>',       self.tkButtonEnter)
		self.bind('<Any-Leave>',       self.tkButtonLeave)
		self.bind('<1>',               self.tkButtonDown)
		self.bind('<ButtonRelease-1>', self.tkButtonUp)

class Tributton(Button):
	def __init__(self, master=None, cnf={}, **kw):
		Widget.__init__(self, master, 'tributton', cnf, kw)
		self.bind('<Any-Enter>',       self.tkButtonEnter)
		self.bind('<Any-Leave>',       self.tkButtonLeave)
		self.bind('<1>',               self.tkButtonDown)
		self.bind('<ButtonRelease-1>', self.tkButtonUp)
		self['fg']               = self['bg']
		self['activebackground'] = self['bg']

######################################################################
# Test:

def _test():
	root = Tk()
	label = Label(root, text="Proof-of-existence test for Tk")
	label.pack()
	test = Button(root, text="Click me!",
		      command=lambda root=root: root.test.config(
			      text="[%s]" % root.test['text']))
	test.pack()
	root.test = test
	quit = Button(root, text="QUIT", command=root.destroy)
	quit.pack()
	root.mainloop()

if __name__ == '__main__':
	_test()


# Emacs cruft
# Local Variables:
# py-indent-offset: 8
# End:
