# Tkinter.py -- Tk/Tcl widget wrappers
import tkinter
from tkinter import TclError

class _Dummy:
	def meth(self):	return

def _isfunctype(func):
	return type(func) in (type(_Dummy.meth), type(_isfunctype))	

FunctionType = type(_isfunctype)
ClassType = type(_Dummy)
MethodType = type(_Dummy.meth)

def tkerror(err):
	pass

class Event:
	pass

class Misc:
	def tk_strictMotif(self, boolean=None):
		self.tk.getboolean(self.tk.call(
			'set', 'tk_strictMotif', boolean))
	def waitvar(self, name='VAR'):
		self.tk.call('tkwait', 'variable', name)
	def setvar(self, name='VAR', value='1'):
		self.tk.setvar(name, value)
	def focus(self):
		self.tk.call('focus', self._w)
	def focus_default(self):
		self.tk.call('focus', 'default', self._w)
	def focus_none(self):
		self.tk.call('focus', 'none')
	#XXX focus_get?
	def after(self, ms, func=None, *args):
		if not func:
			self.tk.call('after', ms)
		else:
			name = self._register(func)
			apply(self.tk.call, ('after', ms, name) + args)
	#XXX grab_current
	def grab_release(self):
		self.tk.call('grab', 'release', self._w)
	def grab_set(self):
		self.tk.call('grab', 'set', self._w)
	def grab_set_global(self):
		self.tk.call('grab', 'set', '-global', self._w)
	def grab_status(self):
		self.tk.call('grab', 'status', self._w)
	def lower(self, belowThis=None):
		self.tk.call('lower', self._w, belowThis)
	def selection_clear(self):
		self.tk.call('selection', 'clear', self._w)
	def selection_get(self, type=None):
		self.tk.call('selection', 'get', type)
	def selection_handle(self, func, type=None, format=None):
		name = self._register(func)
		self.tk.call('selection', 'handle',
			     self._w, name, type, format)
	#XXX def selection_own(self):
	#	self.tk.call('selection', 'own', self._w)
	def send(self, interp, cmd, *args): #XXX
		return apply(self.tk.call, ('send', interp, cmd) + args)
	def colormodel(self, value=None):
		return self.tk.call('tk', 'colormodel', self._w, value)
	def winfo_atom(self, name):
		return self.tk.getint(self.tk.call('winfo', 'atom', name))
	def winfo_atomname(self, id):
		return self.tk.call('winfo', 'atomname', id)
	def winfo_cells(self):
		return self.tk.getint(
			self.tk.call('winfo', 'cells', self._w))
	#XXX winfo_children
	def winfo_class(self):
		return self.tk.call('winfo', 'class', self._w)
	def winfo_containing(self, rootX, rootY):
		return self.tk.call('winfo', 'containing', rootx, rootY)
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
		return self.tk.call('winfo', 'toplevel', self._w)
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
	def bind(self, sequence, func, add=''):
		global _substitute, _subst_prefix
		if add: add = '+'
		name = self._register(func, _substitute)
		self.tk.call('bind', self._w, sequence, 
			     (add + name,) + _subst_prefix)
	def bind_all(self, sequence, func, add=''):
		global _substitute, _subst_prefix
		if add: add = '+'
		name = self._register(func, _substitute)
		self.tk.call('bind', 'all' , sequence, 
			     (add + `name`,) + _subst_prefix)
	def bind_class(self, className, sequence, func, add=''):
		global _substitute, _subst_prefix
		if add: add = '+'
		name = self._register(func, _substitute)
		self.tk.call('bind', className , sequence, 
			     (add + name,) + _subst_prefix)
	def mainloop(self):
		self.tk.mainloop()
	def quit(self):
		self.tk.quit()
	# Utilities
	def _getints(self, string):
		if string:
			res = ()
			for v in self.tk.split(string):
				res = res +  (self.tk.getint(v),)
			return res
		else:
			return string
	def _getboolean(self, string):
		if string:
			return self.tk.getboolean(string)
		else:
			return string
	def _options(self, cnf):
		res = ()
		for k, v in cnf.items():
			if _isfunctype(v):
				v = self._register(v)
			res = res + ('-'+k, v)
		return res
	def _register(self, func, subst=None):
		f = func
		f = _CallSafely(func, subst).__call__
		name = `id(f)`
		if hasattr(func, 'im_func'):
			func = func.im_func
		if hasattr(func, 'func_name') and \
		   type(func.func_name) == type(''):
			name = name + func.func_name
		self.tk.createcommand(name, f)
		return name

_subst_prefix = ('%#', '%b', '%f', '%h', '%k', 
		 '%s', '%t', '%w', '%x', '%y',
		 '%A', '%E', '%K', '%N', '%T', '%X', '%Y')

def _substitute(*args):
	global default_root
	global _subst_prefix
	tk = default_root.tk
	if len(args) != len(_subst_prefix): return args
	nsign, b, f, h, k, s, t, w, x, y, A, E, K, N, T, X, Y = args
	# Missing: (a, c, d, m, o, v, B, R, W)
	#XXX Convert %W (_w) to class instance?
	e = Event()
	e.serial = tk.getint(nsign)
	e.num = tk.getint(b)
	try: e.focus = tk.getboolean(f)
	except TclError: pass
	e.height = tk.getint(h)
	e.keycode = tk.getint(k)
	e.state = tk.getint(s)
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
	#XXX %W stuff
	e.x_root = tk.getint(X)
	e.y_root = tk.getint(Y)
	return (e,)

class _CallSafely:
	def __init__(self, func, subst=None):
		self.func = func
		self.subst = subst
	def __call__(self, *args):
		if self.subst:
			args = self.apply_func(self.subst, args)
		args = self.apply_func(self.func, args)
	def apply_func(self, func, args):
		import sys
		try:
			return apply(func, args)
		except:
			try:
				try:
					t = sys.exc_traceback
					while t:
						sys.stderr.write(
							'  %s, line %s\n' %
							(t.tb_frame.f_code,
							 t.tb_lineno))
						t = t.tb_next
				finally:
					sys.stderr.write('%s: %s\n' %
							 (sys.exc_type,
							  sys.exc_value))
			except:
				print '*** Error in error handling ***'
				print sys.exc_type, ':', sys.exc_value

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
		if _isfunctype(func):
			command = self._register(func)
		else:
			command = func
		return self.tk.call(
			'wm', 'protocol', self._w, name, command)
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
		if baseName is None:
			import sys, os
			baseName = os.path.basename(sys.argv[0])
			if baseName[-3:] == '.py': baseName = baseName[:-3]
		self.tk = tkinter.create(screenName, baseName, className)
		self.tk.createcommand('tkerror', tkerror)
	def __del__(self):
		self.tk.call('destroy', '.')
	def __str__(self):
		return '.'

class Pack:
	def config(self, cnf={}):
		apply(self.tk.call, 
		      ('pack', 'configure', self._w) 
		      + self._options(cnf))
	pack = config
	def __setitem__(self, key, value):
		Pack.config({key: value})
	def forget(self):
		self.tk.call('pack', 'forget', self._w)
	def newinfo(self):
		return self.tk.call('pack', 'newinfo', self._w)
	info = newinfo
	def propagate(self, boolean=None):
		if boolean:
			self.tk.call('pack', 'propagate', self._w)
		else:
			return self._getboolean(self.tk.call(
				'pack', 'propagate', self._w))
	def slaves(self):
		return self.tk.splitlist(self.tk.call(
			'pack', 'slaves', self._w))

class Place:
	def config(self, cnf={}):
		apply(self.tk.call, 
		      ('place', 'configure', self._w) 
		      + self._options(cnf))
	place = config
	def __setitem__(self, key, value):
		Place.config({key: value})
	def forget(self):
		self.tk.call('place', 'forget', self._w)
	def info(self):
		return self.tk.call('place', 'info', self._w)
	def slaves(self):
		return self.tk.splitlist(self.tk.call(
			'place', 'slaves', self._w))

default_root = None

class Widget(Misc, Pack, Place):
	def __init__(self, master, widgetName, cnf={}, extra=()):
		global default_root
		if not master:
			if not default_root:
				default_root = Tk()
			master = default_root
		if not default_root:
			default_root = master
		self.master = master
		self.tk = master.tk
		if cnf.has_key('name'):
			name = cnf['name']
			del cnf['name']
		else:
			name = `id(self)`
		if master._w=='.':
			self._w = '.' + name
		else:
			self._w = master._w + '.' + name
		self.widgetName = widgetName
		apply(self.tk.call, (widgetName, self._w) + extra)
		Widget.config(self, cnf)
	def config(self, cnf={}):
		for k in cnf.keys():
			if type(k) == ClassType:
				k.config(self, cnf[k])
				del cnf[k]
		apply(self.tk.call, (self._w, 'configure')
		      + self._options(cnf))
	def __getitem__(self, key):
		v = self.tk.split(self.tk.call(
			self._w, 'configure', '-' + key))
		return v[4]
	def __setitem__(self, key, value):
		Widget.config(self, {key: value})
	def __str__(self):
		return self._w
	def __del__(self):
		self.tk.call('destroy', self._w)
	destroy = __del__
	def _do(self, name, args=()):
		apply(self.tk.call, (self._w, name) + args) 

class Toplevel(Widget, Wm):
	def __init__(self, master=None, cnf={}):
		extra = ()
		if cnf.has_key('screen'):
			extra = ('-screen', cnf['screen'])
			del cnf['screen']
		if cnf.has_key('class'):
			extra = extra + ('-class', cnf['class'])
			del cnf['class']
		Widget.__init__(self, master, 'toplevel', cnf, extra)
		self.iconname(self.tk.call('wm', 'iconname', '.'))
		self.title(self.tk.call('wm', 'title', '.'))

class Button(Widget):
	def __init__(self, master=None, cnf={}):
		Widget.__init__(self, master, 'button', cnf)
	def tk_butEnter(self):
		self.tk.call('tk_butEnter', self._w)
	def tk_butLeave(self):
		self.tk.call('tk_butLeave', self._w)
	def tk_butDown(self):
		self.tk.call('tk_butDown', self._w)
	def tk_butUp(self):
		self.tk.call('tk_butUp', self._w)
	def flash(self):
		self.tk.call(self._w, 'flash')
	def invoke(self):
		self.tk.call(self._w, 'invoke')

# Indices:
def AtEnd():
	return 'end'
def AtInsert():
	return 'insert'
def AtSelFirst():
	return 'sel.first'
def AtSelLast():
	return 'sel.last'
def At(x, y=None):
	if y:
		return '@' + `x` + ',' + `y`
	else:
		return '@' + `x` 

class Canvas(Widget):
	def __init__(self, master=None, cnf={}):
		Widget.__init__(self, master, 'canvas', cnf)
	def addtag(self, *args):
		self._do('addtag', args)
	def bbox(self, *args):
		return self._getints(self._do('bbox', args))
	def bind(self, tagOrId, sequence, func, add=''):
		global _substitute, _subst_prefix
		if add: add='+'
		name = self._register(func, _substitute)
		self.tk.call(self._w, 'bind', tagOrId, sequence, 
			     (add + name,) + _subst_prefix)
	def canvasx(self, screenx, gridspacing=None):
		return self.tk.getint(self.tk.call(
			self._w, 'canvasx', screenx, gridspacing))
	def canvasy(self, screeny, gridspacing=None):
		return self.tk.getint(self.tk.call(
			self._w, 'canvasy', screeny, gridspacing))
	def coords(self, *args):
		return self._do('coords', args)
	def _create(self, itemType, args): # Args: (value, value, ..., cnf={})
		cnf = args[-1]
		if type(cnf) == type({}):
			args = args[:-1]
		else:
			cnf = {}
		v = (self._w, 'create', itemType) + args
		for k in cnf.keys():
			v = v + ('-' + k, cnf[k])
		return self.tk.getint(apply(self.tk.call, v))
	def create_arc(self, *args):
		Canvas._create(self, 'arc', args)
	def create_bitmap(self, *args):
		Canvas._create(self, 'bitmap', args)
	def create_line(self, *args):
		Canvas._create(self, 'line', args)
	def create_oval(self, *args):
		Canvas._create(self, 'oval', args)
	def create_polygon(self, *args):
		Canvas._create(self, 'polygon', args)
	def create_rectangle(self, *args):
		Canvas._create(self, 'rectangle', args)
	def create_text(self, *args):
		Canvas._create(self, 'text', args)
	def create_window(self, *args):
		Canvas._create(self, 'window', args)
	def dchars(self, *args):
		self._do('dchars', args)
	def delete(self, *args):
		self._do('delete', args)
	def dtag(self, *args):
		self._do('dtag', args)
	def find(self, *args):
		self.tk.splitlist(self._do('find', args))
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
	def itemconfig(self, tagOrId, cnf={}):
		self._do('itemconfigure', (tagOrId,) + self._options(cnf))
	def lower(self, *args):
		self._do('lower', args)
	def move(self, *args):
		self._do('move', args)
	def postscript(self, cnf={}):
		return self._do('postscript', self._options(cnf))
	def tkraise(self, *args):
		self._do('raise', args)
	def scale(self, *args):
		self._do('scale', args)
	def scan_mark(self, x, y):
		self.tk.call(self._w, 'scan', 'mark', x, y)
	def scan_dragto(self, x, y):
		self.tk.call(self._w, 'scan', 'dragto', x, y)
	def select_adjust(self, tagOrId, index):
		self.tk.call(
			self._w, 'select', 'adjust', tagOrId, index)
	def select_clear(self):
		self.tk.call(self._w, 'select', 'clear')
	def select_from(self, tagOrId, index):
		self.tk.call(
			self._w, 'select', 'from', tagOrId, index)
	def select_item(self):
		self.tk.call(self._w, 'select', 'item')
	def select_to(self, tagOrId, index):
		self.tk.call(
			self._w, 'select', 'to', tagOrId, index)
	def type(self, tagOrId):
		return self.tk.splitlist(self.tk.call(
			self._w, 'type', tagOrId))
	def xview(self, index):
		self.tk.call(self._w, 'xview', index)
	def yview(self, index):
		self.tk.call(self._w, 'yview', index)

class Checkbutton(Widget):
	def __init__(self, master=None, cnf={}):
		Widget.__init__(self, master, 'checkbutton', cnf)
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
	def __init__(self, master=None, cnf={}):
		Widget.__init__(self, master, 'entry', cnf)
	def tk_entryBackspace(self):
		self.tk.call('tk_entryBackspace', self._w)
	def tk_entryBackword(self):
		self.tk.call('tk_entryBackword', self._w)
	def tk_entrySeeCaret(self):
		self.tk.call('tk_entrySeeCaret', self._w)
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
	def select_adjust(self, index):
		self.tk.call(self._w, 'select', 'adjust', index)
	def select_clear(self):
		self.tk.call(self._w, 'select', 'clear')
	def select_from(self, index):
		self.tk.call(self._w, 'select', 'from', index)
	def select_to(self, index):
		self.tk.call(self._w, 'select', 'to', index)
	def select_view(self, index):
		self.tk.call(self._w, 'select', 'view', index)

class Frame(Widget):
	def __init__(self, master=None, cnf={}):
		extra = ()
		if cnf.has_key('class'):
			extra = ('-class', cnf['class'])
			del cnf['class']
		Widget.__init__(self, master, 'frame', cnf, extra)
	def tk_menuBar(self, *args):
		apply(self.tk.call, ('tk_menuBar', self._w) + args)

class Label(Widget):
	def __init__(self, master=None, cnf={}):
		Widget.__init__(self, master, 'label', cnf)

class Listbox(Widget):
	def __init__(self, master=None, cnf={}):
		Widget.__init__(self, master, 'listbox', cnf)
	def tk_listboxSingleSelect(self):
		self.tk.call('tk_listboxSingleSelect', self._w) 
	def curselection(self):
		return self.tk.splitlist(self.tk.call(
			self._w, 'curselection'))
	def delete(self, first, last=None):
		self.tk.call(self._w, 'delete', first, last)
	def get(self, index):
		return self.tk.call(self._w, 'get', index)
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
	def select_adjust(self, index):
		self.tk.call(self._w, 'select', 'adjust', index)
	def select_clear(self):
		self.tk.call(self._w, 'select', 'clear')
	def select_from(self, index):
		self.tk.call(self._w, 'select', 'from', index)
	def select_to(self, index):
		self.tk.call(self._w, 'select', 'to', index)
	def size(self):
		return self.tk.getint(self.tk.call(self._w, 'size'))
	def xview(self, index):
		self.tk.call(self._w, 'xview', index)
	def yview(self, index):
		self.tk.call(self._w, 'yview', index)

class Menu(Widget):
	def __init__(self, master=None, cnf={}):
		Widget.__init__(self, master, 'menu', cnf)
	def tk_menuBar(self, *args):
		apply(self.tk.call, ('tk_menuBar', self._w) + args)
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
	def activate(self, index):
		self.tk.call(self._w, 'activate', index)
	def add(self, itemType, cnf={}):
		apply(self.tk.call, (self._w, 'add', itemType) 
		      + self._options(cnf))
	def delete(self, index1, index2=None):
		self.tk.call(self._w, 'delete', index1, index2)
	def entryconfig(self, index, cnf={}):
		apply(self.tk.call, (self._w, 'entryconfigure', index)
		      + self._options(cnf))
	def index(self, index):
		return self.tk.call(self._w, 'index', index)
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
	def __init__(self, master=None, cnf={}):
		Widget.__init__(self, master, 'menubutton', cnf)

class Message(Widget):
	def __init__(self, master=None, cnf={}):
		Widget.__init__(self, master, 'message', cnf)

class Radiobutton(Widget):
	def __init__(self, master=None, cnf={}):
		Widget.__init__(self, master, 'radiobutton', cnf)
	def deselect(self):
		self.tk.call(self._w, 'deselect')
	def flash(self):
		self.tk.call(self._w, 'flash')
	def invoke(self):
		self.tk.call(self._w, 'invoke')
	def select(self):
		self.tk.call(self._w, 'select')

class Scale(Widget):
	def __init__(self, master=None, cnf={}):
		Widget.__init__(self, master, 'scale', cnf)
	def get(self):
		return self.tk.getint(self.tk.call(self._w, 'get'))
	def set(self, value):
		self.tk.call(self._w, 'set', value)

class Scrollbar(Widget):
	def __init__(self, master=None, cnf={}):
		Widget.__init__(self, master, 'scrollbar', cnf)
	def get(self):
		return self.tk.getints(self.tk.call(self._w, 'get'))
	def set(self, totalUnits, windowUnits, firstUnit, lastUnit):
		self.tk.call(self._w, 'set', 
			     totalUnits, windowUnits, firstUnit, lastUnit)

class Text(Widget):
	def __init__(self, master=None, cnf={}):
		Widget.__init__(self, master, 'text', cnf)
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
	def get(self, index1, index2=None):
		return self.tk.call(self._w, 'get', index1, index2)
	def index(self, index):
		return self.tk.call(self._w, 'index', index)
	def insert(self, index, chars):
		self.tk.call(self._w, 'insert', index, chars)
	def mark_names(self):
		return self.tk.splitlist(self.tk.call(
			self._w, 'mark', 'names'))
	def mark_set(self, markName, index):
		self.tk.call(self._w, 'mark', 'set', markName, index)
	def mark_unset(self, markNames):
		apply(self.tk.call, (self._w, 'mark', 'unset') + markNames)
	def scan_mark(self, y):
		self.tk.call(self._w, 'scan', 'mark', y)
	def scan_dragto(self, y):
		self.tk.call(self._w, 'scan', 'dragto', y)
	def tag_add(self, tagName, index1, index2=None):
		self.tk.call(
			self._w, 'tag', 'add', tagName, index1, index2)
	def tag_bind(self, tagName, sequence, func, add=''):
		global _substitute, _subst_prefix
		if add: add='+'
		name = self._register(func, _substitute)
		self.tk.call(self._w, 'tag', 'bind', 
			     tagName, sequence, 
			     (add + name,) + _subst_prefix)
	def tag_config(self, tagName, cnf={}):
		apply(self.tk.call, 
		      (self._w, 'tag', 'configure', tagName) 
		      + self._options(cnf))
	def tag_delete(self, tagNames):
		apply(self.tk.call, (self._w, 'tag', 'delete') 
		      + tagNames)
	def tag_lower(self, tagName, belowThis=None):
		self.tk.call(self._w, 'tag', 'lower', 
			     tagName, belowThis)
	def tag_names(self, index=None):
		return self.tk.splitlist(
			self.tk.call(self._w, 'tag', 'names', index))
	def tag_nextrange(self, tagName, index1, index2=None):
		return self.tk.splitlist(self.tk.call(
			self._w, 'tag', 'nextrange', index1, index2))
	def tag_raise(self, tagName, aboveThis=None):
		self.tk.call(
			self._w, 'tag', 'raise', tagName, aboveThis)
	def tag_ranges(self, tagName):
		return self.tk.splitlist(self.tk.call(
			self._w, 'tag', 'ranges', tagName))
	def tag_remove(self, tagName, index1, index2=None):
		self.tk.call(
			self._w, 'tag', 'remove', index1, index2)
	def yview(self, what):
		self.tk.call(self._w, 'yview', what)
	def yview_pickplace(self, what):
		self.tk.call(self._w, 'yview', '-pickplace', what)

#class Dialog:
	
