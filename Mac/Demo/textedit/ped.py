# Test TE module.
# Draw a window in which the user can type.
#
# This test expects Win, Evt and FrameWork (and anything used by those)
# to work.
#
# Actually, it is more a test of FrameWork by now....

from Menu import DrawMenuBar
from FrameWork import *
import Win
import Qd
import TE
import os
import macfs

class TEWindow(Window):
	def open(self, path, name, data):
		self.path = path
		self.name = name
		r = (40, 40, 400, 300)
		w = Win.NewWindow(r, name, 1, 0, -1, 1, 0x55555555)
		self.wid = w
		r2 = (0, 0, 345, 245)
		Qd.SetPort(w)
		Qd.TextFont(4)
		Qd.TextSize(9)
		self.ted = TE.TENew(r2, r2)
		self.ted.TEAutoView(1)
		self.ted.TESetText(data)
		w.DrawGrowIcon()
		self.changed = 0
		self.do_postopen()
		self.parent.updatemenubar()
		
	def do_idle(self):
		self.ted.TEIdle()
		
	def do_activate(self, onoff, evt):
		if onoff:
			self.ted.TEActivate()
			self.parent.active = self
			self.parent.updatemenubar()
		else:
			self.ted.TEDeactivate()

	def do_update(self, wid, event):
		Qd.EraseRect(wid.GetWindowPort().portRect)
		self.ted.TEUpdate(wid.GetWindowPort().portRect)
		
	def do_contentclick(self, local, modifiers, evt):
		shifted = (modifiers & 0x200)
		self.ted.TEClick(local, shifted)
		self.parent.updatemenubar()

	def do_char(self, ch, event):
		self.ted.TEKey(ord(ch))
		self.changed = 1
		self.parent.updatemenubar()
		
	def close(self):
		if self.changed:
			save = EasyDialogs.AskYesNoCancel('Save window "%s" before closing?'%self.name, 1)
			if save > 0:
				self.menu_save()
			elif save < 0:
				return
		if self.parent.active == self:
			self.parent.active = None
		self.parent.updatemenubar()
		del self.ted
		self.do_postclose()
		
	def menu_save(self):
		if not self.path:
			self.menu_save_as()
			return # Will call us recursively
		print 'Saving to ', self.path
		dhandle = self.ted.TEGetText()
		data = dhandle.data
		fp = open(self.path, 'wb')  # NOTE: wb, because data has CR for end-of-line
		fp.write(data)
		if data[-1] <> '\r': fp.write('\r')
		fp.close()
		self.changed = 0
		
	def menu_save_as(self):
		fss, ok = macfs.StandardPutFile('Save as:')
		if not ok: return
		self.path = fss.as_pathname()
		self.name = os.path.split(self.path)[-1]
		self.wid.SetWTitle(self.name)
		self.menu_save()
		
	def menu_cut(self):
		self.ted.TECut()
		self.parent.updatemenubar()
		
	def menu_copy(self):
		self.ted.TECopy()
		
	def menu_paste(self):
		self.ted.TEPaste()
		self.parent.updatemenubar()
		
	def menu_clear(self):
		self.ted.TEDelete()
		self.parent.updatemenubar()
		
	def have_selection(self):
##		return (self.ted.selStart > self.ted.selEnd)
		return 1

class Ped(Application):
	def __init__(self):
		Application.__init__(self)
		self.num = 0
		self.active = None
		self.updatemenubar()
		
	def makeusermenus(self):
		self.filemenu = m = Menu(self.menubar, "File")
		self.newitem = MenuItem(m, "New window", "N", self.open)
		self.openitem = MenuItem(m, "Open...", "O", self.openfile)
		self.closeitem = MenuItem(m, "Close", "W", self.closewin)
		m.addseparator()
		self.saveitem = MenuItem(m, "Save", "S", self.save)
		self.saveasitem = MenuItem(m, "Save as...", "", self.saveas)
		m.addseparator()
		self.quititem = MenuItem(m, "Quit", "Q", self.quit)
		
		self.editmenu = m = Menu(self.menubar, "Edit")
		self.undoitem = MenuItem(m, "Undo", "Z", self.undo)
		self.cutitem = MenuItem(m, "Cut", "X", self.cut)
		self.copyitem = MenuItem(m, "Copy", "C", self.copy)
		self.pasteitem = MenuItem(m, "Paste", "V", self.paste)
		self.clearitem = MenuItem(m, "Clear", "", self.clear)
		
		# Not yet implemented:
		self.undoitem.enable(0)
		
		# Groups of items enabled together:
		self.windowgroup = [self.closeitem, self.saveitem, self.saveasitem, self.editmenu]
		self.focusgroup = [self.cutitem, self.copyitem, self.clearitem]
		self.windowgroup_on = -1
		self.focusgroup_on = -1
		
	def updatemenubar(self):
		changed = 0
		on = (self.active <> None)
		if on <> self.windowgroup_on:
			for m in self.windowgroup:
				m.enable(on)
			self.windowgroup_on = on
			changed = 1
		if on:
			on = self.active.have_selection()
		if on <> self.focusgroup_on:
			for m in self.focusgroup:
				m.enable(on)
			self.focusgroup_on = on
			changed = 1
		if changed:
			DrawMenuBar()

	#
	# Apple menu
	#
	
	def do_about(self, id, item, window, event):
		EasyDialogs.Message("A simple single-font text editor")
			
	#
	# File menu
	#

	def open(self, *args):
		self._open(0)
		
	def openfile(self, *args):
		self._open(1)

	def _open(self, askfile):
		if askfile:
			fss, ok = macfs.StandardGetFile('TEXT')
			if not ok:
				return
			path = fss.as_pathname()
			name = os.path.split(path)[-1]
			try:
				fp = open(path, 'rb') # NOTE binary, we need cr as end-of-line
				data = fp.read()
				fp.close()
			except IOError, arg:
				EasyDialogs.Message("IOERROR: "+`arg`)
				return
		else:
			path = None
			name = "Untitled %d"%self.num
			data = ''
		w = TEWindow(self)
		w.open(path, name, data)
		self.num = self.num + 1
		
	def closewin(self, *args):
		if self.active:
			self.active.close()
		else:
			EasyDialogs.Message("No active window?")
		
	def save(self, *args):
		if self.active:
			self.active.menu_save()
		else:
			EasyDialogs.Message("No active window?")
		
	def saveas(self, *args):
		if self.active:
			self.active.menu_save_as()
		else:
			EasyDialogs.Message("No active window?")
			
		
	def quit(self, *args):
		for w in self._windows.values():
			w.close()
		if self._windows:
			return
		raise self
		
	#
	# Edit menu
	#
	
	def undo(self, *args):
		pass
		
	def cut(self, *args):
		if self.active:
			self.active.menu_cut()
		else:
			EasyDialogs.Message("No active window?")
		
	def copy(self, *args):
		if self.active:
			self.active.menu_copy()
		else:
			EasyDialogs.Message("No active window?")
		
	def paste(self, *args):
		if self.active:
			self.active.menu_paste()
		else:
			EasyDialogs.Message("No active window?")

	def clear(self, *args):
		if self.active:
			self.active.menu_clear()
		else:
			EasyDialogs.Message("No active window?")
		
	#
	# Other stuff
	#	

	def idle(self, *args):
		for l in self._windows.values():
			l.do_idle()

def main():
	App = Ped()
	App.mainloop()
	
if __name__ == '__main__':
	main()
	
