#! /ufs/guido/bin/sgi/tkpython

# Tk man page browser -- currently only shows the Tcl/Tk man pages

import sys
import os
import string
import regex
from Tkinter import *
from ManPage import ManPage

MANDIR = '/usr/local/man/mann'

def listmanpages(mandir = MANDIR):
	files = os.listdir(mandir)
	names = []
	for file in files:
		if file[-2:] == '.n':
			names.append(file[:-2])
	names.sort()
	return names

class SelectionBox:

	def __init__(self, master=None):
		self.choices = []

		self.frame = Frame(master, {
			Pack: {'expand': 1, 'fill': 'both'}})
		self.master = self.frame.master
		self.subframe = Frame(self.frame, {
			Pack: {'expand': 0, 'fill': 'both'}})
		self.listbox = Listbox(self.subframe,
				       {'relief': 'sunken', 'bd': 2,
					'geometry': '20x6',
					Pack: {'side': 'right',
					       'expand': 1, 'fill': 'both'}})
		self.subsubframe = Frame(self.subframe, {
			Pack: {'side': 'left', 'expand': 1, 'fill': 'both'}})
		self.l1 = Button(self.subsubframe,
				{'text': 'Display manual page named:',
				 'command': self.entry_cb,
				 Pack: {'side': 'top'}})
		self.entry = Entry(self.subsubframe,
				   {'relief': 'sunken', 'bd': 2,
				    'width': 20,
				    Pack: {'side': 'top',
					   'expand': 0, 'fill': 'x'}})
		self.l2frame = Frame(self.subsubframe, {
			Pack: {'expand': 0, 'fill': 'none'}})
		self.l2 = Button(self.l2frame,
				{'text': 'Search regexp:',
				 'command': self.search_cb,
				 Pack: {'side': 'left'}})
		self.casesense = Checkbutton(self.l2frame,
					     {'text': 'Case sensitive',
					      'variable': 'casesense',
					      'relief': 'flat',
					      Pack: {'side': 'left'}})
		self.search = Entry(self.subsubframe,
				   {'relief': 'sunken', 'bd': 2,
				    'width': 20,
				    Pack: {'side': 'top',
					   'expand': 0, 'fill': 'x'}})
		self.title = Label(self.subsubframe,
				   {'text': '(none)',
				    Pack: {'side': 'bottom'}})
		self.text = ManPage(self.frame,
					 {'relief': 'sunken', 'bd': 2,
					  'wrap': 'none', 'width': 72,
					  Pack: {'expand': 1, 'fill': 'both'}})

		self.entry.bind('<Return>', self.entry_cb)
		self.search.bind('<Return>', self.search_cb)
		self.listbox.bind('<Double-1>', self.listbox_cb)

		self.entry.bind('<Tab>', self.entry_tab)
		self.search.bind('<Tab>', self.search_tab)
		self.text.bind('<Tab>', self.text_tab)

		self.entry.focus_set()

	def addchoice(self, choice):
		if choice not in self.choices:
			self.choices.append(choice)
			self.choices.sort()
		self.update()

	def addlist(self, list):
		self.choices[len(self.choices):] = list
		self.choices.sort()
		self.update()

	def entry_cb(self, *e):
		self.update()

	def listbox_cb(self, e):
		selection = self.listbox.curselection()
		if selection and len(selection) == 1:
			name = self.listbox.get(selection[0])
			self.show_page(name)

	def search_cb(self, *e):
		self.search_string(self.search.get())

	def entry_tab(self, e):
		self.search.focus_set()

	def search_tab(self, e):
		self.entry.focus_set()

	def text_tab(self, e):
		self.entry.focus_set()

	def updatelist(self):
		key = self.entry.get()
		ok = filter(lambda name, key=key, n=len(key): name[:n]==key,
			 self.choices)
		self.listbox.delete(0, AtEnd())
		exactmatch = 0
		for item in ok:
			if item == key: exactmatch = 1
			self.listbox.insert(AtEnd(), item)
		if exactmatch:
			return key
		elif self.listbox.size() == 1:
			return self.listbox.get(0)
		# Else return None, meaning not a unique selection

	def update(self):
		name = self.updatelist()
		if name:
			self.show_page(name)
			self.entry.delete(0, AtEnd())
			self.updatelist()

	def show_page(self, name):
		file = '%s/%s.n' % (MANDIR, name)
		fp = os.popen('nroff -man %s | ul -i' % file, 'r')
		self.text.kill()
		self.title['text'] = name
		self.text.parsefile(fp)

	def search_string(self, search):
		if not search:
			print 'Empty search string'
			return
		if self.frame.tk.getvar('casesense') != '1':
			map = regex.casefold
		else:
			map = None
		try:
			if map:
				prog = regex.compile(search, map)
			else:
				prog = regex.compile(search)
		except regex.error, msg:
			print 'Regex error:', msg
			return
		here = self.text.index(AtInsert())
		lineno = string.atoi(here[:string.find(here, '.')])
		end = self.text.index(AtEnd())
		endlineno = string.atoi(end[:string.find(end, '.')])
		wraplineno = lineno
		while 1:
			lineno = lineno + 1
			if lineno > endlineno:
				if wraplineno <= 0:
					break
				endlineno = wraplineno
				lineno = 0
				wraplineno = 0
			line = self.text.get('%d.0 linestart' % lineno,
					     '%d.0 lineend' % lineno)
			i = prog.search(line)
			if i >= 0:
				n = max(1, len(prog.group(0)))
				try:
					self.text.tag_remove('sel',
							     AtSelFirst(),
							     AtSelLast())
				except TclError:
					pass
				self.text.tag_add('sel',
						  '%d.%d' % (lineno, i),
						  '%d.%d' % (lineno, i+n))
				self.text.mark_set(AtInsert(),
						   '%d.%d' % (lineno, i))
				self.text.yview_pickplace(AtInsert())
				break

def main():
	root = Tk()
	sb = SelectionBox(root)
	sb.addlist(listmanpages())
	if sys.argv[1:]:
		sb.show_page(sys.argv[1])
	root.minsize(1, 1)
	root.mainloop()

main()
