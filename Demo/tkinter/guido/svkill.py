#! /usr/local/bin/python

# Tkinter interface to SYSV `kill' command.

from Tkinter import *
from string import splitfields
from string import split
import commands
import os

user = os.environ['LOGNAME']

class BarButton(Menubutton):
	_CNF = {Pack: {'side': 'left'}}
	def __init__(self, master=None, cnf={}):
		Menubutton.__init__(self, master, (self._CNF, cnf))
		self.menu = Menu(self, {'name': 'menu'})
		self['menu'] = self.menu		

class Kill(Frame):
	# List of (name, option, pid_column)
	view_list = [
		('Default', ''),
		('Every (-e)', '-e'),
		('Non process group leaders (-d)', '-d'),
		('Non leaders with tty (-a)', '-a'),
		('For this user (-u %s)' % user, '-u %s' % user),
		]
	format_list = [
		('Default', '', 0),
		('Long (-l)', '-l', 3),
		('Full (-f)', '-f', 1),
		('Full Long (-f -l)', '-l -f', 3),
		('Session and group ID (-j)', '-j', 0),
		('Scheduler properties (-c)', '-c', 0),
		]
	def kill(self, selected):
		c = self.format_list[self.format.get()][2]
		pid = split(selected)[c]
		os.system('kill' + ' -9 ' + pid)
		self.do_update()
	def do_update(self):
		format = self.format_list[self.format.get()][1]
		view = self.view_list[self.view.get()][1]
		s = commands.getoutput('ps %s %s' % (view, format))
		list = splitfields(s, '\n')
		self.header.set(list[0] + '          ')
		del list[0]
		y = self.frame.vscroll.get()[2]
		self.frame.list.delete(0, AtEnd())
		for line in list:
			self.frame.list.insert(0, line)
		self.frame.list.yview(y)
	def do_motion(self, e):
		e.widget.select_from(e.widget.nearest(e.y))
	def do_leave(self, e):
		e.widget.select_clear()
	def do_1(self, e):
		self.kill(e.widget.get(e.widget.nearest(e.y)))
	def __init__(self, master=None, cnf={}):
		Frame.__init__(self, master, cnf)
		self.pack({'expand': 'yes', 'fill': 'both'})
		self.bar = Frame(
			self,
			{'name': 'bar',
			 'relief': 'raised',
			 'bd': 2,
			 Pack: {'side': 'top',
				'fill': 'x'}})
		self.bar.file = BarButton(self.bar, {'text': 'File'})
		self.bar.file.menu.add_command(
			{'label': 'Quit', 'command': self.quit})
		self.bar.view = BarButton(self.bar, {'text': 'View'})
		self.bar.format = BarButton(self.bar, {'text': 'Format'})
		self.view = IntVar(self)
		self.view.set(0)
		self.format = IntVar(self)
		self.format.set(0)
		for num in range(len(self.view_list)):
			label, option = self.view_list[num]
			self.bar.view.menu.add_radiobutton(
				{'label': label,
				 'command': self.do_update,
				 'variable': self.view,
				 'value': num})
		for num in range(len(self.format_list)):
			label, option, col = self.format_list[num]
			self.bar.format.menu.add_radiobutton(
				{'label': label,
				 'command': self.do_update,
				 'variable': self.format,
				 'value': num})
		self.bar.tk_menuBar(self.bar.file,
				    self.bar.view,
				    self.bar.format)
		self.frame = Frame(
			self, 
			{'relief': 'raised', 'bd': 2,
			 Pack: {'side': 'top',
				'expand': 'yes',
				'fill': 'both'}})
		self.header = StringVar(self)
		self.frame.label = Label(
			self.frame, 
			{'relief': 'flat',
			 'anchor': 'nw',
			 'borderwidth': 0,
			 'font': '*-Courier-Bold-R-Normal-*-120-*',
			 'textvariable': self.header,
			 Pack: {'side': 'top', 
			 	'fill': 'y',
				'anchor': 'w'}})
		self.frame.vscroll = Scrollbar(
			self.frame,
			{'orient': 'vertical'})
		self.frame.list = Listbox(
			self.frame, 
			{'relief': 'sunken',
			 'font': '*-Courier-Medium-R-Normal-*-120-*',
			 'geometry': '40x10',
			 'selectbackground': '#eed5b7',
			 'selectborderwidth': 0,
			 'yscroll': self.frame.vscroll.set})
		self.frame.vscroll['command'] = self.frame.list.yview
		self.frame.vscroll.pack({'side': 'right', 'fill': 'y'})
		self.frame.list.pack(
			{'side': 'top',
			 'expand': 'yes',
			 'fill': 'both'})
		self.update = Button(
			self,
			{'text': 'Update',
			 'command': self.do_update,
			 Pack: {'expand': 'no',
				'fill': 'x'}})
		self.frame.list.bind('<Motion>', self.do_motion)
		self.frame.list.bind('<Leave>', self.do_leave)
		self.frame.list.bind('<1>', self.do_1)
		self.do_update()

if __name__ == '__main__':
	kill = Kill(None, {'bd': 5})
	kill.winfo_toplevel().title('Tkinter Process Killer (SYSV)')
	kill.winfo_toplevel().minsize(1, 1)
	kill.mainloop()
