#! /ufs/guido/bin/sgi/tkpython

# A Python function that generates dialog boxes with a text message,
# optional bitmap, and any number of buttons.
# Cf. Ousterhout, Tcl and the Tk Toolkit, Figs. 27.2-3, pp. 269-270.

from Tkinter import *

def dialog(master, title, text, bitmap, default, *args):

    # 1. Create the top-level window and divide it into top
    # and bottom parts.

    w = Toplevel(master, {'class': 'Dialog'})
    w.tk.call('global', 'button')
    w.title(title)
    w.iconname('Dialog')

    top = Frame(w, {'relief': 'raised', 'bd': 1,
		    Pack: {'side': 'top', 'fill': 'both'}})
    bot = Frame(w, {'relief': 'raised', 'bd': 1,
		    Pack: {'side': 'bottom', 'fill': 'both'}})

    # 2. Fill the top part with the bitmap and message.

    msg = Message(top,
		  {'width': '3i',
		   'text': text,
		   'font': '-Adobe-Times-Medium-R-Normal-*-180-*',
		   Pack: {'side': 'right', 'expand': 1,
			  'fill': 'both',
			  'padx': '3m', 'pady': '3m'}})
    if bitmap:
	bm = Label(top, {'bitmap': bitmap,
			 Pack: {'side': 'left',
				'padx': '3m', 'pady': '3m'}})

    # 3. Create a row of buttons at the bottom of the dialog.

    buttons = []
    i = 0
    for but in args:
	b = Button(bot, {'text': but,
			 'command': ('set', 'button', i)})
	buttons.append(b)
	if i == default:
	    bd = Frame(bot, {'relief': 'sunken', 'bd': 1,
			     Pack: {'side': 'left', 'expand': 1,
				    'padx': '3m', 'pady': '2m'}})
	    w.tk.call('raise', b)
	    b.pack ({'in': bd, 'side': 'left',
		     'padx': '2m', 'pady': '2m',
		     'ipadx': '2m', 'ipady': '1m'})
	else:
	    b.pack ({'side': 'left', 'expand': 1,
		     'padx': '3m', 'pady': '3m',
		     'ipady': '2m', 'ipady': '1m'})
	i = i+1

    # 4. Set up a binding for <Return>, if there's a default,
    # set a grab, and claim the focus too.

    if default >= 0:
	w.bind('<Return>',
	       lambda b=buttons[default], i=default:
	       (b.cmd('flash'),
		b.tk.call('set', 'button', i)))

    oldFocus = w.tk.call('focus')
    w.tk.call('grab', 'set', w)
    w.tk.call('focus', w)

    # 5. Wait for the user to respond, then restore the focus
    # and return the index of the selected button.

    w.tk.call('tkwait', 'variable', 'button')
    w.tk.call('destroy', w)
    w.tk.call('focus', oldFocus)
    return w.tk.call('set', 'button')

# The rest is the test program.

def go():
    i = dialog(mainWidget,
	       'Not Responding',
	       "The file server isn't responding right now; "
	       "I'll keep trying.",
	       '',
	       -1,
	       'OK')
    print 'pressed button', i
    i = dialog(mainWidget,
	       'File Modified',
	       'File "tcl.h" has been modified since '
	       'the last time it was saved. '
	       'Do you want to save it before exiting the application?',
	       'warning',
	       0,
	       'Save File',
	       'Discard Changes',
	       'Return To Editor')
    print 'pressed button', i

def test():
    import sys
    global mainWidget
    mainWidget = Frame()
    Pack.config(mainWidget)
    start = Button(mainWidget,
		   {'text': 'Press Here To Start', 'command': go})
    start.pack()
    endit = Button(mainWidget,
		   {'text': 'Exit',
		    'command': 'exit',
		    Pack: {'fill' : 'both'}})
    mainWidget.tk.mainloop()

if __name__ == '__main__':
    test()
