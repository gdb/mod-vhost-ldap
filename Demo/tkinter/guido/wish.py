# This is about all it requires to write a wish shell in Python!

import tkinter

tk = tkinter.create(':0', 'wish', 'Tk', 1)
tk.call('update')

cmd = ''

while 1:
	if cmd: prompt = ''
	else: prompt = '% '
	try:
		line = raw_input(prompt)
	except EOFError:
		break
	cmd = cmd + (line + '\n')
	tk.record(line)
	if tk.getboolean(tk.call('info', 'complete', cmd)):
		try:
			result = tk.call('eval', cmd)
		except tkinter.TclError, msg:
			print 'TclError:', msg
		else:
			if result: print result
		cmd = ''
