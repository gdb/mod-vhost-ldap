# Combine a real-time scheduling queue and stdwin event handling.
# Keeps times in milliseconds.

import stdwin, stdwinq
from stdwinevents import WE_TIMER
import mainloop
import sched
import time

# Delay function called by the scheduler when it has nothing to do.
# Return immediately when something is done, or when the delay is up.
#
def delayfunc(msecs):
	msecs = int(msecs)
	#
	# Check for immediate stdwin event
	#
	event = stdwinq.pollevent()
	if event:
		mainloop.dispatch(event)
		return
	#
	# Use sleep for very short delays or if there are no windows
	#
	if msecs < 100 or mainloop.countwindows() == 0:
		if msecs > 0:
			time.sleep(msecs * 0.001)
		return
	#
	# Post a timer event on an arbitrary window and wait for it
	#
	window = mainloop.anywindow()
	window.settimer(msecs/100)
	event = stdwinq.getevent()
	window.settimer(0)
	if event[0] <> WE_TIMER:
		mainloop.dispatch(event)

def millitimer():
	return time.time() * 1000

q = sched.scheduler(millitimer, delayfunc)

# Export functions enter, enterabs and cancel just like a scheduler
#
enter = q.enter
enterabs = q.enterabs
cancel = q.cancel

# Emptiness check must check both queues
#
def empty():
	return q.empty() and mainloop.countwindows() == 0

# Run until there is nothing left to do
#
def run():
	while not empty():
		if q.empty():
			mainloop.dispatch(stdwinq.getevent())
		else:
			q.run()
