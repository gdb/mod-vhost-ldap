#! /usr/bin/env python

"""Pynche: The PYthon Natural Color and Hue Editor.

Pynche is based largely on a similar color editor I wrote years ago for the
Sunview window system.  That editor was called ICE: the Interactive Color
Editor.  I'd always wanted to port the editor to X but didn't feel like
hacking X and C code to do it.  Fast forward many years, to where Python +
Tkinter provides such a nice programming environment, with enough power, that
I finally buckled down and implemented it.  I changed the name because these
days, too many other systems have the acronym `ICE'.

This program currently requires Python 1.5 with Tkinter.  It has only been
tested on Solaris 2.6.  Feedback is greatly appreciated.  Send email to
bwarsaw@python.org

Usage: %(PROGRAM)s [-d file] [-h] [initialcolor]

Where:
    --database file
    -d file
        Alternate location of a color database file

    --help
    -h
        print this message

    initialcolor
        initial color, as a color name or #RRGGBB format

"""

__version__ = '1.0'

import sys
import getopt
import ColorDB
from PyncheWidget import PyncheWidget
from Switchboard import Switchboard
from StripViewer import StripViewer
from ChipViewer import ChipViewer
from TypeinViewer import TypeinViewer



PROGRAM = sys.argv[0]

# Default locations of rgb.txt or other textual color database
RGB_TXT = [
    # Solaris OpenWindows
    '/usr/openwin/lib/rgb.txt',
    # add more here
    ]



def usage(status, msg=''):
    print __doc__ % globals()
    if msg:
	print msg
    sys.exit(status)



def initial_color(s, colordb):
    # function called on every color
    def scan_color(s, colordb=colordb):
        try:
            r, g, b = colordb.find_byname(s)
        except ColorDB.BadColor:
            try:
                r, g, b = ColorDB.rrggbb_to_triplet(s)
            except ColorDB.BadColor:
                return None, None, None
        return r, g, b
    #
    # First try the passed in color
    r, g, b = scan_color(s)
    if r is None:
        # try the same color with '#' prepended, since some shells require
        # this to be escaped, which is a pain
        r, g, b = scan_color('#' + s)
    if r is None:
        print 'Bad initial color, using gray50:', s
        r, g, b = scan_color('gray50')
    if r is None:
        usage(1, 'Cannot find an initial color to use')
        # does not return
    return r, g, b



def main():
    try:
	opts, args = getopt.getopt(
            sys.argv[1:],
            'hd:',
            ['database=', 'help'])
    except getopt.error, msg:
	usage(1, msg)

    if len(args) == 0:
        initialcolor = 'grey50'
    elif len(args) == 1:
        initialcolor = args[0]
    else:
	usage(1)

    for opt, arg in opts:
	if opt in ('-h', '--help'):
	    usage(0)
	elif opt in ('-d', '--database'):
	    RGB_TXT.insert(0, arg)

    # create the windows and go
    for f in RGB_TXT:
	try:
	    colordb = ColorDB.get_colordb(f)
            if colordb:
                break
	except IOError:
	    pass
    else:
        usage(1, 'No color database file found, see the -d option.')

    # get the initial color as components
    red, green, blue = initial_color(initialcolor, colordb)

    # create all output widgets
    s = Switchboard(colordb)

    # create the application window decorations
    app = PyncheWidget(__version__, s)
    parent = app.parent()

    s.add_view(StripViewer(s, parent))
    s.add_view(ChipViewer(s, parent))
    s.add_view(TypeinViewer(s, parent))
    s.update_views(red, green, blue)

    try:
	app.start()
    except KeyboardInterrupt:
	pass



if __name__ == '__main__':
    main()
