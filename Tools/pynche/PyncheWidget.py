"""Main Pynche (Pythonically Natural Color and Hue Editor) widget.
"""

from Tkinter import *
import Pmw
import ColorDB
from ChipWidget import ChipWidget
from TypeinWidget import TypeinWidget
from StripWidget import StripWidget


def constant(numchips):
    step = 255.0 / (numchips - 1)
    start = 0.0
    seq = []
    while numchips > 0:
	seq.append(int(start))
	start = start + step
	numchips = numchips - 1
    return seq

def constant_red_generator(numchips, rgbtuple):
    red = rgbtuple[0]
    seq = constant(numchips)
    return map(None, [red] * numchips, seq, seq)

def constant_green_generator(numchips, rgbtuple):
    green = rgbtuple[1]
    seq = constant(numchips)
    return map(None, seq, [green] * numchips, seq)

def constant_blue_generator(numchips, rgbtuple):
    blue = rgbtuple[2]
    seq = constant(numchips)
    return map(None, seq, seq, [blue] * numchips)



class PyncheWidget(Pmw.MegaWidget):
    def __init__(self, colordb, parent=None, **kw):
	self.__colordb = colordb

	options = (('color', (128, 128, 128), self.__set_color),
		   ('delegate', None, None),
		   )
	self.defineoptions(kw, options)

	# initialize base class -- after defining options
	Pmw.MegaWidget.__init__(self, parent)
	interiorarg = (self.interior(),)

	# create color selectors
	group = Pmw.Group(parent, tag_text='Color Selectors')
	group.pack(side=TOP, expand=YES, fill=BOTH)
	self.__reds = StripWidget(group.interior(),
				  generator=constant_red_generator)
	self.__reds.pack()
	self.__blues = StripWidget(group.interior(),
				   generator=constant_blue_generator)
	self.__blues.pack()
	self.__greens = StripWidget(group.interior(),
				    generator=constant_green_generator)
	self.__greens.pack()

	# create chip window
	group = Pmw.Group(parent, tag_text='Current Color')
	group.pack(side=LEFT, fill=Y)
	self.__selected = ChipWidget(group.interior(),
				     label_text='Selected')
	self.__selected.grid()
	self.__nearest = ChipWidget(group.interior(),
				    label_text='Nearest')
	self.__nearest.grid(row=0, column=1)

	# create the options window
	group = Pmw.Group(parent, tag_text='Options')
	group.pack(expand=YES, fill=BOTH)
	self.__typein = TypeinWidget(group.interior())
	self.__typein.grid()

	# Check keywords and initialize options
	self.initialiseoptions(PyncheWidget)

	self.__typein.configure(delegate=self)

    #
    # PUBLIC INTERFACE
    #


    def set_color(self, obj, rgbtuple):
	nearest = self.__colordb.nearest(rgbtuple)
	red, green, blue = self.__colordb.find_byname(nearest)
	# for an exact match, use the color name
	if (red, green, blue) == rgbtuple:
	    self.__selected.configure(color=nearest)
	# otherwise, use the #rrggbb name
	else:
	    rrggbb = ColorDB.triplet_to_rrggbb(rgbtuple)
	    self.__selected.configure(color=rrggbb)

	# configure all subwidgets
	self.__nearest.configure(color=nearest)
	self.__typein.configure(color=rgbtuple)
	self.__reds.configure(color=rgbtuple)
	self.__greens.configure(color=rgbtuple)
	self.__blues.configure(color=rgbtuple)
	delegate = self['delegate']
	if delegate:
	    delegate.set_color(self, rgbtuple)

    #
    # PRIVATE INTERFACE
    #

    def __set_color(self):
	self.set_color(self, self['color'])
