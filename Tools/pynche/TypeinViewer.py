from Tkinter import *
import string
import re

class TypeinViewer:
    def __init__(self, switchboard, parent=None):
        # non-gui ivars
        self.__sb = switchboard
        self.__hexp = BooleanVar()
        self.__uwtyping = BooleanVar()
        # create the gui
        self.__frame = Frame(parent, relief=GROOVE, borderwidth=2)
        self.__frame.pack(side=RIGHT)
        # Red
        self.__xl = Label(self.__frame, text='Red:')
        self.__xl.grid(row=0, column=0, sticky=E)
        self.__x = Entry(self.__frame, width=4)
        self.__x.grid(row=0, column=1)
        self.__x.bindtags(self.__x.bindtags() + ('Normalize', 'Update'))
        self.__x.bind_class('Normalize', '<Key>', self.__normalize)
        self.__x.bind_class('Update'   , '<Key>', self.__maybeupdate)
        # Green
        self.__yl = Label(self.__frame, text='Green:')
        self.__yl.grid(row=1, column=0, sticky=E)
        self.__y = Entry(self.__frame, width=4)
        self.__y.grid(row=1, column=1)
        self.__y.bindtags(self.__y.bindtags() + ('Normalize', 'Update'))
        # Blue
        self.__zl = Label(self.__frame, text='Blue:')
        self.__zl.grid(row=2, column=0, sticky=E)
        self.__z = Entry(self.__frame, width=4)
        self.__z.grid(row=2, column=1)
        self.__z.bindtags(self.__z.bindtags() + ('Normalize', 'Update'))
        # Update while typing?
        self.__uwt = Checkbutton(self.__frame,
                                 text='Update while typing',
                                 variable=self.__uwtyping)
        self.__uwt.grid(row=3, column=0, columnspan=2, sticky=W)
        # Hex/Dec
        self.__hex = Checkbutton(self.__frame,
                                 text='Hexadecimal',
                                 variable=self.__hexp)
        self.__hex.grid(row=4, column=0, columnspan=2, sticky=W)

    def __normalize(self, event=None):
        ew = event.widget
        contents = ew.get()
        if contents == '':
            contents = '0'
        # figure out what the contents value is in the current base
        try:
            if self.__hexp.get():
                v = string.atoi(contents, 16)
            else:
                v = string.atoi(contents)
        except ValueError:
            v = None
        # if value is not legal, delete the last character and ring the bell
        if v is None or v < 0 or v > 255:
            contents = contents[:-1]
            ew.bell()
        elif self.__hexp.get():
            contents = hex(v)
        else:
            contents = int(v)
        ew.delete(0, END)
        ew.insert(0, contents)

    def __maybeupdate(self, event=None):
        if self.__uwtyping.get() or event.keysym in ('Return', 'Tab'):
            self.__update(event)

    def __update(self, event=None):
        redstr = self.__x.get()
        greenstr = self.__y.get()
        bluestr = self.__z.get()
        if self.__hexp.get():
            red = string.atoi(redstr, 16)
            green = string.atoi(greenstr, 16)
            blue = string.atoi(bluestr, 16)
        else:
            red, green, blue = map(string.atoi, (redstr, greenstr, bluestr))
        self.__sb.update_views(red, green, blue)

    def update_yourself(self, red, green, blue):
        if self.__hexp.get():
            redstr, greenstr, bluestr = map(hex, (red, green, blue))
        else:
            redstr, greenstr, bluestr = map(int, (red, green, blue))
        self.__x.delete(0, END)
        self.__y.delete(0, END)
        self.__z.delete(0, END)
        self.__x.insert(0, redstr)
        self.__y.insert(0, greenstr)
        self.__z.insert(0, bluestr)
