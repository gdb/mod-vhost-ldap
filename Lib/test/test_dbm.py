#! /usr/bin/env python
"""Test script for the dbm module
   Roger E. Masse
"""
import dbm
from dbm import error
filename= '/tmp/delete_me'

d = dbm.open(filename, 'c')
d['a'] = 'b'
d['12345678910'] = '019237410982340912840198242'
d.keys()
d.has_key('a')
d.close()
d = dbm.open(filename, 'r')
d.close()
d = dbm.open(filename, 'rw')
d.close()
d = dbm.open(filename, 'w')
d.close()
d = dbm.open(filename, 'n')
d.close()

try:
    import os
    os.unlink(filename + '.dir')
    os.unlink(filename + '.pag')
except:
    pass
