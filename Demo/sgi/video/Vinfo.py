#! /usr/local/python

# Print some info about a CMIF movie file


# Usage:
#
# Vinfo [-d] [-q] [-s] [file] ...


# Options:
#
# -d       : print deltas between frames instead of frame times
# -q       : quick: don't read the frames
# -s       : don't print times (but do count frames and print the total)
# file ... : file(s) to inspect; default film.video


import sys
sys.path.append('/ufs/guido/src/video')
import VFile
import getopt


# Global options

short = 0
quick = 0
delta = 0


# Main program -- mostly command line parsing

def main():
	global short, quick, delta
	opts, args = getopt.getopt(sys.argv[1:], 'dqs')
	for opt, arg in opts:
		if opt == '-q':
			quick = 1
		elif opt == '-d':
			delta = 1
		elif opt == '-s':
			short = 1
	if not args:
		args = ['film.video']
	sts = 0
	for filename in args:
		if process(filename):
			sts = 1
	sys.exit(sts)


# Process one file

def process(filename):
	try:
		vin = VFile.RandomVinFile().init(filename)
	except IOError, msg:
		sys.stderr.write(filename + ': I/O error: ' + `msg` + '\n')
		return 1
	except VFile.Error, msg:
		sys.stderr.write(msg + '\n')
		return 1
	except EOFError:
		sys.stderr.write(filename + ': EOF in video file\n')
		return 1

	vin.printinfo()

	if quick:
		vin.close()
		return

	try:
		vin.readcache()
		print '[Using cached index]'
	except VFile.Error:
		print '[Constructing index on the fly]'

	if not short:
		if delta:
			print 'Frame time deltas:',
		else:
			print 'Frame times:',

	n = 0
	t = 0
	told = 0
	datasize = 0
	while 1:
		try:
			t, ds, cs = vin.getnextframeheader()
			vin.skipnextframedata(ds, cs)
		except EOFError:
			break
		datasize = datasize + ds
		if cs: datasize = datasize + cs
		if not short:
			if n%8 == 0:
				sys.stdout.write('\n')
			if delta:
				sys.stdout.write('\t' + `t - told`)
				told = t
			else:
				sys.stdout.write('\t' + `t`)
		n = n+1

	if not short: print

	print 'Total', n, 'frames in', t*0.001, 'sec.',
	if t: print '-- average', int(n*10000.0/t)*0.1, 'frames/sec',
	print
	print 'Total data', 0.1 * int(datasize / 102.4), 'Kbytes',
	if t:
		print '-- average',
		print 0.1 * int(datasize / 0.1024 / t), 'Kbytes/sec',
	print

	vin.close()


# Don't forget to call the main program

try:
	main()
except KeyboardInterrupt:
	print '[Interrupt]'
