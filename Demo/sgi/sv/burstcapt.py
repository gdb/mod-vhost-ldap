import sv, SV
import gl, GL, DEVICE

def main():
	format = SV.RGB8_FRAMES
	requestedwidth = SV.PAL_XMAX
	queuesize = 2

	v = sv.OpenVideo()
	svci = (format, requestedwidth, 0, queuesize, 0)

	svci, buffer, bitvec = v.CaptureBurst(svci)
	[bitvec]

	w, h = svci[1:3]
	framesize = w * h

	gl.prefposition(300, 300+w-1, 100, 100+h-1)
	gl.foreground()
	win = gl.winopen('Burst Capture')
	gl.RGBmode()
	gl.gconfig()
	gl.qdevice(DEVICE.LEFTMOUSE)
	gl.qdevice(DEVICE.ESCKEY)

	for i in range(svci[3]):
		inverted_frame = sv.RGB8toRGB32(1, \
			  buffer[i*framesize:(i+1)*framesize], w, h)
		gl.lrectwrite(0, 0, w-1, h-1, inverted_frame)
		while 1:
			dev, val = gl.qread()
			if dev == DEVICE.LEFTMOUSE and val == 1:
				break
			if dev == DEVICE.REDRAW:
				gl.lrectwrite(0, 0, w-1, h-1, inverted_frame)
			if dev == DEVICE.ESCKEY:
				v.CloseVideo()
				gl.winclose(win)
				return
	v.CloseVideo()
	gl.winclose(win)

main()
