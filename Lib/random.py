#	R A N D O M   V A R I A B L E   G E N E R A T O R S
#
#	distributions on the real line:
#	------------------------------
#	       normal (Gaussian)
#	       lognormal
#	       negative exponential
#	       gamma
#	       beta
#
#	distributions on the circle (angles 0 to 2pi)
#	---------------------------------------------
#	       circular uniform
#	       von Mises

# Translated from anonymously contributed C/C++ source.

from whrandom import random, uniform, randint, choice # Also for export!
from math import log, exp, pi, e, sqrt, acos, cos, sin

# Housekeeping function to verify that magic constants have been
# computed correctly

def verify(name, expected):
	computed = eval(name)
	if abs(computed - expected) > 1e-7:
		raise ValueError, \
  'computed value for %s deviates too much (computed %g, expected %g)' % \
  (name, computed, expected)

# -------------------- normal distribution --------------------

NV_MAGICCONST = 4*exp(-0.5)/sqrt(2)
verify('NV_MAGICCONST', 1.71552776992141)
def normalvariate(mu, sigma):
	# mu = mean, sigma = standard deviation

	# Uses Kinderman and Monahan method. Reference: Kinderman,
	# A.J. and Monahan, J.F., "Computer generation of random
	# variables using the ratio of uniform deviates", ACM Trans
	# Math Software, 3, (1977), pp257-260.

	while 1:
		u1 = random()
		u2 = random()
		z = NV_MAGICCONST*(u1-0.5)/u2
		zz = z*z/4
		if zz <= -log(u2):
			break
	return mu+z*sigma

# -------------------- lognormal distribution --------------------

def lognormvariate(mu, sigma):
	return exp(normalvariate(mu, sigma))

# -------------------- circular uniform --------------------

def cunifvariate(mean, arc):
	# mean: mean angle (in radians between 0 and pi)
	# arc:  range of distribution (in radians between 0 and pi)

	return (mean + arc * (random() - 0.5)) % pi

# -------------------- exponential distribution --------------------

def expovariate(lambd):
	# lambd: rate lambd = 1/mean
	# ('lambda' is a Python reserved word)

	u = random()
	while u <= 1e-7:
		u = random()
	return -log(u)/lambd

# -------------------- von Mises distribution --------------------

TWOPI = 2*pi
verify('TWOPI', 6.28318530718)

def vonmisesvariate(mu, kappa):
	# mu:    mean angle (in radians between 0 and 180 degrees)
	# kappa: concentration parameter kappa (>= 0)
	
	# if kappa = 0 generate uniform random angle
	if kappa <= 1e-6:
		return TWOPI * random()

	a = 1.0 + sqrt(1 + 4 * kappa * kappa)
	b = (a - sqrt(2 * a))/(2 * kappa)
	r = (1 + b * b)/(2 * b)

	while 1:
		u1 = random()

		z = cos(pi * u1)
		f = (1 + r * z)/(r + z)
		c = kappa * (r - f)

		u2 = random()

		if not (u2 >= c * (2.0 - c) and u2 > c * exp(1.0 - c)):
			break

	u3 = random()
	if u3 > 0.5:
		theta = mu + 0.5*acos(f)
	else:
		theta = mu - 0.5*acos(f)

	return theta % pi

# -------------------- gamma distribution --------------------

LOG4 = log(4)
verify('LOG4', 1.38629436111989)

def gammavariate(alpha, beta):
        # beta times standard gamma
	ainv = sqrt(2 * alpha - 1)
	return beta * stdgamma(alpha, ainv, alpha - LOG4, alpha + ainv)

SG_MAGICCONST = 1+log(4.5)
verify('SG_MAGICCONST', 2.50407739677627)

def stdgamma(alpha, ainv, bbb, ccc):
	# ainv = sqrt(2 * alpha - 1)
	# bbb = alpha - log(4)
	# ccc = alpha + ainv

	if alpha <= 0.0:
		raise ValueError, 'stdgamma: alpha must be > 0.0'

	if alpha > 1.0:

		# Uses R.C.H. Cheng, "The generation of Gamma
		# variables with non-integral shape parameters",
		# Applied Statistics, (1977), 26, No. 1, p71-74

		while 1:
			u1 = random()
			u2 = random()
			v = log(u1/(1-u1))/ainv
			x = alpha*exp(v)
			z = u1*u1*u2
			r = bbb+ccc*v-x
			if r + SG_MAGICCONST - 4.5*z >= 0 or r >= log(z):
				return x

	elif alpha == 1.0:
		# expovariate(1)
		u = random()
		while u <= 1e-7:
			u = random()
		return -log(u)

	else:	# alpha is between 0 and 1 (exclusive)

		# Uses ALGORITHM GS of Statistical Computing - Kennedy & Gentle

		while 1:
			u = random()
			b = (e + alpha)/e
			p = b*u
			if p <= 1.0:
				x = pow(p, 1.0/alpha)
			else:
				# p > 1
				x = -log((b-p)/alpha)
			u1 = random()
			if not (((p <= 1.0) and (u1 > exp(-x))) or
				  ((p > 1)  and  (u1 > pow(x, alpha - 1.0)))):
				break
		return x


# -------------------- Gauss (faster alternative) --------------------

# When x and y are two variables from [0, 1), uniformly distributed, then
#
#    cos(2*pi*x)*log(1-y)
#    sin(2*pi*x)*log(1-y)
#
# are two *independent* variables with normal distribution (mu = 0, sigma = 1).
# (Lambert Meertens)

gauss_next = None
def gauss(mu, sigma):
	global gauss_next
	if gauss_next != None:
		z = gauss_next
		gauss_next = None
	else:
		x2pi = random() * TWOPI
		log1_y = log(1.0 - random())
		z = cos(x2pi) * log1_y
		gauss_next = sin(x2pi) * log1_y
	return mu + z*sigma

# -------------------- beta --------------------

def betavariate(alpha, beta):
	y = expovariate(alpha)
	z = expovariate(1.0/beta)
	return z/(y+z)

# -------------------- test program --------------------

def test():
	print 'TWOPI         =', TWOPI
	print 'LOG4          =', LOG4
	print 'NV_MAGICCONST =', NV_MAGICCONST
	print 'SG_MAGICCONST =', SG_MAGICCONST
	N = 200
	test_generator(N, 'random()')
	test_generator(N, 'normalvariate(0.0, 1.0)')
	test_generator(N, 'lognormvariate(0.0, 1.0)')
	test_generator(N, 'cunifvariate(0.0, 1.0)')
	test_generator(N, 'expovariate(1.0)')
	test_generator(N, 'vonmisesvariate(0.0, 1.0)')
	test_generator(N, 'gammavariate(0.5, 1.0)')
	test_generator(N, 'gammavariate(0.9, 1.0)')
	test_generator(N, 'gammavariate(1.0, 1.0)')
	test_generator(N, 'gammavariate(2.0, 1.0)')
	test_generator(N, 'gammavariate(20.0, 1.0)')
	test_generator(N, 'gammavariate(200.0, 1.0)')
	test_generator(N, 'gauss(0.0, 1.0)')
	test_generator(N, 'betavariate(3.0, 3.0)')

def test_generator(n, funccall):
	import time
	print n, 'times', funccall
	code = compile(funccall, funccall, 'eval')
	sum = 0.0
	sqsum = 0.0
	smallest = 1e10
	largest = 1e-10
	t0 = time.time()
	for i in range(n):
		x = eval(code)
		sum = sum + x
		sqsum = sqsum + x*x
		smallest = min(x, smallest)
		largest = max(x, largest)
	t1 = time.time()
	print round(t1-t0, 3), 'sec,', 
	avg = sum/n
	stddev = sqrt(sqsum/n - avg*avg)
	print 'avg %g, stddev %g, min %g, max %g' % \
		  (avg, stddev, smallest, largest)

if __name__ == '__main__':
	test()
