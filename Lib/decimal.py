# Copyright (c) 2004 Python Software Foundation.
# All rights reserved.

# Written by Eric Price <eprice at tjhsst.edu>
#    and Facundo Batista <facundo at taniquetil.com.ar>
#    and Raymond Hettinger <python at rcn.com>
#    and Aahz <aahz at pobox.com>
#    and Tim Peters


# Todo:
#    Add rich comparisons for equality testing with other types


"""
This is a Py2.3 implementation of decimal floating point arithmetic based on
the General Decimal Arithmetic Specification:

    www2.hursley.ibm.com/decimal/decarith.html

and IEEE standard 854-1987:

    www.cs.berkeley.edu/~ejr/projects/754/private/drafts/854-1987/dir.html

Decimal floating point has finite precision with arbitrarily large bounds.

The purpose of the module is to support arithmetic using familiar
"schoolhouse" rules and to avoid the some of tricky representation
issues associated with binary floating point.  The package is especially
useful for financial applications or for contexts where users have
expectations that are at odds with binary floating point (for instance,
in binary floating point, 1.00 % 0.1 gives 0.09999999999999995 instead
of the expected Decimal("0.00") returned by decimal floating point).

Here are some examples of using the decimal module:

>>> from decimal import *
>>> getcontext().prec=9
>>> Decimal(0)
Decimal("0")
>>> Decimal("1")
Decimal("1")
>>> Decimal("-.0123")
Decimal("-0.0123")
>>> Decimal(123456)
Decimal("123456")
>>> Decimal("123.45e12345678901234567890")
Decimal("1.2345E+12345678901234567892")
>>> Decimal("1.33") + Decimal("1.27")
Decimal("2.60")
>>> Decimal("12.34") + Decimal("3.87") - Decimal("18.41")
Decimal("-2.20")
>>> dig = Decimal(1)
>>> print dig / Decimal(3)
0.333333333
>>> getcontext().prec = 18
>>> print dig / Decimal(3)
0.333333333333333333
>>> print dig.sqrt()
1
>>> print Decimal(3).sqrt()
1.73205080756887729
>>> print Decimal(3) ** 123
4.85192780976896427E+58
>>> inf = Decimal(1) / Decimal(0)
>>> print inf
Infinity
>>> neginf = Decimal(-1) / Decimal(0)
>>> print neginf
-Infinity
>>> print neginf + inf
NaN
>>> print neginf * inf
-Infinity
>>> print dig / 0
Infinity
>>> getcontext().trap_enablers[DivisionByZero] = 1
>>> print dig / 0
Traceback (most recent call last):
  ...
  ...
  ...
DivisionByZero: x / 0
>>> c = Context()
>>> c.trap_enablers[DivisionUndefined] = 0
>>> print c.flags[DivisionUndefined]
0
>>> c.divide(Decimal(0), Decimal(0))
Decimal("NaN")
>>> c.trap_enablers[DivisionUndefined] = 1
>>> print c.flags[DivisionUndefined]
1
>>> c.flags[DivisionUndefined] = 0
>>> print c.flags[DivisionUndefined]
0
>>> print c.divide(Decimal(0), Decimal(0))
Traceback (most recent call last):
  ...
  ...
  ...
DivisionUndefined: 0 / 0
>>> print c.flags[DivisionUndefined]
1
>>> c.flags[DivisionUndefined] = 0
>>> c.trap_enablers[DivisionUndefined] = False
>>> print c.divide(Decimal(0), Decimal(0))
NaN
>>> print c.flags[DivisionUndefined]
1
>>>
"""

__all__ = [
    # Two major classes
    'Decimal', 'Context',

    # Contexts
    'DefaultContext', 'BasicContext', 'ExtendedContext',

    # Exceptions
    'DecimalException', 'Clamped', 'InvalidOperation', 'ConversionSyntax',
    'DivisionByZero', 'DivisionImpossible', 'DivisionUndefined',
    'Inexact', 'InvalidContext', 'Rounded', 'Subnormal', 'Overflow',
    'Underflow',

    # Constants for use in setting up contexts
    'ROUND_DOWN', 'ROUND_HALF_UP', 'ROUND_HALF_EVEN', 'ROUND_CEILING',
    'ROUND_FLOOR', 'ROUND_UP', 'ROUND_HALF_DOWN',
    'Signals',    # <-- Used for building trap/flag dictionaries

    # Functions for manipulating contexts
    'setcontext', 'getcontext'
]

import threading
import copy
import operator

#Exponent Range
DEFAULT_MAX_EXPONENT = 999999999
DEFAULT_MIN_EXPONENT = -999999999

#Rounding
ROUND_DOWN = 'ROUND_DOWN'
ROUND_HALF_UP = 'ROUND_HALF_UP'
ROUND_HALF_EVEN = 'ROUND_HALF_EVEN'
ROUND_CEILING = 'ROUND_CEILING'
ROUND_FLOOR = 'ROUND_FLOOR'
ROUND_UP = 'ROUND_UP'
ROUND_HALF_DOWN = 'ROUND_HALF_DOWN'

#Rounding decision (not part of the public API)
NEVER_ROUND = 'NEVER_ROUND'    # Round in division (non-divmod), sqrt ONLY
ALWAYS_ROUND = 'ALWAYS_ROUND'  # Every operation rounds at end.

#Errors

class DecimalException(ArithmeticError):
    """Base exception class, defines default things.

    Used exceptions derive from this.
    If an exception derives from another exception besides this (such as
    Underflow (Inexact, Rounded, Subnormal) that indicates that it is only
    called if the others are present.  This isn't actually used for
    anything, though.

    Attributes:

    default -- If the context is basic, the trap_enablers are set to
               this by default.  Extended contexts start out with them set
               to 0, regardless.

    handle  -- Called when context._raise_error is called and the
               trap_enabler is set.  First argument is self, second is the
               context.  More arguments can be given, those being after
               the explanation in _raise_error (For example,
               context._raise_error(NewError, '(-x)!', self._sign) would
               call NewError().handle(context, self._sign).)

    To define a new exception, it should be sufficient to have it derive
    from DecimalException.
    """
    default = 1
    def handle(self, context, *args):
        pass


class Clamped(DecimalException):
    """Exponent of a 0 changed to fit bounds.

    This occurs and signals clamped if the exponent of a result has been
    altered in order to fit the constraints of a specific concrete
    representation. This may occur when the exponent of a zero result would
    be outside the bounds of a representation, or  when a large normal
    number would have an encoded exponent that cannot be represented. In
    this latter case, the exponent is reduced to fit and the corresponding
    number of zero digits are appended to the coefficient ("fold-down").
    """


class InvalidOperation(DecimalException):
    """An invalid operation was performed.

    Various bad things cause this:

    Something creates a signaling NaN
    -INF + INF
     0 * (+-)INF
     (+-)INF / (+-)INF
    x % 0
    (+-)INF % x
    x._rescale( non-integer )
    sqrt(-x) , x > 0
    0 ** 0
    x ** (non-integer)
    x ** (+-)INF
    An operand is invalid
    """
    def handle(self, context, *args):
        if args:
            if args[0] == 1: #sNaN, must drop 's' but keep diagnostics
                return Decimal( (args[1]._sign, args[1]._int, 'n') )
        return NaN

# XXX Is there a logic error in subclassing InvalidOperation?
# Setting the InvalidOperation trap to zero does not preclude ConversionSyntax.
# Also, incrementing Conversion syntax flag will not increment InvalidOperation.
# Both of these issues interfere with cross-language portability because
# code following the spec would not know about the Python subclasses.

class ConversionSyntax(InvalidOperation):
    """Trying to convert badly formed string.

    This occurs and signals invalid-operation if an string is being
    converted to a number and it does not conform to the numeric string
    syntax. The result is [0,qNaN].
    """

    def handle(self, context, *args):
        return (0, (0,), 'n') #Passed to something which uses a tuple.

class DivisionByZero(DecimalException, ZeroDivisionError):
    """Division by 0.

    This occurs and signals division-by-zero if division of a finite number
    by zero was attempted (during a divide-integer or divide operation, or a
    power operation with negative right-hand operand), and the dividend was
    not zero.

    The result of the operation is [sign,inf], where sign is the exclusive
    or of the signs of the operands for divide, or is 1 for an odd power of
    -0, for power.
    """

    def handle(self, context, sign, double = None, *args):
        if double is not None:
            return (Infsign[sign],)*2
        return Infsign[sign]

class DivisionImpossible(InvalidOperation):
    """Cannot perform the division adequately.

    This occurs and signals invalid-operation if the integer result of a
    divide-integer or remainder operation had too many digits (would be
    longer than precision). The result is [0,qNaN].
    """

    def handle(self, context, *args):
        return (NaN, NaN)

class DivisionUndefined(InvalidOperation, ZeroDivisionError):
    """Undefined result of division.

    This occurs and signals invalid-operation if division by zero was
    attempted (during a divide-integer, divide, or remainder operation), and
    the dividend is also zero. The result is [0,qNaN].
    """

    def handle(self, context, tup=None, *args):
        if tup is not None:
            return (NaN, NaN) #for 0 %0, 0 // 0
        return NaN

class Inexact(DecimalException):
    """Had to round, losing information.

    This occurs and signals inexact whenever the result of an operation is
    not exact (that is, it needed to be rounded and any discarded digits
    were non-zero), or if an overflow or underflow condition occurs. The
    result in all cases is unchanged.

    The inexact signal may be tested (or trapped) to determine if a given
    operation (or sequence of operations) was inexact.
    """
    default = 0

class InvalidContext(InvalidOperation):
    """Invalid context.  Unknown rounding, for example.

    This occurs and signals invalid-operation if an invalid context was
    detected during an operation. This can occur if contexts are not checked
    on creation and either the precision exceeds the capability of the
    underlying concrete representation or an unknown or unsupported rounding
    was specified. These aspects of the context need only be checked when
    the values are required to be used. The result is [0,qNaN].
    """

    def handle(self, context, *args):
        return NaN

class Rounded(DecimalException):
    """Number got rounded (not  necessarily changed during rounding).

    This occurs and signals rounded whenever the result of an operation is
    rounded (that is, some zero or non-zero digits were discarded from the
    coefficient), or if an overflow or underflow condition occurs. The
    result in all cases is unchanged.

    The rounded signal may be tested (or trapped) to determine if a given
    operation (or sequence of operations) caused a loss of precision.
    """
    default = 0

class Subnormal(DecimalException):
    """Exponent < Emin before rounding.

    This occurs and signals subnormal whenever the result of a conversion or
    operation is subnormal (that is, its adjusted exponent is less than
    Emin, before any rounding). The result in all cases is unchanged.

    The subnormal signal may be tested (or trapped) to determine if a given
    or operation (or sequence of operations) yielded a subnormal result.
    """
    pass

class Overflow(Inexact, Rounded):
    """Numerical overflow.

    This occurs and signals overflow if the adjusted exponent of a result
    (from a conversion or from an operation that is not an attempt to divide
    by zero), after rounding, would be greater than the largest value that
    can be handled by the implementation (the value Emax).

    The result depends on the rounding mode:

    For round-half-up and round-half-even (and for round-half-down and
    round-up, if implemented), the result of the operation is [sign,inf],
    where sign is the sign of the intermediate result. For round-down, the
    result is the largest finite number that can be represented in the
    current precision, with the sign of the intermediate result. For
    round-ceiling, the result is the same as for round-down if the sign of
    the intermediate result is 1, or is [0,inf] otherwise. For round-floor,
    the result is the same as for round-down if the sign of the intermediate
    result is 0, or is [1,inf] otherwise. In all cases, Inexact and Rounded
    will also be raised.
   """

    def handle(self, context, sign, *args):
        if context.rounding in (ROUND_HALF_UP, ROUND_HALF_EVEN,
                                     ROUND_HALF_DOWN, ROUND_UP):
            return Infsign[sign]
        if sign == 0:
            if context.rounding == ROUND_CEILING:
                return Infsign[sign]
            return Decimal((sign, (9,)*context.prec,
                            context.Emax-context.prec+1))
        if sign == 1:
            if context.rounding == ROUND_FLOOR:
                return Infsign[sign]
            return Decimal( (sign, (9,)*context.prec,
                             context.Emax-context.prec+1))


class Underflow(Inexact, Rounded, Subnormal):
    """Numerical underflow with result rounded to 0.

    This occurs and signals underflow if a result is inexact and the
    adjusted exponent of the result would be smaller (more negative) than
    the smallest value that can be handled by the implementation (the value
    Emin). That is, the result is both inexact and subnormal.

    The result after an underflow will be a subnormal number rounded, if
    necessary, so that its exponent is not less than Etiny. This may result
    in 0 with the sign of the intermediate result and an exponent of Etiny.

    In all cases, Inexact, Rounded, and Subnormal will also be raised.
    """


def _filterfunc(obj):
    """Returns true if a subclass of DecimalException"""
    try:
        return issubclass(obj, DecimalException)
    except TypeError:
        return False

#Signals holds the exceptions
Signals = filter(_filterfunc, globals().values())

del _filterfunc


##### Context Functions #######################################

#To fix reloading, force it to create a new context
#Old contexts have different exceptions in their dicts, making problems.
if hasattr(threading.currentThread(), '__decimal_context__'):
    del threading.currentThread().__decimal_context__

def setcontext(context):
    """Set this thread's context to context."""
    if context == DefaultContext:
        context = Context()
    threading.currentThread().__decimal_context__ = context

def getcontext():
    """Returns this thread's context.

    If this thread does not yet have a context, returns
    a new context and sets this thread's context.
    New contexts are copies of DefaultContext.
    """
    try:
        return threading.currentThread().__decimal_context__
    except AttributeError:
        context = Context()
        threading.currentThread().__decimal_context__ = context
        return context


##### Decimal class ###########################################

class Decimal(object):
    """Floating point class for decimal arithmetic."""

    __slots__ = ('_exp','_int','_sign')

    def __init__(self, value="0", context=None):
        """Create a decimal point instance.

        >>> Decimal('3.14')              # string input
        Decimal("3.14")
        >>> Decimal((0, (3, 1, 4), -2))  # tuple input (sign, digit_tuple, exponent)
        Decimal("3.14")
        >>> Decimal(314)                 # int or long
        Decimal("314")
        >>> Decimal(Decimal(314))        # another decimal instance
        Decimal("314")
        """
        if context is None:
            context = getcontext()

        if isinstance(value, (int,long)):
            value = str(value)

        # String?
        # REs insist on real strings, so we can too.
        if isinstance(value, basestring):
            if _isinfinity(value):
                self._exp = 'F'
                self._int = (0,)
                sign = _isinfinity(value)
                if sign == 1:
                    self._sign = 0
                else:
                    self._sign = 1
                return
            if _isnan(value):
                sig, sign, diag = _isnan(value)
                if len(diag) > context.prec: #Diagnostic info too long
                    self._sign, self._int, self._exp = \
                                context._raise_error(ConversionSyntax)
                    return
                if sig == 1:
                    self._exp = 'n' #qNaN
                else: #sig == 2
                    self._exp = 'N' #sNaN
                self._sign = sign
                self._int = tuple(map(int, diag)) #Diagnostic info
                return
            try:
                self._sign, self._int, self._exp = _string2exact(value)
            except ValueError:
                self._sign, self._int, self._exp = context._raise_error(ConversionSyntax)
            return

        # tuple/list conversion (possibly from as_tuple())
        if isinstance(value, (list,tuple)):
            if len(value) != 3:
                raise ValueError, 'Invalid arguments'
            if value[0] not in [0,1]:
                raise ValueError, 'Invalid sign'
            for digit in value[1]:
                if not isinstance(digit, (int,long)) or digit < 0:
                    raise ValueError, "The second value in the tuple must be composed of non negative integer elements."

            self._sign = value[0]
            self._int  = tuple(value[1])
            if value[2] in ('F','n','N'):
                self._exp = value[2]
            else:
                self._exp  = int(value[2])
            return

        # Turn an intermediate value back to Decimal()
        if isinstance(value, _WorkRep):
            if value.sign == 1:
                self._sign = 0
            else:
                self._sign = 1
            self._int = tuple(value.int)
            self._exp = int(value.exp)
            return

        if isinstance(value, Decimal):
          self._exp  = value._exp
          self._sign = value._sign
          self._int  = value._int
          return

        raise TypeError("Can't convert %r" % value)

    def _convert_other(self, other):
        """Convert other to Decimal.

        Verifies that it's ok to use in an implicit construction.
        """
        if isinstance(other, Decimal):
            return other
        if isinstance(other, (int, long)):
            other = Decimal(other)
            return other

        raise TypeError, "You can interact Decimal only with int, long or Decimal data types."

    def _isnan(self):
        """Returns whether the number is not actually one.

        0 if a number
        1 if NaN
        2 if sNaN
        """
        if self._exp == 'n':
            return 1
        elif self._exp == 'N':
            return 2
        return 0

    def _isinfinity(self):
        """Returns whether the number is infinite

        0 if finite or not a number
        1 if +INF
        -1 if -INF
        """
        if self._exp == 'F':
            if self._sign:
                return -1
            return 1
        return 0

    def _check_nans(self, other = None, context=None):
        """Returns whether the number is not actually one.

        if self, other are sNaN, signal
        if self, other are NaN return nan
        return 0

        Done before operations.
        """
        if context is None:
            context = getcontext()

        if self._isnan() == 2:
            return context._raise_error(InvalidOperation, 'sNaN',
                                       1, self)
        if other is not None and other._isnan() == 2:
            return context._raise_error(InvalidOperation, 'sNaN',
                                       1, other)
        if self._isnan():
            return self
        if other is not None and other._isnan():
            return other
        return 0

    def __nonzero__(self):
        """Is the number non-zero?

        0 if self == 0
        1 if self != 0
        """
        if isinstance(self._exp, str):
            return 1
        return self._int != (0,)*len(self._int)

    def __cmp__(self, other, context=None):
        if context is None:
            context = getcontext()
        other = self._convert_other(other)

        ans = self._check_nans(other, context)
        if ans:
            return 1

        if not self and not other:
            return 0 #If both 0, sign comparison isn't certain.

        #If different signs, neg one is less
        if other._sign < self._sign:
            return -1
        if self._sign < other._sign:
            return 1

        # INF = INF
        if self._isinfinity() and other._isinfinity():
            return 0
        if self._isinfinity():
            return (-1)**self._sign
        if other._isinfinity():
            return -((-1)**other._sign)

        if self.adjusted() == other.adjusted() and \
           self._int + (0,)*(self._exp - other._exp) == \
           other._int + (0,)*(other._exp - self._exp):
            return 0 #equal, except in precision. ([0]*(-x) = [])
        elif self.adjusted() > other.adjusted() and self._int[0] != 0:
            return (-1)**self._sign
        elif self.adjusted < other.adjusted() and other._int[0] != 0:
            return -((-1)**self._sign)

        context = context.copy()
        rounding = context._set_rounding(ROUND_UP) #round away from 0

        flags = context._ignore_all_flags()
        res = self.__sub__(other, context=context)

        context._regard_flags(*flags)

        context.rounding = rounding

        if not res:
            return 0
        elif res._sign:
            return -1
        return 1

    def compare(self, other, context=None):
        """Compares one to another.

        -1 => a < b
        0  => a = b
        1  => a > b
        NaN => one is NaN
        Like __cmp__, but returns Decimal instances.
        """
        if context is None:
            context = getcontext()
        other = self._convert_other(other)

        #compare(NaN, NaN) = NaN
        ans = self._check_nans(other, context)
        if ans:
            return ans

        return Decimal(self.__cmp__(other, context))

    def __hash__(self):
        """x.__hash__() <==> hash(x)"""
        # Decimal integers must hash the same as the ints
        # Non-integer decimals are normalized and hashed as strings
        # Normalization assures that hast(100E-1) == hash(10)
        i = int(self)
        if self == Decimal(i):
            return hash(i)
        assert self.__nonzero__()   # '-0' handled by integer case
        return hash(str(self.normalize()))

    def as_tuple(self):
        """Represents the number as a triple tuple.

        To show the internals exactly as they are.
        """
        return (self._sign, self._int, self._exp)

    def __repr__(self):
        """Represents the number as an instance of Decimal."""
        # Invariant:  eval(repr(d)) == d
        return 'Decimal("%s")' % str(self)

    def __str__(self, eng = 0, context=None):
        """Return string representation of the number in scientific notation.

        Captures all of the information in the underlying representation.
        """

        if self._isnan():
            minus = '-'*self._sign
            if self._int == (0,):
                info = ''
            else:
                info = ''.join(map(str, self._int))
            if self._isnan() == 2:
                return minus + 'sNaN' + info
            return minus + 'NaN' + info
        if self._isinfinity():
            minus = '-'*self._sign
            return minus + 'Infinity'

        if context is None:
            context = getcontext()

        tmp = map(str, self._int)
        numdigits = len(self._int)
        leftdigits = self._exp + numdigits
        if eng and not self: #self = 0eX wants 0[.0[0]]eY, not [[0]0]0eY
            if self._exp < 0 and self._exp >= -6: #short, no need for e/E
                s = '-'*self._sign + '0.' + '0'*(abs(self._exp))
                return s
            #exp is closest mult. of 3 >= self._exp
            exp = ((self._exp - 1)// 3 + 1) * 3
            if exp != self._exp:
                s = '0.'+'0'*(exp - self._exp)
            else:
                s = '0'
            if exp != 0:
                if context.capitals:
                    s += 'E'
                else:
                    s += 'e'
                if exp > 0:
                    s += '+' #0.0e+3, not 0.0e3
                s += str(exp)
            s = '-'*self._sign + s
            return s
        if eng:
            dotplace = (leftdigits-1)%3+1
            adjexp = leftdigits -1 - (leftdigits-1)%3
        else:
            adjexp = leftdigits-1
            dotplace = 1
        if self._exp == 0:
            pass
        elif self._exp < 0 and adjexp >= 0:
            tmp.insert(leftdigits, '.')
        elif self._exp < 0 and adjexp >= -6:
            tmp[0:0] = ['0'] * int(-leftdigits)
            tmp.insert(0, '0.')
        else:
            if numdigits > dotplace:
                tmp.insert(dotplace, '.')
            elif numdigits < dotplace:
                tmp.extend(['0']*(dotplace-numdigits))
            if adjexp:
                if not context.capitals:
                    tmp.append('e')
                else:
                    tmp.append('E')
                    if adjexp > 0:
                        tmp.append('+')
                tmp.append(str(adjexp))
        if eng:
            while tmp[0:1] == ['0']:
                tmp[0:1] = []
            if len(tmp) == 0 or tmp[0] == '.' or tmp[0].lower() == 'e':
                tmp[0:0] = ['0']
        if self._sign:
            tmp.insert(0, '-')

        return ''.join(tmp)

    def to_eng_string(self, context=None):
        """Convert to engineering-type string.

        Engineering notation has an exponent which is a multiple of 3, so there
        are up to 3 digits left of the decimal place.

        Same rules for when in exponential and when as a value as in __str__.
        """
        if context is None:
            context = getcontext()
        return self.__str__(eng=1, context=context)

    def __neg__(self, context=None):
        """Returns a copy with the sign switched.

        Rounds, if it has reason.
        """
        if context is None:
            context = getcontext()
        ans = self._check_nans(context=context)
        if ans:
            return ans

        if not self:
            # -Decimal('0') is Decimal('0'), not Decimal('-0')
            sign = 0
        elif self._sign:
            sign = 0
        else:
            sign = 1
        if context._rounding_decision == ALWAYS_ROUND:
            return Decimal((sign, self._int, self._exp))._fix(context=context)
        return Decimal( (sign, self._int, self._exp))

    def __pos__(self, context=None):
        """Returns a copy, unless it is a sNaN.

        Rounds the number (if more then precision digits)
        """
        if context is None:
            context = getcontext()
        ans = self._check_nans(context=context)
        if ans:
            return ans

        sign = self._sign
        if not self:
            # + (-0) = 0
            sign = 0

        if context._rounding_decision == ALWAYS_ROUND:
            ans = self._fix(context=context)
        else:
            ans = Decimal(self)
        ans._sign = sign
        return ans

    def __abs__(self, round=1, context=None):
        """Returns the absolute value of self.

        If the second argument is 0, do not round.
        """
        if context is None:
            context = getcontext()
        ans = self._check_nans(context=context)
        if ans:
            return ans

        if not round:
            context = context.copy()
            context._set_rounding_decision(NEVER_ROUND)

        if self._sign:
            ans = self.__neg__(context=context)
        else:
            ans = self.__pos__(context=context)

        return ans

    def __add__(self, other, context=None):
        """Returns self + other.

        -INF + INF (or the reverse) cause InvalidOperation errors.
        """
        if context is None:
            context = getcontext()
        other = self._convert_other(other)

        ans = self._check_nans(other, context)
        if ans:
            return ans

        if self._isinfinity():
            #If both INF, same sign => same as both, opposite => error.
            if self._sign != other._sign and other._isinfinity():
                return context._raise_error(InvalidOperation, '-INF + INF')
            return Decimal(self)
        if other._isinfinity():
            return Decimal(other)  #Can't both be infinity here

        shouldround = context._rounding_decision == ALWAYS_ROUND

        exp = min(self._exp, other._exp)
        negativezero = 0
        if context.rounding == ROUND_FLOOR and self._sign != other._sign:
            #If the answer is 0, the sign should be negative, in this case.
            negativezero = 1

        if not self and not other:
            sign = min(self._sign, other._sign)
            if negativezero:
                sign = 1
            return Decimal( (sign, (0,), exp))
        if not self:
            if exp < other._exp - context.prec-1:
                exp = other._exp - context.prec-1
            ans = other._rescale(exp, watchexp=0, context=context)
            if shouldround:
                ans = ans._fix(context=context)
            return ans
        if not other:
            if exp < self._exp - context.prec-1:
                exp = self._exp - context.prec-1
            ans = self._rescale(exp, watchexp=0, context=context)
            if shouldround:
                ans = ans._fix(context=context)
            return ans

        op1 = _WorkRep(self)
        op2 = _WorkRep(other)
        op1, op2 = _normalize(op1, op2, shouldround, context.prec)

        result = _WorkRep()

        if op1.sign != op2.sign:
            diff = cmp(abs(op1), abs(op2))
            # Equal and opposite
            if diff == 0:
                if exp < context.Etiny():
                    exp = context.Etiny()
                    context._raise_error(Clamped)
                return Decimal((negativezero, (0,), exp))
            if diff < 0:
                op1, op2 = op2, op1
                #OK, now abs(op1) > abs(op2)
            if op1.sign == -1:
                result.sign = -1
                op1.sign, op2.sign = op2.sign, op1.sign
            else:
                result.sign = 1
                #So we know the sign, and op1 > 0.
        elif op1.sign == -1:
            result.sign = -1
            op1.sign, op2.sign = (1, 1)
        else:
            result.sign = 1
        #Now, op1 > abs(op2) > 0

        op1.int.reverse()
        op2.int.reverse()

        if op2.sign == 1:
            result.int = resultint = map(operator.add, op1.int, op2.int)
            carry = 0
            for i in xrange(len(op1.int)):
                tmp = resultint[i] + carry
                carry = 0
                if tmp > 9:
                    carry = 1
                    tmp -= 10
                resultint[i] = tmp
            if carry:
                resultint.append(1)
        else:
            result.int = resultint = map(operator.sub, op1.int, op2.int)
            loan = 0
            for i in xrange(len(op1.int)):
                tmp = resultint[i] - loan
                loan = 0
                if tmp < 0:
                    loan = 1
                    tmp += 10
                resultint[i] = tmp
            assert not loan

        while resultint[-1] == 0:
            resultint.pop()
        resultint.reverse()

        result.exp = op1.exp
        ans = Decimal(result)
        if shouldround:
            ans = ans._fix(context=context)
        return ans

    __radd__ = __add__

    def __sub__(self, other, context=None):
        """Return self + (-other)"""
        if context is None:
            context = getcontext()
        other = self._convert_other(other)

        ans = self._check_nans(other, context=context)
        if ans:
            return ans

        # -Decimal(0) = Decimal(0), which we don't want since
        # (-0 - 0 = -0 + (-0) = -0, but -0 + 0 = 0.)
        # so we change the sign directly to a copy
        tmp = Decimal(other)
        tmp._sign = 1-tmp._sign

        return self.__add__(tmp, context=context)

    def __rsub__(self, other, context=None):
        """Return other + (-self)"""
        if context is None:
            context = getcontext()
        other = self._convert_other(other)

        tmp = Decimal(self)
        tmp._sign = 1 - tmp._sign
        return other.__add__(tmp, context=context)

    def _increment(self, round=1, context=None):
        """Special case of add, adding 1eExponent

        Since it is common, (rounding, for example) this adds
        (sign)*one E self._exp to the number more efficiently than add.

        For example:
        Decimal('5.624e10')._increment() == Decimal('5.625e10')
        """
        if context is None:
            context = getcontext()
        ans = self._check_nans(context=context)
        if ans:
            return ans

        L = list(self._int)
        L[-1] += 1
        spot = len(L)-1
        while L[spot] == 10:
            L[spot] = 0
            if spot == 0:
                L[0:0] = [1]
                break
            L[spot-1] += 1
            spot -= 1
        ans = Decimal((self._sign, L, self._exp))

        if round and context._rounding_decision == ALWAYS_ROUND:
            ans = ans._fix(context=context)
        return ans

    def __mul__(self, other, context=None):
        """Return self * other.

        (+-) INF * 0 (or its reverse) raise InvalidOperation.
        """
        if context is None:
            context = getcontext()
        other = self._convert_other(other)

        ans = self._check_nans(other, context)
        if ans:
            return ans

        resultsign = operator.xor(self._sign, other._sign)
        if self._isinfinity():
            if not other:
                return context._raise_error(InvalidOperation, '(+-)INF * 0')
            return Infsign[resultsign]

        if other._isinfinity():
            if not self:
                return context._raise_error(InvalidOperation, '0 * (+-)INF')
            return Infsign[resultsign]

        resultexp = self._exp + other._exp
        shouldround = context._rounding_decision == ALWAYS_ROUND

        # Special case for multiplying by zero
        if not self or not other:
            ans = Decimal((resultsign, (0,), resultexp))
            if shouldround:
                #Fixing in case the exponent is out of bounds
                ans = ans._fix(context=context)
            return ans

        # Special case for multiplying by power of 10
        if self._int == (1,):
            ans = Decimal((resultsign, other._int, resultexp))
            if shouldround:
                ans = ans._fix(context=context)
            return ans
        if other._int == (1,):
            ans = Decimal((resultsign, self._int, resultexp))
            if shouldround:
                ans = ans._fix(context=context)
            return ans

        op1 = list(self._int)
        op2 = list(other._int)
        op1.reverse()
        op2.reverse()
        # Minimize Decimal additions
        if len(op2) > len(op1):
            op1, op2 = op2, op1

        _divmod = divmod
        accumulator = [0]*(len(self._int) + len(other._int))
        for i in xrange(len(op2)):
            if op2[i] == 0:
                continue
            mult = op2[i]
            carry = 0
            for j in xrange(len(op1)):
                carry, accumulator[i+j] = _divmod( mult * op1[j] + carry
                                                  + accumulator[i+j], 10)

            if carry:
                accumulator[i + j + 1] += carry
        while not accumulator[-1]:
            accumulator.pop()
        accumulator.reverse()

        ans = Decimal( (resultsign, accumulator, resultexp))
        if shouldround:
            ans = ans._fix(context=context)

        return ans
    __rmul__ = __mul__

    def __div__(self, other, context=None):
        """Return self / other."""
        return self._divide(other, context=context)
    __truediv__ = __div__

    def _divide(self, other, divmod = 0, context=None):
        """Return a / b, to context.prec precision.

        divmod:
        0 => true division
        1 => (a //b, a%b)
        2 => a //b
        3 => a%b

        Actually, if divmod is 2 or 3 a tuple is returned, but errors for
        computing the other value are not raised.
        """
        if context is None:
            context = getcontext()
        other = self._convert_other(other)

        ans = self._check_nans(other, context)
        if ans:
            if divmod:
                return (ans, ans)
            else:
                return ans

        sign = operator.xor(self._sign, other._sign)
        if not self and not other:
            if divmod:
                return context._raise_error(DivisionUndefined, '0 / 0', 1)
            return context._raise_error(DivisionUndefined, '0 / 0')
        if self._isinfinity() and other._isinfinity():
            if not divmod:
                return context._raise_error(InvalidOperation, '(+-)INF/(+-)INF')
            else:
                return (context._raise_error(InvalidOperation,
                                         '(+-)INF // (+-)INF'),
                        context._raise_error(InvalidOperation,
                                         '(+-)INF % (+-)INF'))

        if not divmod:
            if other._isinfinity():
                context._raise_error(Clamped, 'Division by infinity')
                return Decimal((sign, (0,), context.Etiny()))
            if self._isinfinity():
                return Infsign[sign]
            #These two have different precision.
            if not self:
                exp = self._exp - other._exp
                if exp < context.Etiny():
                    exp = context.Etiny()
                    context._raise_error(Clamped, '0e-x / y')
                if exp > context.Emax:
                    exp = context.Emax
                    context._raise_error(Clamped, '0e+x / y')
                return Decimal( (sign, (0,), exp) )

            if not other:
                return context._raise_error(DivisionByZero, 'x / 0', sign)
        if divmod:
            if other._isinfinity():
                return (Decimal((sign, (0,), 0)), Decimal(self))
            if self._isinfinity():
                if divmod == 1:
                    return (Infsign[sign],
                            context._raise_error(InvalidOperation, 'INF % x'))
                elif divmod == 2:
                    return (Infsign[sign], NaN)
                elif divmod == 3:
                    return (Infsign[sign],
                            context._raise_error(InvalidOperation, 'INF % x'))
            if not self:
                otherside = Decimal(self)
                otherside._exp = min(self._exp, other._exp)
                return (Decimal((sign, (0,), 0)),  otherside)

            if not other:
                return context._raise_error(DivisionByZero, 'divmod(x,0)',
                                           sign, 1)

        #OK, so neither = 0, INF

        shouldround = context._rounding_decision == ALWAYS_ROUND

        #If we're dividing into ints, and self < other, stop.
        #self.__abs__(0) does not round.
        if divmod and (self.__abs__(0, context) < other.__abs__(0, context)):

            if divmod == 1 or divmod == 3:
                exp = min(self._exp, other._exp)
                ans2 = self._rescale(exp, context=context, watchexp=0)
                if shouldround:
                    ans2 = ans2._fix(context=context)
                return (Decimal( (sign, (0,), 0) ),
                        ans2)

            elif divmod == 2:
                #Don't round the mod part, if we don't need it.
                return (Decimal( (sign, (0,), 0) ), Decimal(self))

        if sign:
            sign = -1
        else:
            sign = 1
        adjust = 0
        op1 = _WorkRep(self)
        op2 = _WorkRep(other)
        op1, op2, adjust = _adjust_coefficients(op1, op2)
        res = _WorkRep( (sign, [0], (op1.exp - op2.exp)) )
        if divmod and res.exp > context.prec + 1:
            return context._raise_error(DivisionImpossible)

        ans = None
        while 1:
            while( (len(op2.int) < len(op1.int) and op1.int[0]) or
                   (len(op2.int) == len(op1.int) and op2.int <= op1.int)):
                   #Meaning, while op2.int < op1.int, when normalized.
                res._increment()
                op1.subtract(op2.int)
            if res.exp == 0 and divmod:
                if len(res.int) > context.prec and shouldround:
                    return context._raise_error(DivisionImpossible)
                otherside = Decimal(op1)
                frozen = context._ignore_all_flags()

                exp = min(self._exp, other._exp)
                otherside = otherside._rescale(exp, context=context,
                                              watchexp=0)
                context._regard_flags(*frozen)
                if shouldround:
                    otherside = otherside._fix(context=context)
                return (Decimal(res), otherside)

            if op1.int == [0]*len(op1.int) and adjust >= 0 and not divmod:
                break
            if (len(res.int) > context.prec) and shouldround:
                if divmod:
                    return context._raise_error(DivisionImpossible)
                shouldround=1
                # Really, the answer is a bit higher, so adding a one to
                # the end will make sure the rounding is right.
                if op1.int != [0]*len(op1.int):
                    res.int.append(1)
                    res.exp -= 1

                break
            res.exp -= 1
            adjust += 1
            res.int.append(0)
            op1.int.append(0)
            op1.exp -= 1

            if res.exp == 0 and divmod and (len(op2.int) > len(op1.int) or
                                            (len(op2.int) == len(op1.int) and
                                             op2.int > op1.int)):
                #Solves an error in precision.  Same as a previous block.

                if len(res.int) > context.prec and shouldround:
                    return context._raise_error(DivisionImpossible)
                otherside = Decimal(op1)
                frozen = context._ignore_all_flags()

                exp = min(self._exp, other._exp)
                otherside = otherside._rescale(exp, context=context)

                context._regard_flags(*frozen)

                return (Decimal(res), otherside)

        ans = Decimal(res)
        if shouldround:
            ans = ans._fix(context=context)
        return ans

    def __rdiv__(self, other, context=None):
        """Swaps self/other and returns __div__."""
        other = self._convert_other(other)
        return other.__div__(self, context=context)
    __rtruediv__ = __rdiv__

    def __divmod__(self, other, context=None):
        """
        (self // other, self % other)
        """
        return self._divide(other, 1, context)

    def __rdivmod__(self, other, context=None):
        """Swaps self/other and returns __divmod__."""
        other = self._convert_other(other)
        return other.__divmod__(self, context=context)

    def __mod__(self, other, context=None):
        """
        self % other
        """
        if context is None:
            context = getcontext()
        other = self._convert_other(other)

        ans = self._check_nans(other, context)
        if ans:
            return ans

        if self and not other:
            return context._raise_error(InvalidOperation, 'x % 0')

        return self._divide(other, 3, context)[1]

    def __rmod__(self, other, context=None):
        """Swaps self/other and returns __mod__."""
        other = self._convert_other(other)
        return other.__mod__(self, context=context)

    def remainder_near(self, other, context=None):
        """
        Remainder nearest to 0-  abs(remainder-near) <= other/2
        """
        if context is None:
            context = getcontext()
        other = self._convert_other(other)

        ans = self._check_nans(other, context)
        if ans:
            return ans
        if self and not other:
            return context._raise_error(InvalidOperation, 'x % 0')

        # If DivisionImpossible causes an error, do not leave Rounded/Inexact
        # ignored in the calling function.
        context = context.copy()
        flags = context._ignore_flags(Rounded, Inexact)
        #keep DivisionImpossible flags
        (side, r) = self.__divmod__(other, context=context)

        if r._isnan():
            context._regard_flags(*flags)
            return r

        context = context.copy()
        rounding = context._set_rounding_decision(NEVER_ROUND)

        if other._sign:
            comparison = other.__div__(Decimal(-2), context=context)
        else:
            comparison = other.__div__(Decimal(2), context=context)

        context._set_rounding_decision(rounding)
        context._regard_flags(*flags)

        s1, s2 = r._sign, comparison._sign
        r._sign, comparison._sign = 0, 0

        if r < comparison:
            r._sign, comparison._sign = s1, s2
            #Get flags now
            self.__divmod__(other, context=context)
            return r._fix(context=context)
        r._sign, comparison._sign = s1, s2

        rounding = context._set_rounding_decision(NEVER_ROUND)

        (side, r) = self.__divmod__(other, context=context)
        context._set_rounding_decision(rounding)
        if r._isnan():
            return r

        decrease = not side._iseven()
        rounding = context._set_rounding_decision(NEVER_ROUND)
        side = side.__abs__(context=context)
        context._set_rounding_decision(rounding)

        s1, s2 = r._sign, comparison._sign
        r._sign, comparison._sign = 0, 0
        if r > comparison or decrease and r == comparison:
            r._sign, comparison._sign = s1, s2
            context.prec += 1
            if len(side.__add__(Decimal(1), context=context)._int) >= context.prec:
                context.prec -= 1
                return context._raise_error(DivisionImpossible)[1]
            context.prec -= 1
            if self._sign == other._sign:
                r = r.__sub__(other, context=context)
            else:
                r = r.__add__(other, context=context)
        else:
            r._sign, comparison._sign = s1, s2

        return r._fix(context=context)

    def __floordiv__(self, other, context=None):
        """self // other"""
        return self._divide(other, 2, context)[0]

    def __rfloordiv__(self, other, context=None):
        """Swaps self/other and returns __floordiv__."""
        other = self._convert_other(other)
        return other.__floordiv__(self, context=context)

    def __float__(self):
        """Float representation."""
        return float(str(self))

    def __int__(self):
        """Converts self to a int, truncating if necessary."""
        if self._isnan():
            context = getcontext()
            return context._raise_error(InvalidContext)
        elif self._isinfinity():
            raise OverflowError, "Cannot convert infinity to long"
        if not self:
            return 0
        sign = '-'*self._sign
        if self._exp >= 0:
            s = sign + ''.join(map(str, self._int)) + '0'*self._exp
            return int(s)
        s = sign + ''.join(map(str, self._int))[:self._exp]
        return int(s)
        tmp = list(self._int)
        tmp.reverse()
        val = 0
        while tmp:
            val *= 10
            val += tmp.pop()
        return int(((-1) ** self._sign) * val * 10.**int(self._exp))

    def __long__(self):
        """Converts to a long.

        Equivalent to long(int(self))
        """
        return long(self.__int__())

    def _fix(self, prec=None, rounding=None, folddown=None, context=None):
        """Round if it is necessary to keep self within prec precision.

        Rounds and fixes the exponent.  Does not raise on a sNaN.

        Arguments:
        self - Decimal instance
        prec - precision to which  to round.  By default, the context decides.
        rounding - Rounding method.  By default, the context decides.
        folddown - Fold down high elements, by default context._clamp
        context - context used.
        """
        if self._isinfinity() or self._isnan():
            return self
        if context is None:
            context = getcontext()
        if prec is None:
            prec = context.prec
        ans = Decimal(self)
        ans = ans._fixexponents(prec, rounding, folddown=folddown,
                               context=context)
        if len(ans._int) > prec:
            ans = ans._round(prec, rounding, context=context)
        ans = ans._fixexponents(prec, rounding, folddown=folddown,
                               context=context)
        return ans

    def _fixexponents(self, prec=None, rounding=None, folddown=None,
                     context=None):
        """Fix the exponents and return a copy with the exponent in bounds."""
        if self._isinfinity():
            return self
        if context is None:
            context = getcontext()
        if prec is None:
            prec = context.prec
        if folddown is None:
            folddown = context._clamp
        Emin, Emax = context.Emin, context.Emax
        Etop = context.Etop()
        ans = Decimal(self)
        if ans.adjusted() < Emin:
            Etiny = context.Etiny()
            if ans._exp < Etiny:
                if not ans:
                    ans._exp = Etiny
                    context._raise_error(Clamped)
                    return ans
                ans = ans._rescale(Etiny, context=context)
                #It isn't zero, and exp < Emin => subnormal
                context._raise_error(Subnormal)
                if context.flags[Inexact]:
                    context._raise_error(Underflow)
            else:
                if ans:
                    #Only raise subnormal if non-zero.
                    context._raise_error(Subnormal)
        elif folddown and ans._exp > Etop:
            context._raise_error(Clamped)
            ans = ans._rescale(Etop, context=context)
        elif ans.adjusted() > Emax:
            if not ans:
                ans._exp = Emax
                context._raise_error(Clamped)
                return ans
            context._raise_error(Inexact)
            context._raise_error(Rounded)
            return context._raise_error(Overflow, 'above Emax', ans._sign)
        return ans

    def _round(self, prec=None, rounding=None, context=None):
        """Returns a rounded version of self.

        You can specify the precision or rounding method.  Otherwise, the
        context determines it.
        """

        if context is None:
            context = getcontext()
        ans = self._check_nans(context=context)
        if ans:
            return ans

        if self._isinfinity():
            return Decimal(self)

        if rounding is None:
            rounding = context.rounding
        if prec is None:
            prec = context.prec

        if not self:
            if prec <= 0:
                dig = (0,)
                exp = len(self._int) - prec + self._exp
            else:
                dig = (0,) * prec
                exp = len(self._int) + self._exp - prec
            ans = Decimal((self._sign, dig, exp))
            context._raise_error(Rounded)
            return ans

        if prec == 0:
            temp = Decimal(self)
            temp._int = (0,)+temp._int
            prec = 1
        elif prec < 0:
            exp = self._exp + len(self._int) - prec - 1
            temp = Decimal( (self._sign, (0, 1), exp))
            prec = 1
        else:
            temp = Decimal(self)

        numdigits = len(temp._int)
        if prec == numdigits:
            return temp

        # See if we need to extend precision
        expdiff = prec - numdigits
        if expdiff > 0:
            tmp = list(temp._int)
            tmp.extend([0] * expdiff)
            ans =  Decimal( (temp._sign, tmp, temp._exp - expdiff))
            return ans

        #OK, but maybe all the lost digits are 0.
        lostdigits = self._int[expdiff:]
        if lostdigits == (0,) * len(lostdigits):
            ans = Decimal( (temp._sign, temp._int[:prec], temp._exp - expdiff))
            #Rounded, but not Inexact
            context._raise_error(Rounded)
            return ans

        # Okay, let's round and lose data

        this_function = getattr(temp, self._pick_rounding_function[rounding])
        #Now we've got the rounding function

        if prec != context.prec:
            context = context.copy()
            context.prec = prec
        ans = this_function(prec, expdiff, context)
        context._raise_error(Rounded)
        context._raise_error(Inexact, 'Changed in rounding')

        return ans

    _pick_rounding_function = {}

    def _round_down(self, prec, expdiff, context):
        """Also known as round-towards-0, truncate."""
        return Decimal( (self._sign, self._int[:prec], self._exp - expdiff) )

    def _round_half_up(self, prec, expdiff, context, tmp = None):
        """Rounds 5 up (away from 0)"""

        if tmp is None:
            tmp = Decimal( (self._sign,self._int[:prec], self._exp - expdiff))
        if self._int[prec] >= 5:
            tmp = tmp._increment(round=0, context=context)
            if len(tmp._int) > prec:
                return Decimal( (tmp._sign, tmp._int[:-1], tmp._exp + 1))
        return tmp

    def _round_half_even(self, prec, expdiff, context):
        """Round 5 to even, rest to nearest."""

        tmp = Decimal( (self._sign, self._int[:prec], self._exp - expdiff))
        half = (self._int[prec] == 5)
        if half:
            for digit in self._int[prec+1:]:
                if digit != 0:
                    half = 0
                    break
        if half:
            if self._int[prec-1] %2 == 0:
                return tmp
        return self._round_half_up(prec, expdiff, context, tmp)

    def _round_half_down(self, prec, expdiff, context):
        """Round 5 down"""

        tmp = Decimal( (self._sign, self._int[:prec], self._exp - expdiff))
        half = (self._int[prec] == 5)
        if half:
            for digit in self._int[prec+1:]:
                if digit != 0:
                    half = 0
                    break
        if half:
            return tmp
        return self._round_half_up(prec, expdiff, context, tmp)

    def _round_up(self, prec, expdiff, context):
        """Rounds away from 0."""
        tmp = Decimal( (self._sign, self._int[:prec], self._exp - expdiff) )
        for digit in self._int[prec:]:
            if digit != 0:
                tmp = tmp._increment(round=1, context=context)
                if len(tmp._int) > prec:
                    return Decimal( (tmp._sign, tmp._int[:-1], tmp._exp + 1))
                else:
                    return tmp
        return tmp

    def _round_ceiling(self, prec, expdiff, context):
        """Rounds up (not away from 0 if negative.)"""
        if self._sign:
            return self._round_down(prec, expdiff, context)
        else:
            return self._round_up(prec, expdiff, context)

    def _round_floor(self, prec, expdiff, context):
        """Rounds down (not towards 0 if negative)"""
        if not self._sign:
            return self._round_down(prec, expdiff, context)
        else:
            return self._round_up(prec, expdiff, context)

    def __pow__(self, n, modulo = None, context=None):
        """Return self ** n (mod modulo)

        If modulo is None (default), don't take it mod modulo.
        """
        if context is None:
            context = getcontext()
        n = self._convert_other(n)

        #Because the spot << doesn't work with really big exponents
        if n._isinfinity() or n.adjusted() > 8:
            return context._raise_error(InvalidOperation, 'x ** INF')

        ans = self._check_nans(n, context)
        if ans:
            return ans

        if not n._isinfinity() and not n._isinteger():
            return context._raise_error(InvalidOperation, 'x ** (non-integer)')

        if not self and not n:
            return context._raise_error(InvalidOperation, '0 ** 0')

        if not n:
            return Decimal(1)

        if self == Decimal(1):
            return Decimal(1)

        sign = self._sign and not n._iseven()
        n = int(n)

        if self._isinfinity():
            if modulo:
                return context._raise_error(InvalidOperation, 'INF % x')
            if n > 0:
                return Infsign[sign]
            return Decimal( (sign, (0,), 0) )

        #with ludicrously large exponent, just raise an overflow and return inf.
        if not modulo and n > 0 and (self._exp + len(self._int) - 1) * n > context.Emax \
           and self:

            tmp = Decimal('inf')
            tmp._sign = sign
            context._raise_error(Rounded)
            context._raise_error(Inexact)
            context._raise_error(Overflow, 'Big power', sign)
            return tmp

        elength = len(str(abs(n)))
        firstprec = context.prec

        if not modulo and firstprec + elength + 1 > DEFAULT_MAX_EXPONENT:
            return context._raise_error(Overflow, 'Too much precision.', sign)

        mul = Decimal(self)
        val = Decimal(1)
        context = context.copy()
        context.prec = firstprec + elength + 1
        rounding = context.rounding
        if n < 0:
            #n is a long now, not Decimal instance
            n = -n
            mul = Decimal(1).__div__(mul, context=context)

        shouldround = context._rounding_decision == ALWAYS_ROUND

        spot = 1
        while spot <= n:
            spot <<= 1

        spot >>= 1
        #Spot is the highest power of 2 less than n
        while spot:
            val = val.__mul__(val, context=context)
            if val._isinfinity():
                val = Infsign[sign]
                break
            if spot & n:
                val = val.__mul__(mul, context=context)
            if modulo is not None:
                val = val.__mod__(modulo, context=context)
            spot >>= 1
        context.prec = firstprec

        if shouldround:
            return val._fix(context=context)
        return val

    def __rpow__(self, other, context=None):
        """Swaps self/other and returns __pow__."""
        other = self._convert_other(other)
        return other.__pow__(self, context=context)

    def normalize(self, context=None):
        """Normalize- strip trailing 0s, change anything equal to 0 to 0e0"""
        if context is None:
            context = getcontext()

        ans = self._check_nans(context=context)
        if ans:
            return ans

        dup = self._fix(context=context)
        if dup._isinfinity():
            return dup

        if not dup:
            return Decimal( (dup._sign, (0,), 0) )
        end = len(dup._int)
        exp = dup._exp
        while dup._int[end-1] == 0:
            exp += 1
            end -= 1
        return Decimal( (dup._sign, dup._int[:end], exp) )


    def quantize(self, exp, rounding = None, context=None, watchexp = 1):
        """Quantize self so its exponent is the same as that of exp.

        Similar to self._rescale(exp._exp) but with error checking.
        """
        if context is None:
            context = getcontext()

        ans = self._check_nans(exp, context)
        if ans:
            return ans

        if exp._isinfinity() or self._isinfinity():
            if exp._isinfinity() and self._isinfinity():
                return self  #if both are inf, it is OK
            return context._raise_error(InvalidOperation,
                                       'quantize with one INF')
        return self._rescale(exp._exp, rounding, context, watchexp)

    def same_quantum(self, other):
        """Test whether self and other have the same exponent.

        same as self._exp == other._exp, except NaN == sNaN
        """
        if self._isnan() or other._isnan():
            return self._isnan() and other._isnan() and True
        if self._isinfinity() or other._isinfinity():
            return self._isinfinity() and other._isinfinity() and True
        return self._exp == other._exp

    def _rescale(self, exp, rounding = None, context=None, watchexp = 1):
        """Rescales so that the exponent is exp.

        exp = exp to scale to (an integer)
        rounding = rounding version
        watchexp: if set (default) an error is returned if exp is greater
        than Emax or less than Etiny.
        """
        if context is None:
            context = getcontext()

        if self._isinfinity():
            return context._raise_error(InvalidOperation, 'rescale with an INF')

        ans = self._check_nans(context=context)
        if ans:
            return ans

        out = 0

        if watchexp and (context.Emax  < exp or context.Etiny() > exp):
            return context._raise_error(InvalidOperation, 'rescale(a, INF)')

        if not self:
            ans = Decimal(self)
            ans._int = (0,)
            ans._exp = exp
            return ans

        diff = self._exp - exp
        digits = len(self._int)+diff

        if watchexp and digits > context.prec:
            return context._raise_error(InvalidOperation, 'Rescale > prec')

        tmp = Decimal(self)
        tmp._int = (0,)+tmp._int
        digits += 1

        prevexact = context.flags[Inexact]
        if digits < 0:
            tmp._exp = -digits + tmp._exp
            tmp._int = (0,1)
            digits = 1
        tmp = tmp._round(digits, rounding, context=context)

        if tmp._int[0] == 0 and len(tmp._int) > 1:
            tmp._int = tmp._int[1:]
        tmp._exp = exp

        if tmp and tmp.adjusted() < context.Emin:
            context._raise_error(Subnormal)
        elif tmp and tmp.adjusted() > context.Emax:
            return context._raise_error(InvalidOperation, 'rescale(a, INF)')
        return tmp

    def to_integral(self, rounding = None, context=None):
        """Rounds to the nearest integer, without raising inexact, rounded."""
        if context is None:
            context = getcontext()
        ans = self._check_nans(context=context)
        if ans:
            return ans
        if self._exp >= 0:
            return self
        flags = context._ignore_flags(Rounded, Inexact)
        ans = self._rescale(0, rounding, context=context)
        context._regard_flags(flags)
        return ans

    def sqrt(self, context=None):
        """Return the square root of self.

        Uses a converging algorithm (Xn+1 = 0.5*(Xn + self / Xn))
        Should quadratically approach the right answer.
        """
        if context is None:
            context = getcontext()

        ans = self._check_nans(context=context)
        if ans:
            return ans

        if not self:
            #exponent = self._exp / 2, using round_down.
            #if self._exp < 0:
            #    exp = (self._exp+1) // 2
            #else:
            exp = (self._exp) // 2
            if self._sign == 1:
                #sqrt(-0) = -0
                return Decimal( (1, (0,), exp))
            else:
                return Decimal( (0, (0,), exp))

        if self._sign == 1:
            return context._raise_error(InvalidOperation, 'sqrt(-x), x > 0')

        if self._isinfinity():
            return Decimal(self)

        tmp = Decimal(self)

        expadd = tmp._exp / 2
        if tmp._exp % 2 == 1:
            tmp._int += (0,)
            tmp._exp = 0
        else:
            tmp._exp = 0

        context = context.copy()
        flags = context._ignore_all_flags()
        firstprec = context.prec
        context.prec = 3
        if tmp.adjusted() % 2 == 0:
            ans = Decimal( (0, (8,1,9), tmp.adjusted()  - 2) )
            ans = ans.__add__(tmp.__mul__(Decimal((0, (2,5,9), -2)),
                                          context=context), context=context)
            ans._exp -= 1 + tmp.adjusted()/2
        else:
            ans = Decimal( (0, (2,5,9), tmp._exp + len(tmp._int)- 3) )
            ans = ans.__add__(tmp.__mul__(Decimal((0, (8,1,9), -3)),
                                          context=context), context=context)
            ans._exp -= 1 + tmp.adjusted()/2

        #ans is now a linear approximation.

        Emax, Emin = context.Emax, context.Emin
        context.Emax, context.Emin = DEFAULT_MAX_EXPONENT, DEFAULT_MIN_EXPONENT


        half = Decimal('0.5')

        count = 1
        maxp = firstprec + 2
        rounding = context._set_rounding(ROUND_HALF_EVEN)
        while 1:
            context.prec = min(2*context.prec - 2, maxp)
            ans = half.__mul__(ans.__add__(tmp.__div__(ans, context=context),
                                           context=context), context=context)
            if context.prec == maxp:
                break

        #round to the answer's precision-- the only error can be 1 ulp.
        context.prec = firstprec
        prevexp = ans.adjusted()
        ans = ans._round(context=context)

        #Now, check if the other last digits are better.
        context.prec = firstprec + 1
        # In case we rounded up another digit and we should actually go lower.
        if prevexp != ans.adjusted():
            ans._int += (0,)
            ans._exp -= 1


        lower = ans.__sub__(Decimal((0, (5,), ans._exp-1)), context=context)
        context._set_rounding(ROUND_UP)
        if lower.__mul__(lower, context=context) > (tmp):
            ans = ans.__sub__(Decimal((0, (1,), ans._exp)), context=context)

        else:
            upper = ans.__add__(Decimal((0, (5,), ans._exp-1)),context=context)
            context._set_rounding(ROUND_DOWN)
            if upper.__mul__(upper, context=context) < tmp:
                ans = ans.__add__(Decimal((0, (1,), ans._exp)),context=context)

        ans._exp += expadd

        context.prec = firstprec
        context.rounding = rounding
        ans = ans._fix(context=context)

        rounding = context._set_rounding_decision(NEVER_ROUND)
        if not ans.__mul__(ans, context=context) == self:
            # Only rounded/inexact if here.
            context._regard_flags(flags)
            context._raise_error(Rounded)
            context._raise_error(Inexact)
        else:
            #Exact answer, so let's set the exponent right.
            #if self._exp < 0:
            #    exp = (self._exp +1)// 2
            #else:
            exp = self._exp // 2
            context.prec += ans._exp - exp
            ans = ans._rescale(exp, context=context)
            context.prec = firstprec
            context._regard_flags(flags)
        context.Emax, context.Emin = Emax, Emin

        return ans._fix(context=context)

    def max(self, other, context=None):
        """Returns the larger value.

        like max(self, other) except if one is not a number, returns
        NaN (and signals if one is sNaN).  Also rounds.
        """
        if context is None:
            context = getcontext()
        other = self._convert_other(other)

        ans = self._check_nans(other, context)
        if ans:
            return ans

        ans = self
        if self < other:
            ans = other
        shouldround = context._rounding_decision == ALWAYS_ROUND
        if shouldround:
            ans = ans._fix(context=context)
        return ans

    def min(self, other, context=None):
        """Returns the smaller value.

        like min(self, other) except if one is not a number, returns
        NaN (and signals if one is sNaN).  Also rounds.
        """
        if context is None:
            context = getcontext()
        other = self._convert_other(other)

        ans = self._check_nans(other, context)
        if ans:
            return ans

        ans = self

        if self > other:
            ans = other

        if context._rounding_decision == ALWAYS_ROUND:
            ans = ans._fix(context=context)

        return ans

    def _isinteger(self):
        """Returns whether self is an integer"""
        if self._exp >= 0:
            return True
        rest = self._int[self._exp:]
        return rest == (0,)*len(rest)

    def _iseven(self):
        """Returns 1 if self is even.  Assumes self is an integer."""
        if self._exp > 0:
            return 1
        return self._int[-1+self._exp] % 2 == 0

    def adjusted(self):
        """Return the adjusted exponent of self"""
        try:
            return self._exp + len(self._int) - 1
        #If NaN or Infinity, self._exp is string
        except TypeError:
            return 0

    #properties to immutability-near feature
    def _get_sign(self):
        return self._sign
    def _get_int(self):
        return self._int
    def _get_exp(self):
        return self._exp
    sign = property(_get_sign)
    int = property(_get_int)
    exp = property(_get_exp)

    # support for pickling, copy, and deepcopy
    def __reduce__(self):
        return (self.__class__, (str(self),))

    def __copy__(self):
        if type(self) == Decimal:
            return self     # I'm immutable; therefore I am my own clone
        return self.__class__(str(self))

    def __deepcopy__(self, memo):
        if type(self) == Decimal:
            return self     # My components are also immutable
        return self.__class__(str(self))

##### Context class ###########################################


# get rounding method function:
rounding_functions = [name for name in Decimal.__dict__.keys() if name.startswith('_round_')]
for name in rounding_functions:
    #name is like _round_half_even, goes to the global ROUND_HALF_EVEN value.
    globalname = name[1:].upper()
    val = globals()[globalname]
    Decimal._pick_rounding_function[val] = name

del name, val, globalname, rounding_functions

class Context(object):
    """Contains the context for a Decimal instance.

    Contains:
    prec - precision (for use in rounding, division, square roots..)
    rounding - rounding type. (how you round)
    _rounding_decision - ALWAYS_ROUND, NEVER_ROUND -- do you round?
    trap_enablers - If trap_enablers[exception] = 1, then the exception is
                    raised when it is caused.  Otherwise, a value is
                    substituted in.
    flags  - When an exception is caused, flags[exception] is incremented.
             (Whether or not the trap_enabler is set)
             Should be reset by user of Decimal instance.
    Emin -   Minimum exponent
    Emax -   Maximum exponent
    capitals -      If 1, 1*10^1 is printed as 1E+1.
                    If 0, printed as 1e1
    _clamp - If 1, change exponents if too high (Default 0)
    """

    DefaultLock = threading.Lock()

    def __init__(self, prec=None, rounding=None,
                 trap_enablers=None, flags=None,
                 _rounding_decision=None,
                 Emin=None, Emax=None,
                 capitals=None, _clamp=0,
                 _ignored_flags=[]):
        if flags is None:
            flags = dict.fromkeys(Signals, 0)
        self.DefaultLock.acquire()
        for name, val in locals().items():
            if val is None:
                setattr(self, name, copy.copy(getattr(DefaultContext, name)))
            else:
                setattr(self, name, val)
        self.DefaultLock.release()
        del self.self

    def __repr__(self):
        """Show the current context in readable form, not in a form for eval()."""
        s = []
        s.append('Context(prec=%(prec)d, rounding=%(rounding)s, Emin=%(Emin)d, Emax=%(Emax)d' % vars(self))
        s.append('setflags=%r' % [f.__name__ for f, v in self.flags.items() if v])
        s.append('settraps=%r' % [t.__name__ for t, v in self.trap_enablers.items() if v])
        return ', '.join(s) + ')'

    def clear_flags(self):
        """Reset all flags to zero"""
        for flag in self.flags:
            self.flags[flag] = 0

    def copy(self):
        """Returns a copy from self."""
        nc = Context(self.prec, self.rounding, self.trap_enablers, self.flags,
                         self._rounding_decision, self.Emin, self.Emax,
                         self.capitals, self._clamp, self._ignored_flags)
        return nc
    __copy__ = copy

    def _raise_error(self, error, explanation = None, *args):
        """Handles an error

        If the flag is in _ignored_flags, returns the default response.
        Otherwise, it increments the flag, then, if the corresponding
        trap_enabler is set, it reaises the exception.  Otherwise, it returns
        the default value after incrementing the flag.
        """
        if error in self._ignored_flags:
            #Don't touch the flag
            return error().handle(self, *args)

        self.flags[error] += 1
        if not self.trap_enablers[error]:
            #The errors define how to handle themselves.
            return error().handle(self, *args)

        # Errors should only be risked on copies of the context
        #self._ignored_flags = []
        raise error, explanation

    def _ignore_all_flags(self):
        """Ignore all flags, if they are raised"""
        return self._ignore_flags(*Signals)

    def _ignore_flags(self, *flags):
        """Ignore the flags, if they are raised"""
        # Do not mutate-- This way, copies of a context leave the original
        # alone.
        self._ignored_flags = (self._ignored_flags + list(flags))
        return list(flags)

    def _regard_flags(self, *flags):
        """Stop ignoring the flags, if they are raised"""
        if flags and isinstance(flags[0], (tuple,list)):
            flags = flags[0]
        for flag in flags:
            self._ignored_flags.remove(flag)

    def Etiny(self):
        """Returns Etiny (= Emin - prec + 1)"""
        return int(self.Emin - self.prec + 1)

    def Etop(self):
        """Returns maximum exponent (= Emax - prec + 1)"""
        return int(self.Emax - self.prec + 1)

    def _set_rounding_decision(self, type):
        """Sets the rounding decision.

        Sets the rounding decision, and returns the current (previous)
        rounding decision.  Often used like:

        context = context.copy()
        # That so you don't change the calling context
        # if an error occurs in the middle (say DivisionImpossible is raised).

        rounding = context._set_rounding_decision(NEVER_ROUND)
        instance = instance / Decimal(2)
        context._set_rounding_decision(rounding)

        This will make it not round for that operation.
        """

        rounding = self._rounding_decision
        self._rounding_decision = type
        return rounding

    def _set_rounding(self, type):
        """Sets the rounding type.

        Sets the rounding type, and returns the current (previous)
        rounding type.  Often used like:

        context = context.copy()
        # so you don't change the calling context
        # if an error occurs in the middle.
        rounding = context._set_rounding(ROUND_UP)
        val = self.__sub__(other, context=context)
        context._set_rounding(rounding)

        This will make it round up for that operation.
        """
        rounding = self.rounding
        self.rounding= type
        return rounding

    def create_decimal(self, num):
        """Creates a new Decimal instance but using self as context."""
        d = Decimal(num, context=self)
        return d._fix(context=self)

    #Methods
    def abs(self, a):
        """Returns the absolute value of the operand.

        If the operand is negative, the result is the same as using the minus
        operation on the operand. Otherwise, the result is the same as using
        the plus operation on the operand.

        >>> ExtendedContext.abs(Decimal('2.1'))
        Decimal("2.1")
        >>> ExtendedContext.abs(Decimal('-100'))
        Decimal("100")
        >>> ExtendedContext.abs(Decimal('101.5'))
        Decimal("101.5")
        >>> ExtendedContext.abs(Decimal('-101.5'))
        Decimal("101.5")
        """
        return a.__abs__(context=self)

    def add(self, a, b):
        """Return the sum of the two operands.

        >>> ExtendedContext.add(Decimal('12'), Decimal('7.00'))
        Decimal("19.00")
        >>> ExtendedContext.add(Decimal('1E+2'), Decimal('1.01E+4'))
        Decimal("1.02E+4")
        """
        return a.__add__(b, context=self)

    def _apply(self, a):
        return str(a._fix(context=self))

    def compare(self, a, b):
        """Compares values numerically.

        If the signs of the operands differ, a value representing each operand
        ('-1' if the operand is less than zero, '0' if the operand is zero or
        negative zero, or '1' if the operand is greater than zero) is used in
        place of that operand for the comparison instead of the actual
        operand.

        The comparison is then effected by subtracting the second operand from
        the first and then returning a value according to the result of the
        subtraction: '-1' if the result is less than zero, '0' if the result is
        zero or negative zero, or '1' if the result is greater than zero.

        >>> ExtendedContext.compare(Decimal('2.1'), Decimal('3'))
        Decimal("-1")
        >>> ExtendedContext.compare(Decimal('2.1'), Decimal('2.1'))
        Decimal("0")
        >>> ExtendedContext.compare(Decimal('2.1'), Decimal('2.10'))
        Decimal("0")
        >>> ExtendedContext.compare(Decimal('3'), Decimal('2.1'))
        Decimal("1")
        >>> ExtendedContext.compare(Decimal('2.1'), Decimal('-3'))
        Decimal("1")
        >>> ExtendedContext.compare(Decimal('-3'), Decimal('2.1'))
        Decimal("-1")
        """
        return a.compare(b, context=self)

    def divide(self, a, b):
        """Decimal division in a specified context.

        >>> ExtendedContext.divide(Decimal('1'), Decimal('3'))
        Decimal("0.333333333")
        >>> ExtendedContext.divide(Decimal('2'), Decimal('3'))
        Decimal("0.666666667")
        >>> ExtendedContext.divide(Decimal('5'), Decimal('2'))
        Decimal("2.5")
        >>> ExtendedContext.divide(Decimal('1'), Decimal('10'))
        Decimal("0.1")
        >>> ExtendedContext.divide(Decimal('12'), Decimal('12'))
        Decimal("1")
        >>> ExtendedContext.divide(Decimal('8.00'), Decimal('2'))
        Decimal("4.00")
        >>> ExtendedContext.divide(Decimal('2.400'), Decimal('2.0'))
        Decimal("1.20")
        >>> ExtendedContext.divide(Decimal('1000'), Decimal('100'))
        Decimal("10")
        >>> ExtendedContext.divide(Decimal('1000'), Decimal('1'))
        Decimal("1000")
        >>> ExtendedContext.divide(Decimal('2.40E+6'), Decimal('2'))
        Decimal("1.20E+6")
        """
        return a.__div__(b, context=self)

    def divide_int(self, a, b):
        """Divides two numbers and returns the integer part of the result.

        >>> ExtendedContext.divide_int(Decimal('2'), Decimal('3'))
        Decimal("0")
        >>> ExtendedContext.divide_int(Decimal('10'), Decimal('3'))
        Decimal("3")
        >>> ExtendedContext.divide_int(Decimal('1'), Decimal('0.3'))
        Decimal("3")
        """
        return a.__floordiv__(b, context=self)

    def divmod(self, a, b):
        return a.__divmod__(b, context=self)

    def max(self, a,b):
        """max compares two values numerically and returns the maximum.

        If either operand is a NaN then the general rules apply.
        Otherwise, the operands are compared as as though by the compare
        operation. If they are numerically equal then the left-hand operand
        is chosen as the result. Otherwise the maximum (closer to positive
        infinity) of the two operands is chosen as the result.

        >>> ExtendedContext.max(Decimal('3'), Decimal('2'))
        Decimal("3")
        >>> ExtendedContext.max(Decimal('-10'), Decimal('3'))
        Decimal("3")
        >>> ExtendedContext.max(Decimal('1.0'), Decimal('1'))
        Decimal("1.0")
        """
        return a.max(b, context=self)

    def min(self, a,b):
        """min compares two values numerically and returns the minimum.

        If either operand is a NaN then the general rules apply.
        Otherwise, the operands are compared as as though by the compare
        operation. If they are numerically equal then the left-hand operand
        is chosen as the result. Otherwise the minimum (closer to negative
        infinity) of the two operands is chosen as the result.

        >>> ExtendedContext.min(Decimal('3'), Decimal('2'))
        Decimal("2")
        >>> ExtendedContext.min(Decimal('-10'), Decimal('3'))
        Decimal("-10")
        >>> ExtendedContext.min(Decimal('1.0'), Decimal('1'))
        Decimal("1.0")
        """
        return a.min(b, context=self)

    def minus(self, a):
        """Minus corresponds to unary prefix minus in Python.

        The operation is evaluated using the same rules as subtract; the
        operation minus(a) is calculated as subtract('0', a) where the '0'
        has the same exponent as the operand.

        >>> ExtendedContext.minus(Decimal('1.3'))
        Decimal("-1.3")
        >>> ExtendedContext.minus(Decimal('-1.3'))
        Decimal("1.3")
        """
        return a.__neg__(context=self)

    def multiply(self, a, b):
        """multiply multiplies two operands.

        If either operand is a special value then the general rules apply.
        Otherwise, the operands are multiplied together ('long multiplication'),
        resulting in a number which may be as long as the sum of the lengths
        of the two operands.

        >>> ExtendedContext.multiply(Decimal('1.20'), Decimal('3'))
        Decimal("3.60")
        >>> ExtendedContext.multiply(Decimal('7'), Decimal('3'))
        Decimal("21")
        >>> ExtendedContext.multiply(Decimal('0.9'), Decimal('0.8'))
        Decimal("0.72")
        >>> ExtendedContext.multiply(Decimal('0.9'), Decimal('-0'))
        Decimal("-0.0")
        >>> ExtendedContext.multiply(Decimal('654321'), Decimal('654321'))
        Decimal("4.28135971E+11")
        """
        return a.__mul__(b, context=self)

    def normalize(self, a):
        """normalize reduces an operand to its simplest form.

        Essentially a plus operation with all trailing zeros removed from the
        result.

        >>> ExtendedContext.normalize(Decimal('2.1'))
        Decimal("2.1")
        >>> ExtendedContext.normalize(Decimal('-2.0'))
        Decimal("-2")
        >>> ExtendedContext.normalize(Decimal('1.200'))
        Decimal("1.2")
        >>> ExtendedContext.normalize(Decimal('-120'))
        Decimal("-1.2E+2")
        >>> ExtendedContext.normalize(Decimal('120.00'))
        Decimal("1.2E+2")
        >>> ExtendedContext.normalize(Decimal('0.00'))
        Decimal("0")
        """
        return a.normalize(context=self)

    def plus(self, a):
        """Plus corresponds to unary prefix plus in Python.

        The operation is evaluated using the same rules as add; the
        operation plus(a) is calculated as add('0', a) where the '0'
        has the same exponent as the operand.

        >>> ExtendedContext.plus(Decimal('1.3'))
        Decimal("1.3")
        >>> ExtendedContext.plus(Decimal('-1.3'))
        Decimal("-1.3")
        """
        return a.__pos__(context=self)

    def power(self, a, b, modulo=None):
        """Raises a to the power of b, to modulo if given.

        The right-hand operand must be a whole number whose integer part (after
        any exponent has been applied) has no more than 9 digits and whose
        fractional part (if any) is all zeros before any rounding. The operand
        may be positive, negative, or zero; if negative, the absolute value of
        the power is used, and the left-hand operand is inverted (divided into
        1) before use.

        If the increased precision needed for the intermediate calculations
        exceeds the capabilities of the implementation then an Invalid operation
        condition is raised.

        If, when raising to a negative power, an underflow occurs during the
        division into 1, the operation is not halted at that point but
        continues.

        >>> ExtendedContext.power(Decimal('2'), Decimal('3'))
        Decimal("8")
        >>> ExtendedContext.power(Decimal('2'), Decimal('-3'))
        Decimal("0.125")
        >>> ExtendedContext.power(Decimal('1.7'), Decimal('8'))
        Decimal("69.7575744")
        >>> ExtendedContext.power(Decimal('Infinity'), Decimal('-2'))
        Decimal("0")
        >>> ExtendedContext.power(Decimal('Infinity'), Decimal('-1'))
        Decimal("0")
        >>> ExtendedContext.power(Decimal('Infinity'), Decimal('0'))
        Decimal("1")
        >>> ExtendedContext.power(Decimal('Infinity'), Decimal('1'))
        Decimal("Infinity")
        >>> ExtendedContext.power(Decimal('Infinity'), Decimal('2'))
        Decimal("Infinity")
        >>> ExtendedContext.power(Decimal('-Infinity'), Decimal('-2'))
        Decimal("0")
        >>> ExtendedContext.power(Decimal('-Infinity'), Decimal('-1'))
        Decimal("-0")
        >>> ExtendedContext.power(Decimal('-Infinity'), Decimal('0'))
        Decimal("1")
        >>> ExtendedContext.power(Decimal('-Infinity'), Decimal('1'))
        Decimal("-Infinity")
        >>> ExtendedContext.power(Decimal('-Infinity'), Decimal('2'))
        Decimal("Infinity")
        >>> ExtendedContext.power(Decimal('0'), Decimal('0'))
        Decimal("NaN")
        """
        return a.__pow__(b, modulo, context=self)

    def quantize(self, a, b):
        """Returns a value equal to 'a' (rounded) and having the exponent of 'b'.

        The coefficient of the result is derived from that of the left-hand
        operand. It may be rounded using the current rounding setting (if the
        exponent is being increased), multiplied by a positive power of ten (if
        the exponent is being decreased), or is unchanged (if the exponent is
        already equal to that of the right-hand operand).

        Unlike other operations, if the length of the coefficient after the
        quantize operation would be greater than precision then an Invalid
        operation condition is raised. This guarantees that, unless there is an
        error condition, the exponent of the result of a quantize is always
        equal to that of the right-hand operand.

        Also unlike other operations, quantize will never raise Underflow, even
        if the result is subnormal and inexact.

        >>> ExtendedContext.quantize(Decimal('2.17'), Decimal('0.001'))
        Decimal("2.170")
        >>> ExtendedContext.quantize(Decimal('2.17'), Decimal('0.01'))
        Decimal("2.17")
        >>> ExtendedContext.quantize(Decimal('2.17'), Decimal('0.1'))
        Decimal("2.2")
        >>> ExtendedContext.quantize(Decimal('2.17'), Decimal('1e+0'))
        Decimal("2")
        >>> ExtendedContext.quantize(Decimal('2.17'), Decimal('1e+1'))
        Decimal("0E+1")
        >>> ExtendedContext.quantize(Decimal('-Inf'), Decimal('Infinity'))
        Decimal("-Infinity")
        >>> ExtendedContext.quantize(Decimal('2'), Decimal('Infinity'))
        Decimal("NaN")
        >>> ExtendedContext.quantize(Decimal('-0.1'), Decimal('1'))
        Decimal("-0")
        >>> ExtendedContext.quantize(Decimal('-0'), Decimal('1e+5'))
        Decimal("-0E+5")
        >>> ExtendedContext.quantize(Decimal('+35236450.6'), Decimal('1e-2'))
        Decimal("NaN")
        >>> ExtendedContext.quantize(Decimal('-35236450.6'), Decimal('1e-2'))
        Decimal("NaN")
        >>> ExtendedContext.quantize(Decimal('217'), Decimal('1e-1'))
        Decimal("217.0")
        >>> ExtendedContext.quantize(Decimal('217'), Decimal('1e-0'))
        Decimal("217")
        >>> ExtendedContext.quantize(Decimal('217'), Decimal('1e+1'))
        Decimal("2.2E+2")
        >>> ExtendedContext.quantize(Decimal('217'), Decimal('1e+2'))
        Decimal("2E+2")
        """
        return a.quantize(b, context=self)

    def remainder(self, a, b):
        """Returns the remainder from integer division.

        The result is the residue of the dividend after the operation of
        calculating integer division as described for divide-integer, rounded to
        precision digits if necessary. The sign of the result, if non-zero, is
        the same as that of the original dividend.

        This operation will fail under the same conditions as integer division
        (that is, if integer division on the same two operands would fail, the
        remainder cannot be calculated).

        >>> ExtendedContext.remainder(Decimal('2.1'), Decimal('3'))
        Decimal("2.1")
        >>> ExtendedContext.remainder(Decimal('10'), Decimal('3'))
        Decimal("1")
        >>> ExtendedContext.remainder(Decimal('-10'), Decimal('3'))
        Decimal("-1")
        >>> ExtendedContext.remainder(Decimal('10.2'), Decimal('1'))
        Decimal("0.2")
        >>> ExtendedContext.remainder(Decimal('10'), Decimal('0.3'))
        Decimal("0.1")
        >>> ExtendedContext.remainder(Decimal('3.6'), Decimal('1.3'))
        Decimal("1.0")
        """
        return a.__mod__(b, context=self)

    def remainder_near(self, a, b):
        """Returns to be "a - b * n", where n is the integer nearest the exact
        value of "x / b" (if two integers are equally near then the even one
        is chosen). If the result is equal to 0 then its sign will be the
        sign of a.

        This operation will fail under the same conditions as integer division
        (that is, if integer division on the same two operands would fail, the
        remainder cannot be calculated).

        >>> ExtendedContext.remainder_near(Decimal('2.1'), Decimal('3'))
        Decimal("-0.9")
        >>> ExtendedContext.remainder_near(Decimal('10'), Decimal('6'))
        Decimal("-2")
        >>> ExtendedContext.remainder_near(Decimal('10'), Decimal('3'))
        Decimal("1")
        >>> ExtendedContext.remainder_near(Decimal('-10'), Decimal('3'))
        Decimal("-1")
        >>> ExtendedContext.remainder_near(Decimal('10.2'), Decimal('1'))
        Decimal("0.2")
        >>> ExtendedContext.remainder_near(Decimal('10'), Decimal('0.3'))
        Decimal("0.1")
        >>> ExtendedContext.remainder_near(Decimal('3.6'), Decimal('1.3'))
        Decimal("-0.3")
        """
        return a.remainder_near(b, context=self)

    def same_quantum(self, a, b):
        """Returns True if the two operands have the same exponent.

        The result is never affected by either the sign or the coefficient of
        either operand.

        >>> ExtendedContext.same_quantum(Decimal('2.17'), Decimal('0.001'))
        False
        >>> ExtendedContext.same_quantum(Decimal('2.17'), Decimal('0.01'))
        True
        >>> ExtendedContext.same_quantum(Decimal('2.17'), Decimal('1'))
        False
        >>> ExtendedContext.same_quantum(Decimal('Inf'), Decimal('-Inf'))
        True
        """
        return a.same_quantum(b)

    def sqrt(self, a):
        """Returns the square root of a non-negative number to context precision.

        If the result must be inexact, it is rounded using the round-half-even
        algorithm.

        >>> ExtendedContext.sqrt(Decimal('0'))
        Decimal("0")
        >>> ExtendedContext.sqrt(Decimal('-0'))
        Decimal("-0")
        >>> ExtendedContext.sqrt(Decimal('0.39'))
        Decimal("0.624499800")
        >>> ExtendedContext.sqrt(Decimal('100'))
        Decimal("10")
        >>> ExtendedContext.sqrt(Decimal('1'))
        Decimal("1")
        >>> ExtendedContext.sqrt(Decimal('1.0'))
        Decimal("1.0")
        >>> ExtendedContext.sqrt(Decimal('1.00'))
        Decimal("1.0")
        >>> ExtendedContext.sqrt(Decimal('7'))
        Decimal("2.64575131")
        >>> ExtendedContext.sqrt(Decimal('10'))
        Decimal("3.16227766")
        >>> ExtendedContext.prec
        9
        """
        return a.sqrt(context=self)

    def subtract(self, a, b):
        """Return the sum of the two operands.

        >>> ExtendedContext.subtract(Decimal('1.3'), Decimal('1.07'))
        Decimal("0.23")
        >>> ExtendedContext.subtract(Decimal('1.3'), Decimal('1.30'))
        Decimal("0.00")
        >>> ExtendedContext.subtract(Decimal('1.3'), Decimal('2.07'))
        Decimal("-0.77")
        """
        return a.__sub__(b, context=self)

    def to_eng_string(self, a):
        """Converts a number to a string, using scientific notation.

        The operation is not affected by the context.
        """
        return a.to_eng_string(context=self)

    def to_sci_string(self, a):
        """Converts a number to a string, using scientific notation.

        The operation is not affected by the context.
        """
        return a.__str__(context=self)

    def to_integral(self, a):
        """Rounds to an integer.

        When the operand has a negative exponent, the result is the same
        as using the quantize() operation using the given operand as the
        left-hand-operand, 1E+0 as the right-hand-operand, and the precision
        of the operand as the precision setting, except that no flags will
        be set. The rounding mode is taken from the context.

        >>> ExtendedContext.to_integral(Decimal('2.1'))
        Decimal("2")
        >>> ExtendedContext.to_integral(Decimal('100'))
        Decimal("100")
        >>> ExtendedContext.to_integral(Decimal('100.0'))
        Decimal("100")
        >>> ExtendedContext.to_integral(Decimal('101.5'))
        Decimal("102")
        >>> ExtendedContext.to_integral(Decimal('-101.5'))
        Decimal("-102")
        >>> ExtendedContext.to_integral(Decimal('10E+5'))
        Decimal("1.0E+6")
        >>> ExtendedContext.to_integral(Decimal('7.89E+77'))
        Decimal("7.89E+77")
        >>> ExtendedContext.to_integral(Decimal('-Inf'))
        Decimal("-Infinity")
        """
        return a.to_integral(context=self)

class _WorkRep(object):
    __slots__ = ('sign','int','exp')
    # sign: -1 None 1
    # int:  list
    # exp:  None, int, or string

    def __init__(self, value=None):
        if value is None:
            self.sign = None
            self.int = []
            self.exp = None
        if isinstance(value, Decimal):
            if value._sign:
                self.sign = -1
            else:
                self.sign = 1
            self.int = list(value._int)
            self.exp = value._exp
        if isinstance(value, tuple):
            self.sign = value[0]
            self.int = value[1]
            self.exp = value[2]

    def __repr__(self):
        return "(%r, %r, %r)" % (self.sign, self.int, self.exp)

    __str__ = __repr__

    def __neg__(self):
        if self.sign == 1:
            return _WorkRep( (-1, self.int, self.exp) )
        else:
            return _WorkRep( (1, self.int, self.exp) )

    def __abs__(self):
        if self.sign == -1:
            return -self
        else:
            return self

    def __cmp__(self, other):
        if self.exp != other.exp:
            raise ValueError("Operands not normalized: %r, %r" % (self, other))
        if self.sign != other.sign:
            if self.sign == -1:
                return -1
            else:
                return 1
        if self.sign == -1:
            direction = -1
        else:
            direction = 1
        int1 = self.int
        int2 = other.int
        if len(int1) > len(int2):
            return direction * 1
        if len(int1) < len(int2):
            return direction * -1
        for i in xrange(len(int1)):
            if int1[i] > int2[i]:
                return direction * 1
            if int1[i] < int2[i]:
                return direction * -1
        return 0

    def _increment(self):
        curspot = len(self.int) - 1
        self.int[curspot]+= 1
        while (self.int[curspot] >= 10):
            self.int[curspot] -= 10
            if curspot == 0:
                self.int[0:0] = [1]
                break
            self.int[curspot-1] += 1
            curspot -= 1

    def subtract(self, alist):
        """Subtract a list from the current int (in place).

        It is assured that (len(list) = len(self.int) and list < self.int) or
        len(list) = len(self.int)-1
        (i.e. that int(join(list)) < int(join(self.int)))
        """

        selfint = self.int
        selfint.reverse()
        alist.reverse()

        carry = 0
        for x in xrange(len(alist)):
            selfint[x] -= alist[x] + carry
            if selfint[x] < 0:
                carry = 1
                selfint[x] += 10
            else:
              carry = 0
        if carry:
            selfint[x+1] -= 1
        last = len(selfint)-1
        while len(selfint) > 1 and selfint[last] == 0:
            last -= 1
            if last == 0:
                break
        selfint[last+1:]=[]
        selfint.reverse()
        alist.reverse()
        return


def _normalize(op1, op2, shouldround = 0, prec = 0):
    """Normalizes op1, op2 to have the same exp and length of coefficient.

    Done during addition.
    """
    # Yes, the exponent is a long, but the difference between exponents
    # must be an int-- otherwise you'd get a big memory problem.
    numdigits = int(op1.exp - op2.exp)
    if numdigits < 0:
        numdigits = -numdigits
        tmp = op2
        other = op1
    else:
        tmp = op1
        other = op2

    if shouldround and numdigits > len(other.int) + prec + 1 -len(tmp.int):
        # If the difference in adjusted exps is > prec+1, we know
        # other is insignificant, so might as well put a 1 after the precision.
        # (since this is only for addition.)  Also stops MemoryErrors.

        extend = prec + 2 -len(tmp.int)
        if extend <= 0:
            extend = 1
        tmp.int.extend([0]*extend)
        tmp.exp -= extend
        other.int[:] = [0]*(len(tmp.int)-1)+[1]
        other.exp = tmp.exp
        return op1, op2

    tmp.int.extend([0] * numdigits)
    tmp.exp = tmp.exp - numdigits
    numdigits = len(op1.int) - len(op2.int)
    # numdigits != 0 => They have the same exponent, but not the same length
    # of the coefficient.
    if numdigits < 0:
        numdigits = -numdigits
        tmp = op1
    else:
        tmp = op2
    tmp.int[0:0] = [0] * numdigits
    return op1, op2

def _adjust_coefficients(op1, op2):
    """Adjust op1, op2 so that op2.int+[0] > op1.int >= op2.int.

    Returns the adjusted op1, op2 as well as the change in op1.exp-op2.exp.

    Used on _WorkRep instances during division.
    """
    adjust = 0
    #If op1 is smaller, get it to same size
    if len(op2.int) > len(op1.int):
        diff = len(op2.int) - len(op1.int)
        op1.int.extend([0]*diff)
        op1.exp -= diff
        adjust = diff

    #Same length, wrong order
    if len(op1.int) == len(op2.int) and op1.int < op2.int:
        op1.int.append(0)
        op1.exp -= 1
        adjust+= 1
        return op1, op2, adjust

    if len(op1.int) > len(op2.int) + 1:
        diff = len(op1.int) - len(op2.int) - 1
        op2.int.extend([0]*diff)
        op2.exp -= diff
        adjust -= diff

    if len(op1.int) == len(op2.int)+1 and op1.int > op2.int:

        op2.int.append(0)
        op2.exp -= 1
        adjust -= 1
    return op1, op2, adjust

##### Helper Functions ########################################

_infinity_map = {
    'inf' : 1,
    'infinity' : 1,
    '+inf' : 1,
    '+infinity' : 1,
    '-inf' : -1,
    '-infinity' : -1
}

def _isinfinity(num):
    """Determines whether a string or float is infinity.

    +1 for negative infinity; 0 for finite ; +1 for positive infinity
    """
    num = str(num).lower()
    return _infinity_map.get(num, 0)

def _isnan(num):
    """Determines whether a string or float is NaN

    (1, sign, diagnostic info as string) => NaN
    (2, sign, diagnostic info as string) => sNaN
    0 => not a NaN
    """
    num = str(num).lower()
    if not num:
        return 0

    #get the sign, get rid of trailing [+-]
    sign = 0
    if num[0] == '+':
        num = num[1:]
    elif num[0] == '-':  #elif avoids '+-nan'
        num = num[1:]
        sign = 1

    if num.startswith('nan'):
        if len(num) > 3 and not num[3:].isdigit(): #diagnostic info
            return 0
        return (1, sign, num[3:].lstrip('0'))
    if num.startswith('snan'):
        if len(num) > 4 and not num[4:].isdigit():
            return 0
        return (2, sign, num[4:].lstrip('0'))
    return 0


##### Setup Specific Contexts ################################

_basic_traps = dict.fromkeys(Signals, 1)
_basic_traps.update({Inexact:0, Rounded:0, Subnormal:0})

# The default context prototype used by Context()
# Is mutable, so than new contexts can have different default values

DefaultContext = Context(
        prec=28, rounding=ROUND_HALF_EVEN,
        trap_enablers=dict.fromkeys(Signals, 0),
        flags=None,
        _rounding_decision=ALWAYS_ROUND,
        Emax=DEFAULT_MAX_EXPONENT,
        Emin=DEFAULT_MIN_EXPONENT,
        capitals=1
)
DefaultContext.trap_enablers.update({ConversionSyntax : 1})

# Pre-made alternate contexts offered by the specification
# Don't change these; the user should be able to select these
# contexts and be able to reproduce results from other implementations
# of the spec.

BasicContext = Context(
        prec=9, rounding=ROUND_HALF_UP,
        trap_enablers=_basic_traps,
        flags=None,
        _rounding_decision=ALWAYS_ROUND,
)

ExtendedContext = Context(
        prec=9, rounding=ROUND_HALF_EVEN,
        trap_enablers=dict.fromkeys(Signals, 0),
        flags=None,
        _rounding_decision=ALWAYS_ROUND,
)


##### Useful Constants (internal use only) ####################

#Reusable defaults
Inf = Decimal('Inf')
negInf = Decimal('-Inf')

#Infsign[sign] is infinity w/ that sign
Infsign = (Inf, negInf)

NaN = Decimal('NaN')


##### crud for parsing strings #################################
import re

# There's an optional sign at the start, and an optional exponent
# at the end.  The exponent has an optional sign and at least one
# digit.  In between, must have either at least one digit followed
# by an optional fraction, or a decimal point followed by at least
# one digit.  Yuck.

_parser = re.compile(r"""
#    \s*
    (?P<sign>[-+])?
    (
        (?P<int>\d+) (\. (?P<frac>\d*))?
    |
        \. (?P<onlyfrac>\d+)
    )
    ([eE](?P<exp>[-+]? \d+))?
#    \s*
    $
""", re.VERBOSE).match #Uncomment the \s* to allow leading or trailing spaces.

del re

# return sign, n, p s.t. float string value == -1**sign * n * 10**p exactly

def _string2exact(s):
    m = _parser(s)
    if m is None:
        raise ValueError("invalid literal for Decimal: %r" % s)

    if m.group('sign') == "-":
        sign = 1
    else:
        sign = 0

    exp = m.group('exp')
    if exp is None:
        exp = 0
    else:
        exp = int(exp)

    intpart = m.group('int')
    if intpart is None:
        intpart = ""
        fracpart = m.group('onlyfrac')
    else:
        fracpart = m.group('frac')
        if fracpart is None:
            fracpart = ""

    exp -= len(fracpart)

    mantissa = intpart + fracpart
    tmp = map(int, mantissa)
    backup = tmp
    while tmp and tmp[0] == 0:
        del tmp[0]

    # It's a zero
    if not tmp:
        if backup:
            return (sign, tuple(backup), exp)
        return (sign, (0,), exp)
    mantissa = tuple(tmp)

    return (sign, mantissa, exp)


if __name__ == '__main__':
    import doctest, sys
    doctest.testmod(sys.modules[__name__])
