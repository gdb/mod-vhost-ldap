# Simple test suite for Cookie.py

from test_support import verify
import Cookie
from test_support import verify, verbose

# Currently this only tests SimpleCookie

cases = [
    ('chips=ahoy; vienna=finger', {'chips':'ahoy', 'vienna':'finger'}),
    ('keebler="E=mc2; L=\\"Loves\\"; fudge=\\012;";',
     {'keebler' : 'E=mc2; L="Loves"; fudge=\012;'}),
    ]

for data, dict in cases:
    C = Cookie.SimpleCookie() ; C.load(data)
    print repr(C)
    print str(C)
    for k, v in dict.items():
        print ' ', k, repr( C[k].value ), repr(v)
        verify(C[k].value == v)
        print C[k]

C = Cookie.SimpleCookie()
C.load('Customer="WILE_E_COYOTE"; Version=1; Path=/acme')

verify(C['Customer'].value == 'WILE_E_COYOTE')
verify(C['Customer']['version'] == '1')
verify(C['Customer']['path'] == '/acme')

print C.output(['path'])
print C.js_output()
print C.js_output(['path'])

# Try cookie with quoted meta-data
C = Cookie.SimpleCookie()
C.load('Customer="WILE_E_COYOTE"; Version="1"; Path="/acme"')
verify(C['Customer'].value == 'WILE_E_COYOTE')
verify(C['Customer']['version'] == '1')
verify(C['Customer']['path'] == '/acme')
