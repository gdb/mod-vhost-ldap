import pprint
import sys
import unittest

import test_support


class HookWatcher:
    def __init__(self):
        self.frames = []
        self.events = []

    def callback(self, frame, event, arg):
        self.add_event(event, frame)

    def add_event(self, event, frame=None):
        """Add an event to the log."""
        if frame is None:
            frame = sys._getframe(1)

        try:
            frameno = self.frames.index(frame)
        except ValueError:
            frameno = len(self.frames)
            self.frames.append(frame)

        self.events.append((frameno, event, ident(frame)))

    def get_events(self):
        """Remove calls to add_event()."""
        disallowed = [ident(self.add_event.im_func), ident(ident)]
        self.frames = None

        return [item for item in self.events if item[2] not in disallowed]


class ProfileSimulator(HookWatcher):
    def __init__(self):
        self.stack = []
        HookWatcher.__init__(self)

    def callback(self, frame, event, arg):
        self.dispatch[event](self, frame)

    def trace_call(self, frame):
        self.add_event('call', frame)
        self.stack.append(frame)

    def trace_return(self, frame):
        self.add_event('return', frame)
        self.stack.pop()

    def trace_exception(self, frame):
        if len(self.stack) >= 2 and frame is self.stack[-2]:
            self.add_event('propogate-from', self.stack[-1])
            self.stack.pop()
        else:
            self.add_event('ignore', frame)

    dispatch = {
        'call': trace_call,
        'exception': trace_exception,
        'return': trace_return,
        }


class TestCaseBase(unittest.TestCase):
    def check_events(self, callable, expected):
        events = capture_events(callable, self.new_watcher())
        if events != expected:
            self.fail("Expected events:\n%s\nReceived events:\n%s"
                      % (pprint.pformat(expected), pprint.pformat(events)))


class ProfileHookTestCase(TestCaseBase):
    def new_watcher(self):
        return HookWatcher()

    def test_simple(self):
        def f(p):
            pass
        f_ident = ident(f)
        self.check_events(f, [(1, 'call', f_ident),
                              (1, 'return', f_ident),
                              ])

    def test_exception(self):
        def f(p):
            1/0
        f_ident = ident(f)
        self.check_events(f, [(1, 'call', f_ident),
                              (1, 'exception', f_ident),
                              (0, 'exception', protect_ident),
                              ])

    def test_caught_exception(self):
        def f(p):
            try: 1/0
            except: pass
        f_ident = ident(f)
        self.check_events(f, [(1, 'call', f_ident),
                              (1, 'exception', f_ident),
                              (1, 'return', f_ident),
                              ])

    def test_caught_nested_exception(self):
        def f(p):
            try: 1/0
            except: pass
        f_ident = ident(f)
        self.check_events(f, [(1, 'call', f_ident),
                              (1, 'exception', f_ident),
                              (1, 'return', f_ident),
                              ])

    def test_nested_exception(self):
        def f(p):
            1/0
        f_ident = ident(f)
        self.check_events(f, [(1, 'call', f_ident),
                              (1, 'exception', f_ident),
                              # This isn't what I expected:
                              (0, 'exception', protect_ident),
                              # I expected this again:
                              # (1, 'exception', f_ident),
                              ])

    def test_exception_in_except_clause(self):
        def f(p):
            1/0
        def g(p):
            try:
                f(p)
            except:
                try: f(p)
                except: pass
        f_ident = ident(f)
        g_ident = ident(g)
        self.check_events(g, [(1, 'call', g_ident),
                              (2, 'call', f_ident),
                              (2, 'exception', f_ident),
                              (1, 'exception', g_ident),
                              (3, 'call', f_ident),
                              (3, 'exception', f_ident),
                              (1, 'exception', g_ident),
                              (1, 'return', g_ident),
                              ])

    def test_exception_propogation(self):
        def f(p):
            1/0
        def g(p):
            try: f(p)
            finally: p.add_event("falling through")
        f_ident = ident(f)
        g_ident = ident(g)
        self.check_events(g, [(1, 'call', g_ident),
                              (2, 'call', f_ident),
                              (2, 'exception', f_ident),
                              (1, 'exception', g_ident),
                              (1, 'falling through', g_ident),
                              (0, 'exception', protect_ident),
                              ])

    def test_raise_twice(self):
        def f(p):
            try: 1/0
            except: 1/0
        f_ident = ident(f)
        self.check_events(f, [(1, 'call', f_ident),
                              (1, 'exception', f_ident),
                              (1, 'exception', f_ident),
                              (0, 'exception', protect_ident)
                              ])

    def test_raise_reraise(self):
        def f(p):
            try: 1/0
            except: raise
        f_ident = ident(f)
        self.check_events(f, [(1, 'call', f_ident),
                              (1, 'exception', f_ident),
                              (0, 'exception', protect_ident)
                              ])

    def test_raise(self):
        def f(p):
            raise Exception()
        f_ident = ident(f)
        self.check_events(f, [(1, 'call', f_ident),
                              (1, 'exception', f_ident),
                              (0, 'exception', protect_ident)
                              ])


class ProfileSimulatorTestCase(TestCaseBase):
    def new_watcher(self):
        return ProfileSimulator()

    def test_simple(self):
        def f(p):
            pass
        f_ident = ident(f)
        self.check_events(f, [(1, 'call', f_ident),
                              (1, 'return', f_ident),
                              ])

    def test_basic_exception(self):
        def f(p):
            1/0
        f_ident = ident(f)
        self.check_events(f, [(1, 'call', f_ident),
                              (1, 'ignore', f_ident),
                              (1, 'propogate-from', f_ident),
                              ])


def ident(function):
    if hasattr(function, "f_code"):
        code = function.f_code
    else:
        code = function.func_code
    return code.co_firstlineno, code.co_name


def protect(f, p):
    try: f(p)
    except: pass

protect_ident = ident(protect)


def capture_events(callable, p=None):
    if p is None:
        p = HookWatcher()
    sys.setprofile(p.callback)
    protect(callable, p)
    sys.setprofile(None)
    return p.get_events()[1:-1]


def show_events(callable):
    import pprint
    pprint.pprint(capture_events(callable))


def test_main():
    loader = unittest.TestLoader()
    suite = unittest.TestSuite()
    suite.addTest(loader.loadTestsFromTestCase(ProfileHookTestCase))
    suite.addTest(loader.loadTestsFromTestCase(ProfileSimulatorTestCase))
    test_support.run_suite(suite)


if __name__ == "__main__":
    test_main()
