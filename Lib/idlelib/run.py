import sys
import os
import time
import socket
import traceback
import threading
import Queue

import boolcheck

import CallTips
import RemoteDebugger
import RemoteObjectBrowser
import StackViewer
import rpc
import interrupt

import __main__

# Thread shared globals: Establish a queue between a subthread (which handles
# the socket) and the main thread (which runs user code), plus global
# completion and exit flags:

exit_now = False
quitting = False

def main():
    """Start the Python execution server in a subprocess

    In the Python subprocess, RPCServer is instantiated with handlerclass
    MyHandler, which inherits register/unregister methods from RPCHandler via
    the mix-in class SocketIO.

    When the RPCServer 'server' is instantiated, the TCPServer initialization
    creates an instance of run.MyHandler and calls its handle() method.
    handle() instantiates a run.Executive object, passing it a reference to the
    MyHandler object.  That reference is saved as attribute rpchandler of the
    Executive instance.  The Executive methods have access to the reference and
    can pass it on to entities that they command
    (e.g. RemoteDebugger.Debugger.start_debugger()).  The latter, in turn, can
    call MyHandler(SocketIO) register/unregister methods via the reference to
    register and unregister themselves.

    """
    global exit_now
    global quitting
    port = 8833
    if sys.argv[1:]:
        port = int(sys.argv[1])
    sys.argv[:] = [""]
    sockthread = threading.Thread(target=manage_socket,
                                  name='SockThread',
                                  args=(('localhost', port),))
    sockthread.setDaemon(True)
    sockthread.start()
    while 1:
        try:
            if exit_now:
                try:
                    sys.exit(0)
                except KeyboardInterrupt:
                    # exiting but got an extra KBI? Try again!
                    continue
            try:
                seq, request = rpc.request_queue.get(0)
            except Queue.Empty:
                time.sleep(0.05)
                continue
            method, args, kwargs = request
            ret = method(*args, **kwargs)
            rpc.response_queue.put((seq, ret))
        except KeyboardInterrupt:
            if quitting:
                exit_now = True
            continue
        except SystemExit:
            raise
        except:
            type, value, tb = sys.exc_info()
            try:
                print_exception()
                rpc.response_queue.put((seq, None))
            except:
                # Link didn't work, print same exception to __stderr__
                traceback.print_exception(type, value, tb, file=sys.__stderr__)
                sys.exit(0)
            else:
                continue

def manage_socket(address):
    for i in range(6):
        time.sleep(i)
        try:
            server = MyRPCServer(address, MyHandler)
            break
        except socket.error, err:
            if i < 3:
                print>>sys.__stderr__, ".. ",
            else:
                print>>sys.__stderr__,"\nPython subprocess socket error: "\
                                              + err[1] + ", retrying...."
    else:
        print>>sys.__stderr__, "\nConnection to Idle failed, exiting."
        global exit_now
        exit_now = True
        return
    server.handle_request() # A single request only

def print_exception():
    flush_stdout()
    efile = sys.stderr
    typ, val, tb = sys.exc_info()
    tbe = traceback.extract_tb(tb)
    print >>efile, '\nTraceback (most recent call last):'
    exclude = ("run.py", "rpc.py", "threading.py", "Queue.py",
               "RemoteDebugger.py", "bdb.py")
    cleanup_traceback(tbe, exclude)
    traceback.print_list(tbe, file=efile)
    lines = traceback.format_exception_only(typ, val)
    for line in lines:
        print>>efile, line,

def cleanup_traceback(tb, exclude):
    "Remove excluded traces from beginning/end of tb; get cached lines"
    orig_tb = tb[:]
    while tb:
        for rpcfile in exclude:
            if tb[0][0].count(rpcfile):
                break    # found an exclude, break for: and delete tb[0]
        else:
            break        # no excludes, have left RPC code, break while:
        del tb[0]
    while tb:
        for rpcfile in exclude:
            if tb[-1][0].count(rpcfile):
                break
        else:
            break
        del tb[-1]
    if len(tb) == 0:
        # exception was in IDLE internals, don't prune!
        tb[:] = orig_tb[:]
        print>>sys.stderr, "** IDLE Internal Exception: "
    rpchandler = rpc.objecttable['exec'].rpchandler
    for i in range(len(tb)):
        fn, ln, nm, line = tb[i]
        if nm == '?':
            nm = "-toplevel-"
        if not line and fn.startswith("<pyshell#"):
            line = rpchandler.remotecall('linecache', 'getline',
                                              (fn, ln), {})
        tb[i] = fn, ln, nm, line

def flush_stdout():
    try:
        if sys.stdout.softspace:
            sys.stdout.softspace = 0
            sys.stdout.write("\n")
    except (AttributeError, EOFError):
        pass


class MyRPCServer(rpc.RPCServer):

    def handle_error(self, request, client_address):
        """Override RPCServer method for IDLE

        Interrupt the MainThread and exit server if link is dropped.

        """
        try:
            raise
        except SystemExit:
            raise
        except EOFError:
            global exit_now
            exit_now = True
            interrupt.interrupt_main()
        except:
            erf = sys.__stderr__
            print>>erf, '\n' + '-'*40
            print>>erf, 'Unhandled server exception!'
            print>>erf, 'Thread: %s' % threading.currentThread().getName()
            print>>erf, 'Client Address: ', client_address
            print>>erf, 'Request: ', repr(request)
            traceback.print_exc(file=erf)
            print>>erf, '\n*** Unrecoverable, server exiting!'
            print>>erf, '-'*40
            sys.exit(0)


class MyHandler(rpc.RPCHandler):

    def handle(self):
        """Override base method"""
        executive = Executive(self)
        self.register("exec", executive)
        sys.stdin = self.get_remote_proxy("stdin")
        sys.stdout = self.get_remote_proxy("stdout")
        sys.stderr = self.get_remote_proxy("stderr")
        rpc.RPCHandler.getresponse(self, myseq=None, wait=0.05)

    def exithook(self):
        "override SocketIO method - wait for MainThread to shut us down"
        time.sleep(10)

    def EOFhook(self):
        "Override SocketIO method - terminate wait on callback and exit thread"
        global quitting
        quitting = True
        interrupt.interrupt_main()

    def decode_interrupthook(self):
        "interrupt awakened thread"
        global quitting
        quitting = True
        interrupt.interrupt_main()


class Executive:

    def __init__(self, rpchandler):
        self.rpchandler = rpchandler
        self.locals = __main__.__dict__
        self.calltip = CallTips.CallTips()

    def runcode(self, code):
        try:
            exec code in self.locals
        except:
            if quitting:
                sys.exit(0)
            # even print a user code SystemExit exception, continue
            print_exception()
        else:
            flush_stdout()

    def interrupt_the_server(self):
        interrupt.interrupt_main()

    def start_the_debugger(self, gui_adap_oid):
        return RemoteDebugger.start_debugger(self.rpchandler, gui_adap_oid)

    def stop_the_debugger(self, idb_adap_oid):
        "Unregister the Idb Adapter.  Link objects and Idb then subject to GC"
        self.rpchandler.unregister(idb_adap_oid)

    def get_the_calltip(self, name):
        return self.calltip.fetch_tip(name)

    def stackviewer(self, flist_oid=None):
        if not hasattr(sys, "last_traceback"):
            return None
        flist = None
        if flist_oid is not None:
            flist = self.rpchandler.get_remote_proxy(flist_oid)
        tb = sys.last_traceback
        while tb and tb.tb_frame.f_globals["__name__"] in ["rpc", "run"]:
            tb = tb.tb_next
        item = StackViewer.StackTreeItem(flist, tb)
        return RemoteObjectBrowser.remote_object_tree_item(item)
