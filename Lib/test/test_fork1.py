"""This test checks for correct fork() behavior.

We want fork1() semantics -- only the forking thread survives in the
child after a fork().

On some systems (e.g. Solaris without posix threads) we find that all
active threads survive in the child after a fork(); this is an error.

"""

import os, sys, time, thread

LONGSLEEP = 2

SHORTSLEEP = 0.5

NUM_THREADS = 4

alive = {}

def f(id):
    while 1:
        alive[id] = os.getpid()
        try:
            time.sleep(SHORTSLEEP)
        except IOError:
            pass

def main():
    for i in range(NUM_THREADS):
        thread.start_new(f, (i,))

    time.sleep(LONGSLEEP)

    a = alive.keys()
    a.sort()
    assert a == range(NUM_THREADS)

    prefork_lives = alive.copy()

    cpid = os.fork()

    if cpid == 0:
        # Child
        time.sleep(LONGSLEEP)
        n = 0
        for key in alive.keys():
            if alive[key] != prefork_lives[key]:
                n = n+1
        os._exit(n)
    else:
        # Parent
        spid, status = os.waitpid(cpid, 0)
        assert spid == cpid
        assert status == 0, "cause = %d, exit = %d" % (status&0xff, status>>8)

main()
