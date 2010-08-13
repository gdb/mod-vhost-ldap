#
# Module providing the `Pool` class for managing a process pool
#
# multiprocessing/pool.py
#
# Copyright (c) 2007-2008, R Oudkerk --- see COPYING.txt
#

__all__ = ['Pool']

#
# Imports
#

import threading
import Queue
import itertools
import collections
import os
import sys
import time

from multiprocessing import Process, cpu_count, TimeoutError
from multiprocessing.util import Finalize, debug

#
# Constants representing the state of a pool
#

RUN = 0
CLOSE = 1
TERMINATE = 2

ACK = 'ACK'
NACK = 'NACK'

#
# Miscellaneous
#

job_counter = itertools.count()

def mapstar(args):
    return map(*args)

#
# Code run by worker processes
#

def worker(inqueue, outqueue, report_task, get_ack, initializer=None, initargs=(), maxtasks=None, pid=None):
    # Worker protocol:
    # - Task handler puts task into outqueue
    # - Worker removes task from queue, puts report into report_task_queue
    # - Task handler reads pending reports and ACKs the first worker to claim
    #   the current task, NACKing all other worker claims.
    #   - If the task handler waits a second without receiving any reports,
    #     it reschedules the current task.
    # - Once the worker receives an ACK, it proceeds.  If it receives a NACK
    #   it drops the task it's holding and begins the cycle anew.
    #
    # If the worker exits with a nonzero exit status, then all tasks
    # currently assigned to the worker are treated as if they had run
    # a RuntimeError.
    #
    # This protocol ensures that each task is begun exactly once, and
    # only after the task handler has recorded which worker has the
    # task.
    assert maxtasks is None or (type(maxtasks) == int and maxtasks > 0)
    put = outqueue.put
    get = inqueue.get
    if hasattr(inqueue, '_writer'):
        inqueue._writer.close()
        outqueue._reader.close()

    if initializer is not None:
        initializer(*initargs)
    if pid is None:
        pid = os.getpid()

    completed = 0
    while maxtasks is None or (maxtasks and completed < maxtasks):
        try:
            task = get()
        except (EOFError, IOError):
            debug('worker got EOFError or IOError -- exiting')
            sys.exit(1)

        if task is None:
            debug('worker got sentinel -- exiting')
            break

        job, i, func, args, kwds = task
        report_task((pid, job, i))
        try:
            acked_job, acked_i, response = get_ack()
        except Exception, e:
            debug('could not retrieve ACK from parent -- %s' % e)
            sys.exit(1)

        assert job == acked_job
        assert i == acked_i

        if response == NACK:
            continue

        assert response == ACK
        try:
            result = (True, func(*args, **kwds))
        except Exception, e:
            result = (False, e)
        put((pid, job, i, result))
        completed += 1
    debug('worker exiting after %d tasks' % completed)


class LockableDict(dict):
    '''
    A dictionary class with its own lock.
    '''
    def __init__(self):
        self.lock = threading.Lock()

#
# Class representing a process pool
#

class Pool(object):
    '''
    Class which supports an async version of the `apply()` builtin
    '''
    Process = Process

    def __init__(self, processes=None, initializer=None, initargs=(),
                 maxtasksperchild=None):
        self._setup_queues()
        self._taskqueue = Queue.Queue()
        self._cache = {}
        self._state = RUN
        self._maxtasksperchild = maxtasksperchild
        self._initializer = initializer
        self._initargs = initargs

        if processes is None:
            try:
                processes = cpu_count()
            except NotImplementedError:
                processes = 1

        if initializer is not None and not hasattr(initializer, '__call__'):
            raise TypeError('initializer must be a callable')

        self._putmsg_by_pid = LockableDict()
        self._task_assignments = LockableDict()

        self._report_task_queue = self._queue_factory()

        self._processes = processes
        self._pool = []
        self._repopulate_pool()

        self._worker_handler = threading.Thread(
            target=Pool._handle_workers,
            args=(self, )
            )
        self._worker_handler.daemon = True
        self._worker_handler._state = RUN
        self._worker_handler.start()

        def get_reported_tasks(target_job, target_i):
            """Page through the queue of reported tasks until one with
            the desired job and i value are found."""
            reported_tasks = []
            while self._report_task_queue._reader.poll(1):
                report = self._report_task_queue.get()
                reported_tasks.append(report)
                pid, job, i = report
                if job == target_job and i == target_i:
                   break
            return reported_tasks

        self._task_handler = threading.Thread(
            target=Pool._handle_tasks,
            args=(self._taskqueue, self._quick_put, self._outqueue, self._pool,
                  get_reported_tasks, self._putmsg_by_pid, self._task_assignments)
            )
        self._task_handler.daemon = True
        self._task_handler._state = RUN
        self._task_handler.start()

        self._result_handler = threading.Thread(
            target=Pool._handle_results,
            args=(self._outqueue, self._quick_get, self._cache, self._task_assignments)
            )
        self._result_handler.daemon = True
        self._result_handler._state = RUN
        self._result_handler.start()

        self._terminate = Finalize(
            self, self._terminate_pool,
            args=(self._taskqueue, self._inqueue, self._outqueue, self._pool,
                  self._worker_handler, self._task_handler,
                  self._result_handler, self._cache),
            exitpriority=15
            )

    def _join_exited_workers(self):
        """Cleanup after any worker processes which have exited due to reaching
        their specified lifetime.  Returns True if any workers were cleaned up.
        """
        cleaned = False
        for i in reversed(range(len(self._pool))):
            worker = self._pool[i]
            if worker.exitcode is not None:
                # worker exited
                debug('cleaning up worker %d' % i)
                worker.join()
                cleaned = True
                del self._pool[i]
                with self._putmsg_by_pid.lock:
                    del self._putmsg_by_pid[worker.pid]
                if not worker.exitcode:
                    continue

                if worker.exitcode > 0:
                    msg = 'worker %d exited with code %d' % \
                        (worker.pid, worker.exitcode)
                else:
                    msg = 'worker %d killed with signal %d' % \
                        (worker.pid, -worker.exitcode)
                with self._task_assignments.lock:
                    # If it has no assigned task, then there's nothing to worry about.
                    tasks = self._task_assignments.get(worker.pid)
                    for (job, i) in tasks:
                        debug("inserting error as result for worker %s's work on job %s, index %s" %
                              (worker.pid, job, i))
                        result = (False, RuntimeError(msg))
                        self._outqueue.put((worker.pid, job, i, result))
        return cleaned

    def _repopulate_pool(self):
        """Bring the number of pool processes up to the specified number,
        for use after reaping workers which have exited.
        """
        for i in range(self._processes - len(self._pool)):
            q = self._queue_factory()
            w = self.Process(target=worker,
                             args=(self._inqueue, self._outqueue,
                                   self._report_task_queue.put, q.get,
                                   self._initializer,
                                   self._initargs, self._maxtasksperchild)
                            )
            self._pool.append(w)
            w.name = w.name.replace('Process', 'PoolWorker')
            w.daemon = True
            # We don't know the pid before starting w, but once we
            # start w another thread might have to look it up in
            # self._putmsg_by_pid.  So we take out its lock.
            with self._putmsg_by_pid.lock:
                w.start()
                assert w.pid not in self._putmsg_by_pid
                self._putmsg_by_pid[w.pid] = q.put
            debug('added worker')

    def _maintain_pool(self):
        """Clean up any exited workers and start replacements for them.
        """
        if self._join_exited_workers():
            self._repopulate_pool()

    def _setup_queues(self):
        from .queues import SimpleQueue
        self._inqueue = SimpleQueue()
        self._outqueue = SimpleQueue()
        self._quick_put = self._inqueue._writer.send
        self._quick_get = self._outqueue._reader.recv
        self._queue_factory = SimpleQueue

    def apply(self, func, args=(), kwds={}):
        '''
        Equivalent of `apply()` builtin
        '''
        assert self._state == RUN
        return self.apply_async(func, args, kwds).get()

    def map(self, func, iterable, chunksize=None):
        '''
        Equivalent of `map()` builtin
        '''
        assert self._state == RUN
        return self.map_async(func, iterable, chunksize).get()

    def imap(self, func, iterable, chunksize=1):
        '''
        Equivalent of `itertools.imap()` -- can be MUCH slower than `Pool.map()`
        '''
        assert self._state == RUN
        if chunksize == 1:
            result = IMapIterator(self._cache)
            self._taskqueue.put((((result._job, i, func, (x,), {})
                         for i, x in enumerate(iterable)), result._set_length))
            return result
        else:
            assert chunksize > 1
            task_batches = Pool._get_tasks(func, iterable, chunksize)
            result = IMapIterator(self._cache)
            self._taskqueue.put((((result._job, i, mapstar, (x,), {})
                     for i, x in enumerate(task_batches)), result._set_length))
            return (item for chunk in result for item in chunk)

    def imap_unordered(self, func, iterable, chunksize=1):
        '''
        Like `imap()` method but ordering of results is arbitrary
        '''
        assert self._state == RUN
        if chunksize == 1:
            result = IMapUnorderedIterator(self._cache)
            self._taskqueue.put((((result._job, i, func, (x,), {})
                         for i, x in enumerate(iterable)), result._set_length))
            return result
        else:
            assert chunksize > 1
            task_batches = Pool._get_tasks(func, iterable, chunksize)
            result = IMapUnorderedIterator(self._cache)
            self._taskqueue.put((((result._job, i, mapstar, (x,), {})
                     for i, x in enumerate(task_batches)), result._set_length))
            return (item for chunk in result for item in chunk)

    def apply_async(self, func, args=(), kwds={}, callback=None):
        '''
        Asynchronous equivalent of `apply()` builtin
        '''
        assert self._state == RUN
        result = ApplyResult(self._cache, callback)
        self._taskqueue.put(([(result._job, None, func, args, kwds)], None))
        return result

    def map_async(self, func, iterable, chunksize=None, callback=None):
        '''
        Asynchronous equivalent of `map()` builtin
        '''
        assert self._state == RUN
        if not hasattr(iterable, '__len__'):
            iterable = list(iterable)

        if chunksize is None:
            chunksize, extra = divmod(len(iterable), len(self._pool) * 4)
            if extra:
                chunksize += 1
        if len(iterable) == 0:
            chunksize = 0

        task_batches = Pool._get_tasks(func, iterable, chunksize)
        result = MapResult(self._cache, chunksize, len(iterable), callback)
        self._taskqueue.put((((result._job, i, mapstar, (x,), {})
                              for i, x in enumerate(task_batches)), None))
        return result

    @staticmethod
    def _handle_workers(pool):
        while pool._worker_handler._state == RUN and pool._state == RUN:
            pool._maintain_pool()
            time.sleep(0.1)
        debug('worker handler exiting')

    @staticmethod
    def _send_task(put, get_reported_tasks, putmsg_by_pid, task_assignments, task):
        thread = threading.current_thread()
        while True:
            if thread._state:
                debug('task handler found thread._state != RUN')
                return False

            try:
                put(task)
            except IOError:
                debug('could not put task on queue')
                return False

            if task is None:
                return False

            job, i, func, args, kwds = task
            assigned = False

            try:
                for pid, acked_job, acked_i in get_reported_tasks(job, i):
                    # Hold the putmsg_by_pid lock throughout to body
                    # of the loop, just in case the worker dies while
                    # we are in the middle.
                    with putmsg_by_pid.lock:
                        try:
                            putmsg = putmsg_by_pid[pid]
                        except KeyError:
                            # If pid not in putmsg_by_pid, then the worker
                            # with the given pid has died.  Move along.
                            debug("Couldn't find putmsg method for worker with pid %d" % pid)
                            continue

                        if job == acked_job and i == acked_i and not assigned:
                            msg = ACK
                        else:
                            msg = NACK

                        with task_assignments.lock:
                            try:
                                putmsg((acked_job, acked_i, msg))
                            except IOError:
                                # Couldn't send an ACK?  That's fine.
                                debug("Couldn't send method for worker with pid %d" % pid)
                                continue
                            else:
                                if msg == ACK:
                                    assigned = True
                                    task_assignments.setdefault(pid, set()).add((acked_job, acked_i))
            except Exception, e:
                debug('could not retrieve ack from queue: %s' % e)
                return False
            else:
                if assigned:
                    return True
                else:
                    continue

    @staticmethod
    def _handle_tasks(taskqueue, put, outqueue, pool, get_reported_tasks, putmsg_by_pid, task_assignments):
        for taskseq, set_length in iter(taskqueue.get, None):
            i = -1
            for i, task in enumerate(taskseq):
                if not Pool._send_task(put, get_reported_tasks, putmsg_by_pid, task_assignments, task):
                    break
            else:
                if set_length:
                    debug('doing set_length()')
                    set_length(i+1)
                continue
            break
        else:
            debug('task handler got sentinel')


        try:
            # tell result handler to finish when cache is empty
            debug('task handler sending sentinel to result handler')
            outqueue.put(None)

            # tell workers there is no more work
            debug('task handler sending sentinel to workers')
            for p in pool:
                put(None)
        except IOError:
            debug('task handler got IOError when sending sentinels')

        debug('task handler exiting')

    @staticmethod
    def _handle_results(outqueue, get, cache, task_assignments):
        thread = threading.current_thread()

        while 1:
            try:
                task = get()
            except (IOError, EOFError):
                debug('result handler got EOFError/IOError -- exiting')
                return

            if thread._state:
                assert thread._state == TERMINATE
                debug('result handler found thread._state=TERMINATE')
                break

            if task is None:
                debug('result handler got sentinel')
                break

            pid, job, i, obj = task
            with task_assignments.lock:
                # If the process died right after trying to send a
                # result, the worker handler may have inserted a
                # result for it, yielding 2 results for the same task.
                try:
                    assignments = task_assignments[pid]
                    assignments.remove((job, i))
                except KeyError:
                    continue
                if not assignments:
                    del task_assignments[pid]

            try:
                cache[job]._set(i, obj)
            except KeyError:
                pass

        while cache and thread._state != TERMINATE:
            try:
                task = get()
            except (IOError, EOFError):
                debug('result handler got EOFError/IOError -- exiting')
                return

            if task is None:
                debug('result handler ignoring extra sentinel')
                continue

            pid, job, i, obj = task
            with task_assignments.lock:
                assignments = task_assignments[pid]
                try:
                    assignments.remove((job, i))
                except KeyError:
                    continue
                if not assignments:
                    del task_assignments[pid]

            try:
                cache[job]._set(i, obj)
            except KeyError:
                pass

        if hasattr(outqueue, '_reader'):
            debug('ensuring that outqueue is not full')
            # If we don't make room available in outqueue then
            # attempts to add the sentinel (None) to outqueue may
            # block.  There is guaranteed to be no more than 2 sentinels.
            try:
                for i in range(10):
                    if not outqueue._reader.poll():
                        break
                    get()
            except (IOError, EOFError):
                pass

        debug('result handler exiting: len(cache)=%s, thread._state=%s',
              len(cache), thread._state)

    @staticmethod
    def _get_tasks(func, it, size):
        it = iter(it)
        while 1:
            x = tuple(itertools.islice(it, size))
            if not x:
                return
            yield (func, x)

    def __reduce__(self):
        raise NotImplementedError(
              'pool objects cannot be passed between processes or pickled'
              )

    def close(self):
        debug('closing pool')
        if self._state == RUN:
            self._state = CLOSE
            self._worker_handler._state = CLOSE
            self._taskqueue.put(None)

    def terminate(self):
        debug('terminating pool')
        self._state = TERMINATE
        self._worker_handler._state = TERMINATE
        self._terminate()

    def join(self):
        debug('joining pool')
        assert self._state in (CLOSE, TERMINATE)
        self._worker_handler.join()
        self._task_handler.join()
        self._result_handler.join()
        for p in self._pool:
            p.join()

    @staticmethod
    def _help_stuff_finish(inqueue, task_handler, size):
        # task_handler may be blocked trying to put items on inqueue
        debug('removing tasks from inqueue until task handler finished')
        inqueue._rlock.acquire()
        while task_handler.is_alive() and inqueue._reader.poll():
            inqueue._reader.recv()
            time.sleep(0)

    @classmethod
    def _terminate_pool(cls, taskqueue, inqueue, outqueue, pool,
                        worker_handler, task_handler, result_handler, cache):
        # this is guaranteed to only be called once
        debug('finalizing pool')

        worker_handler._state = TERMINATE
        task_handler._state = TERMINATE
        taskqueue.put(None)                 # sentinel

        debug('helping task handler/workers to finish')
        cls._help_stuff_finish(inqueue, task_handler, len(pool))

        assert result_handler.is_alive() or len(cache) == 0

        result_handler._state = TERMINATE
        outqueue.put(None)                  # sentinel

        # Terminate workers which haven't already finished.
        if pool and hasattr(pool[0], 'terminate'):
            debug('terminating workers')
            for p in pool:
                if p.exitcode is None:
                    p.terminate()

        debug('joining task handler')
        task_handler.join(1e100)

        debug('joining result handler')
        result_handler.join(1e100)

        if pool and hasattr(pool[0], 'terminate'):
            debug('joining pool workers')
            for p in pool:
                if p.is_alive():
                    # worker has not yet exited
                    debug('cleaning up worker %d' % p.pid)
                    p.join()

#
# Class whose instances are returned by `Pool.apply_async()`
#

class ApplyResult(object):

    def __init__(self, cache, callback):
        self._cond = threading.Condition(threading.Lock())
        self._job = job_counter.next()
        self._cache = cache
        self._ready = False
        self._callback = callback
        cache[self._job] = self

    def ready(self):
        return self._ready

    def successful(self):
        assert self._ready
        return self._success

    def wait(self, timeout=None):
        self._cond.acquire()
        try:
            if not self._ready:
                self._cond.wait(timeout)
        finally:
            self._cond.release()

    def get(self, timeout=None):
        self.wait(timeout)
        if not self._ready:
            raise TimeoutError
        if self._success:
            return self._value
        else:
            raise self._value

    def _set(self, i, obj):
        self._success, self._value = obj
        if self._callback and self._success:
            self._callback(self._value)
        self._cond.acquire()
        try:
            self._ready = True
            self._cond.notify()
        finally:
            self._cond.release()
        del self._cache[self._job]

#
# Class whose instances are returned by `Pool.map_async()`
#

class MapResult(ApplyResult):

    def __init__(self, cache, chunksize, length, callback):
        ApplyResult.__init__(self, cache, callback)
        self._success = True
        self._value = [None] * length
        self._chunksize = chunksize
        if chunksize <= 0:
            self._number_left = 0
            self._ready = True
        else:
            self._number_left = length//chunksize + bool(length % chunksize)

    def _set(self, i, success_result):
        success, result = success_result
        if success:
            self._value[i*self._chunksize:(i+1)*self._chunksize] = result
            self._number_left -= 1
            if self._number_left == 0:
                if self._callback:
                    self._callback(self._value)
                del self._cache[self._job]
                self._cond.acquire()
                try:
                    self._ready = True
                    self._cond.notify()
                finally:
                    self._cond.release()

        else:
            self._success = False
            self._value = result
            del self._cache[self._job]
            self._cond.acquire()
            try:
                self._ready = True
                self._cond.notify()
            finally:
                self._cond.release()

#
# Class whose instances are returned by `Pool.imap()`
#

class IMapIterator(object):

    def __init__(self, cache):
        self._cond = threading.Condition(threading.Lock())
        self._job = job_counter.next()
        self._cache = cache
        self._items = collections.deque()
        self._index = 0
        self._length = None
        self._unsorted = {}
        cache[self._job] = self

    def __iter__(self):
        return self

    def next(self, timeout=None):
        self._cond.acquire()
        try:
            try:
                item = self._items.popleft()
            except IndexError:
                if self._index == self._length:
                    raise StopIteration
                self._cond.wait(timeout)
                try:
                    item = self._items.popleft()
                except IndexError:
                    if self._index == self._length:
                        raise StopIteration
                    raise TimeoutError
        finally:
            self._cond.release()

        success, value = item
        if success:
            return value
        raise value

    __next__ = next                    # XXX

    def _set(self, i, obj):
        self._cond.acquire()
        try:
            if self._index == i:
                self._items.append(obj)
                self._index += 1
                while self._index in self._unsorted:
                    obj = self._unsorted.pop(self._index)
                    self._items.append(obj)
                    self._index += 1
                self._cond.notify()
            else:
                self._unsorted[i] = obj

            if self._index == self._length:
                del self._cache[self._job]
        finally:
            self._cond.release()

    def _set_length(self, length):
        self._cond.acquire()
        try:
            self._length = length
            if self._index == self._length:
                self._cond.notify()
                del self._cache[self._job]
        finally:
            self._cond.release()

#
# Class whose instances are returned by `Pool.imap_unordered()`
#

class IMapUnorderedIterator(IMapIterator):

    def _set(self, i, obj):
        self._cond.acquire()
        try:
            self._items.append(obj)
            self._index += 1
            self._cond.notify()
            if self._index == self._length:
                del self._cache[self._job]
        finally:
            self._cond.release()

#
#
#

class ThreadPool(Pool):

    from .dummy import Process

    def __init__(self, processes=None, initializer=None, initargs=()):
        raise NotImplementedError('Have not yet added support for threaded pool')
        Pool.__init__(self, processes, initializer, initargs)

    def _setup_queues(self):
        self._inqueue = Queue.Queue()
        self._outqueue = Queue.Queue()
        self._quick_put = self._inqueue.put
        self._quick_get = self._outqueue.get

    @staticmethod
    def _help_stuff_finish(inqueue, task_handler, size):
        # put sentinels at head of inqueue to make workers finish
        inqueue.not_empty.acquire()
        try:
            inqueue.queue.clear()
            inqueue.queue.extend([None] * size)
            inqueue.not_empty.notify_all()
        finally:
            inqueue.not_empty.release()
