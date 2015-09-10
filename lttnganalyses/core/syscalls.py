#!/usr/bin/env python3
#
# The MIT License (MIT)
#
# Copyright (C) 2015 - Antoine Busque <abusque@efficios.com>
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

from .analysis import Analysis


class SyscallsAnalysis(Analysis):
    def __init__(self, state):
        notification_cbs = {
            'syscall_exit': self._process_syscall_exit
        }

        self._state = state
        self._state.register_notification_cbs(notification_cbs)
        self.tids = {}
        self.total_syscalls = 0

    def process_event(self, ev):
        pass

    def reset(self):
        for proc_stats in self.tids.values():
            proc_stats.syscalls = {}

    def _process_syscall_exit(self, **kwargs):
        proc = kwargs['proc']
        tid = proc.tid
        current_syscall = proc.current_syscall
        name = current_syscall.name

        if tid not in self.tids:
            self.tids[tid] = ProcessSyscallStats.new_from_process(proc)

        proc_stats = self.tids[tid]
        if name not in proc_stats.syscalls:
            proc_stats.syscalls[name] = SyscallStats(name)

        proc_stats.syscalls[name].update_stats(current_syscall)
        proc_stats.total_syscalls += 1
        self.total_syscalls += 1


class ProcessSyscallStats():
    def __init__(self, pid, tid, comm):
        self.pid = pid
        self.tid = tid
        self.comm = comm
        # indexed by syscall name
        self.syscalls = {}
        self.total_syscalls = 0

    @classmethod
    def new_from_process(cls, proc):
        return cls(proc.pid, proc.tid, proc.comm)


class SyscallStats():
    def __init__(self, name):
        self.name = name
        self.min_duration = None
        self.max_duration = None
        self.total_duration = 0
        self.syscalls_list = []

    @property
    def count(self):
        return len(self.syscalls_list)

    def update_stats(self, syscall):
        duration = syscall.duration

        if self.min_duration is None or self.min_duration > duration:
            self.min_duration = duration
        if self.max_duration is None or self.max_duration < duration:
            self.max_duration = duration

        self.total_duration += duration
        self.syscalls_list.append(syscall)
