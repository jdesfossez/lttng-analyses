#!/usr/bin/env python3
#
# The MIT License (MIT)
#
# Copyright (C) 2015 - Julien Desfossez <jdesfossez@efficios.com>
#               2015 - Antoine Busque <abusque@efficios.com>
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

from .command import Command
from ..core import syscalls

import operator
import statistics
import errno


class SyscallsAnalysis(Command):
    _DESC = """The syscallstats command."""

    def __init__(self):
        super().__init__(self._add_arguments, enable_proc_filter_args=True)

    def _validate_transform_args(self):
        pass

    def run(self):
        self._parse_args()
        self._validate_transform_args()
        self._open_trace()
        self._create_analysis()
        self._run_analysis(self._reset_total, self._refresh)
#        self._print_results(self.start_ns, self.trace_end_ts)
        self._print_iocounts_procname(self.start_ns, self.trace_end_ts)
        self._close_trace()

    def _create_analysis(self):
        self._analysis = syscalls.SyscallsAnalysis(self.state)

    def _refresh(self, begin, end):
        #self._print_results(begin, end)
        self._print_iocounts_procname(self.start_ns, self.trace_end_ts)
        self._reset_total(end)

    def _print_iocounts_procname(self, begin_ns, end_ns):
        """Just the number of I/O syscalls per procname"""
        procnames = {}

        for proc_stats in self._analysis.tids.values():
            if proc_stats.comm not in procnames:
                procnames[proc_stats.comm] = 0
            for syscall in proc_stats.syscalls.values():
                for syscall_event in syscall.syscalls_list:
                    if syscall_event.io_rq is None:
                        continue
                    procnames[proc_stats.comm] += 1

        for p in procnames.keys():
            print("%s,%d" % (p, procnames[p]))

    def _print_results(self, begin_ns, end_ns):
        line_format = '{:<38} {:>14} {:>14} {:>14} {:>12} {:>10}  {:<14}'

        self._print_date(begin_ns, end_ns)
        print('Per-TID syscalls statistics (usec)')

        for proc_stats in sorted(self._analysis.tids.values(),
                                 key=operator.attrgetter('total_syscalls'),
                                 reverse=True):
            if not self._filter_process(proc_stats) or \
               proc_stats.total_syscalls == 0:
                continue

            pid = proc_stats.pid
            if proc_stats.pid is None:
                pid = '?'

            print(line_format.format(
                '%s (%s, tid = %d)' % (proc_stats.comm, pid, proc_stats.tid),
                'Count', 'Min', 'Average', 'Max', 'Stdev', 'Return values'))

            for syscall in sorted(proc_stats.syscalls.values(),
                                  key=operator.attrgetter('count'),
                                  reverse=True):
                durations = []
                return_count = {}

                for syscall_event in syscall.syscalls_list:
                    durations.append(syscall_event.duration)

                    if syscall_event.ret >= 0:
                        return_key = 'success'
                    else:
                        try:
                            return_key = errno.errorcode[-syscall_event.ret]
                        except KeyError:
                            return_key = str(syscall_event.ret)

                    if return_key not in return_count:
                        return_count[return_key] = 1

                    return_count[return_key] += 1

                min_duration = round(syscall.min_duration / 1000, 3)
                max_duration = round(syscall.max_duration / 1000, 3)
                avg_duration = round(
                    syscall.total_duration / syscall.count / 1000, 3)

                if len(durations) > 2:
                    stdev = round(statistics.stdev(durations) / 1000, 3)
                else:
                    stdev = '?'

                name = syscall.name
                print(line_format.format(
                    ' - ' + name, syscall.count, min_duration, avg_duration,
                    max_duration, stdev, str(return_count)))

            print(line_format.format('Total:', proc_stats.total_syscalls,
                                     '', '', '', '', ''))
            print('-' * 113)

        print('\nTotal syscalls: %d' % (self._analysis.total_syscalls))

    def _reset_total(self, start_ts):
        self._analysis.reset()

    def _add_arguments(self, ap):
        pass


def run():
    syscallscmd = SyscallsAnalysis()
    syscallscmd.run()
