#!/usr/bin/env python3

from TraceTest import AnalyzesTest
import sys


class CpuTest(AnalyzesTest):
    def __init__(self, delete_trace=True, verbose=False):
        super().__init__(delete_trace=delete_trace,
                         verbose=verbose)
        self.test_list = [('cputop', self.run_no_option)]

    def write_trace(self):
        # runs the whole time: 100%
        self.t.write_sched_switch(1000, 5, "swapper/5", 0, "prog100pc-cpu5", 42)
        # runs for 2s alternating with swapper out every 100ms
        self.t.sched_switch_50pc(1100, 5000, 0, 100,
                                 "swapper/0", 0, "prog20pc-cpu0", 30664)
        # runs for 2.5s alternating with swapper out every 100ms
        self.t.sched_switch_50pc(5100, 10000, 1, 100,
                                 "swapper/1", 0, "prog25pc-cpu1", 30665)
        # switch out prog100pc-cpu5
        self.t.write_sched_switch(11000, 5, "prog100pc-cpu5", 42, "swapper/5", 0)
        self.t.flush()

    def run_no_option(self):
        expected = """Timerange: [1969-12-31 19:00:01.000000000, 1969-12-31 19:00:11.000000000]
Per-TID CPU Usage
###############################################################################
██████████████████████████████████████████████████  100.00 %  prog100pc-cpu5 (42) (prio: 20)
████████████                                        25.00 %  prog25pc-cpu1 (30665) (prio: 20)
██████████                                          20.00 %  prog20pc-cpu0 (30664) (prio: 20)
Per-CPU Usage
###############################################################################
█████████████                                                      20.00 %  CPU 0
████████████████                                                   25.00 %  CPU 1
█████████████████████████████████████████████████████████████████  100.00 %  CPU 5

Total CPU Usage: 48.33%
"""

        return self.compare_output('%slttng-cputop %s "%s"' % (
                       self.cmd_root, self.common_options, self.t.get_trace_root()),
                       expected)


def test_answer():
    t = CpuTest(verbose=True)
    ok = t.run()
    assert(ok)
