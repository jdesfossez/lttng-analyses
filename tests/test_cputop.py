#!/usr/bin/env python3

from TestTrace import TestTrace
import subprocess
import sys

t = TestTrace()

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

# runs the whole time: 100%
t.write_sched_switch(1000, 5, "swapper/5", 0, "prog100pc-cpu5", 42)
# runs for 2s alternating with swapper out every 100ms
t.sched_switch_50pc(1100, 5000, 0, 100,
                    "swapper/0", 0, "prog20pc-cpu0", 30664)
# runs for 2.5s alternating with swapper out every 100ms
t.sched_switch_50pc(5100, 10000, 1, 100,
                    "swapper/1", 0, "prog25pc-cpu1", 30665)
# switch out prog100pc-cpu5
t.write_sched_switch(11000, 5, "prog100pc-cpu5", 42, "swapper/5", 0)

t.flush()

result = subprocess.getoutput('./lttng-cputop --no-progress --skip-validation "%s"' % t.get_trace_root())

ok = t.compare_output(expected, result)
t.delete_trace()

if not ok:
    sys.exit(1)
sys.exit(0)
