#!/usr/bin/env python3

from TraceTest import AnalyzesTest
import sys


class IrqTest(AnalyzesTest):
    def __init__(self, delete_trace=True, verbose=False):
        super().__init__(delete_trace=delete_trace,
                         verbose=verbose)
        self.test_list = [('irqstats', self.run_irqstats),
                          ('irqlog', self.run_irqlog)]

    def write_trace(self):
        self.t.write_softirq_raise(1000 , 1, 1)
        self.t.write_softirq_raise(1001 , 3, 1)
        self.t.write_softirq_raise(1002 , 1, 9)
        self.t.write_softirq_exit(1003 , 0, 4)
        self.t.write_softirq_raise(1004 , 3, 9)
        self.t.write_softirq_raise(1005 , 3, 7)
        self.t.write_softirq_entry(1006 , 3, 1)
        self.t.write_softirq_entry(1007 , 1, 1)
        self.t.write_softirq_exit(1008 , 1, 1)
        self.t.write_softirq_exit(1009 , 3, 1)
        self.t.write_softirq_entry(1010 , 1, 9)
        self.t.write_softirq_entry(1011 , 3, 7)
        self.t.write_softirq_exit(1012 , 1, 9)
        self.t.write_softirq_exit(1013 , 3, 7)
        self.t.write_softirq_entry(1014 , 3, 9)
        self.t.write_softirq_exit(1015 , 3, 9)
        self.t.write_irq_handler_entry(1016 , 0, 41, "ahci")
        self.t.write_softirq_raise(1017 , 0, 4)
        self.t.write_irq_handler_exit(1018 , 0, 41, 1)
        self.t.write_softirq_entry(1019 , 0, 4)
        self.t.write_softirq_exit(1020 , 0, 4)
        self.t.write_irq_handler_entry(1021 , 0, 41, "ahci")
        self.t.write_softirq_raise(1022 , 0, 4)
        self.t.write_irq_handler_exit(1023 , 0, 41, 1)
        self.t.write_softirq_entry(1024 , 0, 4)
        self.t.write_softirq_exit(1025 , 0, 4)
        self.t.write_irq_handler_entry(1026 , 0, 41, "ahci")
        self.t.write_softirq_raise(1027 , 0, 4)
        self.t.write_irq_handler_exit(1028 , 0, 41, 1)
        self.t.write_softirq_entry(1029 , 0, 4)
        self.t.write_softirq_exit(1030 , 0, 4)
        self.t.write_irq_handler_entry(1031 , 0, 41, "ahci")
        self.t.write_softirq_raise(1032 , 0, 4)
        self.t.write_irq_handler_exit(1033 , 0, 41, 1)
        self.t.write_softirq_entry(1034 , 0, 4)
        self.t.write_softirq_exit(1035 , 0, 4)
        self.t.write_irq_handler_entry(1036 , 0, 41, "ahci")
        self.t.write_softirq_raise(1037 , 0, 4)
        self.t.write_irq_handler_exit(1038 , 0, 41, 1)
        self.t.write_softirq_entry(1039 , 0, 4)
        self.t.write_softirq_exit(1040 , 0, 4)
        self.t.write_irq_handler_entry(1041 , 0, 41, "ahci")
        self.t.write_softirq_raise(1042 , 0, 4)
        self.t.write_irq_handler_exit(1043 , 0, 41, 1)
        self.t.write_softirq_entry(1044 , 0, 4)
        self.t.write_softirq_exit(1045 , 0, 4)
        self.t.flush()

    def run_irqstats(self):
        expected = """Timerange: [1969-12-31 19:00:01.000000000, 1969-12-31 19:00:01.045000000]
Hard IRQ                                             Duration (us)
                       count          min          avg          max        stdev       
----------------------------------------------------------------------------------|
41: <ahci>                 6     2000.000     2000.000     2000.000        0.000  |

Soft IRQ                                             Duration (us)                                        Raise latency (us)
                       count          min          avg          max        stdev  |  count          min          avg          max        stdev       
----------------------------------------------------------------------------------|------------------------------------------------------------
1:  <TIMER_SOFTIRQ>        2     1000.000     2000.000     3000.000     1414.214  |      2     5000.000     6000.000     7000.000     1414.214
4:  <BLOCK_SOFTIRQ>        6     1000.000     1000.000     1000.000        0.000  |      6     2000.000     2000.000     2000.000        0.000
7:  <SCHED_SOFTIRQ>        1     2000.000     2000.000     2000.000            ?  |      1     6000.000     6000.000     6000.000            ?
9:  <RCU_SOFTIRQ>          2     1000.000     1500.000     2000.000      707.107  |      2     8000.000     9000.000    10000.000     1414.214"""

        return self.compare_output('%slttng-irqstats %s "%s"' % (
                       self.cmd_root, self.common_options, self.t.get_trace_root()),
                       expected)

    def run_irqlog(self):
        expected = """Timerange: [1969-12-31 19:00:01.000000000, 1969-12-31 19:00:01.045000000]
Begin                End                   Duration (us)  CPU  Type         #  Name                  
[19:00:01.007000000, 19:00:01.008000000]        1000.000    1  SoftIRQ      1  TIMER_SOFTIRQ (raised at 19:00:01.000000000)
[19:00:01.006000000, 19:00:01.009000000]        3000.000    3  SoftIRQ      1  TIMER_SOFTIRQ (raised at 19:00:01.001000000)
[19:00:01.010000000, 19:00:01.012000000]        2000.000    1  SoftIRQ      9  RCU_SOFTIRQ (raised at 19:00:01.002000000)
[19:00:01.011000000, 19:00:01.013000000]        2000.000    3  SoftIRQ      7  SCHED_SOFTIRQ (raised at 19:00:01.005000000)
[19:00:01.014000000, 19:00:01.015000000]        1000.000    3  SoftIRQ      9  RCU_SOFTIRQ (raised at 19:00:01.004000000)
[19:00:01.016000000, 19:00:01.018000000]        2000.000    0  IRQ         41  ahci                  
[19:00:01.019000000, 19:00:01.020000000]        1000.000    0  SoftIRQ      4  BLOCK_SOFTIRQ (raised at 19:00:01.017000000)
[19:00:01.021000000, 19:00:01.023000000]        2000.000    0  IRQ         41  ahci                  
[19:00:01.024000000, 19:00:01.025000000]        1000.000    0  SoftIRQ      4  BLOCK_SOFTIRQ (raised at 19:00:01.022000000)
[19:00:01.026000000, 19:00:01.028000000]        2000.000    0  IRQ         41  ahci                  
[19:00:01.029000000, 19:00:01.030000000]        1000.000    0  SoftIRQ      4  BLOCK_SOFTIRQ (raised at 19:00:01.027000000)
[19:00:01.031000000, 19:00:01.033000000]        2000.000    0  IRQ         41  ahci                  
[19:00:01.034000000, 19:00:01.035000000]        1000.000    0  SoftIRQ      4  BLOCK_SOFTIRQ (raised at 19:00:01.032000000)
[19:00:01.036000000, 19:00:01.038000000]        2000.000    0  IRQ         41  ahci                  
[19:00:01.039000000, 19:00:01.040000000]        1000.000    0  SoftIRQ      4  BLOCK_SOFTIRQ (raised at 19:00:01.037000000)
[19:00:01.041000000, 19:00:01.043000000]        2000.000    0  IRQ         41  ahci                  
[19:00:01.044000000, 19:00:01.045000000]        1000.000    0  SoftIRQ      4  BLOCK_SOFTIRQ (raised at 19:00:01.042000000)"""

        return self.compare_output('%slttng-irqlog %s "%s"' % (
                       self.cmd_root, self.common_options, self.t.get_trace_root()),
                       expected)


def test_answer():
    t = IrqTest(verbose=True)
    ok = t.run()
    assert(ok)
