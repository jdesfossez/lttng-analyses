#!/usr/bin/env python3

from TraceTest import AnalyzesTest
import sys


class IoTest(AnalyzesTest):
    def __init__(self, delete_trace=False, verbose=False):
        super().__init__(delete_trace=delete_trace,
                         verbose=verbose)
        self.test_list = [('iousagetop', self.run_iousagetop),
                          ('iolatencytop', self.run_iolatencytop)]

    def write_trace(self):
        # app (99) is known at statedump
        self.t.write_lttng_statedump_process_state(1000, 0, 99, 99, 99, 99, 98,
                                                   98, "app", 0, 5, 0, 5, 0)
        # app2 (100) unknown at statedump has testfile, FD 3 defined at
        # statedump
        self.t.write_lttng_statedump_file_descriptor(1001, 0, 100, 3, 0, 0,
                                                     "testfile")
        # app write 10 bytes to FD 4
        self.t.write_sched_switch(1002, 0, "swapper/0", 0, "app", 99)
        self.t.write_syscall_write(1004, 0, 1, 4, 0xabcd, 10, 10)
        # app2 reads 100 bytes in FD 3
        self.t.write_sched_switch(1006, 0, "app", 99, "app2", 100)
        self.t.write_syscall_read(1008, 0, 1, 3, 0xcafe, 100, 100)
        # app3 and its FD 3 are completely unknown at statedump, tries to read 100
        # bytes from FD 3 but only gets 42
        self.t.write_sched_switch(1010, 0, "app2", 100, "app3", 101)
        self.t.write_syscall_read(1012, 0, 1, 3, 0xcafe, 100, 42)
        # block write
        self.t.write_block_rq_issue(1015, 0, 264241152, 33, 10, 40, 99, 0, 0, "", "app")
        self.t.write_block_rq_complete(1016, 0, 264241152, 33, 10, 0, 0, 0, "")
        # block read
        # FIXME: does not look right
        self.t.write_block_rq_issue(1017, 0, 8388608, 33, 11, 90, 101, 1, 0, "", "app3")
        self.t.write_block_rq_complete(1018, 0, 8388608, 33, 11, 0, 1, 0, "")
        # net xmit
        # FIXME: does not look right
        self.t.write_net_dev_xmit(1020, 2, 0xff, 32, 0, "wlan0")
        # net receive
        self.t.write_netif_receive_skb(1021, 1, 0xff, 100, "wlan1")
        self.t.write_netif_receive_skb(1022, 1, 0xff, 200, "wlan0")
        # syscall open
        self.t.write_syscall_open(1023, 0, 1, "test/open/file", 0, 0, 42)
        self.t.flush()

    def run_iousagetop(self):
        expected = """Timerange: [1969-12-31 19:00:01.000000000, 1969-12-31 19:00:01.022000000]
Per-process I/O Read
###############################################################################
██████████████████████████████████████████████████   100.00 B   (100)                         0 B  file      0 B  net 100.00 B  unknown
█████████████████████                                 42.00 B  app3 (unknown (tid=101))       0 B  file      0 B  net  42.00 B  unknown
                                                          0 B  app (99)                       0 B  file      0 B  net      0 B  unknown
Per-process I/O Write
###############################################################################
██████████████████████████████████████████████████    10.00 B  app (99)                       0 B  file      0 B  net  10.00 B  unknown
                                                          0 B   (100)                         0 B  file      0 B  net      0 B  unknown
                                                          0 B  app3 (unknown (tid=101))       0 B  file      0 B  net      0 B  unknown
Files read
###############################################################################
██████████████████████████████████████████████████   100.00 B  testfile fd 3 in  (100) 
█████████████████████                                 42.00 B  unknown(app3) fd 3 in app3 (101) 
Files write
###############################################################################
██████████████████████████████████████████████████    10.00 B  unknown(app) fd 4 in app (99) 
Block I/O Read
###############################################################################
██████████████████████████████████████████████████     5.00 KB app (pid=99)          
Block I/O Write
###############################################################################
██████████████████████████████████████████████████     5.00 KB app (pid=99)          
Disk requests sector count
###############################################################################
██████████████████████████████████████████████████████████████████  11.00 sectors  (8,0)  
████████████████████████████████████████████████████████████        10.00 sectors  (252,0)
Disk request count
###############################################################################
███████████████████████████████████████████████████████████████████  1.00 requests  (252,0)
███████████████████████████████████████████████████████████████████  1.00 requests  (8,0)  
Disk request average latency
###############################################################################
█████████████████████████████████████████████████████████████████  1.00 ms  (252,0)
█████████████████████████████████████████████████████████████████  1.00 ms  (8,0)  
Network received bytes
###############################################################################
██████████████████████████████████████████████████████████  200.00 B wlan0
█████████████████████████████                               100.00 B wlan1
Network sent bytes
###############################################################################
                                                                   0 B wlan0
                                                                   0 B wlan1"""

        return self.compare_output('%slttng-iousagetop %s "%s"' % (
                       self.cmd_root, self.common_options, self.t.get_trace_root()),
                       expected)

    def run_iolatencytop(self):
        expected = """Timerange: [1969-12-31 19:00:01.000000000, 1969-12-31 19:00:01.022000000]

Top system call latencies read (usec)
Begin               End                  Name             Duration (usec)         Size  Proc                     PID      Filename      
[19:00:01.008000000,19:00:01.009000000]  read                    1000.000     100.00 B                           100      testfile (fd=3)
[19:00:01.008000000,19:00:01.009000000]  read                    1000.000     100.00 B                           100      testfile (fd=3)
[19:00:01.012000000,19:00:01.013000000]  read                    1000.000      42.00 B  app3                     101      unknown (fd=3)
[19:00:01.012000000,19:00:01.013000000]  read                    1000.000      42.00 B  app3                     101      unknown (fd=3)

Top system call latencies write (usec)
Begin               End                  Name             Duration (usec)         Size  Proc                     PID      Filename      
[19:00:01.004000000,19:00:01.005000000]  write                   1000.000      10.00 B  app                      99       unknown (fd=4)
[19:00:01.004000000,19:00:01.005000000]  write                   1000.000      10.00 B  app                      99       unknown (fd=4)"""

        return self.compare_output('%slttng-iolatencytop %s "%s"' % (
            self.cmd_root, self.common_options,
            self.t.get_trace_root()), expected)


def test_answer():
    t = IoTest(verbose=True)
    ok = t.run()
    assert(ok)

test_answer()
