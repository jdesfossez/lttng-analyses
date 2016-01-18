#!/usr/bin/env python3

import sys
import os
import shutil
import tempfile
import difflib
import subprocess
from babeltrace import CTFWriter, CTFStringEncoding


class TraceTest():
    def __init__(self, delete_trace=True):
        self.delete_trace = delete_trace
        self.trace_root = tempfile.mkdtemp()
        self.trace_path = os.path.join(self.trace_root, "kernel")
        self.create_writer()
        self.create_stream_class()
        self.define_base_types()
        self.define_events()
        self.create_stream()

    def __del__(self):
        if self.delete_trace:
            self.rm_trace()

    def get_trace_root(self):
        return self.trace_root

    def rm_trace(self):
        shutil.rmtree(self.trace_root)

    def flush(self):
        self.writer.flush_metadata()
        self.stream.flush()

    def create_writer(self):
        self.clock = CTFWriter.Clock("A_clock")
        self.clock.description = "Simple clock"
        self.writer = CTFWriter.Writer(self.trace_path)
        self.writer.add_clock(self.clock)
        self.writer.add_environment_field("Python_version",
                                          str(sys.version_info))
        self.writer.add_environment_field("tracer_major", 2)
        self.writer.add_environment_field("tracer_minor", 8)
        self.writer.add_environment_field("tracer_patchlevel", 0)

    def create_stream_class(self):
        self.stream_class = CTFWriter.StreamClass("test_stream")
        self.stream_class.clock = self.clock

    def define_base_types(self):
        self.char8_type = CTFWriter.IntegerFieldDeclaration(8)
        self.char8_type.signed = True
        self.char8_type.encoding = CTFStringEncoding.UTF8
        self.char8_type.alignment = 8

        self.int32_type = CTFWriter.IntegerFieldDeclaration(32)
        self.int32_type.signed = True
        self.int32_type.alignment = 8

        self.uint32_type = CTFWriter.IntegerFieldDeclaration(32)
        self.uint32_type.signed = False
        self.uint32_type.alignment = 8

        self.int64_type = CTFWriter.IntegerFieldDeclaration(64)
        self.int64_type.signed = True
        self.int64_type.alignment = 8

        self.uint64_type = CTFWriter.IntegerFieldDeclaration(64)
        self.uint64_type.signed = False
        self.uint64_type.alignment = 8

        self.array16_type = CTFWriter.ArrayFieldDeclaration(self.char8_type, 16)

        self.string_type = CTFWriter.StringFieldDeclaration()

    def add_event(self, event):
        event.add_field(self.uint32_type, "_cpu_id")
        self.stream_class.add_event_class(event)

    def define_sched_switch(self):
        self.sched_switch = CTFWriter.EventClass("sched_switch")
        self.sched_switch.add_field(self.array16_type, "_prev_comm")
        self.sched_switch.add_field(self.int32_type, "_prev_tid")
        self.sched_switch.add_field(self.int32_type, "_prev_prio")
        self.sched_switch.add_field(self.int64_type, "_prev_state")
        self.sched_switch.add_field(self.array16_type, "_next_comm")
        self.sched_switch.add_field(self.int32_type, "_next_tid")
        self.sched_switch.add_field(self.int32_type, "_next_prio")
        self.add_event(self.sched_switch)

    def define_softirq_raise(self):
        self.softirq_raise = CTFWriter.EventClass("softirq_raise")
        self.softirq_raise.add_field(self.uint32_type, "_vec")
        self.add_event(self.softirq_raise)

    def define_softirq_entry(self):
        self.softirq_entry = CTFWriter.EventClass("softirq_entry")
        self.softirq_entry.add_field(self.uint32_type, "_vec")
        self.add_event(self.softirq_entry)

    def define_softirq_exit(self):
        self.softirq_exit = CTFWriter.EventClass("softirq_exit")
        self.softirq_exit.add_field(self.uint32_type, "_vec")
        self.add_event(self.softirq_exit)

    def define_irq_handler_entry(self):
        self.irq_handler_entry = CTFWriter.EventClass("irq_handler_entry")
        self.irq_handler_entry.add_field(self.int32_type, "_irq")
        self.irq_handler_entry.add_field(self.string_type, "_name")
        self.add_event(self.irq_handler_entry)

    def define_irq_handler_exit(self):
        self.irq_handler_exit = CTFWriter.EventClass("irq_handler_exit")
        self.irq_handler_exit.add_field(self.int32_type, "_irq")
        self.irq_handler_exit.add_field(self.int32_type, "_ret")
        self.add_event(self.irq_handler_exit)

    def define_syscall_entry_write(self):
        self.syscall_entry_write = CTFWriter.EventClass("syscall_entry_write")
        self.syscall_entry_write.add_field(self.uint32_type, "_fd")
        self.syscall_entry_write.add_field(self.uint64_type, "_buf")
        self.syscall_entry_write.add_field(self.uint64_type, "_count")
        self.add_event(self.syscall_entry_write)

    def define_syscall_exit_write(self):
        self.syscall_exit_write = CTFWriter.EventClass("syscall_exit_write")
        self.syscall_exit_write.add_field(self.int64_type, "_ret")
        self.add_event(self.syscall_exit_write)

    def define_syscall_entry_read(self):
        self.syscall_entry_read = CTFWriter.EventClass("syscall_entry_read")
        self.syscall_entry_read.add_field(self.uint32_type, "_fd")
        self.syscall_entry_read.add_field(self.uint64_type, "_count")
        self.add_event(self.syscall_entry_read)

    def define_syscall_exit_read(self):
        self.syscall_exit_read = CTFWriter.EventClass("syscall_exit_read")
        self.syscall_exit_read.add_field(self.uint64_type, "_buf")
        self.syscall_exit_read.add_field(self.int64_type, "_ret")
        self.add_event(self.syscall_exit_read)

    def define_lttng_statedump_process_state(self):
        self.lttng_statedump_process_state = CTFWriter.EventClass("lttng_statedump_process_state")
        self.lttng_statedump_process_state.add_field(self.int32_type, "_tid")
        self.lttng_statedump_process_state.add_field(self.int32_type, "_vtid")
        self.lttng_statedump_process_state.add_field(self.int32_type, "_pid")
        self.lttng_statedump_process_state.add_field(self.int32_type, "_vpid")
        self.lttng_statedump_process_state.add_field(self.int32_type, "_ppid")
        self.lttng_statedump_process_state.add_field(self.int32_type, "_vppid")
        self.lttng_statedump_process_state.add_field(self.array16_type, "_name")
        self.lttng_statedump_process_state.add_field(self.int32_type, "_type")
        self.lttng_statedump_process_state.add_field(self.int32_type, "_mode")
        self.lttng_statedump_process_state.add_field(self.int32_type, "_submode")
        self.lttng_statedump_process_state.add_field(self.int32_type, "_status")
        self.lttng_statedump_process_state.add_field(self.int32_type, "_ns_level")
        self.add_event(self.lttng_statedump_process_state)

    def define_lttng_statedump_file_descriptor(self):
        self.lttng_statedump_file_descriptor = CTFWriter.EventClass("lttng_statedump_file_descriptor")
        self.lttng_statedump_file_descriptor.add_field(self.int32_type, "_pid")
        self.lttng_statedump_file_descriptor.add_field(self.int32_type, "_fd")
        self.lttng_statedump_file_descriptor.add_field(self.uint32_type, "_flags")
        self.lttng_statedump_file_descriptor.add_field(self.uint32_type, "_fmode")
        self.lttng_statedump_file_descriptor.add_field(self.string_type, "_filename")
        self.add_event(self.lttng_statedump_file_descriptor)

    def define_sched_wakeup(self):
        self.sched_wakeup = CTFWriter.EventClass("sched_wakeup")
        self.sched_wakeup.add_field(self.array16_type, "_comm")
        self.sched_wakeup.add_field(self.int32_type, "_tid")
        self.sched_wakeup.add_field(self.int32_type, "_prio")
        self.sched_wakeup.add_field(self.int32_type, "_success")
        self.sched_wakeup.add_field(self.int32_type, "_target_cpu")
        self.add_event(self.sched_wakeup)

    def define_sched_waking(self):
        self.sched_waking = CTFWriter.EventClass("sched_waking")
        self.sched_waking.add_field(self.array16_type, "_comm")
        self.sched_waking.add_field(self.int32_type, "_tid")
        self.sched_waking.add_field(self.int32_type, "_prio")
        self.sched_waking.add_field(self.int32_type, "_target_cpu")
        self.add_event(self.sched_waking)

    def define_block_rq_complete(self):
        self.block_rq_complete = CTFWriter.EventClass("block_rq_complete")
        self.block_rq_complete.add_field(self.uint32_type, "_dev")
        self.block_rq_complete.add_field(self.uint64_type, "_sector")
        self.block_rq_complete.add_field(self.uint32_type, "_nr_sector")
        self.block_rq_complete.add_field(self.int32_type, "_errors")
        self.block_rq_complete.add_field(self.uint32_type, "_rwbs")
        self.block_rq_complete.add_field(self.uint64_type, "__cmd_length")
        self.block_rq_complete.add_field(self.array16_type, "_cmd")
        self.add_event(self.block_rq_complete)

    def define_block_rq_issue(self):
        self.block_rq_issue = CTFWriter.EventClass("block_rq_issue")
        self.block_rq_issue.add_field(self.uint32_type, "_dev")
        self.block_rq_issue.add_field(self.uint64_type, "_sector")
        self.block_rq_issue.add_field(self.uint32_type, "_nr_sector")
        self.block_rq_issue.add_field(self.uint32_type, "_bytes")
        self.block_rq_issue.add_field(self.int32_type, "_tid")
        self.block_rq_issue.add_field(self.uint32_type, "_rwbs")
        self.block_rq_issue.add_field(self.uint64_type, "__cmd_length")
        self.block_rq_issue.add_field(self.array16_type, "_cmd")
        self.block_rq_issue.add_field(self.array16_type, "_comm")
        self.add_event(self.block_rq_issue)

    def define_net_dev_xmit(self):
        self.net_dev_xmit = CTFWriter.EventClass("net_dev_xmit")
        self.net_dev_xmit.add_field(self.uint64_type, "_skbaddr")
        self.net_dev_xmit.add_field(self.int32_type, "_rc")
        self.net_dev_xmit.add_field(self.uint32_type, "_len")
        self.net_dev_xmit.add_field(self.string_type, "_name")
        self.add_event(self.net_dev_xmit)

    def define_netif_receive_skb(self):
        self.netif_receive_skb = CTFWriter.EventClass("netif_receive_skb")
        self.netif_receive_skb.add_field(self.uint64_type, "_skbaddr")
        self.netif_receive_skb.add_field(self.uint32_type, "_len")
        self.netif_receive_skb.add_field(self.string_type, "_name")
        self.add_event(self.netif_receive_skb)

    def define_events(self):
        self.define_sched_switch()
        self.define_softirq_raise()
        self.define_softirq_entry()
        self.define_softirq_exit()
        self.define_irq_handler_entry()
        self.define_irq_handler_exit()
        self.define_syscall_entry_write()
        self.define_syscall_exit_write()
        self.define_syscall_entry_read()
        self.define_syscall_exit_read()
        self.define_lttng_statedump_process_state()
        self.define_lttng_statedump_file_descriptor()
        self.define_sched_wakeup()
        self.define_sched_waking()
        self.define_block_rq_complete()
        self.define_block_rq_issue()
        self.define_net_dev_xmit()
        self.define_netif_receive_skb()

    def create_stream(self):
        self.stream = self.writer.create_stream(self.stream_class)

    def set_char_array(self, event, string):
        if len(string) > 16:
            string = string[0:16]
        else:
            string = "%s" % (string + "\0" * (16 - len(string)))

        for i in range(len(string)):
            a = event.field(i)
            a.value = ord(string[i])

    def set_int(self, event, value):
        event.value = value

    def set_string(self, event, value):
        event.value = value

    def write_softirq_raise(self, time_ms, cpu_id, vec):
        event = CTFWriter.Event(self.softirq_raise)
        self.clock.time = time_ms * 1000000
        self.set_int(event.payload("_cpu_id"), cpu_id)
        self.set_int(event.payload("_vec"), vec)
        self.stream.append_event(event)
        self.stream.flush()

    def write_softirq_entry(self, time_ms, cpu_id, vec):
        event = CTFWriter.Event(self.softirq_entry)
        self.clock.time = time_ms * 1000000
        self.set_int(event.payload("_cpu_id"), cpu_id)
        self.set_int(event.payload("_vec"), vec)
        self.stream.append_event(event)
        self.stream.flush()

    def write_softirq_exit(self, time_ms, cpu_id, vec):
        event = CTFWriter.Event(self.softirq_exit)
        self.clock.time = time_ms * 1000000
        self.set_int(event.payload("_cpu_id"), cpu_id)
        self.set_int(event.payload("_vec"), vec)
        self.stream.append_event(event)
        self.stream.flush()

    def write_irq_handler_entry(self, time_ms, cpu_id, irq, name):
        event = CTFWriter.Event(self.irq_handler_entry)
        self.clock.time = time_ms * 1000000
        self.set_int(event.payload("_cpu_id"), cpu_id)
        self.set_int(event.payload("_irq"), irq)
        self.set_string(event.payload("_name"), name)
        self.stream.append_event(event)
        self.stream.flush()

    def write_irq_handler_exit(self, time_ms, cpu_id, irq, ret):
        event = CTFWriter.Event(self.irq_handler_exit)
        self.clock.time = time_ms * 1000000
        self.set_int(event.payload("_cpu_id"), cpu_id)
        self.set_int(event.payload("_irq"), irq)
        self.set_int(event.payload("_ret"), ret)
        self.stream.append_event(event)
        self.stream.flush()

    def write_syscall_write(self, time_ms, cpu_id, delay, fd, buf, count, ret):
        entry = CTFWriter.Event(self.syscall_entry_write)
        self.clock.time = time_ms * 1000000
        self.set_int(entry.payload("_cpu_id"), cpu_id)
        self.set_int(entry.payload("_fd"), fd)
        self.set_int(entry.payload("_buf"), buf)
        self.set_int(entry.payload("_count"), count)
        self.stream.append_event(entry)

        exit = CTFWriter.Event(self.syscall_exit_write)
        self.clock.time = (time_ms + delay) * 1000000
        self.set_int(exit.payload("_cpu_id"), cpu_id)
        self.set_int(exit.payload("_ret"), ret)
        self.stream.append_event(exit)
        self.stream.flush()

    def write_syscall_read(self, time_ms, cpu_id, delay, fd, buf, count, ret):
        entry = CTFWriter.Event(self.syscall_entry_read)
        self.clock.time = time_ms * 1000000
        self.set_int(entry.payload("_cpu_id"), cpu_id)
        self.set_int(entry.payload("_fd"), fd)
        self.set_int(entry.payload("_count"), count)
        self.stream.append_event(entry)

        exit = CTFWriter.Event(self.syscall_exit_read)
        self.clock.time = (time_ms + delay) * 1000000
        self.set_int(exit.payload("_cpu_id"), cpu_id)
        self.set_int(exit.payload("_buf"), buf)
        self.set_int(exit.payload("_ret"), ret)
        self.stream.append_event(exit)
        self.stream.flush()

    def write_lttng_statedump_file_descriptor(self, time_ms, cpu_id, pid, fd,
                                              flags, fmode, filename):
        event = CTFWriter.Event(self.lttng_statedump_file_descriptor)
        self.clock.time = time_ms * 1000000
        self.set_int(event.payload("_cpu_id"), cpu_id)
        self.set_int(event.payload("_pid"), pid)
        self.set_int(event.payload("_fd"), fd)
        self.set_int(event.payload("_flags"), flags)
        self.set_int(event.payload("_fmode"), fmode)
        self.set_string(event.payload("_filename"), filename)
        self.stream.append_event(event)
        self.stream.flush()

    def write_lttng_statedump_process_state(self, time_ms, cpu_id, tid, vtid,
                                            pid, vpid, ppid, vppid, name, type,
                                            mode, submode, status, ns_level):
        event = CTFWriter.Event(self.lttng_statedump_process_state)
        self.clock.time = time_ms * 1000000
        self.set_int(event.payload("_cpu_id"), cpu_id)
        self.set_int(event.payload("_tid"), tid)
        self.set_int(event.payload("_vtid"), vtid)
        self.set_int(event.payload("_pid"), pid)
        self.set_int(event.payload("_vpid"), vpid)
        self.set_int(event.payload("_ppid"), ppid)
        self.set_int(event.payload("_vppid"), vppid)
        self.set_char_array(event.payload("_name"), name)
        self.set_int(event.payload("_type"), type)
        self.set_int(event.payload("_mode"), mode)
        self.set_int(event.payload("_submode"), submode)
        self.set_int(event.payload("_status"), status)
        self.set_int(event.payload("_ns_level"), ns_level)
        self.stream.append_event(event)
        self.stream.flush()

    def write_sched_wakeup(self, time_ms, cpu_id, comm, tid, prio, target_cpu):
        event = CTFWriter.Event(self.sched_wakeup)
        self.clock.time = time_ms * 1000000
        self.set_int(event.payload("_cpu_id"), cpu_id)
        self.set_char_array(event.payload("_comm"), comm)
        self.set_int(event.payload("_tid"), tid)
        self.set_int(event.payload("_prio"), prio)
        self.set_int(event.payload("_target_cpu"), target_cpu)
        self.stream.append_event(event)
        self.stream.flush()

    def write_sched_waking(self, time_ms, cpu_id, comm, tid, prio, target_cpu):
        event = CTFWriter.Event(self.sched_waking)
        self.clock.time = time_ms * 1000000
        self.set_int(event.payload("_cpu_id"), cpu_id)
        self.set_char_array(event.payload("_comm"), comm)
        self.set_int(event.payload("_tid"), tid)
        self.set_int(event.payload("_prio"), prio)
        self.set_int(event.payload("_target_cpu"), target_cpu)
        self.stream.append_event(event)
        self.stream.flush()

    def write_block_rq_complete(self, time_ms, cpu_id, dev, sector, nr_sector,
                                errors, rwbs, _cmd_length, cmd):
        event = CTFWriter.Event(self.block_rq_complete)
        self.clock.time = time_ms * 1000000
        self.set_int(event.payload("_cpu_id"), cpu_id)
        self.set_int(event.payload("_dev"), dev)
        self.set_int(event.payload("_sector"), sector)
        self.set_int(event.payload("_nr_sector"), nr_sector)
        self.set_int(event.payload("_errors"), errors)
        self.set_int(event.payload("_rwbs"), rwbs)
        self.set_int(event.payload("__cmd_length"), _cmd_length)
        self.set_char_array(event.payload("_cmd"), cmd)
        self.stream.append_event(event)
        self.stream.flush()

    def write_block_rq_issue(self, time_ms, cpu_id, dev, sector, nr_sector,
                             bytes, tid, rwbs, _cmd_length, cmd, comm):
        event = CTFWriter.Event(self.block_rq_issue)
        self.clock.time = time_ms * 1000000
        self.set_int(event.payload("_cpu_id"), cpu_id)
        self.set_int(event.payload("_dev"), dev)
        self.set_int(event.payload("_sector"), sector)
        self.set_int(event.payload("_nr_sector"), nr_sector)
        self.set_int(event.payload("_bytes"), bytes)
        self.set_int(event.payload("_tid"), tid)
        self.set_int(event.payload("_rwbs"), rwbs)
        self.set_int(event.payload("__cmd_length"), _cmd_length)
        self.set_char_array(event.payload("_cmd"), cmd)
        self.set_char_array(event.payload("_comm"), comm)
        self.stream.append_event(event)
        self.stream.flush()

    def write_net_dev_xmit(self, time_ms, cpu_id, skbaddr, rc, len, name):
        event = CTFWriter.Event(self.net_dev_xmit)
        self.clock.time = time_ms * 1000000
        self.set_int(event.payload("_cpu_id"), cpu_id)
        self.set_int(event.payload("_skbaddr"), skbaddr)
        self.set_int(event.payload("_rc"), rc)
        self.set_int(event.payload("_len"), len)
        self.set_string(event.payload("_name"), name)
        self.stream.append_event(event)
        self.stream.flush()

    def write_netif_receive_skb(self, time_ms, cpu_id, skbaddr, len, name):
        event = CTFWriter.Event(self.netif_receive_skb)
        self.clock.time = time_ms * 1000000
        self.set_int(event.payload("_cpu_id"), cpu_id)
        self.set_int(event.payload("_skbaddr"), skbaddr)
        self.set_int(event.payload("_len"), len)
        self.set_string(event.payload("_name"), name)
        self.stream.append_event(event)
        self.stream.flush()

    def write_sched_switch(self, time_ms, cpu_id, prev_comm, prev_tid,
                           next_comm, next_tid, prev_prio=20, prev_state=1,
                           next_prio=20):
        event = CTFWriter.Event(self.sched_switch)
        self.clock.time = time_ms * 1000000
        self.set_char_array(event.payload("_prev_comm"), prev_comm)
        self.set_int(event.payload("_prev_tid"), prev_tid)
        self.set_int(event.payload("_prev_prio"), prev_prio)
        self.set_int(event.payload("_prev_state"), prev_state)
        self.set_char_array(event.payload("_next_comm"), next_comm)
        self.set_int(event.payload("_next_tid"), next_tid)
        self.set_int(event.payload("_next_prio"), next_prio)
        self.set_int(event.payload("_cpu_id"), cpu_id)
        self.stream.append_event(event)
        self.stream.flush()

    def sched_switch_50pc(self, start_time_ms, end_time_ms, cpu_id, period,
                          comm1, tid1, comm2, tid2):
        current = start_time_ms
        while current < end_time_ms:
            self.write_sched_switch(current, cpu_id, comm1, tid1, comm2, tid2)
            current += period
            self.write_sched_switch(current, cpu_id, comm2, tid2, comm1, tid1)
            current += period

    def compare_output(self, cmd, expected):
        result = subprocess.getoutput(cmd)
        diff = difflib.ndiff(expected.split('\n'), result.split('\n'))
        txt = ""
        ok = True
        for l in diff:
            if l[0] != ' ':
                ok = False
            txt = txt + (l) + '\n'
        if not ok:
            print(txt)
        return ok


class AnalyzesTest():
    def __init__(self, delete_trace=True, verbose=False):
        self.verbose = verbose
        self.t = TraceTest(delete_trace=delete_trace)
        self.common_options = '--no-progress --skip-validation'
        self.cmd_root = './'
        self.log('Trace in %s' % (self.t.get_trace_root()))

    def log(self, msg):
        if self.verbose:
            print(msg)

    def compare_output(self, cmd, expected):
        return self.t.compare_output(cmd, expected)

    def run(self):
        ok = True
        self.write_trace()
        for t in self.test_list:
            ret = t[1]()
            self.log('%s: %s' % (t[0], ret))
            if not ret:
                ok = False
        return ok
