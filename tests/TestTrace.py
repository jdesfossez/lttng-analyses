#!/usr/bin/env python3

import sys
import os
import shutil
import tempfile
import difflib
from babeltrace import CTFWriter, CTFStringEncoding


class TestTrace():
    def __init__(self):
        self.trace_root = tempfile.mkdtemp()
        self.trace_path = os.path.join(self.trace_root, "kernel")
        self.create_writer()
        self.create_stream_class()
        self.define_base_types()
        self.define_events()
        self.create_stream()

    def get_trace_root(self):
        return self.trace_root

    def delete_trace(self):
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

        self.array_type = CTFWriter.ArrayFieldDeclaration(self.char8_type, 16)

    def define_sched_switch(self):
        self.sched_switch = CTFWriter.EventClass("sched_switch")

        self.sched_switch.add_field(self.array_type, "_prev_comm")
        self.sched_switch.add_field(self.int32_type, "_prev_tid")
        self.sched_switch.add_field(self.int32_type, "_prev_prio")
        self.sched_switch.add_field(self.int64_type, "_prev_state")
        self.sched_switch.add_field(self.array_type, "_next_comm")
        self.sched_switch.add_field(self.int32_type, "_next_tid")
        self.sched_switch.add_field(self.int32_type, "_next_prio")
        self.sched_switch.add_field(self.uint32_type, "_cpu_id")

        self.stream_class.add_event_class(self.sched_switch)

    def define_events(self):
        self.define_sched_switch()

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

    def compare_output(self, expected, result, complete_output=False):
        diff = difflib.ndiff(expected.split('\n'), result.split('\n'))
        err = False
        for l in diff:
            if l[0] != ' ':
                err = True
            if l[0] == ' ' and not complete_output:
                continue
            print(l)
        return err
