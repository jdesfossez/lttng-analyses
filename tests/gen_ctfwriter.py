#!/usr/bin/env python3
#
# The MIT License (MIT)
#
# Copyright (C) 2016 - Julien Desfossez <jdesfossez@efficios.com>
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

# Helper tool to generate CTFWriter code from the metadata of an existing
# trace.
# It used to add code in TraceTest.py.
# Only the basic types are supported, a warning is generated if a field cannot
# be generated so it is easy to look manually at the metadata and fix it.

import sys
import argparse

from babeltrace import TraceCollection, CTFScope, CTFTypeId


def get_definition_type(field, event):
    if field.type == CTFTypeId.INTEGER:
        signed = ''
        if field.signedness == 0:
            signed = 'u'
        length = field.length
        print('        self.%s.add_field(self.%sint%s_type, "_%s")' %
              (event.name, signed, length, field.name))
    elif field.type == CTFTypeId.ARRAY:
        print('        self.%s.add_field(self.array%s_type, "_%s")' %
              (event.name, field.length, field.name))
    elif field.type == CTFTypeId.STRING:
        print('        self.%s.add_field(self.string_type, "_%s")' %
              (event.name, field.name))
    else:
        print('        # FIXME %s.%s: Unhandled type %d' % (event.name,
                                                            field.name,
                                                            field.type))


def gen_define(event):
        fields = []
        print('    def define_%s(self):' % (event.name))
        print('        self.%s = CTFWriter.EventClass("%s")' %
              (event.name, event.name))
        for field in event.fields:
            if field.scope == CTFScope.EVENT_FIELDS:
                fname = field.name
                fields.append(fname)
                get_definition_type(field, event)
        print('        self.add_event(self.%s)' % event.name)
        print('')
        return fields


def gen_write(event, fields):
        f_list = None
        for f in fields:
            if f_list is None:
                f_list = f
            else:
                f_list = f_list + ", %s" % (f)
        print('    def write_%s(self, time_ms, cpu_id, %s):' % (event.name,
                                                                f_list))
        print('        event = CTFWriter.Event(self.%s)' % (event.name))
        print('        self.clock.time = time_ms * 1000000')
        print('        self.set_int(event.payload("_cpu_id"), cpu_id)')
        for field in event.fields:
            if field.scope == CTFScope.EVENT_FIELDS:
                fname = field.name
                if field.type == CTFTypeId.INTEGER:
                    print('        self.set_int(event.payload("_%s"), %s)' %
                          (fname, fname))
                elif field.type == CTFTypeId.ARRAY:
                    print('        self.set_char_array(event.payload("_%s"), '
                          '%s)' % (fname, fname))
                elif field.type == CTFTypeId.STRING:
                    print('        self.set_string(event.payload("_%s"), %s)' %
                          (fname, fname))
                else:
                    print('        # FIXME %s.%s: Unhandled type %d' %
                          (event.name, field.name, field.type))
        print('        self.stream.append_event(event)')
        print('        self.stream.flush()')
        print('')


def gen_parser(handle, args):
    for h in handle.values():
        for event in h.events:
            fields = gen_define(event)
            gen_write(event, fields)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='CTFWriter code generator')
    parser.add_argument('path', metavar="<path/to/trace>", help='Trace path')
    args = parser.parse_args()

    traces = TraceCollection()
    handle = traces.add_traces_recursive(args.path, "ctf")
    if handle is None:
        sys.exit(1)

    gen_parser(handle, args)

    for h in handle.values():
        traces.remove_trace(h)
