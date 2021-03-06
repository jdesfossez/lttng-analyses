# The MIT License (MIT)
#
# Copyright (C) 2015 - Julien Desfossez <jdesfossez@efficios.com>
#               2015 - Antoine Busque <abusque@efficios.com>
#               2015 - Philippe Proulx <pproulx@efficios.com>
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

import operator
from . import mi
from ..core import cputop
from .command import Command
from ..ascii_graph import Pyasciigraph


class Cputop(Command):
    _DESC = """The cputop command."""
    _ANALYSIS_CLASS = cputop.Cputop
    _MI_TITLE = 'Top CPU usage'
    _MI_DESCRIPTION = 'Per-TID, per-CPU, and total top CPU usage'
    _MI_TAGS = [mi.Tags.CPU, mi.Tags.TOP]
    _MI_TABLE_CLASS_PER_PROC = 'per-process'
    _MI_TABLE_CLASS_PER_CPU = 'per-cpu'
    _MI_TABLE_CLASS_TOTAL = 'total'
    _MI_TABLE_CLASS_SUMMARY = 'summary'
    _MI_TABLE_CLASSES = [
        (
            _MI_TABLE_CLASS_PER_PROC,
            'Per-TID top CPU usage', [
                ('process', 'Process', mi.Process),
                ('migrations', 'Migration count', mi.Integer, 'migrations'),
                ('usage', 'CPU usage', mi.Ratio),
            ]
        ),
        (
            _MI_TABLE_CLASS_PER_CPU,
            'Per-CPU top CPU usage', [
                ('cpu', 'CPU', mi.Cpu),
                ('usage', 'CPU usage', mi.Ratio),
            ]),
        (
            _MI_TABLE_CLASS_TOTAL,
            'Total CPU usage', [
                ('usage', 'CPU usage', mi.Ratio),
            ]
        ),
        (
            _MI_TABLE_CLASS_SUMMARY,
            'CPU usage - summary', [
                ('time_range', 'Time range', mi.TimeRange),
                ('usage', 'Total CPU usage', mi.Ratio),
            ]
        ),
    ]

    def _filter_process(self, proc):
        # Exclude swapper
        if proc.tid == 0:
            return False

        if self._args.proc_list and proc.comm not in self._args.proc_list:
            return False

        return True

    def _analysis_tick(self, begin_ns, end_ns):
        per_tid_table = self._get_per_tid_usage_result_table(begin_ns, end_ns)
        per_cpu_table = self._get_per_cpu_usage_result_table(begin_ns, end_ns)
        total_table = self._get_total_usage_result_table(begin_ns, end_ns)

        if self._mi_mode:
            self._mi_append_result_table(per_tid_table)
            self._mi_append_result_table(per_cpu_table)
            self._mi_append_result_table(total_table)
        else:
            self._print_date(begin_ns, end_ns)
            self._print_per_tid_usage(per_tid_table)
            self._print_per_cpu_usage(per_cpu_table)

            if total_table:
                self._print_total_cpu_usage(total_table)

    def _create_summary_result_tables(self):
        total_tables = self._mi_get_result_tables(self._MI_TABLE_CLASS_TOTAL)
        begin = total_tables[0].timerange.begin
        end = total_tables[-1].timerange.end
        summary_table = \
            self._mi_create_result_table(self._MI_TABLE_CLASS_SUMMARY,
                                         begin, end)

        for total_table in total_tables:
            usage = total_table.rows[0].usage
            summary_table.append_row(
                time_range=total_table.timerange,
                usage=usage,
            )

        self._mi_clear_result_tables()
        self._mi_append_result_table(summary_table)

    def _get_per_tid_usage_result_table(self, begin_ns, end_ns):
        result_table = \
            self._mi_create_result_table(self._MI_TABLE_CLASS_PER_PROC,
                                         begin_ns, end_ns)
        count = 0

        for tid in sorted(self._analysis.tids.values(),
                          key=operator.attrgetter('usage_percent'),
                          reverse=True):
            if not self._filter_process(tid):
                continue

            result_table.append_row(
                process=mi.Process(tid.comm, tid=tid.tid),
                migrations=mi.Integer(tid.migrate_count),
                usage=mi.Ratio.from_percentage(tid.usage_percent)
            )
            count += 1

            if self._args.limit > 0 and count >= self._args.limit:
                break

        return result_table

    def _get_per_cpu_usage_result_table(self, begin_ns, end_ns):
        result_table = \
            self._mi_create_result_table(self._MI_TABLE_CLASS_PER_CPU,
                                         begin_ns, end_ns)

        for cpu in sorted(self._analysis.cpus.values(),
                          key=operator.attrgetter('usage_percent'),
                          reverse=True):
            result_table.append_row(
                cpu=mi.Cpu(cpu.cpu_id),
                usage=mi.Ratio.from_percentage(cpu.usage_percent)
            )

        return result_table

    def _get_total_usage_result_table(self, begin_ns, end_ns):
        result_table = \
            self._mi_create_result_table(self._MI_TABLE_CLASS_TOTAL,
                                         begin_ns, end_ns)

        cpu_count = len(self.state.cpus)
        usage_percent = 0

        if not cpu_count:
            return

        for cpu in sorted(self._analysis.cpus.values(),
                          key=operator.attrgetter('usage_percent'),
                          reverse=True):
            usage_percent += cpu.usage_percent

        # average per CPU
        usage_percent /= cpu_count
        result_table.append_row(
            usage=mi.Ratio.from_percentage(usage_percent),
        )

        return result_table

    def _print_per_tid_usage(self, result_table):
        graph = Pyasciigraph()
        values = []

        for row in result_table.rows:
            process_do = row.process
            migration_count = row.migrations.value
            output_str = '%s (%d)' % (process_do.name, process_do.tid)

            if migration_count > 0:
                output_str += ', %d migrations' % (migration_count)

            values.append((output_str, row.usage.to_percentage()))

        for line in graph.graph('Per-TID CPU Usage', values, unit=' %'):
            print(line)

    def _print_per_cpu_usage(self, result_table):
        graph = Pyasciigraph()
        values = []

        for row in result_table.rows:
            cpu = row.cpu
            values.append(('CPU %d' % cpu.id, row.usage.to_percentage()))

        for line in graph.graph('Per-CPU Usage', values, unit=' %'):
            print(line)

    def _print_total_cpu_usage(self, result_table):
        usage_percent = result_table.rows[0].usage.to_percentage()
        print('\nTotal CPU Usage: %0.02f%%\n' % usage_percent)

    def _add_arguments(self, ap):
        Command._add_proc_filter_args(ap)


def _run(mi_mode):
    cputopcmd = Cputop(mi_mode=mi_mode)
    cputopcmd.run()


# entry point (human)
def run():
    _run(mi_mode=False)


# entry point (MI)
def run_mi():
    _run(mi_mode=True)
