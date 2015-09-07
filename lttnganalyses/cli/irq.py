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
from ..core import irq as core_irq
from ..linuxautomaton import common, sv
from ..ascii_graph import Pyasciigraph

import math
import statistics


class IrqAnalysisCommand(Command):
    _DESC = """The irq command."""

    def __init__(self):
        super().__init__(self._add_arguments,
                         enable_max_min_args=True,
                         enable_freq_arg=True,
                         enable_log_arg=True,
                         enable_stats_arg=True)

    def _validate_transform_args(self):
        self._arg_irq_filter_list = None
        self._arg_softirq_filter_list = None

        if self._args.irq:
            self._arg_irq_filter_list = self._args.irq.split(',')
        if self._args.softirq:
            self._arg_softirq_filter_list = self._args.softirq.split(',')

    def _default_args(self, stats, log, freq):
        if stats:
            self._arg_stats = True
        if log:
            self._arg_log = True
        if freq:
            self._arg_freq = True

    def run(self, stats=False, log=False, freq=False):
        # parse arguments first
        self._parse_args()
        # validate, transform and save specific arguments
        self._validate_transform_args()
        # handle the default args for different executables
        self._default_args(stats, log, freq)
        # open the trace
        self._open_trace()
        # create the appropriate analysis/analyses
        self._create_analysis()
        # run the analysis
        self._run_analysis(self._reset_total, self._refresh)
        # print results
        self._print_results(self.start_ns, self.trace_end_ts)
        # close the trace
        self._close_trace()

    def run_stats(self):
        self.run(stats=True)

    def run_log(self):
        self.run(log=True)

    def run_freq(self):
        self.run(freq=True)

    def _create_analysis(self):
        self._analysis = core_irq.IrqAnalysis(self.state,
                                              self._arg_min,
                                              self._arg_max)

    def _compute_duration_stdev(self, irq_stats_item):
        if irq_stats_item.count < 2:
            return float('nan')

        durations = []
        for irq in irq_stats_item.irq_list:
            durations.append(irq.end_ts - irq.begin_ts)

        return statistics.stdev(durations)

    def _compute_raise_latency_stdev(self, irq_stats_item):
        if irq_stats_item.raise_count < 2:
            return float('nan')

        raise_latencies = []
        for irq in irq_stats_item.irq_list:
            if irq.raise_ts is None:
                continue

            raise_latencies.append(irq.begin_ts - irq.raise_ts)

        return statistics.stdev(raise_latencies)

    def _print_frequency_distribution(self, irq_stats_item, id):
        # The number of bins for the histogram
        resolution = self._arg_freq_resolution

        if self._arg_min is not None:
            min_duration = self._arg_min
        else:
            min_duration = irq_stats_item.min_duration
            # ns to µs
            min_duration /= 1000

        if self._arg_max is not None:
            max_duration = self._arg_max
        else:
            max_duration = irq_stats_item.max_duration
            # ns to µs
            max_duration /= 1000

        step = (max_duration - min_duration) / resolution
        if step == 0:
            return

        buckets = []
        values = []
        graph = Pyasciigraph()
        for i in range(resolution):
            buckets.append(i * step)
            values.append(0)
        for irq in irq_stats_item.irq_list:
            duration = (irq.end_ts - irq.begin_ts) / 1000
            index = min(int((duration - min_duration) / step), resolution - 1)
            values[index] += 1

        graph_data = []
        for index, value in enumerate(values):
            # The graph data format is a tuple (info, value). Here info
            # is the lower bound of the bucket, value the bucket's count
            graph_data.append(('%0.03f' % (index * step + min_duration),
                               value))

        graph_lines = graph.graph(
            'Handler duration frequency distribution %s (%s) (usec)' %
            (irq_stats_item.name, id),
            graph_data,
            info_before=True,
            count=True
        )

        for line in graph_lines:
            print(line)

    def _filter_irq(self, irq):
        if type(irq) is sv.HardIRQ:
            if self._arg_irq_filter_list:
                return str(irq.id) in self._arg_irq_filter_list
            if self._arg_softirq_filter_list:
                return False
        else:  # SoftIRQ
            if self._arg_softirq_filter_list:
                return str(irq.id) in self._arg_softirq_filter_list
            if self._arg_irq_filter_list:
                return False

        return True

    def _print_irq_log(self):
        fmt = '[{:<18}, {:<18}] {:>15} {:>4}  {:<9} {:>4}  {:<22}'
        title_fmt = '{:<20} {:<19} {:>15} {:>4}  {:<9} {:>4}  {:<22}'
        print(title_fmt.format('Begin', 'End', 'Duration (us)', 'CPU',
                               'Type', '#', 'Name'))
        for irq in self._analysis.irq_list:
            if not self._filter_irq(irq):
                continue

            raise_ts = ''
            if type(irq) is sv.HardIRQ:
                name = self._analysis.hard_irq_stats[irq.id].name
                irqtype = 'IRQ'
            else:
                name = self._analysis.softirq_stats[irq.id].name
                irqtype = 'SoftIRQ'
                if irq.raise_ts is not None:
                    raise_ts = ' (raised at %s)' % \
                               (common.ns_to_hour_nsec(irq.raise_ts,
                                                       self._arg_multi_day,
                                                       self._arg_gmt))

            print(fmt.format(common.ns_to_hour_nsec(irq.begin_ts,
                                                    self._arg_multi_day,
                                                    self._arg_gmt),
                             common.ns_to_hour_nsec(irq.end_ts,
                                                    self._arg_multi_day,
                                                    self._arg_gmt),
                             '%0.03f' % ((irq.end_ts - irq.begin_ts) / 1000),
                             '%d' % irq.cpu_id, irqtype, irq.id,
                             name + raise_ts))

    def _print_irq_stats(self, irq_stats, filter_list, header):
        header_printed = False
        for id in sorted(irq_stats):
            if filter_list and str(id) not in filter_list:
                continue

            irq_stats_item = irq_stats[id]
            if irq_stats_item.count == 0:
                continue

            if self._arg_stats:
                if self._arg_freq or not header_printed:
                    print(header)
                    header_printed = True

                if type(irq_stats_item) is core_irq.HardIrqStats:
                    self._print_hard_irq_stats_item(irq_stats_item, id)
                else:
                    self._print_soft_irq_stats_item(irq_stats_item, id)

            if self._arg_freq:
                self._print_frequency_distribution(irq_stats_item, id)

        print()

    def _print_hard_irq_stats_item(self, irq_stats_item, id):
        output_str = self._get_duration_stats_str(irq_stats_item, id)
        print(output_str)

    def _print_soft_irq_stats_item(self, irq_stats_item, id):
        output_str = self._get_duration_stats_str(irq_stats_item, id)
        if irq_stats_item.raise_count != 0:
            output_str += self._get_raise_latency_str(irq_stats_item, id)

        print(output_str)

    def _get_duration_stats_str(self, irq_stats_item, id):
        format_str = '{:<3} {:<18} {:>5} {:>12} {:>12} {:>12} {:>12} {:<2}'

        avg_duration = irq_stats_item.total_duration / irq_stats_item.count
        duration_stdev = self._compute_duration_stdev(irq_stats_item)
        min_duration = irq_stats_item.min_duration
        max_duration = irq_stats_item.max_duration
        # ns to µs
        avg_duration /= 1000
        duration_stdev /= 1000
        min_duration /= 1000
        max_duration /= 1000

        if math.isnan(duration_stdev):
            duration_stdev_str = '?'
        else:
            duration_stdev_str = '%0.03f' % duration_stdev

        output_str = format_str.format('%d:' % id,
                                       '<%s>' % irq_stats_item.name,
                                       '%d' % irq_stats_item.count,
                                       '%0.03f' % min_duration,
                                       '%0.03f' % avg_duration,
                                       '%0.03f' % max_duration,
                                       '%s' % duration_stdev_str,
                                       ' |')
        return output_str

    def _get_raise_latency_str(self, irq_stats_item, id):
        format_str = ' {:>6} {:>12} {:>12} {:>12} {:>12}'

        avg_raise_latency = (irq_stats_item.total_raise_latency /
                             irq_stats_item.raise_count)
        raise_latency_stdev = self._compute_raise_latency_stdev(irq_stats_item)
        min_raise_latency = irq_stats_item.min_raise_latency
        max_raise_latency = irq_stats_item.max_raise_latency
        # ns to µs
        avg_raise_latency /= 1000
        raise_latency_stdev /= 1000
        min_raise_latency /= 1000
        max_raise_latency /= 1000

        if math.isnan(raise_latency_stdev):
            raise_latency_stdev_str = '?'
        else:
            raise_latency_stdev_str = '%0.03f' % raise_latency_stdev

        output_str = format_str.format(irq_stats_item.raise_count,
                                       '%0.03f' % min_raise_latency,
                                       '%0.03f' % avg_raise_latency,
                                       '%0.03f' % max_raise_latency,
                                       '%s' % raise_latency_stdev_str)
        return output_str

    def _print_results(self, begin_ns, end_ns):
        if self._arg_stats or self._arg_freq:
            self._print_stats(begin_ns, end_ns)
        if self._arg_log:
            self._print_irq_log()

    def _print_stats(self, begin_ns, end_ns):
        self._print_date(begin_ns, end_ns)

        if self._arg_irq_filter_list is not None or \
           self._arg_softirq_filter_list is None:
            header_format = '{:<52} {:<12}\n' \
                            '{:<22} {:<14} {:<12} {:<12} {:<10} {:<12}\n'
            header = header_format.format(
                'Hard IRQ', 'Duration (us)',
                '', 'count', 'min', 'avg', 'max', 'stdev'
            )
            header += ('-' * 82 + '|')
            self._print_irq_stats(self._analysis.hard_irq_stats,
                                  self._arg_irq_filter_list,
                                  header)

        if self._arg_softirq_filter_list is not None or \
           self._arg_irq_filter_list is None:
            header_format = '{:<52} {:<52} {:<12}\n' \
                            '{:<22} {:<14} {:<12} {:<12} {:<10} {:<4} ' \
                            '{:<3} {:<14} {:<12} {:<12} {:<10} {:<12}\n'
            header = header_format.format(
                'Soft IRQ', 'Duration (us)',
                'Raise latency (us)', '',
                'count', 'min', 'avg', 'max', 'stdev', ' |',
                'count', 'min', 'avg', 'max', 'stdev'
            )
            header += '-' * 82 + '|' + '-' * 60
            self._print_irq_stats(self._analysis.softirq_stats,
                                  self._arg_softirq_filter_list,
                                  header)

    def _reset_total(self, start_ts):
        self._analysis.reset()

    def _refresh(self, begin, end):
        self._print_results(begin, end)
        self._reset_total(end)

    def _add_arguments(self, ap):
        ap.add_argument('--irq', type=str, default=None,
                        help='Show results only for the list of IRQ')
        ap.add_argument('--softirq', type=str, default=None,
                        help='Show results only for the list of '
                             'SoftIRQ')


# entry point
def runstats():
    # create command
    irqcmd = IrqAnalysisCommand()
    # execute command
    irqcmd.run_stats()


def runlog():
    # create command
    irqcmd = IrqAnalysisCommand()
    # execute command
    irqcmd.run_log()


def runfreq():
    # create command
    irqcmd = IrqAnalysisCommand()
    # execute command
    irqcmd.run_freq()
