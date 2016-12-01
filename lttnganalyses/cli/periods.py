# The MIT License (MIT)
#
# Copyright (C) 2016 - Julien Desfossez <jdesfossez@efficios.com>
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

import sys
import math
import operator
import statistics
import collections
import ast
from collections import OrderedDict
from . import mi, termgraph
from ..core import periods
from .command import Command


class _StatsFreqTables():
    def __init__(self):
        # Stats tables
        self.per_parent_stats_table = None
        self.per_parent_count_table = None
        self.per_parent_pc_table = None
        self.global_duration_table = None
        self.global_count_table = None
        self.global_pc_table = None

        # Raw values for the frequency distributions
        # *_values[period][child] = []
        self.duration_values = {}
        self.count_values = {}
        self.pc_values = {}
        self.global_duration_values = {}
        self.global_count_values = {}
        self.global_pc_values = {}

        # Freq tables
        self.per_parent_freq_tables = []
        self.per_parent_count_freq_tables = []
        self.per_parent_pc_freq_tables = []
        self.global_duration_freq_tables = []
        self.global_count_freq_tables = []
        self.global_pc_freq_tables = []


class _PeriodStats():
    def __init__(self, count=0, min=None, max=0, stdev=0, total=0):
        self.count = count
        self.min = min
        self.max = max
        self.stdev = stdev
        self.total = total
        self.count_array = []
        self.durations = []
        self.min_count = None
        self.max_count = 0
        self.total_count = 0
        # Percentage of the parent period time spent
        self.min_pc = None
        self.max_pc = 0
        self.total_pc = 0
        self.pc_array = []
        # How many parent periods have us as a child, indexed by
        # parent period name.
        self.parent_count = {}

    def add_count(self, count):
        if self.min_count is None or count < self.min_count:
            self.min_count = count
        if self.max_count < count:
            self.max_count = count
        self.total_count += count
        self.count_array.append(count)

    def add_duration(self, duration):
        if self.min is None or duration < self.min:
            self.min = duration
        if self.max < duration:
            self.max = duration
        self.total += duration
        self.durations.append(duration)

    def add_percentage(self, pc):
        if self.min_pc is None or pc < self.min_pc:
            self.min_pc = pc
        if self.max_pc < pc:
            self.max_pc = pc
        self.total_pc += pc
        self.pc_array.append(pc)


class _TmpAggregation():
    def __init__(self, parent=None):
        # self._children[name] = [durations]
        self._children = {}
        self._parent = parent
        self.capture_groups = None

    @property
    def children(self):
        return self._children

    def add_child(self, name, duration):
        if name not in self._children.keys():
            self._children[name] = []
        self._children[name].append(duration)

        parent = self._parent
        while parent is not None:
            parent.add_child(name, duration)
            parent = parent._parent


class _AggregatedPeriodStats():
    def __init__(self, registry, name):
        self._reg = registry
        self._name = name
        self._children = OrderedDict()
        self._stats = _PeriodStats()
        self.nr_periods = 0
        self._init_children()

    def _recurs_find_children(self, period):
        for child in period.children:
            self._children[child.name] = _PeriodStats()
            self._recurs_find_children(child)

    def _init_children(self):
        period_def = self._reg.get_period_def(self._name)
        if period_def is None:
            return
        self._recurs_find_children(period_def)

    def finish_period(self, start_ts, end_ts, child_dict):
        parent_duration = end_ts - start_ts
        for child in child_dict.keys():
            count = len(child_dict[child])
            duration = 0
            for period in child_dict[child]:
                duration += period
            c = self._children[child]
            pc = (duration / parent_duration) * 100

            c.add_count(count)
            c.add_duration(duration)
            c.add_percentage(pc)

            if self._name not in c.parent_count.keys():
                c.parent_count[self._name] = 0
            c.parent_count[self._name] += 1
        self.nr_periods += 1


class _AggregatedItem():
    def __init__(self, event, parent_event, group_by_captures, full_captures):
        self._event = event
        self._parent = parent_event
        self._group_by_captures = group_by_captures
        self._full_captures = full_captures

    @property
    def event(self):
        return self._event

    @property
    def parent_event(self):
        return self._parent

    @property
    def group_by_captures(self):
        return self._group_by_captures

    @property
    def full_captures(self):
        return self._full_captures


class PeriodAnalysisCommand(Command):
    _DESC = """The periods command."""
    _ANALYSIS_CLASS = periods.PeriodAnalysis
    _MI_TITLE = 'Periods analysis'
    _MI_DESCRIPTION = \
        'Periods frequency distribution, statistics, top, and log'
    _MI_TAGS = [mi.Tags.PERIOD, mi.Tags.STATS, mi.Tags.FREQ, mi.Tags.TOP,
                mi.Tags.LOG]
    _MI_TABLE_CLASS_LOG = 'log'
    _MI_TABLE_CLASS_TOP = 'top'
    _MI_TABLE_CLASS_PER_PERIOD_STATS = 'per_period_stats'
    _MI_TABLE_CLASS_PER_PARENT_STATS = 'per_parent_stats'
    _MI_TABLE_CLASS_PER_PARENT_COUNT = 'per_parent_count'
    _MI_TABLE_CLASS_PER_PARENT_PC = 'per_parent_percentage'
    _MI_TABLE_CLASS_FREQ_DURATION = 'freq_duration'
    _MI_TABLE_CLASS_FREQ_COUNT = 'freq_count'
    _MI_TABLE_CLASS_FREQ_PC = 'freq_ratio'
    _MI_TABLE_CLASS_HIERARCHICAL_LOG = 'aggregated_log'
    _MI_TABLE_CLASS_AGGREGATED_TOP = 'aggregated_top'
    _MI_TABLE_CLASS_AGGREGATED_LOG = 'aggregated_stats'
    _MI_TABLE_CLASSES = [
        (
            _MI_TABLE_CLASS_LOG,
            'Period log', [
                ('begin_ts', 'Period begin timestamp', mi.Timestamp),
                ('end_ts', 'Period end timestamp', mi.Timestamp),
                ('duration', 'Period duration', mi.Duration),
                ('name', 'Period name', mi.String),
                ('begin_captures', 'Begin captures', mi.String),
                ('end_captures', 'End captures', mi.String),
            ]
        ),
        (
            _MI_TABLE_CLASS_TOP,
            'Period top', [
                ('begin_ts', 'Period begin timestamp', mi.Timestamp),
                ('end_ts', 'Period end timestamp', mi.Timestamp),
                ('duration', 'Period duration', mi.Duration),
                ('name', 'Period name', mi.String),
                ('begin_captures', 'Begin captures', mi.String),
                ('end_captures', 'End captures', mi.String),
            ]
        ),
        (
            _MI_TABLE_CLASS_PER_PERIOD_STATS,
            'Period statistics', [
                ('name', 'Period name', mi.String),
                ('count', 'Period count', mi.Number, 'occurences'),
                ('min_duration', 'Minimum duration', mi.Duration),
                ('avg_duration', 'Average duration', mi.Duration),
                ('max_duration', 'Maximum duration', mi.Duration),
                ('stdev_duration', 'Period duration standard deviation',
                 mi.Duration),
                ('runtime', 'Total runtime', mi.Duration),
            ]
        ),
        (
            _MI_TABLE_CLASS_FREQ_DURATION,
            'Period duration frequency distribution', [
                ('lower', 'Duration (lower bound)', mi.Duration),
                ('upper', 'Duration (upper bound)', mi.Duration),
                ('count', 'Period duration', mi.Number, 'us'),
            ]
        ),
        (
            _MI_TABLE_CLASS_FREQ_COUNT,
            'Period count frequency distribution', [
                ('lower', 'Count (lower bound)', mi.Number),
                ('upper', 'Count (upper bound)', mi.Number),
                ('count', 'Period count', mi.Number, 'count'),
            ]
        ),
        (
            _MI_TABLE_CLASS_FREQ_PC,
            'Period usage ratio frequency distribution', [
                ('lower', 'Ratio (lower bound)', mi.Number),
                ('upper', 'Ratio (upper bound)', mi.Number),
                ('count', 'Period usage ratio', mi.Number, '%'),
            ]
        ),
        (
            _MI_TABLE_CLASS_HIERARCHICAL_LOG,
            'Hierarchical period log', [
                ('parent_begin_ts', 'Parent begin timestamp', mi.Timestamp),
                ('parent_end_ts', 'Parent end timestamp', mi.Timestamp),
                ('parent_name', 'Parent period name', mi.String),
                ('child_begin_ts', 'Child begin timestamp', mi.Timestamp),
                ('child_end_ts', 'Child end timestamp', mi.Timestamp),
                ('child_name', 'Child period name', mi.String),
                ('child_duration', 'Child period duration', mi.Duration),
                ('parent_duration', 'Parent period duration', mi.Duration),
                ('captures', 'Captures', mi.String),
            ]
        ),
        (
            _MI_TABLE_CLASS_AGGREGATED_TOP,
            'Aggregated period top', [
                ('parent_begin_ts', 'Parent begin timestamp', mi.Timestamp),
                ('parent_end_ts', 'Parent end timestamp', mi.Timestamp),
                ('parent_name', 'Parent period name', mi.String),
                ('child_begin_ts', 'Child begin timestamp', mi.Timestamp),
                ('child_end_ts', 'Child end timestamp', mi.Timestamp),
                ('child_name', 'Child period name', mi.String),
                ('child_duration', 'Child period duration', mi.Duration),
                ('parent_duration', 'Parent period duration', mi.Duration),
                ('captures', 'Captures', mi.String),
            ]
        ),
        (
            _MI_TABLE_CLASS_AGGREGATED_LOG,
            'Aggregated log', [
                ('parent_name', 'Parent period name', mi.String),
                ('parent_begin_ts', 'Parent begin timestamp', mi.Timestamp),
                ('parent_end_ts', 'Parent end timestamp', mi.Timestamp),
                ('child_name', 'Child period name', mi.String),
                ('count', 'Period count', mi.Number, 'occurences'),
                ('min_duration', 'Minimum duration', mi.Duration),
                ('avg_duration', 'Average duration', mi.Duration),
                ('max_duration', 'Maximum duration', mi.Duration),
                ('stdev_duration', 'Period duration standard deviation',
                 mi.Duration),
                ('runtime', 'Total runtime', mi.Duration),
                ('parent_captures', 'Parent captures', mi.String),
            ]
        ),
        (
            _MI_TABLE_CLASS_PER_PARENT_STATS,
            'Per-parent period duration statistics', [
                ('name', 'Period name', mi.String),
                ('parent', 'Parent', mi.String),
                ('min_duration', 'Minimum duration', mi.Duration),
                ('avg_duration', 'Average duration', mi.Duration),
                ('max_duration', 'Maximum duration', mi.Duration),
                ('stdev_duration', 'Period duration standard deviation',
                 mi.Duration),
            ]
        ),
        (
            _MI_TABLE_CLASS_PER_PARENT_COUNT,
            'Per-parent period count statistics', [
                ('name', 'Period name', mi.String),
                ('parent', 'Parent', mi.String),
                ('min', 'Minimum', mi.Number, 'occurences'),
                ('avg', 'Average', mi.Number, 'occurences'),
                ('max', 'Maximum', mi.Number, 'occurences'),
                ('stdev', 'Standard deviation', mi.Duration),
            ]
        ),
        (
            _MI_TABLE_CLASS_PER_PARENT_PC,
            'Per-parent duration ratio', [
                ('name', 'Period name', mi.String),
                ('parent', 'Parent', mi.String),
                ('min', 'Minimum', mi.Number, 'occurences'),
                ('avg', 'Average', mi.Number, 'occurences'),
                ('max', 'Maximum', mi.Number, 'occurences'),
                ('stdev', 'Standard deviation', mi.Duration),
            ]
        ),
    ]

    def _filter_duration(self, duration):
        if self._args.min_duration is not None and \
                duration < (self._args.min_duration * 1000):
            return False
        if self._args.max_duration is not None and \
                duration > (self._args.max_duration * 1000):
            return False
        return True

    def _filter_event_duration(self, period_event):
        return self._filter_duration(period_event.duration)

    def _get_period_tree(self, period, period_tree):
        period_tree[period.name] = OrderedDict()
        for child in period.children:
            self._get_period_tree(child, period_tree[period.name])

    def _analysis_tick(self, period_data, end_ns):
        # We only output something at the end of the analysis
        # not when each period finishes
        if period_data is not None:
            return

        # Override the timestamps since we are only interested in the
        # whole analysis timestamps, not the ones from the last period.
        begin_ns = self._analysis.first_event_ts
        end_ns = self._analysis.last_event_ts
        log_table = None
        top_table = None
        per_period_stats_table = None
        per_period_freq_tables = None

        aggregated_groups = None
        hierarchical_list = None
        aggregated_log_tables = None
        per_parent_aggregated_dict = None

        per_parent_stats_freq_group_by_tables = OrderedDict()
        per_period_stats_group_by_tables = OrderedDict()
        per_period_freq_group_by_tables = OrderedDict()

        period_tree = OrderedDict()
        reg = self._analysis_conf.period_def_registry
        for parent in reg.root_period_defs:
            self._get_period_tree(parent, period_tree)

        if self._args.select or self._args.order_by == "hierarchy" or \
                self._args.stats or self._args.freq:
            per_parent_aggregated_dict, hierarchical_list, per_period_stats, \
                per_parent_period_group_by_stats, \
                per_period_group_by_stats = self._get_aggregated_lists()
            if self._args.group_by:
                aggregated_groups = self._get_aggregated_groups(
                    per_parent_aggregated_dict)

        if self._args.log:
            # hierarchical view
            if self._args.order_by == "hierarchy":
                log_table = self._get_log_result_table(
                    begin_ns, end_ns, hierarchical_list)
            # aggregated view
            elif self._args.select:
                aggregated_log_tables = \
                    self._get_aggregated_log_table(
                        begin_ns, end_ns,
                        per_parent_aggregated_dict, aggregated_groups,
                        top=True)
            else:
                # time-based view
                log_table = self._get_log_result_table(
                    begin_ns, end_ns, self._analysis.all_period_list)

        if self._args.top:
            top_table = self._get_top_result_table(
                begin_ns, end_ns, self._analysis.all_period_list)

        # Common tables for stats and freq
        if self._args.stats or self._args.freq:
            per_period_stats_table = \
                self._get_per_period_stats_result_table(begin_ns, end_ns,
                                                        period_tree)
            per_parent_stats_freq_tables = \
                self._get_per_parent_stats_result_table(
                    begin_ns, end_ns, per_period_stats,
                    '', per_period_stats)

            for group in per_parent_period_group_by_stats.keys():
                per_period_stats_group_by_tables[group], \
                        per_period_freq_group_by_tables[group] = \
                        self._get_grouped_by_period_stats_freq(
                            begin_ns, end_ns,
                            per_period_group_by_stats[group],
                            "'%s' - " % group)
                # One _StatsFreqTables per group
                per_parent_stats_freq_group_by_tables[group] = \
                    self._get_per_parent_stats_result_table(
                        begin_ns, end_ns,
                        per_parent_period_group_by_stats[group],
                        "'%s' - " % group, per_period_stats)

        if self._args.freq:
            per_period_freq_tables = \
                self._get_per_period_freq_result_tables(begin_ns, end_ns)
            # This updates per_parent_stats_freq_tables with the new tables,
            # nothing to return.
            self._get_per_parent_freq_result_table(
                begin_ns, end_ns, per_parent_stats_freq_tables)

            for group in per_parent_period_group_by_stats.keys():
                self._get_per_parent_freq_result_table(
                    begin_ns, end_ns,
                    per_parent_stats_freq_group_by_tables[group],
                    "'%s' -- " % group)

        if self._mi_mode:
            if log_table:
                self._mi_append_result_table(log_table)

            if top_table:
                self._mi_append_result_table(top_table)

            if self._args.stats:
                self._mi_append_result_table(per_period_stats_table)
                self._mi_append_result_table(
                    per_parent_stats_freq_tables.per_parent_stats_table)
                self._mi_append_result_table(
                    per_parent_stats_freq_tables.per_parent_count_table)
                self._mi_append_result_table(
                    per_parent_stats_freq_tables.per_parent_pc_table)
                self._mi_append_result_table(
                    per_parent_stats_freq_tables.global_duration_table)
                self._mi_append_result_table(
                    per_parent_stats_freq_tables.global_count_table)
                self._mi_append_result_table(
                    per_parent_stats_freq_tables.global_pc_table)

                for group in per_parent_period_group_by_stats.keys():
                    self._mi_append_result_table(
                        per_parent_stats_freq_group_by_tables[group].
                        per_parent_stats_table)
                    self._mi_append_result_table(
                        per_parent_stats_freq_group_by_tables[group].
                        per_parent_count_table)
                    self._mi_append_result_table(
                        per_parent_stats_freq_group_by_tables[group].
                        per_parent_pc_table)
                    self._mi_append_result_table(
                        per_parent_stats_freq_group_by_tables[group].
                        global_duration_table)
                    self._mi_append_result_table(
                        per_parent_stats_freq_group_by_tables[group].
                        global_count_table)
                    self._mi_append_result_table(
                        per_parent_stats_freq_group_by_tables[group].
                        global_pc_table)

            if self._args.freq:
                self._mi_append_result_tables(per_period_freq_tables)
                self._mi_append_result_tables(
                    per_parent_stats_freq_tables.per_parent_freq_tables)
                self._mi_append_result_tables(
                    per_parent_stats_freq_tables.per_parent_count_freq_tables)
                self._mi_append_result_tables(
                    per_parent_stats_freq_tables.per_parent_pc_freq_tables)
                self._mi_append_result_tables(
                    per_parent_stats_freq_tables.global_duration_freq_tables)
                self._mi_append_result_tables(
                    per_parent_stats_freq_tables.global_count_freq_tables)
                self._mi_append_result_tables(
                    per_parent_stats_freq_tables.global_pc_freq_tables)

                for group in per_parent_period_group_by_stats.keys():
                    self._mi_append_result_tables(
                        per_period_freq_group_by_tables[group])
                    self._mi_append_result_tables(
                        per_parent_stats_freq_group_by_tables[group].
                        per_parent_freq_tables)
                    self._mi_append_result_tables(
                        per_parent_stats_freq_group_by_tables[group].
                        per_parent_count_freq_tables)
                    self._mi_append_result_tables(
                        per_parent_stats_freq_group_by_tables[group].
                        per_parent_pc_freq_tables)
                    self._mi_append_result_tables(
                        per_parent_stats_freq_group_by_tables[group].
                        global_duration_freq_tables)
                    self._mi_append_result_tables(
                        per_parent_stats_freq_group_by_tables[group].
                        global_count_freq_tables)
                    self._mi_append_result_tables(
                        per_parent_stats_freq_group_by_tables[group].
                        global_pc_freq_tables)
        else:
            self._print_date(begin_ns, end_ns)

            if self._args.stats:
                self._print_per_period_stats(per_period_stats_table,
                                             period_tree)
                self._print_per_parent_stats(
                    per_parent_stats_freq_tables.per_parent_stats_table)
                self._print_per_parent_pc(
                    per_parent_stats_freq_tables.per_parent_pc_table)
                self._print_per_parent_count(
                    per_parent_stats_freq_tables.per_parent_count_table)
                self._print_per_parent_stats(
                    per_parent_stats_freq_tables.global_duration_table)
                self._print_per_parent_pc(
                    per_parent_stats_freq_tables.global_pc_table)
                self._print_per_parent_count(
                    per_parent_stats_freq_tables.global_count_table)

                for group in per_parent_period_group_by_stats.keys():
                    print("\n\n### Group: %s ###" % group)
                    self._print_per_period_stats(
                        per_period_stats_group_by_tables[group],
                        period_tree)
                    self._print_per_parent_stats(
                        per_parent_stats_freq_group_by_tables[group].
                        per_parent_stats_table)
                    self._print_per_parent_pc(
                        per_parent_stats_freq_group_by_tables[group].
                        per_parent_pc_table)
                    self._print_per_parent_count(
                        per_parent_stats_freq_group_by_tables[group].
                        per_parent_count_table)
                    self._print_per_parent_stats(
                        per_parent_stats_freq_group_by_tables[group].
                        global_duration_table)
                    self._print_per_parent_pc(
                        per_parent_stats_freq_group_by_tables[group].
                        global_pc_table)
                    self._print_per_parent_count(
                        per_parent_stats_freq_group_by_tables[group].
                        global_count_table)

            if self._args.freq:
                self._print_freq(per_period_freq_tables, 'us')
                self._print_freq(
                    per_parent_stats_freq_tables.per_parent_freq_tables, 'us')
                self._print_freq(
                    per_parent_stats_freq_tables.per_parent_pc_freq_tables,
                    '%')
                self._print_freq(
                    per_parent_stats_freq_tables.per_parent_count_freq_tables,
                    'instances')
                self._print_freq(
                    per_parent_stats_freq_tables.global_duration_freq_tables,
                    'us')
                self._print_freq(
                    per_parent_stats_freq_tables.global_pc_freq_tables, '%')
                self._print_freq(
                    per_parent_stats_freq_tables.global_count_freq_tables,
                    'instances')

                for group in per_parent_period_group_by_stats.keys():
                    print("\n\n### Group: %s ###" % group)
                    self._print_freq(per_period_freq_group_by_tables[group],
                                     'us')
                    self._print_freq(
                        per_parent_stats_freq_group_by_tables[group].
                        per_parent_freq_tables, 'us')
                    self._print_freq(
                        per_parent_stats_freq_group_by_tables[group].
                        per_parent_pc_freq_tables,
                        '%')
                    self._print_freq(
                        per_parent_stats_freq_group_by_tables[group].
                        per_parent_count_freq_tables,
                        'instances')
                    self._print_freq(
                        per_parent_stats_freq_group_by_tables[group].
                        global_duration_freq_tables,
                        'us')
                    self._print_freq(
                        per_parent_stats_freq_group_by_tables[group].
                        global_pc_freq_tables, '%')
                    self._print_freq(
                        per_parent_stats_freq_group_by_tables[group].
                        global_count_freq_tables,
                        'instances')

            if log_table:
                self._print_period_events(log_table)

            if top_table:
                self._print_period_events(top_table)

            if aggregated_log_tables:
                self._print_aggregated_log(aggregated_log_tables)

    def _get_filtered_min_max_count_avg_total_values(self, durations):
        min = None
        max = None
        count = 0
        avg = 0
        total = 0
        filter_list = []
        for d in durations:
            if not self._filter_duration(d):
                continue
            if min is None or min > d:
                min = d
            if max is None or max < d:
                max = d
            count += 1
            total += d
            filter_list.append(d)
        if count > 0:
            avg = total / count
        else:
            avg = 0
        return min, max, count, avg, total, filter_list

    def _get_filtered_min_max_count_avg_total_flist(self, period_list):
        min = None
        max = None
        count = 0
        avg = 0
        total = 0
        filter_list = []
        for period_event in period_list:
            if not self._filter_event_duration(period_event):
                continue
            if min is None or min > period_event.duration:
                min = period_event.duration
            if max is None or max < period_event.duration:
                max = period_event.duration
            count += 1
            total += period_event.duration
            filter_list.append(period_event)
        if count > 0:
            avg = total / count
        else:
            avg = 0
        return min, max, count, avg, total, filter_list

    def _get_agg_filtered_min_max_count_avg_total_flist(self, ag_list):
        min = None
        max = None
        count = 0
        avg = 0
        total = 0
        filter_list = []
        for ag_event in ag_list:
            period_event = ag_event.event
            if not self._filter_event_duration(period_event):
                continue
            if min is None or min > period_event.duration:
                min = period_event.duration
            if max is None or max < period_event.duration:
                max = period_event.duration
            count += 1
            total += period_event.duration
            filter_list.append(period_event)
        if count > 0:
            avg = total / count
        else:
            avg = 0
        return min, max, count, avg, total, filter_list

    def _find_aggregated_subperiods(self, root, event, aggregated_list,
                                    group_by_captures,
                                    full_captures):
        if len(self._analysis_conf._select) == 0 or \
                event.name in self._analysis_conf._select:
            aggregated_list.append(_AggregatedItem(event, root,
                                                   group_by_captures,
                                                   full_captures))
        for capture in event.filtered_captures(
                self._analysis_conf._group_by):
            group_by_captures.append(capture)
        for capture in event.full_captures():
            full_captures.append(capture)
        for child in event.children:
            self._find_aggregated_subperiods(root, child, aggregated_list,
                                             group_by_captures,
                                             full_captures)

    def _add_parent_per_group_active_periods(self, event,
                                             per_group_active_periods,
                                             group_key):
        p = None
        if event.parent is not None and \
                event.parent not in per_group_active_periods[group_key].keys():
            p = self._add_parent_per_group_active_periods(
                event.parent, per_group_active_periods, group_key)
        per_group_active_periods[group_key][event] = _TmpAggregation(p)
        return per_group_active_periods[group_key][event]

    def _account_parents_in_group(self, event, full_captures,
                                  per_parent_period_group_by_stats,
                                  per_group_active_periods,
                                  per_period_group_by_stats):
        for g in full_captures:
            group_key = ''
            if len(g) < len(self._analysis_conf._group_by.keys()):
                continue
            for group in sorted(g, key=lambda x: x[0]):
                if len(group_key) == 0:
                    group_key = '%s = %s' % (group[0], group[1])
                else:
                    group_key = '%s, %s = %s' % (group_key, group[0],
                                                 group[1])

            if group_key not in per_group_active_periods.keys():
                per_group_active_periods[group_key] = OrderedDict()

            # Statistics for this event alone in this group
            if group_key not in per_period_group_by_stats.keys():
                per_period_group_by_stats[group_key] = OrderedDict()
            if event.name not in per_period_group_by_stats[group_key].keys():
                per_period_group_by_stats[group_key][event.name] = \
                    _PeriodStats()
            per_period_group_by_stats[group_key][event.name].add_duration(
                event.duration)

            if group_key not in per_parent_period_group_by_stats.keys():
                per_parent_period_group_by_stats[group_key] = OrderedDict()
            if event.name not in \
                    per_parent_period_group_by_stats[group_key].keys():
                per_parent_period_group_by_stats[group_key][event.name] = \
                    _AggregatedPeriodStats(
                            self._analysis_conf.period_def_registry,
                            event.name)
            # Account all parent periods of this event in all of its groups
            _parent = event.parent
            _child = event
            while _parent is not None:
                if _parent not in per_group_active_periods[group_key].keys():
                    self._add_parent_per_group_active_periods(
                        _parent, per_group_active_periods, group_key)
                if _parent.name not in \
                        per_parent_period_group_by_stats[group_key].keys():
                    per_parent_period_group_by_stats[group_key][_parent.name] \
                            = _AggregatedPeriodStats(
                            self._analysis_conf.period_def_registry,
                            _parent.name)
                per_group_active_periods[group_key][_parent].add_child(
                    _child.name, _child.duration)
                _parent = _parent.parent

            if event in per_group_active_periods[group_key].keys():
                per_parent_period_group_by_stats[group_key][event.name]. \
                    finish_period(
                        event.start_ts, event.end_ts,
                        per_group_active_periods[group_key][event].children)

    def _hierarchical_sub(self, tmp_hierarchical_list, event, per_period_stats,
                          per_parent_period_group_by_stats, active_periods,
                          ancestors_captures, per_group_active_periods,
                          per_period_group_by_stats):
        tmp_hierarchical_list.append(event)

        event_captures = event.filtered_captures(self._analysis_conf._group_by)
#        print(parent_captures, event_captures)

        # Our local level capture to return to our parent combined with the
        # captures of our children.
        local_captures = []
        global_captures = []

        # Recursively iterate over all the children of this period
        for child in event.children:
            if child.name not in per_period_stats.keys():
                per_period_stats[child.name] = _AggregatedPeriodStats(
                    self._analysis_conf.period_def_registry,
                    child.name)
            active_periods[event].add_child(child.name, child.duration)
            active_periods[child] = _TmpAggregation(active_periods[event])
#            print('passing', ancestors_captures + event_captures)
            child_captures = self._hierarchical_sub(
                tmp_hierarchical_list, child, per_period_stats,
                per_parent_period_group_by_stats, active_periods,
                ancestors_captures + event_captures,
                per_group_active_periods, per_period_group_by_stats)
            del(active_periods[child])
#            print('returned', child_captures)
            for c in child_captures:
                local_captures.append(event_captures + c)
                global_captures.append(event_captures.copy() + c)
        if len(local_captures) == 0:
            local_captures = [event_captures]
            global_captures = [event_captures.copy()]
#        print('in', event.name, 'local + children', local_captures)
        full_captures = []
        for c in global_captures:
            tmp_c = c.copy()
            for d in ancestors_captures:
                tmp_c.append(d)
            # dedup
            if tmp_c not in full_captures:
                full_captures.append(tmp_c)
#        print('in2', event.name, full_captures)
        active_periods[event].capture_groups = full_captures

        self._account_parents_in_group(event, full_captures,
                                       per_parent_period_group_by_stats,
                                       per_group_active_periods,
                                       per_period_group_by_stats)

        per_period_stats[event.name].finish_period(
            event.start_ts, event.end_ts,
            active_periods[event].children)

        return local_captures

    def _get_aggregated_lists(self):
        # Dict with parent period as key. Each entry contains a dict
        # of all child period that each contain a list of _AggregatedItem.
        # parent_aggregated_dict[parent_period][child_period] = []
        parent_aggregated_dict = {}
        # List of PeriodEvent ordered in hierarchy (parents are followed
        # by their children)
        hierarchical_list = []
        # dict of _AggregatedPeriodStats
        # OrderedDict because we want the same order as the period_tree
        per_period_stats = OrderedDict()
        per_parent_period_group_by_stats = OrderedDict()
        # Just the stats for the period per group (not relative to
        # its parents)
        per_period_group_by_stats = OrderedDict()
        # active_periods[period_event] = _TmpAggregation()
        active_periods = {}
        per_group_active_periods = {}
        for period_event in self._analysis.all_period_list:
            if self._analysis_conf._order_by == "hierarchy" or \
                    self._args.stats or self._args.freq:
                # Only top-level events to start the recursive iteration
                # and extract per_parent stats/freq and hierarchical list
                # of periods
                if period_event.parent is None:
                    active_periods[period_event] = _TmpAggregation()
                    hierarchical_list.append(period_event)
                    if period_event.name not in per_period_stats.keys():
                        per_period_stats[period_event.name] = \
                            _AggregatedPeriodStats(
                                self._analysis_conf.period_def_registry,
                                period_event.name)

                    tmp_hierarchical_list = []
                    self._hierarchical_sub(
                        tmp_hierarchical_list, period_event, per_period_stats,
                        per_parent_period_group_by_stats, active_periods, [],
                        per_group_active_periods, per_period_group_by_stats)
                    del(active_periods[period_event])
                    for item in tmp_hierarchical_list:
                        hierarchical_list.append(item)

            if period_event.name != self._analysis_conf._aggregate_by:
                continue
            if not self._filter_event_duration(period_event):
                continue
            if period_event not in parent_aggregated_dict.keys():
                parent_aggregated_dict[period_event] = {}
            # Associate the periods with their full capture list (each period
            # sees its own capture and the capture of all its children)
            tmp_list = []
            for child in period_event.children:
                self._find_aggregated_subperiods(
                    period_event,
                    child, tmp_list,
                    period_event.filtered_captures(
                        self._analysis_conf._group_by),
                    period_event.full_captures())
            for item in tmp_list:
                if item.event.name not in \
                        parent_aggregated_dict[period_event].keys():
                    parent_aggregated_dict[period_event][item.event.name] = []
                parent_aggregated_dict[period_event][item.event.name]. \
                    append(item)
        ordered_parent = collections.OrderedDict(
            sorted(parent_aggregated_dict.items(),
                   key=lambda t: t[0].start_ts))

        return ordered_parent, hierarchical_list, per_period_stats, \
            per_parent_period_group_by_stats, per_period_group_by_stats

    def _get_aggregated_groups(self, per_parent_aggregated_dict):
        # Group and flatten event list by captured keys, aggregate by parent
        # groups[group_key][parent][child] = [_AggregatedItem, ...]
        groups = {}
        for parent in per_parent_aggregated_dict.keys():
            for child in per_parent_aggregated_dict[parent].keys():
                for ag_event in per_parent_aggregated_dict[parent][child]:
                    group_key = ""
                    for group in sorted(ag_event.group_by_captures,
                                        key=lambda x: x[0]):
                        if len(group_key) == 0:
                            group_key = "%s = %s" % (group[0], group[1])
                        else:
                            group_key = "%s, %s = %s" % (group_key, group[0],
                                                         group[1])

                    if group_key not in groups.keys():
                        groups[group_key] = {}
                    if parent not in groups[group_key].keys():
                        groups[group_key][parent] = {}
                    if child not in groups[group_key][parent].keys():
                        groups[group_key][parent][child] = []
                    groups[group_key][parent][child].append(ag_event)
        return groups

    def _get_total_period_lists_stats(self):
        if self._args.min_duration is None and \
                self._args.max_duration is None:
            total_list = self._analysis.all_period_list
            stdev = self._compute_period_duration_stdev(total_list)
            total_stats = _PeriodStats(
                count=self._analysis.all_count,
                min=self._analysis.all_min_duration,
                max=self._analysis.all_max_duration,
                stdev=stdev,
                total=self._analysis.all_total_duration
            )
        else:
            min, max, count, avg, total, total_list = \
                self._get_filtered_min_max_count_avg_total_flist(
                    self._analysis.all_period_list)
            total_stats = _PeriodStats(
                count=count,
                min=min,
                max=max,
                stdev=self._compute_period_duration_stdev(total_list),
                total=total,
            )

        return [total_list], total_stats

    def _get_one_hierarchical_log_table(self, begin_ns, end_ns,
                                        aggregated_list, sub, top):
        if top:
            table = self._mi_create_result_table(
                self._MI_TABLE_CLASS_AGGREGATED_TOP, begin_ns, end_ns,
                subtitle=sub)
            top_events = sorted(aggregated_list, key=operator.attrgetter(
                'event.duration'), reverse=True)
            top_events = top_events[:self._args.limit]
            for ag_event in top_events:
                table.append_row(
                    parent_begin_ts=mi.Timestamp(
                        ag_event.parent_event.start_ts),
                    parent_end_ts=mi.Timestamp(
                        ag_event.parent_event.end_ts),
                    parent_name=mi.String(ag_event.parent_event.name),
                    child_begin_ts=mi.Timestamp(ag_event.event.start_ts),
                    child_end_ts=mi.Timestamp(ag_event.event.end_ts),
                    child_name=mi.String(ag_event.event.name),
                    child_duration=mi.Duration(ag_event.event.duration),
                    parent_duration=mi.Duration(
                        ag_event.parent_event.duration),
                    captures=mi.String(str(ag_event.full_captures)),
                )
        else:
            table = self._mi_create_result_table(
                self._MI_TABLE_CLASS_HIERARCHICAL_LOG, begin_ns, end_ns,
                subtitle=sub)
            for ag_event in aggregated_list:
                table.append_row(
                    parent_begin_ts=mi.Timestamp(
                        ag_event.parent_event.start_ts),
                    parent_end_ts=mi.Timestamp(ag_event.parent_event.end_ts),
                    parent_name=mi.String(ag_event.parent_event.name),
                    child_begin_ts=mi.Timestamp(ag_event.event.start_ts),
                    child_end_ts=mi.Timestamp(ag_event.event.end_ts),
                    child_name=mi.String(ag_event.event.name),
                    child_duration=mi.Duration(ag_event.event.duration),
                    parent_duration=mi.Duration(
                        ag_event.parent_event.duration),
                    captures=mi.String(str(ag_event.full_captures)),
                )
        return table

    def _get_hierarchical_log_top_result_table(
            self, begin_ns, end_ns, aggregated_list, aggregated_groups,
            top=False):
        result_tables = []
        ag_list = ""
        for i in self._analysis_conf._select:
            if len(ag_list) == 0:
                ag_list = i
            else:
                ag_list = "%s, %s" % (ag_list, i)
        sub = "Aggregation of (%s) by %s" % (
            ag_list, self._analysis_conf._aggregate_by)

        if aggregated_groups is None:
            table = self._get_one_hierarchical_log_table(begin_ns, end_ns,
                                                         aggregated_list, sub,
                                                         top)
            result_tables.append(table)
        else:
            for group in aggregated_groups.keys():
                group_sub = "%s, group: %s" % (sub, group)
                result_tables.append(self._get_one_hierarchical_log_table(
                    begin_ns, end_ns, aggregated_groups[group], group_sub,
                    top))

        return result_tables

    def _get_full_period_path(self, period_name):
        if len(period_name) == 0:
            return period_name
        return self._analysis_conf.period_def_registry.period_full_path(
            period_name)

    def _get_log_result_table(self, begin_ns, end_ns, period_list):
        result_table = self._mi_create_result_table(self._MI_TABLE_CLASS_LOG,
                                                    begin_ns, end_ns)
        for period_event in period_list:
            if not self._filter_event_duration(period_event):
                continue
            result_table.append_row(
                begin_ts=mi.Timestamp(period_event.start_ts),
                end_ts=mi.Timestamp(period_event.end_ts),
                duration=mi.Duration(period_event.duration),
                name=mi.String(self._get_full_period_path(period_event.name)),
                begin_captures=mi.String(period_event.begin_captures),
                end_captures=mi.String(period_event.end_captures),
            )
        return result_table

    def _get_top_result_table(self, begin_ns, end_ns, event_list):
        result_table = self._mi_create_result_table(
            self._MI_TABLE_CLASS_TOP, begin_ns, end_ns)

        top_events = sorted(event_list,
                            key=operator.attrgetter('duration'),
                            reverse=True)
        count = 0

        for period_event in top_events:
            if not self._filter_event_duration(period_event):
                continue
            if self._args.select and period_event.name not in \
                    self._args.select:
                continue
            result_table.append_row(
                begin_ts=mi.Timestamp(period_event.start_ts),
                end_ts=mi.Timestamp(period_event.end_ts),
                duration=mi.Duration(period_event.duration),
                name=mi.String(period_event.name),
                begin_captures=mi.String(period_event.begin_captures),
                end_captures=mi.String(period_event.end_captures),
            )
            count += 1
            if count == self._args.limit:
                break
        return result_table

    def _get_ordered_period_stats_list(self, parent_name, period_stats_list,
                                       period_tree):
        if parent_name not in self._analysis.all_period_stats.keys():
            return
        period_stats_list.append(self._analysis.all_period_stats[parent_name])
        for child in sorted(period_tree.keys()):
            self._get_ordered_period_stats_list(child, period_stats_list,
                                                period_tree[child])

    def _get_per_parent_stats_result_table(self, begin_ns, end_ns,
                                           per_period_stats, group_prefix,
                                           not_grouped_per_period_stats):
        duration_table = self._mi_create_result_table(
            self._MI_TABLE_CLASS_PER_PARENT_STATS, begin_ns, end_ns,
            subtitle="%sWith active children" % group_prefix)
        count_table = self._mi_create_result_table(
            self._MI_TABLE_CLASS_PER_PARENT_COUNT, begin_ns, end_ns,
            subtitle="%sWith active children" % group_prefix)
        global_duration_table = self._mi_create_result_table(
            self._MI_TABLE_CLASS_PER_PARENT_STATS, begin_ns, end_ns,
            subtitle="%sGlobally" % group_prefix)
        global_count_table = self._mi_create_result_table(
            self._MI_TABLE_CLASS_PER_PARENT_COUNT, begin_ns, end_ns,
            subtitle="%sGlobally" % group_prefix)
        pc_table = self._mi_create_result_table(
            self._MI_TABLE_CLASS_PER_PARENT_PC, begin_ns, end_ns,
            subtitle="%sWith active children" % group_prefix)
        global_pc_table = self._mi_create_result_table(
            self._MI_TABLE_CLASS_PER_PARENT_PC, begin_ns, end_ns,
            subtitle="%sGlobally" % group_prefix)
        ret = _StatsFreqTables()
        ret.per_parent_stats_table = duration_table
        ret.per_parent_count_table = count_table
        ret.global_duration_table = global_duration_table
        ret.global_count_table = global_count_table
        ret.per_parent_pc_table = pc_table
        ret.global_pc_table = global_pc_table

        for period in per_period_stats.keys():
            ret.duration_values[period] = {}
            ret.count_values[period] = {}
            ret.pc_values[period] = {}
            ret.global_duration_values[period] = {}
            ret.global_count_values[period] = {}
            ret.global_pc_values[period] = {}
            for child in per_period_stats[period]._children.keys():
                c = per_period_stats[period]._children[child]
                nogroup_c = not_grouped_per_period_stats[period]
                if per_period_stats[period].nr_periods == 0:
                    global_duration_avg = 0
                    global_count_avg = 0
                    duration_avg = 0
                    count_avg = 0
                    pc_avg = 0
                else:
                    global_duration_avg = c.total / \
                        nogroup_c.nr_periods
                    global_count_avg = c.total_count / \
                        nogroup_c.nr_periods
                    duration_avg = c.total / c.parent_count[period]
                    count_avg = c.total_count / c.parent_count[period]
                    pc_avg = c.total_pc / c.parent_count[period]
                    global_pc_avg = c.total_pc / \
                        nogroup_c.nr_periods

                if len(c.durations) > 2:
                    duration_stdev = mi.Duration(statistics.stdev(c.durations))
                    count_stdev = mi.Number(statistics.stdev(c.count_array))
                    pc_stdev = mi.Number(statistics.stdev(c.pc_array))
                else:
                    duration_stdev = mi.Unknown()
                    count_stdev = mi.Unknown()
                    pc_stdev = mi.Unknown()

                # Make temporary copies in case we need to reuse the
                # original table afterwards.
                global_durations = c.durations.copy()
                global_count_array = c.count_array.copy()
                global_pc_array = c.pc_array.copy()
                # Save the raw values if we need them for the frequency
                # distributions
                ret.duration_values[period][child] = c.durations.copy()
                ret.count_values[period][child] = c.count_array.copy()
                ret.pc_values[period][child] = c.pc_array.copy()
                ret.global_duration_values[period][child] = c.durations.copy()
                ret.global_count_values[period][child] = c.count_array.copy()
                ret.global_pc_values[period][child] = c.pc_array.copy()
                if c.parent_count[period] < \
                        nogroup_c.nr_periods:
                    global_min = 0
                    global_min_count = 0
                    global_min_pc = 0
                    for i in range(nogroup_c.nr_periods -
                                   c.parent_count[period]):
                        global_durations.append(0)
                        global_count_array.append(0)
                        global_pc_array.append(0)
                        ret.global_duration_values[period][child].append(0)
                        ret.global_count_values[period][child].append(0)
                        ret.global_pc_values[period][child].append(0)
                else:
                    global_min = c.min
                    global_min_count = c.min_count
                    global_min_pc = c.min_pc

                if nogroup_c.nr_periods > 2:
                    global_duration_stdev = mi.Duration(
                        statistics.stdev(global_durations))
                    global_count_stdev = mi.Number(
                        statistics.stdev(global_count_array))
                    global_pc_stdev = mi.Number(
                        statistics.stdev(global_pc_array))
                else:
                    global_duration_stdev = mi.Unknown()
                    global_count_stdev = mi.Unknown()
                    global_pc_stdev = mi.Unknown()

                duration_table.append_row(
                    name=mi.String(self._get_full_period_path(child)),
                    parent=mi.String(self._get_full_period_path(period)),
                    min_duration=mi.Duration(c.min),
                    avg_duration=mi.Duration(duration_avg),
                    max_duration=mi.Duration(c.max),
                    stdev_duration=duration_stdev,
                )

                count_table.append_row(
                    name=mi.String(self._get_full_period_path(child)),
                    parent=mi.String(self._get_full_period_path(period)),
                    min=mi.Number(c.min_count),
                    avg=mi.Number(count_avg),
                    max=mi.Number(c.max_count),
                    stdev=count_stdev,
                )

                pc_table.append_row(
                    name=mi.String(self._get_full_period_path(child)),
                    parent=mi.String(self._get_full_period_path(period)),
                    min=mi.Number(c.min_pc),
                    avg=mi.Number(pc_avg),
                    max=mi.Number(c.max_pc),
                    stdev=pc_stdev,
                )

                global_duration_table.append_row(
                    name=mi.String(self._get_full_period_path(child)),
                    parent=mi.String(self._get_full_period_path(period)),
                    min_duration=mi.Duration(global_min),
                    avg_duration=mi.Duration(global_duration_avg),
                    max_duration=mi.Duration(c.max),
                    stdev_duration=global_duration_stdev,
                )

                global_count_table.append_row(
                    name=mi.String(self._get_full_period_path(child)),
                    parent=mi.String(self._get_full_period_path(period)),
                    min=mi.Number(global_min_count),
                    avg=mi.Number(global_count_avg),
                    max=mi.Number(c.max_count),
                    stdev=global_count_stdev,
                )

                global_pc_table.append_row(
                    name=mi.String(self._get_full_period_path(child)),
                    parent=mi.String(self._get_full_period_path(period)),
                    min=mi.Number(global_min_pc),
                    avg=mi.Number(global_pc_avg),
                    max=mi.Number(c.max_pc),
                    stdev=global_pc_stdev,
                )
        return ret

    def _get_grouped_by_period_stats_freq(self, begin_ns, end_ns,
                                          per_period_group_stats,
                                          group_prefix):
        stats_table = \
            self._mi_create_result_table(self._MI_TABLE_CLASS_PER_PERIOD_STATS,
                                         begin_ns, end_ns)
        freq_tables = []
        for period in per_period_group_stats.keys():
            table = per_period_group_stats[period]
            min, max, count, avg, total, total_list = \
                self._get_filtered_min_max_count_avg_total_values(
                    table.durations)
            stdev = self._compute_period_duration_stdev_values(total_list)
            if math.isnan(stdev):
                stdev = mi.Unknown()
            else:
                stdev = mi.Duration(stdev)
            count = len(total_list)

            stats_table.append_row(
                name=mi.String(self._get_full_period_path(period)),
                count=mi.Number(count),
                min_duration=mi.Duration(min),
                avg_duration=mi.Duration(avg),
                max_duration=mi.Duration(max),
                stdev_duration=stdev,
                runtime=mi.Duration(total),
            )

            step = (max - min) / self._args.freq_resolution

            subtitle = '{}Duration of period: {}'.format(group_prefix, period)
            freq_tables.append(self._get_one_freq_result_table(
                self._MI_TABLE_CLASS_FREQ_DURATION, begin_ns, end_ns,
                min, max, step, total_list, subtitle, 1000))
        return stats_table, freq_tables

    def _get_per_period_stats_result_table(self, begin_ns, end_ns,
                                           period_tree):
        stats_table = \
            self._mi_create_result_table(self._MI_TABLE_CLASS_PER_PERIOD_STATS,
                                         begin_ns, end_ns)

        period_stats_list = []
        for parent in period_tree.keys():
            self._get_ordered_period_stats_list(parent, period_stats_list,
                                                period_tree[parent])

        for period_stats in period_stats_list:
            if not period_stats.period_list:
                continue

            if self._args.min_duration is None and \
                    self._args.max_duration is None:
                stdev = self._compute_period_duration_stdev(
                    period_stats.period_list)
                min = period_stats.min_duration
                max = period_stats.max_duration
                count = period_stats.count
                total = period_stats.total_duration
                if count > 0:
                    avg = period_stats.total_duration / \
                        period_stats.count
                else:
                    avg = 0
            else:
                min, max, count, avg, total, period_list = \
                    self._get_filtered_min_max_count_avg_total_flist(
                        period_stats.period_list)
                stdev = self._compute_period_duration_stdev(period_list)

            if math.isnan(stdev):
                stdev = mi.Unknown()
            else:
                stdev = mi.Duration(stdev)

            stats_table.append_row(
                name=mi.String(self._get_full_period_path(period_stats.name)),
                count=mi.Number(count),
                min_duration=mi.Duration(min),
                avg_duration=mi.Duration(avg),
                max_duration=mi.Duration(max),
                stdev_duration=stdev,
                runtime=mi.Duration(total),
            )

        return stats_table

    def _get_one_aggregated_log_table(self, begin_ns, end_ns,
                                      per_parent_aggregated_dict, sub, top):
        table = self._mi_create_result_table(
            self._MI_TABLE_CLASS_AGGREGATED_LOG, begin_ns, end_ns,
            subtitle=sub)
        for parent_period in per_parent_aggregated_dict.keys():
            for child_period in \
                    per_parent_aggregated_dict[parent_period].keys():
                child_period_list = \
                    per_parent_aggregated_dict[parent_period][child_period]
                min, max, count, avg, total, period_list = \
                    self._get_agg_filtered_min_max_count_avg_total_flist(
                        child_period_list)
                stdev = self._compute_period_agg_duration_stdev(
                    child_period_list)

                if math.isnan(stdev):
                    stdev = mi.Unknown()
                else:
                    stdev = mi.Duration(stdev)

                table.append_row(
                    parent_begin_ts=mi.Timestamp(
                        parent_period.start_ts),
                    parent_end_ts=mi.Timestamp(
                        parent_period.end_ts),
                    parent_name=mi.String(parent_period.name),
                    child_name=mi.String(self._get_full_period_path(
                        child_period)),
                    count=mi.Number(count),
                    min_duration=mi.Duration(min),
                    avg_duration=mi.Duration(avg),
                    max_duration=mi.Duration(max),
                    runtime=mi.Duration(total),
                    parent_captures=mi.String(parent_period.full_captures()),
                    stdev_duration=stdev,
                )
        return table

    def _get_aggregated_log_table(self, begin_ns, end_ns,
                                  per_parent_aggregated_dict,
                                  aggregated_groups,
                                  top=False):
        result_tables = []
        ag_list = ""
        for i in self._analysis_conf._select:
            if len(ag_list) == 0:
                ag_list = i
            else:
                ag_list = "%s, %s" % (ag_list, i)
        sub = "Aggregation of (%s) by %s" % (
            ag_list, self._analysis_conf._aggregate_by)

        if aggregated_groups is None:
            table = self._get_one_aggregated_log_table(
                begin_ns, end_ns, per_parent_aggregated_dict, sub, top)
            result_tables.append(table)
        else:
            for group in aggregated_groups.keys():
                group_sub = "%s, group: %s" % (sub, group)
                result_tables.append(self._get_one_aggregated_log_table(
                    begin_ns, end_ns, aggregated_groups[group], group_sub,
                    top))

        return result_tables

    def _fill_freq_result_table(self, period_list, stats, min_duration,
                                max_duration, step, freq_table):
        # The number of bins for the histogram
        resolution = self._args.freq_resolution

        if not self._args.freq_uniform:
            if self._args.min is not None:
                min_duration = self._args.min
            else:
                min_duration = stats.min

            if self._args.max is not None:
                max_duration = self._args.max
            else:
                max_duration = stats.max

            # ns to µs
            if min_duration is None:
                min_duration = 0
            else:
                min_duration /= 1000

            if max_duration is None:
                max_duration = 0
            else:
                max_duration /= 1000

            step = (max_duration - min_duration) / resolution

        if step == 0:
            return

        buckets = []
        counts = []

        for i in range(resolution):
            buckets.append(i * step)
            counts.append(0)

        for period_event in period_list:
            if not self._filter_event_duration(period_event):
                continue
            duration = period_event.duration / 1000
            index = int((duration - min_duration) / step)

            if index >= resolution:
                # special case for max value: put in last bucket (includes
                # its upper bound)
                if duration == max_duration:
                    counts[index - 1] += 1

                continue

            counts[index] += 1

        for index, count in enumerate(counts):
            lower_bound = index * step + min_duration
            upper_bound = (index + 1) * step + min_duration
            freq_table.append_row(
                lower=mi.Duration.from_us(lower_bound),
                upper=mi.Duration.from_us(upper_bound),
                count=mi.Number(count),
            )

    def _fill_freq_result_table_values(self, values, min_duration,
                                       max_duration, step, freq_table, ratio):
        # Differ from _fill_freq_result_table because we work directly with
        # a list of values instead of periods.

        # The number of bins for the histogram
        resolution = self._args.freq_resolution

        if not self._args.freq_uniform:
            if self._args.min is not None:
                min_duration = self._args.min
            else:
                min_duration = min(values) / ratio

            if self._args.max is not None:
                max_duration = self._args.max
            else:
                max_duration = max(values) / ratio

            # ns to µs
            if min_duration is None:
                min_duration = 0

            if max_duration is None:
                max_duration = 0

            step = (max_duration - min_duration) / resolution

        if step == 0:
            return

        buckets = []
        counts = []

        for i in range(resolution):
            buckets.append(i * step)
            counts.append(0)

        for v in values:
            if not self._filter_duration(v):
                continue
            duration = v / ratio
            index = int((duration - min_duration) / step)

            if index >= resolution:
                # special case for max value: put in last bucket (includes
                # its upper bound)
                if duration == max_duration:
                    counts[index - 1] += 1

                continue

            counts[index] += 1

        for index, count in enumerate(counts):
            lower_bound = index * step + min_duration
            upper_bound = (index + 1) * step + min_duration
            freq_table.append_row(
                lower=mi.Duration.from_us(lower_bound),
                upper=mi.Duration.from_us(upper_bound),
                count=mi.Number(count),
            )

    def _get_total_freq_result_tables(self, begin_ns, end_ns):
        freq_tables = []
        period_lists, period_stats = self._get_total_period_lists_stats()
        min_duration = None
        max_duration = None
        step = None
        subtitle = 'All periods'

        if self._args.freq_uniform:
            durations = []

            for period_list in period_lists:
                for period_event in period_list:
                    if not self._filter_event_duration(period_event):
                        continue
                    durations.append(period_event.duration)

            min_duration, max_duration, step = \
                self._find_uniform_freq_values(durations)

        for period_list in period_lists:
            freq_table = \
                self._mi_create_result_table(
                    self._MI_TABLE_CLASS_FREQ_DURATION, begin_ns, end_ns,
                    subtitle)
            self._fill_freq_result_table(period_list, period_stats,
                                         min_duration, max_duration, step,
                                         freq_table)
            freq_tables.append(freq_table)

        return freq_tables

    def _get_period_lists_stats(self):
        period_lists = {}
        period_stats = {}

        for period in self._analysis.all_period_stats.keys():
            period_list = self._analysis.all_period_stats[period].period_list

            if not period_list:
                continue
            if self._args.min_duration is None and \
                    self._args.max_duration is None:
                stdev = self._compute_period_duration_stdev(period_list)
                count = len(period_list)
                min = self._analysis.all_period_stats[period].min_duration
                max = self._analysis.all_period_stats[period].max_duration
                total = \
                    self._analysis.all_period_stats[period].total_duration
            else:
                min, max, count, avg, total, period_list = \
                    self._get_filtered_min_max_count_avg_total_flist(
                        period_list)
                stdev = self._compute_period_duration_stdev(period_list)

            period_stats[period] = _PeriodStats(
                count=count, min=min, max=max, stdev=stdev, total=total)
            period_lists[period] = period_list

        return period_lists, period_stats

    def _find_table_min_max_step(self, table, ratio, category):
        _min = None
        max = 0
        # Find the uniform freq values across all parent/child combinations
        for period in table.keys():
            for child in table[period].keys():
                tmp_min, tmp_max, tmp_step = \
                    self._find_uniform_freq_values(
                        table[period][child], ratio, category)
                if _min is None or tmp_min < _min:
                    _min = tmp_min
                if tmp_max > max:
                    max = tmp_max
        if _min is None:
            steps = 0
        else:
            steps = (max - _min) / self._args.freq_resolution
        return _min, max, steps

    def _find_uniform_values(self, tables):
        if not self._args.freq_uniform:
            return None, None, None, None, None, None, \
                None, None, None, None, None, None, \
                None, None, None, None, None, None

        duration_min, duration_max, duration_step = \
            self._find_table_min_max_step(tables.duration_values, 1000,
                                          'duration')
        global_duration_min, global_duration_max, global_duration_step = \
            self._find_table_min_max_step(tables.global_duration_values, 1000,
                                          'global_duration')

        count_min, count_max, count_step = \
            self._find_table_min_max_step(tables.count_values, 1, 'count')
        global_count_min, global_count_max, global_count_step = \
            self._find_table_min_max_step(tables.global_count_values, 1,
                                          'global_count')

        pc_min, pc_max, pc_step = \
            self._find_table_min_max_step(tables.pc_values, 1, 'pc')
        global_pc_min, global_pc_max, global_pc_step = \
            self._find_table_min_max_step(tables.global_pc_values, 1,
                                          'global_pc')

        return duration_min, duration_max, duration_step, \
            global_duration_min, global_duration_max, \
            global_duration_step, \
            count_min, count_max, count_step, \
            global_count_min, global_count_max, \
            global_count_step, \
            pc_min, pc_max, pc_step, \
            global_pc_min, global_pc_max, \
            global_pc_step

    def _get_one_freq_result_table(self, mi_class, begin_ns, end_ns,
                                   min, max, step, values,
                                   subtitle, ratio=1):
        freq_table = \
            self._mi_create_result_table(mi_class, begin_ns, end_ns, subtitle)
        self._fill_freq_result_table_values(values, min, max, step,
                                            freq_table, ratio)
        return freq_table

    def _get_per_parent_freq_result_table(self, begin_ns, end_ns,
                                          tables, group_prefix=''):
        duration_min, duration_max, duration_step, \
            global_duration_min, global_duration_max, \
            global_duration_step, \
            count_min, count_max, count_step, \
            global_count_min, global_count_max, \
            global_count_step, \
            pc_min, pc_max, pc_step, \
            global_pc_min, global_pc_max, \
            global_pc_step = self._find_uniform_values(tables)

        # sorted to get the same output order between runs
        for period in sorted(tables.duration_values.keys()):
            for child in tables.duration_values[period].keys():
                subtitle = "%sDuration of %s per %s" % (
                    group_prefix,
                    self._get_full_period_path(child),
                    self._get_full_period_path(period))
                # ratio=1000 for ns -> us
                tables.per_parent_freq_tables.append(
                    self._get_one_freq_result_table(
                        self._MI_TABLE_CLASS_FREQ_DURATION,
                        begin_ns, end_ns, duration_min, duration_max,
                        duration_step, tables.duration_values[period][child],
                        subtitle, ratio=1000))

                subtitle = "%sNumber of %s per %s" % (
                    group_prefix,
                    self._get_full_period_path(child),
                    self._get_full_period_path(period))
                tables.per_parent_count_freq_tables.append(
                    self._get_one_freq_result_table(
                        self._MI_TABLE_CLASS_FREQ_COUNT,
                        begin_ns, end_ns, count_min, count_max, count_step,
                        tables.count_values[period][child],
                        subtitle))

                subtitle = "%sUsage ratio of %s per %s" % (
                    group_prefix,
                    self._get_full_period_path(child),
                    self._get_full_period_path(period))
                tables.per_parent_pc_freq_tables.append(
                    self._get_one_freq_result_table(
                        self._MI_TABLE_CLASS_FREQ_PC,
                        begin_ns, end_ns, pc_min, pc_max, pc_step,
                        tables.pc_values[period][child],
                        subtitle))

                subtitle = "%sGlobal duration of %s per %s" % (
                    group_prefix,
                    self._get_full_period_path(child),
                    self._get_full_period_path(period))
                # ratio=1000 for ns -> us
                tables.global_duration_freq_tables.append(
                    self._get_one_freq_result_table(
                        self._MI_TABLE_CLASS_FREQ_DURATION,
                        begin_ns, end_ns, global_duration_min,
                        global_duration_max, global_duration_step,
                        tables.global_duration_values[period][child],
                        subtitle, ratio=1000))

                subtitle = "%sGlobal number of %s per %s" % (
                    group_prefix,
                    self._get_full_period_path(child),
                    self._get_full_period_path(period))
                tables.global_count_freq_tables.append(
                    self._get_one_freq_result_table(
                        self._MI_TABLE_CLASS_FREQ_COUNT,
                        begin_ns, end_ns, global_count_min, global_count_max,
                        global_count_step,
                        tables.global_count_values[period][child],
                        subtitle))

                subtitle = "%sGlobal usage ratio of %s per %s" % (
                    group_prefix,
                    self._get_full_period_path(child),
                    self._get_full_period_path(period))
                tables.global_pc_freq_tables.append(
                    self._get_one_freq_result_table(
                        self._MI_TABLE_CLASS_FREQ_PC,
                        begin_ns, end_ns, global_pc_min, global_pc_max,
                        global_pc_step,
                        tables.global_pc_values[period][child],
                        subtitle))

    def _get_per_period_freq_result_tables(self, begin_ns, end_ns):
        freq_tables = []
        period_lists, period_stats = self._get_period_lists_stats()
        min_duration = None
        max_duration = None
        step = None

        if self._args.freq_uniform:
            durations = []

            for period_list in period_lists.values():
                for period_event in period_list:
                    if not self._filter_event_duration(period_event):
                        continue
                    durations.append(period_event.duration)

            min_duration, max_duration, step = \
                self._find_uniform_freq_values(durations)

        for period in sorted(period_stats.keys()):
            period_list = period_lists[period]
            stats = period_stats[period]
            subtitle = 'Duration of period: {}'.format(period)
            freq_table = \
                self._mi_create_result_table(
                    self._MI_TABLE_CLASS_FREQ_DURATION, begin_ns, end_ns,
                    subtitle)
            self._fill_freq_result_table(period_list, stats,
                                         min_duration, max_duration, step,
                                         freq_table)
            freq_tables.append(freq_table)

        return freq_tables

    def _compute_period_duration_stdev_values(self, durations):
        period_durations = []
        for d in durations:
            if not self._filter_duration(d):
                continue
            period_durations.append(d)
        if len(period_durations) < 2:
            return float('nan')
        return statistics.stdev(period_durations)

    def _compute_period_duration_stdev(self, period_events):
        period_durations = []
        for period_event in period_events:
            if not self._filter_event_duration(period_event):
                continue
            period_durations.append(period_event.duration)
        if len(period_durations) < 2:
            return float('nan')
        return statistics.stdev(period_durations)

    def _compute_period_agg_duration_stdev(self, period_agg_events):
        period_durations = []
        for period_event in period_agg_events:
            if not self._filter_event_duration(period_event.event):
                continue
            period_durations.append(period_event.event.duration)
        if len(period_durations) < 2:
            return float('nan')
        return statistics.stdev(period_durations)

    def _pop_next_capture_string(self, begin_captures, end_captures):
        if len(begin_captures.keys()) > 0:
            b_key, b_value = begin_captures.popitem()
            b_string = '%s = %s' % (b_key, b_value)
        else:
            b_string = ''

        if len(end_captures.keys()) > 0:
            e_key, e_value = end_captures.popitem()
            e_string = '%s = %s' % (e_key, e_value)
        else:
            e_string = ''

        return b_string, e_string

    def _print_period_events(self, result_table):
        fmt = '[{:<18}, {:<18}] {:>15} {:<24} {:<35} {:<35}'
        fmt_captures = '{:<18} {:<18} {:>18} {:<24} {:<35} {:<35}'
        title_fmt = '{:<20} {:<19} {:>15} {:<24} {:<35} {:<35}'
        print()
        print(result_table.title)
        print(title_fmt.format('Begin', 'End', 'Duration (us)', 'Name',
                               'Begin capture', 'End capture'))
        for row in result_table.rows:
            begin_ts = row.begin_ts.value
            end_ts = row.end_ts.value
            duration = row.duration.value
            name = row.name.value
            if name is None:
                name = ''

            # Convert back the string to dict
            begin_captures = ast.literal_eval(row.begin_captures.value)
            # Order the dict based on keys to always get the same output
            if begin_captures is None:
                begin_captures = {}
            begin_captures = collections.OrderedDict(
                sorted(begin_captures.items()))
            end_captures = ast.literal_eval(row.end_captures.value)
            if end_captures is None:
                end_captures = {}
            end_captures = collections.OrderedDict(
                sorted(end_captures.items()))

            b_string, e_string = self._pop_next_capture_string(begin_captures,
                                                               end_captures)

            print(fmt.format(self._format_timestamp(begin_ts),
                             self._format_timestamp(end_ts),
                             '%0.03f' % (duration / 1000), name,
                             b_string, e_string))

            nr_lines = max(len(begin_captures.keys()),
                           len(end_captures.keys()))
            for i in range(nr_lines):
                b_string, e_string = self._pop_next_capture_string(
                    begin_captures, end_captures)
                print(fmt_captures.format('', '', '', '', b_string, e_string))

    def _print_aggregated_period_events(self, result_tables):
        fmt = '[{:<18}, {:<18}] {:>22} {:<15} [{:<18}, {:<18}] {:>22} ' \
            '{:<15} {:<35}'
#        fmt_captures = '{:<18} {:<18} {:>25} {:<15} {:<18} {:<25} {:>18} ' \
#            '{:<15} {:<35}'
        title_fmt = '{:<20} {:<19} {:>22} {:<15} {:<20} {:<19} {:>22} ' \
            '{:<15} {:<35}'
        for result_table in result_tables:
            print()
            print(result_table.title)
            print(result_table.subtitle)
            print(title_fmt.format('Parent begin', 'Parent end',
                                   'Parent duration (us)', 'Parent name',
                                   'Child begin', 'Child end',
                                   'Child duration (us)', 'Child name',
                                   'Captures'))
            for row in result_table.rows:
                parent_begin_ts = row.parent_begin_ts.value
                parent_end_ts = row.parent_end_ts.value
                parent_duration = row.parent_duration.value
                parent_name = row.parent_name.value
                child_begin_ts = row.child_begin_ts.value
                child_end_ts = row.child_end_ts.value
                child_duration = row.child_duration.value
                child_name = row.child_name.value

                # Convert back the string to list of tuple
                captures = ast.literal_eval(row.captures.value)
                # Order the dict based on keys to always get the same output
#                if captures is None:
#                    captures = []
#                    capture_str = ''
#                else:
#                    captures = sorted(captures, key=lambda x: x[0])
#                    captures.reverse()
#                    tmp = captures.pop()
#                    capture_str = "%s = %s" % (tmp[0], tmp[1])
                capture_str = ''
                for i in sorted(captures, key=lambda x: x[0]):
                    if len(capture_str) == 0:
                        capture_str = "%s = %s" % (i[0], i[1])
                    else:
                        capture_str = "%s, %s = %s" % (capture_str, i[0], i[1])

                print(fmt.format(self._format_timestamp(parent_begin_ts),
                                 self._format_timestamp(parent_end_ts),
                                 '%0.03f' % (parent_duration / 1000),
                                 parent_name,
                                 self._format_timestamp(child_begin_ts),
                                 self._format_timestamp(child_end_ts),
                                 '%0.03f' % (child_duration / 1000),
                                 child_name,
                                 capture_str))
#                for i in range(len(captures)):
#                    tmp = captures.pop()
#                    capture_str = "%s = %s" % (tmp[0], tmp[1])
#                    print(fmt_captures.format('', '', '', '', '', '', '', '',
#                                              capture_str))

    def _print_total_stats(self, stats_table):
        row_format = '{:<12} {:<12} {:<12} {:<12} {:<12}'
        header = row_format.format(
            'Count', 'Min', 'Avg', 'Max', 'Stdev'
        )

        if stats_table.rows:
            print()
            print(stats_table.title + ' (us)')
            print(header)
            for row in stats_table.rows:
                if type(row.stdev_duration) is mi.Unknown:
                    stdev_str = '?'
                else:
                    stdev_str = '%0.03f' % row.stdev_duration.to_us()

                row_str = row_format.format(
                    '%d' % row.count.value,
                    '%0.03f' % row.min_duration.to_us(),
                    '%0.03f' % row.avg_duration.to_us(),
                    '%0.03f' % row.max_duration.to_us(),
                    '%s' % stdev_str,
                )

                print(row_str)

    def _print_period_tree(self, period_tree, level):
        for parent in period_tree.keys():
            if level == 0:
                lines = ''
            else:
                lines = "%s|-- " % ((level - 1) * 4 * ' ')
            print("%s%s" % (lines, parent))
            for child in period_tree[parent]:
                self._print_period_tree(period_tree[parent], level + 1)

    def _print_per_period_stats(self, stats_table, period_tree):
        row_format = '{:<25} {:>8}  {:>12}  {:>12}  {:>12}  {:>12} {:>12}'
        header = row_format.format(
            'Period', 'Count', 'Min', 'Avg', 'Max', 'Stdev', 'Runtime'
        )

        print("Period tree:")
        self._print_period_tree(period_tree, 0)

        if stats_table.rows:
            print()
            print(stats_table.title + ' (us)')
            print(header)
            for row in stats_table.rows:
                if type(row.stdev_duration) is mi.Unknown:
                    stdev_str = '?'
                else:
                    stdev_str = '%0.03f' % row.stdev_duration.to_us()

                row_str = row_format.format(
                    '%s' % row.name,
                    '%d' % row.count.value,
                    '%0.03f' % row.min_duration.to_us(),
                    '%0.03f' % row.avg_duration.to_us(),
                    '%0.03f' % row.max_duration.to_us(),
                    '%s' % stdev_str,
                    '%0.03f' % row.runtime.to_us(),
                )

                print(row_str)

    def _print_per_parent_stats(self, table):
        row_format = '{:<25} {:<25}  {:>12}  {:>12}  {:>12}  {:>12}'
        header = row_format.format(
            'Period', 'Parent', 'Min', 'Avg', 'Max', 'Stdev'
        )
        if table.rows:
            print()
            print(table.title + ' (us)')
            print(table.subtitle)
            print(header)
            for row in table.rows:
                if type(row.stdev_duration) is mi.Unknown:
                    stdev_str = '?'
                else:
                    stdev_str = '%0.03f' % row.stdev_duration.to_us()
                row_str = row_format.format(
                    '%s' % row.name,
                    '%s' % row.parent,
                    '%0.03f' % row.min_duration.to_us(),
                    '%0.03f' % row.avg_duration.to_us(),
                    '%0.03f' % row.max_duration.to_us(),
                    '%s' % stdev_str,
                )
                print(row_str)

    def _print_per_parent_count(self, table):
        row_format = '{:<25} {:<25}  {:>12}  {:>12}  {:>12}  {:>12}'
        header = row_format.format(
            'Period', 'Parent', 'Min', 'Avg', 'Max', 'Stdev'
        )
        if table.rows:
            print()
            print(table.title)
            print(table.subtitle)
            print(header)
            for row in table.rows:
                if type(row.stdev) is mi.Unknown:
                    stdev_str = '?'
                else:
                    stdev_str = "%0.03f" % row.stdev.value
                row_str = row_format.format(
                    '%s' % row.name,
                    '%s' % row.parent,
                    '%d' % row.min.value,
                    '%0.03f' % row.avg.value,
                    '%d' % row.max.value,
                    '%s' % stdev_str,
                )
                print(row_str)

    def _print_per_parent_pc(self, table):
        row_format = '{:<25} {:<25}  {:>12}  {:>12}  {:>12}  {:>12}'
        header = row_format.format(
            'Period', 'Parent', 'Min', 'Avg', 'Max', 'Stdev'
        )
        if table.rows:
            print()
            print(table.title + ' (%)')
            print(table.subtitle)
            print(header)
            for row in table.rows:
                if type(row.stdev) is mi.Unknown:
                    stdev_str = '?'
                else:
                    stdev_str = "%0.03f" % row.stdev.value
                row_str = row_format.format(
                    '%s' % row.name,
                    '%s' % row.parent,
                    '%d' % row.min.value,
                    '%0.03f' % row.avg.value,
                    '%d' % row.max.value,
                    '%s' % stdev_str,
                )
                print(row_str)

    def _one_line_captures(self, capture_tuple_list):
        capture_str = None
        for item in capture_tuple_list:
            if capture_str is None:
                capture_str = "%s = %s" % (item[0], item[1])
                continue
            capture_str = "%s, %s = %s" % (capture_str, item[0], item[1])
        return capture_str

    def _print_aggregated_log(self, stats_tables):
        fmt = '[{:<18}, {:<18}] {:>18} {:<15} {:<24} {:>12} | {:>10} ' \
            '{:>12} {:>12} {:>12} {:>13} | {:>12}'
        title_fmt = '{:<20} {:<19} {:>18} {:<15} {:<24} {:>12} | {:>10} ' \
            '{:>12} {:>12} {:>13} {:>12} | {:>12}'
        high_title_fmt = '{:<35} Parent {:<32} | {:<35} | {:<25} ' \
            'Durations (us) {:<22} |'
        for stats_table in stats_tables:
            print()
            print(stats_table.title)
            print(stats_table.subtitle)
            print(high_title_fmt.format('', '', '', '', ''))
            print(title_fmt.format('Begin', 'End',
                                   'Duration (us)', 'Name',
                                   '| Child name', 'Count', 'Min', 'Avg',
                                   'Max', 'Stdev', 'Runtime',
                                   'Parent captures'))

            for row in stats_table.rows:
                parent_begin_ts = row.parent_begin_ts.value
                parent_end_ts = row.parent_end_ts.value
                parent_duration = parent_end_ts - parent_begin_ts
                parent_name = row.parent_name.value
                child_name = row.child_name.value
                captures = self._one_line_captures(row.parent_captures.value)
                if type(row.stdev_duration) is mi.Unknown:
                    stdev_str = '?'
                else:
                    stdev_str = '%0.03f' % row.stdev_duration.to_us()

                row_str = fmt.format(
                    self._format_timestamp(parent_begin_ts),
                    self._format_timestamp(parent_end_ts),
                    '%0.03f' % (parent_duration / 1000),
                    parent_name,
                    '| %s' % child_name,
                    '%d' % row.count.value,
                    '%0.03f' % row.min_duration.to_us(),
                    '%0.03f' % row.avg_duration.to_us(),
                    '%0.03f' % row.max_duration.to_us(),
                    '%s' % stdev_str,
                    '%0.03f' % row.runtime.to_us(),
                    '%s' % captures,
                )

                print(row_str)

    def _print_frequency_distribution(self, freq_table, unit):
        title_fmt = '{} - {}'

        graph = termgraph.FreqGraph(
            data=freq_table.rows,
            get_value=lambda row: row.count.value,
            get_lower_bound=lambda row: row.lower.to_us(),
            title=title_fmt.format(freq_table.title, freq_table.subtitle),
            unit=unit,
        )

        graph.print_graph()

    def _print_freq(self, freq_tables, unit):
        for freq_table in freq_tables:
            self._print_frequency_distribution(freq_table, unit)

    def _validate_transform_args(self):
        args = self._args
        self._analysis_conf._group_by = {}
        self._analysis_conf._aggregate_by = None
        self._analysis_conf._select = []
        self._analysis_conf._order_by = None

        if args.group_by:
            for group in args.group_by.split(','):
                g = group.strip()
                if len(g) == 0:
                    continue
                _period_name = g.split('.')[0]
                _period_field = g.split('.')[1]
                if _period_name not in \
                        self._analysis_conf._group_by.keys():
                    self._analysis_conf._group_by[_period_name] = []
                self._analysis_conf._group_by[_period_name]. \
                    append(_period_field)

        if args.order_by:
            if args.order_by not in ['time', 'hierarchy']:
                self._gen_error("Invalid order-by value")
            self._analysis_conf._order_by = args.order_by

        # TODO: check aggregation and group-by attributes are valid
        if args.select:
            for ag in args.select.split(','):
                self._analysis_conf._select.append(ag.strip())
        self._analysis_conf._aggregate_by = args.aggregate_by

    def _add_arguments(self, ap):
        Command._add_min_max_args(ap)
        Command._add_freq_args(
            ap, help='Output statistics about periods durations')
        Command._add_top_args(ap, help='Output the top sched switch durations')
        Command._add_log_args(
            ap, help='Output the sched switches in chronological order')
        Command._add_stats_args(ap, help='Output sched switch statistics')
        ap.add_argument('--min-duration', type=float,
                        help='Filter out, periods shorter that duration '
                             '(usec)')
        ap.add_argument('--max-duration', type=float,
                        help='Filter out, periods longer than duration (usec)')
        ap.add_argument('--aggregate-by', type=str,
                        help='FIXME')
        ap.add_argument('--select', type=str,
                        help='FIXME')
        ap.add_argument('--group-by', type=str,
                        help='Present the results grouped by a list of fields'
                             '(period.captured_field'
                             '[, period.captured_field2])')
        ap.add_argument('--order-by', type=str,
                        help='hierarchy, time')


def _run(mi_mode):
    schedcmd = PeriodAnalysisCommand(mi_mode=mi_mode)
    schedcmd.run()


def _runstats(mi_mode):
    sys.argv.insert(1, '--stats')
    _run(mi_mode)


def _runlog(mi_mode):
    sys.argv.insert(1, '--log')
    _run(mi_mode)


def _runtop(mi_mode):
    sys.argv.insert(1, '--top')
    _run(mi_mode)


def _runfreq(mi_mode):
    sys.argv.insert(1, '--freq')
    _run(mi_mode)


def runstats():
    _runstats(mi_mode=False)


def runlog():
    _runlog(mi_mode=False)


def runtop():
    _runtop(mi_mode=False)


def runfreq():
    _runfreq(mi_mode=False)


def runstats_mi():
    _runstats(mi_mode=True)


def runlog_mi():
    _runlog(mi_mode=True)


def runtop_mi():
    _runtop(mi_mode=True)


def runfreq_mi():
    _runfreq(mi_mode=True)
