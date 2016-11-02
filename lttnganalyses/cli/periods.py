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


class _TmpAggregation():
    def __init__(self, parent=None):
        # self._children[name] = [durations]
        self._children = {}
        self._parent = parent
        self.current_captures = None

    @property
    def children(self):
        return self._children

    def add_child(self, name, duration):
        if name not in self._children.keys():
            self._children[name] = []
        self._children[name].append(duration)

        if self._parent is not None:
            self._parent.add_child(name, duration)


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
            if child not in self._children.keys():
                continue
            count = len(child_dict[child])
            duration = 0
            for period in child_dict[child]:
                duration += period
            c = self._children[child]
            pc = (duration / parent_duration) * 100

            # Min/Max/Total count
            if c.min_count is None or count < c.min_count:
                c.min_count = count
            if c.max_count < count:
                c.max_count = count
            c.total_count += count
            c.count_array.append(count)

            # Min/Max/Total duration
            if c.min is None or duration < c.min:
                c.min = duration
            if c.max < duration:
                c.max = duration
            c.total += duration
            c.durations.append(duration)

            # Min/Max/Total percentage of parent
            if c.min_pc is None or pc < c.min_pc:
                c.min_pc = pc
            if c.max_pc < pc:
                c.max_pc = pc
            c.total_pc += pc
            c.pc_array.append(pc)

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
    _MI_TABLE_CLASS_FREQ = 'freq'
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
            _MI_TABLE_CLASS_FREQ,
            'Period duration frequency distribution', [
                ('duration_lower', 'Duration (lower bound)', mi.Duration),
                ('duration_upper', 'Duration (upper bound)', mi.Duration),
                ('count', 'Period count', mi.Number, 'occurences'),
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

    def _get_count(self, period_event):
        pass

    def _filter_duration(self, period_event):
        if self._args.min_duration is not None and \
                period_event.duration < (self._args.min_duration * 1000):
            return False
        if self._args.max_duration is not None and \
                period_event.duration > (self._args.max_duration * 1000):
            return False
        return True

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
        per_parent_stats_table = None
        per_parent_count_table = None
        per_period_freq_tables = None

        aggregated_groups = None
        hierarchical_list = None
        hierarchical_log_tables = None
        hierarchical_top_tables = None
        aggregated_log_tables = None
        per_parent_aggregated_dict = None

        period_tree = OrderedDict()
        reg = self._analysis_conf.period_def_registry
        for parent in reg.root_period_defs:
            self._get_period_tree(parent, period_tree)

        if self._args.select or self._args.order_by == "hierarchy" or \
                self._args.stats:
            per_parent_aggregated_dict, hierarchical_list, per_period_stats = \
                self._get_aggregated_lists()
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

        if self._args.stats:
            per_period_stats_table = \
                self._get_per_period_stats_result_table(begin_ns, end_ns,
                                                        period_tree)
            per_parent_stats_table, per_parent_count_table, \
                global_duration_table, global_count_table, \
                pc_table, global_pc_table = \
                self._get_per_parent_stats_result_table(begin_ns, end_ns,
                                                        per_period_stats)

        if self._args.freq:
            per_period_freq_tables = \
                self._get_per_period_freq_result_tables(begin_ns, end_ns)

        if self._mi_mode:
            if log_table:
                self._mi_append_result_table(log_table)

            if top_table:
                self._mi_append_result_table(top_table)

            if per_period_stats_table and per_period_stats_table.rows:
                self._mi_append_result_table(per_period_stats_table)

            if self._args.freq:
                self._mi_append_result_tables(per_period_freq_tables)
        else:
            self._print_date(begin_ns, end_ns)

            if self._args.stats:
                self._print_per_period_stats(per_period_stats_table,
                                             period_tree)
                self._print_per_parent_stats(per_parent_stats_table)
                self._print_per_parent_pc(pc_table)
                self._print_per_parent_count(per_parent_count_table)
                self._print_per_parent_stats(global_duration_table)
                self._print_per_parent_pc(global_pc_table)
                self._print_per_parent_count(global_count_table)

            if self._args.freq:
                self._print_freq(per_period_freq_tables)

            if log_table:
                self._print_period_events(log_table)

            if top_table:
                self._print_period_events(top_table)

            if hierarchical_log_tables:
                self._print_aggregated_period_events(hierarchical_log_tables)

            if hierarchical_top_tables:
                self._print_aggregated_period_events(hierarchical_top_tables)

            if aggregated_log_tables:
                self._print_aggregated_log(aggregated_log_tables)

    def _get_filtered_min_max_count_avg_total_flist(self, period_list):
        min = None
        max = None
        count = 0
        avg = 0
        total = 0
        filter_list = []
        for period_event in period_list:
            if not self._filter_duration(period_event):
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
            if not self._filter_duration(period_event):
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
                                             group_by_captures, full_captures)

    def _hierarchical_sub(self, tmp_hierarchical_list, event, per_period_stats,
                          parent_captures, per_period_group_by_stats,
                          active_periods):
        tmp_hierarchical_list.append(event)

        self._check_period_by_group(
            event,
            self._get_group_by_dict(per_period_group_by_stats,
                                    parent_captures))
        child_captures = self._append_captures(event, parent_captures)
        active_periods[event].current_captures = child_captures

        # Recursively iterate over all the children of this period.
        for child in event.children:
            if child.name not in per_period_stats.keys():
                per_period_stats[child.name] = _AggregatedPeriodStats(
                    self._analysis_conf.period_def_registry,
                    child.name)
            active_periods[event].add_child(child.name, child.duration)
            active_periods[child] = _TmpAggregation(active_periods[event])
            self._hierarchical_sub(
                tmp_hierarchical_list, child, per_period_stats,
                child_captures, per_period_group_by_stats,
                active_periods)
            del(active_periods[child])

        # Period is finished, account all we accumulated in the global
        # stats.
        per_period_stats[event.name].finish_period(
            event.start_ts, event.end_ts,
            active_periods[event].children)

        self._account_event_in_group(
            per_period_group_by_stats,
            child_captures, event, active_periods)

        # Return the new captures we discovered
        new_captures_list = []
        for c in child_captures:
            if c not in parent_captures:
                new_captures_list.append(c)
        parent = event.parent
        print(child_captures)
        if len(new_captures_list) > 0:
            while parent is not None:
                for c in new_captures_list:
                    print("Accounting %s in %s" % (parent.name, c))
                    self._account_event_in_group(
                        per_period_group_by_stats,
                        active_periods[event.parent].current_captures + [c],
                        parent, active_periods)
                parent = parent.parent

    def _account_event_in_group(self, per_period_group_by_stats, captures,
                                event, active_periods):
        # Check if the event name exists at all level of the group
        # chain and create it if necessary.
        d = per_period_group_by_stats
        for c in captures:
            group = d[c]
            if event.name not in group['per_period_stats'].keys():
                group['per_period_stats'][event.name] = _AggregatedPeriodStats(
                    self._analysis_conf.period_def_registry,
                    event.name)
            group['per_period_stats'][event.name].finish_period(
                event.start_ts, event.end_ts,
                active_periods[event].children)
            d = group

    def _check_period_by_group(self, event, group_by_stats,
                               extra_captures=None):
        # group_by_stats[capture1]...[capture-n][parent][child] = \
        #    _PeriodStats()
        grp_dict = group_by_stats
        captures = event.filtered_captures(self._analysis_conf._group_by)
        for c in captures:
            group_key = '%s = %s' % (c[0], c[1])
            if group_key not in grp_dict.keys():
                print("adding", group_key)
                grp_dict[group_key] = {}
                grp_dict[group_key]['per_period_stats'] = OrderedDict()
            grp_dict = grp_dict[group_key]

        if extra_captures is not None:
            for level in extra_captures:
                for group_key in level:
                    if group_key not in grp_dict.keys():
                        print("adding", group_key)
                        grp_dict[group_key] = {}
                        grp_dict[group_key]['per_period_stats'] = OrderedDict()
                grp_dict = grp_dict[group_key]

    def _get_group_by_dict(self, per_period_group_by_stats, captures):
        d = per_period_group_by_stats
        for c in captures:
            d = d[c]
        return d

    def _append_captures(self, event, captures=None):
        if captures is None:
            tmp_cap = []
        else:
            tmp_cap = captures.copy()
        for c in event.filtered_captures(self._analysis_conf._group_by):
            group_key = '%s = %s' % (c[0], c[1])
            tmp_cap.append(group_key)
        return tmp_cap

    def _print_dict(self, d, level=0):
        # Debug function
        for i in d.keys():
            spaces = ' ' * (level)
            if i == 'per_period_stats':
                sp1 = ' %s' % spaces
                print('%skeys:' % sp1)
                for k in d[i].keys():
                    print('%s  %s' % (spaces, k))
                    sp2 = ' %s' % sp1
                    for l in d[i][k]._children.keys():
                        print('%s %s = %s' % (
                            sp2, l, d[i][k]._children[l].count_array))
                continue
            print('%s- %s' % (spaces, i))
            self._print_dict(d[i], level + 1)

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
        per_period_group_by_stats = OrderedDict()
        # active_periods[period_event] = _TmpAggregation()
        active_periods = {}
        for period_event in self._analysis.all_period_list:
            if self._analysis_conf._order_by == "hierarchy" or \
                    self._args.stats:
                # Only top-level events
                if period_event.parent is None:
                    active_periods[period_event] = _TmpAggregation()
                    hierarchical_list.append(period_event)
                    parent_captures = self._append_captures(period_event)
                    active_periods[period_event].current_captures = \
                        parent_captures
                    if period_event.name not in per_period_stats.keys():
                        per_period_stats[period_event.name] = \
                            _AggregatedPeriodStats(
                                self._analysis_conf.period_def_registry,
                                period_event.name)

                    tmp_hierarchical_list = []
                    self._check_period_by_group(
                        period_event, per_period_group_by_stats)
                    self._hierarchical_sub(
                        tmp_hierarchical_list, period_event, per_period_stats,
                        parent_captures,
                        per_period_group_by_stats,
                        active_periods)
#                    self._check_period_by_group(
#                            period_event,
#                            per_period_group_by_stats,
#                            sub_level_captures)
#                    self._account_event_in_group(
#                        per_period_group_by_stats,
#                        parent_captures + sub_level_captures,
#                        period_event, active_periods)
                    del(active_periods[period_event])
                    for item in tmp_hierarchical_list:
                        hierarchical_list.append(item)

            if period_event.name != self._analysis_conf._aggregate_by:
                continue
            if not self._filter_duration(period_event):
                continue
            if period_event not in parent_aggregated_dict.keys():
                parent_aggregated_dict[period_event] = {}
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
#        self._print_dict(per_period_group_by_stats)
        return ordered_parent, hierarchical_list, per_period_stats

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

    def _get_hierarchical_log_top_result_table(self, begin_ns, end_ns,
                                               aggregated_list,
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
            if not self._filter_duration(period_event):
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
            if not self._filter_duration(period_event):
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
        for child in period_tree.keys():
            self._get_ordered_period_stats_list(child, period_stats_list,
                                                period_tree[child])

    def _get_per_parent_stats_result_table(self, begin_ns, end_ns,
                                           per_period_stats):
        duration_table = self._mi_create_result_table(
            self._MI_TABLE_CLASS_PER_PARENT_STATS, begin_ns, end_ns,
            subtitle="With active children")
        count_table = self._mi_create_result_table(
            self._MI_TABLE_CLASS_PER_PARENT_COUNT, begin_ns, end_ns,
            subtitle="With active children")
        global_duration_table = self._mi_create_result_table(
            self._MI_TABLE_CLASS_PER_PARENT_STATS, begin_ns, end_ns,
            subtitle="Globally")
        global_count_table = self._mi_create_result_table(
            self._MI_TABLE_CLASS_PER_PARENT_COUNT, begin_ns, end_ns,
            subtitle="Globally")
        pc_table = self._mi_create_result_table(
            self._MI_TABLE_CLASS_PER_PARENT_PC, begin_ns, end_ns,
            subtitle="With active children")
        global_pc_table = self._mi_create_result_table(
            self._MI_TABLE_CLASS_PER_PARENT_PC, begin_ns, end_ns,
            subtitle="Globally")
        for period in per_period_stats.keys():
            for child in per_period_stats[period]._children.keys():
                c = per_period_stats[period]._children[child]
                if per_period_stats[period].nr_periods == 0:
                    global_duration_avg = 0
                    global_count_avg = 0
                    duration_avg = 0
                    count_avg = 0
                    pc_avg = 0
                else:
                    global_duration_avg = c.total / \
                        per_period_stats[period].nr_periods
                    global_count_avg = c.total_count / \
                        per_period_stats[period].nr_periods
                    duration_avg = c.total / c.parent_count[period]
                    count_avg = c.total_count / c.parent_count[period]
                    pc_avg = c.total_pc / c.parent_count[period]
                    global_pc_avg = c.total_pc / \
                        per_period_stats[period].nr_periods

                if per_period_stats[period].nr_periods > 2:
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
                if c.parent_count[period] < \
                        per_period_stats[period].nr_periods:
                    global_min = 0
                    global_min_count = 0
                    global_min_pc = 0
                    for i in range(per_period_stats[period].nr_periods -
                                   c.parent_count[period]):
                        global_durations.append(0)
                        global_count_array.append(0)
                        global_pc_array.append(0)
                else:
                    global_min = c.min
                    global_min_count = c.min_count
                    global_min_pc = c.min_pc

                if per_period_stats[period].nr_periods > 2:
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
        return duration_table, count_table, global_duration_table, \
            global_count_table, pc_table, global_pc_table

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
            if not self._filter_duration(period_event):
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
                duration_lower=mi.Duration.from_us(lower_bound),
                duration_upper=mi.Duration.from_us(upper_bound),
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
                    if not self._filter_duration(period_event):
                        continue
                    durations.append(period_event.duration)

            min_duration, max_duration, step = \
                self._get_uniform_freq_values(durations)

        for period_list in period_lists:
            freq_table = \
                self._mi_create_result_table(self._MI_TABLE_CLASS_FREQ,
                                             begin_ns, end_ns, subtitle)
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
                count=count,
                min=min,
                max=max,
                stdev=stdev,
                total=total,
            )
            period_lists[period] = period_list

        return period_lists, period_stats

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
                    if not self._filter_duration(period_event):
                        continue
                    durations.append(period_event.duration)

            min_duration, max_duration, step = \
                self._get_uniform_freq_values(durations)

        for period in sorted(period_stats.keys()):
            period_list = period_lists[period]
            stats = period_stats[period]
            subtitle = 'Period: {}'.format(period)
            freq_table = \
                self._mi_create_result_table(self._MI_TABLE_CLASS_FREQ,
                                             begin_ns, end_ns, subtitle)
            self._fill_freq_result_table(period_list, stats,
                                         min_duration, max_duration, step,
                                         freq_table)
            freq_tables.append(freq_table)

        return freq_tables

    def _compute_period_duration_stdev(self, period_events):
        period_durations = []
        for period_event in period_events:
            if not self._filter_duration(period_event):
                continue
            period_durations.append(period_event.duration)
        if len(period_durations) < 2:
            return float('nan')
        return statistics.stdev(period_durations)

    def _compute_period_agg_duration_stdev(self, period_agg_events):
        period_durations = []
        for period_event in period_agg_events:
            if not self._filter_duration(period_event.event):
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

    def _print_frequency_distribution(self, freq_table):
        title_fmt = 'Periods duration frequency distribution - {}'

        graph = termgraph.FreqGraph(
            data=freq_table.rows,
            get_value=lambda row: row.count.value,
            get_lower_bound=lambda row: row.duration_lower.to_us(),
            title=title_fmt.format(freq_table.subtitle),
            unit='µs'
        )

        graph.print_graph()

    def _print_freq(self, freq_tables):
        for freq_table in freq_tables:
            self._print_frequency_distribution(freq_table)

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
