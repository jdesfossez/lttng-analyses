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
from ..core import io
from ..linuxautomaton import common
from ..ascii_graph import Pyasciigraph
import operator
import statistics


class IoAnalysisCommand(Command):
    _DESC = """The I/O command."""

    _LATENCY_STATS_FORMAT = '{:<14} {:>14} {:>14} {:>14} {:>14} {:>14}'
    _SECTION_SEPARATOR_STRING = '-' * 89

    def __init__(self):
        super().__init__(self._add_arguments,
                         enable_proc_filter_args=True,
                         enable_max_min_args=True,
                         enable_max_min_size_arg=True,
                         enable_log_arg=True)

    def _validate_transform_args(self):
        self._arg_usage = self._args.usage
        self._arg_stats = self._args.latencystats
        self._arg_latencytop = self._args.latencytop
        self._arg_freq = self._args.latencyfreq
        self._arg_freq_resolution = self._args.freq_resolution

    def _default_args(self, stats, log, freq, usage, latencytop):
        if stats:
            self._arg_stats = True
        if log:
            self._arg_log = True
        if freq:
            self._arg_freq = True
        if usage:
            self._arg_usage = True
        if latencytop:
            self._arg_latencytop = True

    def run(self, stats=False, log=False, freq=False, usage=False,
            latencytop=False):
        # parse arguments first
        self._parse_args()
        # validate, transform and save specific arguments
        self._validate_transform_args()
        # handle the default args for different executables
        self._default_args(stats, log, freq, usage, latencytop)
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

    def run_latencytop(self):
        self.run(latencytop=True)

    def run_log(self):
        self.run(log=True)

    def run_freq(self):
        self.run(freq=True)

    def run_usage(self):
        self.run(usage=True)

    def _create_analysis(self):
        self._analysis = io.IoAnalysis(self.state)

    def _refresh(self, begin, end):
        self._print_results(begin, end)
        self._reset_total(end)

    # Filter predicates
    def _filter_size(self, size):
        if size is None:
            return True
        if self._arg_maxsize is not None and size > self._arg_maxsize:
            return False
        if self._arg_minsize is not None and size < self._arg_minsize:
            return False
        return True

    def _filter_latency(self, duration):
        if self._arg_max is not None and (duration/1000) > self._arg_max:
            return False
        if self._arg_min is not None and (duration/1000) < self._arg_min:
            return False
        return True

    def _filter_time_range(self, begin, end):
        return not (self._arg_begin and self._arg_end and end and
                    begin > self._arg_end)

    def _filter_io_request(self, io_rq):
        if io_rq.tid in self._analysis.tids:
            proc = self._analysis.tids[io_rq.tid]
        else:
            proc = None
        return self._filter_process(proc) and \
            self._filter_size(io_rq.size) and \
            self._filter_latency(io_rq.duration) and \
            self._filter_time_range(io_rq.begin_ts, io_rq.end_ts)

    def _is_io_rq_out_of_range(self, io_rq):
        return self._arg_begin and io_rq.begin_ts < self._arg_begin or \
            self._arg_end and io_rq.end_ts > self._arg_end

    def _print_ascii_graph(self, input_list, get_datum_cb, graph_label,
                           graph_args=None):
        """Print an ascii graph for given data

        This method wraps the ascii_graph module and facilitates the
        printing of a graph with a limited number of lines.

        Args:
            input_list (list): A list of objects from which the data
            for the graph will be generated.

            get_datum_cb (function): function that takes a single
            object from the input list as an argument, and returns a
            datum tuple for the graph, of the form (string, int). The
            string element is printed as is in the graph, and the int
            is the numeric value corresponding to this graph entry.

            graph_label (string): Label used to identify the printed
            graph.

            graph_args (dict, optional): Dict of keyword args to be
            passed to the graph() function as is.
        """
        count = 0
        limit = self._arg_limit
        graph = Pyasciigraph()
        data = []
        if graph_args is None:
            graph_args = {}

        for elem in input_list:
            datum = get_datum_cb(elem)
            if datum is not None:
                data.append(datum)
                count += 1
                if limit is not None and count >= limit:
                    break

        for line in graph.graph(graph_label, data, **graph_args):
            print(line)

    # I/O Top output methods
    def _get_read_datum(self, proc_stats):
        if not self._filter_process(proc_stats):
            return None

        if proc_stats.pid is None:
            pid_str = 'unknown (tid=%d)' % (proc_stats.tid)
        else:
            pid_str = str(proc_stats.pid)

        format_str = '{:>10} {:<25} {:>9} file {:>9} net {:>9} unknown'
        output_str = format_str.format(
            common.convert_size(proc_stats.total_read, padding_after=True),
            '%s (%s)' % (proc_stats.comm, pid_str),
            common.convert_size(proc_stats.disk_read, padding_after=True),
            common.convert_size(proc_stats.net_read, padding_after=True),
            common.convert_size(proc_stats.unk_read, padding_after=True))

        return (output_str, proc_stats.total_read)

    def _get_write_datum(self, proc_stats):
        if not self._filter_process(proc_stats):
            return None

        if proc_stats.pid is None:
            pid_str = 'unknown (tid=%d)' % (proc_stats.tid)
        else:
            pid_str = str(proc_stats.pid)

        format_str = '{:>10} {:<25} {:>9} file {:>9} net {:>9} unknown'
        output_str = format_str.format(
            common.convert_size(proc_stats.total_write, padding_after=True),
            '%s (%s)' % (proc_stats.comm, pid_str),
            common.convert_size(proc_stats.disk_write, padding_after=True),
            common.convert_size(proc_stats.net_write, padding_after=True),
            common.convert_size(proc_stats.unk_write, padding_after=True))

        return (output_str, proc_stats.total_write)

    def _get_block_read_datum(self, proc_stats):
        if not self._filter_process(proc_stats) or proc_stats.block_read == 0:
            return None

        comm = proc_stats.comm
        if not comm:
            comm = 'unknown'

        if proc_stats.pid is None:
            pid_str = 'unknown (tid=%d)' % (proc_stats.tid)
        else:
            pid_str = str(proc_stats.pid)

        format_str = '{:>10} {:<22}'
        output_str = format_str.format(
            common.convert_size(proc_stats.block_read, padding_after=True),
            '%s (pid=%s)' % (comm, pid_str))

        return (output_str, proc_stats.block_read)

    def _get_block_write_datum(self, proc_stats):
        if not self._filter_process(proc_stats) or \
           proc_stats.block_write == 0:
            return None

        comm = proc_stats.comm
        if not comm:
            comm = 'unknown'

        if proc_stats.pid is None:
            pid_str = 'unknown (tid=%d)' % (proc_stats.tid)
        else:
            pid_str = str(proc_stats.pid)

        format_str = '{:>10} {:<22}'
        output_str = format_str.format(
            common.convert_size(proc_stats.block_write, padding_after=True),
            '%s (pid=%s)' % (comm, pid_str))

        return (output_str, proc_stats.block_write)

    def _get_total_rq_sectors_datum(self, disk):
        if disk.total_rq_sectors == 0:
            return None

        return (disk.disk_name, disk.total_rq_sectors)

    def _get_rq_count_datum(self, disk):
        if disk.rq_count == 0:
            return None

        return (disk.disk_name, disk.rq_count)

    def _get_avg_disk_latency_datum(self, disk):
        if disk.rq_count == 0:
            return None

        avg_latency = ((disk.total_rq_duration / disk.rq_count) /
                       common.MSEC_PER_NSEC)
        avg_latency = round(avg_latency, 3)

        return ('%s' % disk.disk_name, avg_latency)

    def _get_net_recv_bytes_datum(self, iface):
        return ('%s %s' % (common.convert_size(iface.recv_bytes), iface.name),
                iface.recv_bytes)

    def _get_net_sent_bytes_datum(self, iface):
        return ('%s %s' % (common.convert_size(iface.sent_bytes), iface.name),
                iface.sent_bytes)

    def _get_file_read_datum(self, file_stats):
        if file_stats.read == 0:
            return None

        fd_by_pid_str = ''
        for pid, fd in file_stats.fd_by_pid.items():
            comm = self._analysis.tids[pid].comm
            fd_by_pid_str += 'fd %d in %s (%s) ' % (fd, comm, pid)

        format_str = '{:>10} {} {}'
        output_str = format_str.format(
            common.convert_size(file_stats.read, padding_after=True),
            file_stats.filename,
            fd_by_pid_str)

        return (output_str, file_stats.read)

    def _get_file_write_datum(self, file_stats):
        if file_stats.write == 0:
            return None

        fd_by_pid_str = ''
        for pid, fd in file_stats.fd_by_pid.items():
            comm = self._analysis.tids[pid].comm
            fd_by_pid_str += 'fd %d in %s (%s) ' % (fd, comm, pid)

        format_str = '{:>10} {} {}'
        output_str = format_str.format(
            common.convert_size(file_stats.write, padding_after=True),
            file_stats.filename,
            fd_by_pid_str)

        return (output_str, file_stats.write)

    def _output_read(self):
        input_list = sorted(self._analysis.tids.values(),
                            key=operator.attrgetter('total_read'),
                            reverse=True)
        label = 'Per-process I/O Read'
        graph_args = {'with_value': False}
        self._print_ascii_graph(input_list, self._get_read_datum, label,
                                graph_args)

    def _output_write(self):
        input_list = sorted(self._analysis.tids.values(),
                            key=operator.attrgetter('total_write'),
                            reverse=True)
        label = 'Per-process I/O Write'
        graph_args = {'with_value': False}
        self._print_ascii_graph(input_list, self._get_write_datum, label,
                                graph_args)

    def _output_block_read(self):
        input_list = sorted(self._analysis.tids.values(),
                            key=operator.attrgetter('block_read'),
                            reverse=True)
        label = 'Block I/O Read'
        graph_args = {'with_value': False}
        self._print_ascii_graph(input_list, self._get_block_read_datum,
                                label, graph_args)

    def _output_block_write(self):
        input_list = sorted(self._analysis.tids.values(),
                            key=operator.attrgetter('block_write'),
                            reverse=True)
        label = 'Block I/O Write'
        graph_args = {'with_value': False}
        self._print_ascii_graph(input_list, self._get_block_write_datum,
                                label, graph_args)

    def _output_total_rq_sectors(self):
        input_list = sorted(self._analysis.disks.values(),
                            key=operator.attrgetter('total_rq_sectors'),
                            reverse=True)
        label = 'Disk requests sector count'
        graph_args = {'unit': ' sectors'}
        self._print_ascii_graph(input_list, self._get_total_rq_sectors_datum,
                                label, graph_args)

    def _output_rq_count(self):
        input_list = sorted(self._analysis.disks.values(),
                            key=operator.attrgetter('rq_count'),
                            reverse=True)
        label = 'Disk request count'
        graph_args = {'unit': ' requests'}
        self._print_ascii_graph(input_list, self._get_rq_count_datum,
                                label, graph_args)

    def _output_avg_disk_latency(self):
        input_list = self._analysis.disks.values()
        label = 'Disk request average latency'
        graph_args = {'unit': ' ms', 'sort': 2}
        self._print_ascii_graph(input_list, self._get_avg_disk_latency_datum,
                                label, graph_args)

    def _output_net_recv_bytes(self):
        input_list = sorted(self._analysis.ifaces.values(),
                            key=operator.attrgetter('recv_bytes'),
                            reverse=True)
        label = 'Network received bytes'
        graph_args = {'with_value': False}
        self._print_ascii_graph(input_list, self._get_net_recv_bytes_datum,
                                label, graph_args)

    def _output_net_sent_bytes(self):
        input_list = sorted(self._analysis.ifaces.values(),
                            key=operator.attrgetter('sent_bytes'),
                            reverse=True)
        label = 'Network sent bytes'
        graph_args = {'with_value': False}
        self._print_ascii_graph(input_list, self._get_net_sent_bytes_datum,
                                label, graph_args)

    def _output_file_read(self, files):
        input_list = sorted(files.values(),
                            key=lambda file_stats: file_stats.read,
                            reverse=True)
        label = 'Files read'
        graph_args = {'with_value': False, 'sort': 2}
        self._print_ascii_graph(input_list, self._get_file_read_datum,
                                label, graph_args)

    def _output_file_write(self, files):
        input_list = sorted(files.values(),
                            key=lambda file_stats: file_stats.write,
                            reverse=True)
        label = 'Files write'
        graph_args = {'with_value': False, 'sort': 2}
        self._print_ascii_graph(input_list, self._get_file_write_datum,
                                label, graph_args)

    def _output_file_read_write(self):
        files = self._analysis.get_files_stats(self._arg_pid_list,
                                               self._arg_proc_list)
        self._output_file_read(files)
        self._output_file_write(files)

    def iotop_output(self):
        self._output_read()
        self._output_write()
        self._output_file_read_write()
        self._output_block_read()
        self._output_block_write()
        self._output_total_rq_sectors()
        self._output_rq_count()
        self._output_avg_disk_latency()
        self._output_net_recv_bytes()
        self._output_net_sent_bytes()

    # I/O Latency frequency output methods
    def _print_frequency_distribution(self, duration_list, title):
        if not duration_list:
            return

        # The number of bins for the histogram
        resolution = self._arg_freq_resolution

        if self._arg_min is not None:
            min_duration = self._arg_min
        else:
            min_duration = min(duration_list)
            # ns to µs
            min_duration /= 1000

        if self._arg_max is not None:
            max_duration = self._arg_max
        else:
            max_duration = max(duration_list)
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
        for duration in duration_list:
            duration /= 1000
            index = min(int((duration - min_duration) / step), resolution - 1)
            values[index] += 1

        graph_data = []
        for index, value in enumerate(values):
            # The graph data format is a tuple (info, value). Here info
            # is the lower bound of the bucket, value the bucket's count
            graph_data.append(('%0.03f' % (index * step + min_duration),
                               value))

        graph_lines = graph.graph(
            title,
            graph_data,
            info_before=True,
            count=True
        )

        for line in graph_lines:
            print(line)

        print()

    def _output_disk_latency_freq(self):
        for disk in self._analysis.disks.values():
            rq_durations = [rq.duration for rq in disk.rq_list if
                            self._filter_io_request(rq)]
            self._print_frequency_distribution(
                rq_durations,
                'Frequency distribution for disk %s (usec)' % (disk.disk_name))

    def iolatency_output(self):
        self._output_disk_latency_freq()

    def iolatency_syscalls_output(self):
        print()
        self._print_frequency_distribution([io_rq.duration for io_rq in
                                            self._analysis.open_io_requests if
                                            self._filter_io_request(io_rq)],
                                           'Open latency distribution (usec)')
        self._print_frequency_distribution([io_rq.duration for io_rq in
                                            self._analysis.read_io_requests if
                                            self._filter_io_request(io_rq)],
                                           'Read latency distribution (usec)')
        self._print_frequency_distribution([io_rq.duration for io_rq in
                                            self._analysis.write_io_requests if
                                            self._filter_io_request(io_rq)],
                                           'Write latency distribution (usec)')
        self._print_frequency_distribution([io_rq.duration for io_rq in
                                            self._analysis.sync_io_requests if
                                            self._filter_io_request(io_rq)],
                                           'Sync latency distribution (usec)')

    # I/O latency top and log output methods
    def _output_io_request(self, io_rq):
        fmt = '{:<40} {:<16} {:>16} {:>11}  {:<24} {:<8} {:<14}'

        begin_time = common.ns_to_hour_nsec(io_rq.begin_ts,
                                            self._arg_multi_day,
                                            self._arg_gmt)
        end_time = common.ns_to_hour_nsec(io_rq.end_ts,
                                          self._arg_multi_day,
                                          self._arg_gmt)
        time_range_str = '[' + begin_time + ',' + end_time + ']'
        duration_str = '%0.03f' % (io_rq.duration / 1000)

        if io_rq.size is None:
            size = 'N/A'
        else:
            size = common.convert_size(io_rq.size)

        tid = io_rq.tid
        proc_stats = self._analysis.tids[tid]
        comm = proc_stats.comm

        # TODO: handle fd_in/fd_out for RW type operations
        if io_rq.fd is None:
            file_str = 'N/A'
        else:
            fd = io_rq.fd

            parent_proc = proc_stats
            if parent_proc.pid is not None:
                parent_proc = self._analysis.tids[parent_proc.pid]

            fd_stats = parent_proc.get_fd(fd, io_rq.end_ts)
            if fd_stats is not None:
                filename = fd_stats.filename
            else:
                filename = 'unknown'

            file_str = '%s (fd=%s)' % (filename, fd)

        if self._is_io_rq_out_of_range(io_rq):
            time_range_str += '*'
            duration_str += '*'
        else:
            time_range_str += ' '
            duration_str += ' '

        print(fmt.format(time_range_str, io_rq.syscall_name, duration_str,
                         size, comm, tid, file_str))

    def _output_io_requests_list(self, rq_list, title, sort_key, is_top=False):
        if not rq_list:
            return

        count = 0
        has_out_of_range_rq = False

        print()
        print(title)

        header_fmt = '{:<19} {:<20} {:<16} {:<23} {:<5} {:<24} {:<8} {:<14}'
        print(header_fmt.format(
            'Begin', 'End', 'Name', 'Duration (usec)', 'Size', 'Proc', 'PID',
            'Filename'))

        for io_rq in sorted(rq_list, key=operator.attrgetter(sort_key),
                            reverse=is_top):
            if is_top and count > self._arg_limit:
                break

            self._output_io_request(io_rq)
            if not has_out_of_range_rq and self._is_io_rq_out_of_range(io_rq):
                has_out_of_range_rq = True

            count += 1

        if has_out_of_range_rq:
            print('*: Syscalls started and/or completed outside of the '
                  'range specified')

    def _output_latency_log_from_requests(self, io_requests, title, sort_key,
                                          is_top=False):
        io_requests = [io_rq for io_rq in io_requests if
                       self._filter_io_request(io_rq)]
        self._output_io_requests_list(io_requests, title, sort_key, is_top)

    def iolatency_syscalls_top_output(self):
        self._output_latency_log_from_requests(
            [io_rq for io_rq in self._analysis.open_io_requests if
             self._filter_io_request(io_rq)],
            'Top open syscall latencies (usec)',
            'duration', is_top=True)
        self._output_io_requests_list(
            [io_rq for io_rq in self._analysis.read_io_requests if
             self._filter_io_request(io_rq)],
            'Top read syscall latencies (usec)',
            'duration', is_top=True)
        self._output_io_requests_list(
            [io_rq for io_rq in self._analysis.write_io_requests if
             self._filter_io_request(io_rq)],
            'Top write syscall latencies (usec)',
            'duration', is_top=True)
        self._output_io_requests_list(
            [io_rq for io_rq in self._analysis.sync_io_requests if
             self._filter_io_request(io_rq)],
            'Top sync syscall latencies (usec)',
            'duration', is_top=True)

    def iolatency_syscalls_log_output(self):
        self._output_io_requests_list(
            self._analysis.io_requests,
            'Log of all I/O system calls',
            'begin_ts')

    # I/O Stats output methods
    def _output_latency_stats(self, name, rq_durations):
        rq_count = len(rq_durations)
        total_duration = sum(rq_durations)
        if len(rq_durations) > 0:
            min_duration = min(rq_durations)
            max_duration = max(rq_durations)
        else:
            min_duration = 0
            max_duration = 0

        if rq_count < 2:
            stdev = '?'
        else:
            stdev = '%0.03f' % (statistics.stdev(rq_durations) / 1000)

        if rq_count > 0:
            avg = '%0.03f' % (total_duration / (rq_count) / 1000)
        else:
            avg = "0.000"

        min_duration = '%0.03f' % (min_duration / 1000)
        max_duration = '%0.03f' % (max_duration / 1000)

        print(IoAnalysisCommand._LATENCY_STATS_FORMAT.format(
            name, rq_count, min_duration, avg, max_duration, stdev))

    def _output_latency_stats_from_requests(self, io_requests, name):
        rq_durations = [io_rq.duration for io_rq in io_requests if
                        self._filter_io_request(io_rq)]
        self._output_latency_stats(name, rq_durations)

    def _output_syscalls_latency_stats(self):
        print('\nSyscalls latency statistics (usec):')
        print(IoAnalysisCommand._LATENCY_STATS_FORMAT.format(
            'Type', 'Count', 'Min', 'Average', 'Max', 'Stdev'))
        print(IoAnalysisCommand._SECTION_SEPARATOR_STRING)

        self._output_latency_stats_from_requests(
            self._analysis.open_io_requests, 'Open')
        self._output_latency_stats_from_requests(
            self._analysis.read_io_requests, 'Read')
        self._output_latency_stats_from_requests(
            self._analysis.write_io_requests, 'Write')
        self._output_latency_stats_from_requests(
            self._analysis.sync_io_requests, 'Sync')

    def _output_disk_latency_stats(self):
        if not self._analysis.disks:
            return

        print('\nDisk latency statistics (usec):')
        print(IoAnalysisCommand._LATENCY_STATS_FORMAT.format(
            'Name', 'Count', 'Min', 'Average', 'Max', 'Stdev'))
        print(IoAnalysisCommand._SECTION_SEPARATOR_STRING)

        for disk in self._analysis.disks.values():
            if disk.rq_count:
                rq_durations = [rq.duration for rq in disk.rq_list if
                                self._filter_io_request(rq)]
                self._output_latency_stats(disk.disk_name, rq_durations)

    def iostats_output(self):
        self._output_syscalls_latency_stats()
        self._output_disk_latency_stats()

    def _print_results(self, begin_ns, end_ns):
        self._print_date(begin_ns, end_ns)
        if self._arg_usage:
            self.iotop_output()
        if self._arg_stats:
            self.iostats_output()
        if self._arg_latencytop:
            self.iolatency_syscalls_top_output()
        if self._arg_freq:
            self.iolatency_syscalls_output()
            self.iolatency_output()
        if self._arg_log:
            self.iolatency_syscalls_log_output()

    def _reset_total(self, start_ts):
        self._analysis.reset()

    def _add_arguments(self, ap):
        ap.add_argument('--usage', action='store_true',
                        help='Show the I/O usage')
        ap.add_argument('--latencystats', action='store_true',
                        help='Show the I/O latency statistics')
        ap.add_argument('--latencytop', action='store_true',
                        help='Show the I/O latency top')
        ap.add_argument('--latencyfreq', action='store_true',
                        help='Show the I/O latency frequency distribution')
        ap.add_argument('--freq-resolution', type=int, default=20,
                        help='Frequency distribution resolution '
                             '(default 20)')


# entry point
def runstats():
    # create command
    iocmd = IoAnalysisCommand()
    # execute command
    iocmd.run_stats()


def runlatencytop():
    # create command
    iocmd = IoAnalysisCommand()
    # execute command
    iocmd.run_latencytop()


def runlog():
    # create command
    iocmd = IoAnalysisCommand()
    # execute command
    iocmd.run_log()


def runfreq():
    # create command
    iocmd = IoAnalysisCommand()
    # execute command
    iocmd.run_freq()


def runusage():
    # create command
    iocmd = IoAnalysisCommand()
    # execute command
    iocmd.run_usage()
