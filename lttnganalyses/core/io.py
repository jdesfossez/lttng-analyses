# The MIT License (MIT)
#
# Copyright (C) 2015 - Antoine Busque <abusque@efficios.com>
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

from .analysis import Analysis
from ..linuxautomaton import sv


class IoAnalysis(Analysis):
    def __init__(self, state, conf):
        notification_cbs = {
            'net_dev_xmit': self._process_net_dev_xmit,
            'netif_receive_skb': self._process_netif_receive_skb,
            'block_rq_complete': self._process_block_rq_complete,
            'io_rq_exit': self._process_io_rq_exit,
            'create_fd': self._process_create_fd,
            'close_fd': self._process_close_fd,
            'update_fd': self._process_update_fd,
            'create_parent_proc': self._process_create_parent_proc
        }

        event_cbs = {
            'lttng_statedump_block_device':
            self._process_lttng_statedump_block_device
        }

        super().__init__(state, conf)
        self._state.register_notification_cbs(notification_cbs)
        self._register_cbs(event_cbs)

        self.disks = {}
        self.ifaces = {}
        self.tids = {}

    def process_event(self, ev):
        super().process_event(ev)
        self._process_event_cb(ev)

    def reset(self):
        for dev in self.disks:
            self.disks[dev].reset()

        for name in self.ifaces:
            self.ifaces[name].reset()

        for tid in self.tids:
            self.tids[tid].reset()

    @property
    def disk_io_requests(self):
        for disk in self.disks.values():
            for io_rq in disk.rq_list:
                yield io_rq

    @property
    def io_requests(self):
        return self._get_io_requests()

    @property
    def open_io_requests(self):
        return self._get_io_requests(sv.IORequest.OP_OPEN)

    @property
    def read_io_requests(self):
        return self._get_io_requests(sv.IORequest.OP_READ)

    @property
    def write_io_requests(self):
        return self._get_io_requests(sv.IORequest.OP_WRITE)

    @property
    def close_io_requests(self):
        return self._get_io_requests(sv.IORequest.OP_CLOSE)

    @property
    def sync_io_requests(self):
        return self._get_io_requests(sv.IORequest.OP_SYNC)

    @property
    def read_write_io_requests(self):
        return self._get_io_requests(sv.IORequest.OP_READ_WRITE)

    def _get_io_requests(self, io_operation=None):
        """Create a generator of syscall io requests by operation

        Args:
            io_operation (IORequest.OP_*, optional): The operation of
            the io_requests to return. Return all IO requests if None.
        """
        for proc in self.tids.values():
            for io_rq in proc.rq_list:
                if isinstance(io_rq, sv.BlockIORequest):
                    continue

                if io_operation is None or \
                   sv.IORequest.is_equivalent_operation(io_operation,
                                                        io_rq.operation):
                    yield io_rq

    def get_files_stats(self):
        files_stats = {}

        for proc_stats in self.tids.values():
            for fd_list in proc_stats.fds.values():
                for fd_stats in fd_list:
                    filename = fd_stats.filename
                    # Add process name to generic filenames to
                    # distinguish them
                    if FileStats.is_generic_name(filename):
                        filename += '(%s)' % proc_stats.comm

                    if filename not in files_stats:
                        if proc_stats.pid is not None:
                            pid = proc_stats.pid
                        else:
                            pid = proc_stats.tid

                        files_stats[filename] = FileStats(
                            filename, fd_stats.fd, pid)

                    files_stats[filename].update_stats(fd_stats, proc_stats)

        return files_stats

    @staticmethod
    def _assign_fds_to_parent(proc, parent):
        if proc.fds:
            toremove = []
            for fd in proc.fds:
                if fd not in parent.fds:
                    parent.fds[fd] = proc.fds[fd]
                else:
                    # best effort to fix the filename
                    if not parent.get_fd(fd).filename:
                        parent.get_fd(fd).filename = proc.get_fd(fd).filename
                toremove.append(fd)
            for fd in toremove:
                del proc.fds[fd]

    def _process_net_dev_xmit(self, **kwargs):
        name = kwargs['iface_name']
        sent_bytes = kwargs['sent_bytes']
        cpu = kwargs['cpu_id']

        if not self._filter_cpu(cpu):
            return

        if name not in self.ifaces:
            self.ifaces[name] = IfaceStats(name)

        self.ifaces[name].sent_packets += 1
        self.ifaces[name].sent_bytes += sent_bytes

    def _process_netif_receive_skb(self, **kwargs):
        name = kwargs['iface_name']
        recv_bytes = kwargs['recv_bytes']
        cpu = kwargs['cpu_id']

        if not self._filter_cpu(cpu):
            return

        if name not in self.ifaces:
            self.ifaces[name] = IfaceStats(name)

        self.ifaces[name].recv_packets += 1
        self.ifaces[name].recv_bytes += recv_bytes

    def _process_block_rq_complete(self, **kwargs):
        req = kwargs['req']
        proc = kwargs['proc']
        cpu = kwargs['cpu_id']

        if not self._filter_process(proc):
            return
        if not self._filter_cpu(cpu):
            return

        if req.dev not in self.disks:
            self.disks[req.dev] = DiskStats(req.dev)

        self.disks[req.dev].update_stats(req)

        if proc is not None:
            if proc.tid not in self.tids:
                self.tids[proc.tid] = ProcessIOStats.new_from_process(proc)

            self.tids[proc.tid].update_block_stats(req)

    def _process_lttng_statedump_block_device(self, event):
        dev = event['dev']
        disk_name = event['diskname']

        if dev not in self.disks:
            self.disks[dev] = DiskStats(dev, disk_name)
        else:
            self.disks[dev].disk_name = disk_name

    def _process_io_rq_exit(self, **kwargs):
        proc = kwargs['proc']
        parent_proc = kwargs['parent_proc']
        io_rq = kwargs['io_rq']
        cpu = kwargs['cpu_id']

        if not self._filter_process(parent_proc):
            return
        if not self._filter_cpu(cpu):
            return

        if proc.tid not in self.tids:
            self.tids[proc.tid] = ProcessIOStats.new_from_process(proc)

        if parent_proc.tid not in self.tids:
            self.tids[parent_proc.tid] = (
                ProcessIOStats.new_from_process(parent_proc))

        proc_stats = self.tids[proc.tid]
        parent_stats = self.tids[parent_proc.tid]

        fd_types = {}
        if io_rq.errno is None:
            if io_rq.operation == sv.IORequest.OP_READ or \
               io_rq.operation == sv.IORequest.OP_WRITE:
                fd_types['fd'] = parent_stats.get_fd(io_rq.fd).fd_type
            elif io_rq.operation == sv.IORequest.OP_READ_WRITE:
                fd_types['fd_in'] = parent_stats.get_fd(io_rq.fd_in).fd_type
                fd_types['fd_out'] = parent_stats.get_fd(io_rq.fd_out).fd_type

        proc_stats.update_io_stats(io_rq, fd_types)
        parent_stats.update_fd_stats(io_rq)

    def _process_create_parent_proc(self, **kwargs):
        proc = kwargs['proc']
        parent_proc = kwargs['parent_proc']

        if not self._filter_process(parent_proc):
            return

        if proc.tid not in self.tids:
            self.tids[proc.tid] = ProcessIOStats.new_from_process(proc)

        if parent_proc.tid not in self.tids:
            self.tids[parent_proc.tid] = (
                ProcessIOStats.new_from_process(parent_proc))

        proc_stats = self.tids[proc.tid]
        parent_stats = self.tids[parent_proc.tid]

        proc_stats.pid = parent_stats.tid
        IoAnalysis._assign_fds_to_parent(proc_stats, parent_stats)

    def _process_create_fd(self, **kwargs):
        timestamp = kwargs['timestamp']
        parent_proc = kwargs['parent_proc']
        tid = parent_proc.tid
        cpu = kwargs['cpu_id']
        fd = kwargs['fd']

        if not self._filter_process(parent_proc):
            return
        if not self._filter_cpu(cpu):
            return

        if tid not in self.tids:
            self.tids[tid] = ProcessIOStats.new_from_process(parent_proc)

        parent_stats = self.tids[tid]
        if fd not in parent_stats.fds:
            parent_stats.fds[fd] = []
        parent_stats.fds[fd].append(FDStats.new_from_fd(parent_proc.fds[fd],
                                                        timestamp))

    def _process_close_fd(self, **kwargs):
        timestamp = kwargs['timestamp']
        parent_proc = kwargs['parent_proc']
        tid = parent_proc.tid
        cpu = kwargs['cpu_id']
        fd = kwargs['fd']

        if not self._filter_process(parent_proc):
            return
        if not self._filter_cpu(cpu):
            return

        parent_stats = self.tids[tid]
        last_fd = parent_stats.get_fd(fd)
        last_fd.close_ts = timestamp

    def _process_update_fd(self, **kwargs):
        parent_proc = kwargs['parent_proc']
        tid = parent_proc.tid
        fd = kwargs['fd']

        new_filename = parent_proc.fds[fd].filename
        fd_list = self.tids[tid].fds[fd]
        fd_list[-1].filename = new_filename


class DiskStats():
    MINORBITS = 20
    MINORMASK = ((1 << MINORBITS) - 1)

    def __init__(self, dev, disk_name=None):
        self.dev = dev
        if disk_name is not None:
            self.disk_name = disk_name
        else:
            self.disk_name = DiskStats._get_name_from_dev(dev)

        self.min_rq_duration = None
        self.max_rq_duration = None
        self.total_rq_sectors = 0
        self.total_rq_duration = 0
        self.rq_list = []

    @property
    def rq_count(self):
        return len(self.rq_list)

    def update_stats(self, req):
        if self.min_rq_duration is None or req.duration < self.min_rq_duration:
            self.min_rq_duration = req.duration
        if self.max_rq_duration is None or req.duration > self.max_rq_duration:
            self.max_rq_duration = req.duration

        self.total_rq_sectors += req.nr_sector
        self.total_rq_duration += req.duration
        self.rq_list.append(req)

    def reset(self):
        self.min_rq_duration = None
        self.max_rq_duration = None
        self.total_rq_sectors = 0
        self.total_rq_duration = 0
        self.rq_list = []

    @staticmethod
    def _get_name_from_dev(dev):
        # imported from include/linux/kdev_t.h
        major = dev >> DiskStats.MINORBITS
        minor = dev & DiskStats.MINORMASK

        return '(%d,%d)' % (major, minor)


class IfaceStats():
    def __init__(self, name):
        self.name = name
        self.recv_bytes = 0
        self.recv_packets = 0
        self.sent_bytes = 0
        self.sent_packets = 0

    def reset(self):
        self.recv_bytes = 0
        self.recv_packets = 0
        self.sent_bytes = 0
        self.sent_packets = 0


class ProcessIOStats():
    def __init__(self, pid, tid, comm):
        self.pid = pid
        self.tid = tid
        self.comm = comm
        # Number of bytes read or written by the process, by type of I/O
        self.disk_read = 0
        self.disk_write = 0
        self.net_read = 0
        self.net_write = 0
        self.unk_read = 0
        self.unk_write = 0
        # Actual number of bytes read or written by the process at the
        # block layer
        self.block_read = 0
        self.block_write = 0
        # FDStats objects, indexed by fd (fileno)
        self.fds = {}
        self.rq_list = []

    @classmethod
    def new_from_process(cls, proc):
        return cls(proc.pid, proc.tid, proc.comm)

    # Total read/write does not account for block layer I/O
    @property
    def total_read(self):
        return self.disk_read + self.net_read + self.unk_read

    @property
    def total_write(self):
        return self.disk_write + self.net_write + self.unk_write

    def update_fd_stats(self, req):
        if req.errno is not None:
            return

        if req.fd is not None:
            self.get_fd(req.fd).update_stats(req)
        elif isinstance(req, sv.ReadWriteIORequest):
            if req.fd_in is not None:
                self.get_fd(req.fd_in).update_stats(req)

            if req.fd_out is not None:
                self.get_fd(req.fd_out).update_stats(req)

    def update_block_stats(self, req):
        self.rq_list.append(req)

        if req.operation is sv.IORequest.OP_READ:
            self.block_read += req.size
        elif req.operation is sv.IORequest.OP_WRITE:
            self.block_write += req.size

    def update_io_stats(self, req, fd_types):
        self.rq_list.append(req)

        if req.size is None or req.errno is not None:
            return

        if req.operation is sv.IORequest.OP_READ:
            self._update_read(req.returned_size, fd_types['fd'])
        elif req.operation is sv.IORequest.OP_WRITE:
            self._update_write(req.returned_size, fd_types['fd'])
        elif req.operation is sv.IORequest.OP_READ_WRITE:
            self._update_read(req.returned_size, fd_types['fd_in'])
            self._update_write(req.returned_size, fd_types['fd_out'])

    def _update_read(self, size, fd_type):
        if fd_type == sv.FDType.disk:
            self.disk_read += size
        elif fd_type == sv.FDType.net or fd_type == sv.FDType.maybe_net:
            self.net_read += size
        else:
            self.unk_read += size

    def _update_write(self, size, fd_type):
        if fd_type == sv.FDType.disk:
            self.disk_write += size
        elif fd_type == sv.FDType.net or fd_type == sv.FDType.maybe_net:
            self.net_write += size
        else:
            self.unk_write += size

    def _get_current_fd(self, fd):
        fd_stats = self.fds[fd][-1]
        if fd_stats.close_ts is not None:
            return None

        return fd_stats

    @staticmethod
    def _get_fd_by_timestamp(fd_list, timestamp):
        """Return the FDStats object whose lifetime contains timestamp

        This method performs a recursive binary search on the given
        fd_list argument, and will find the FDStats object for which
        the timestamp is contained between its open_ts and close_ts
        attributes.

        Args:
            fd_list (list): list of FDStats object, sorted
            chronologically by open_ts

            timestamp (int): timestamp in nanoseconds (ns) since unix
            epoch which should be contained in the FD's lifetime.

        Returns:
            The FDStats object whose lifetime contains the given
            timestamp, None if no such object exists.
        """
        list_size = len(fd_list)
        if list_size == 0:
            return None

        midpoint = list_size // 2
        fd_stats = fd_list[midpoint]

        # Handle case of currently open fd (i.e. no close_ts)
        if fd_stats.close_ts is None:
            if timestamp >= fd_stats.open_ts:
                return fd_stats
        else:
            if fd_stats.open_ts <= timestamp <= fd_stats.close_ts:
                return fd_stats
            else:
                if timestamp < fd_stats.open_ts:
                    return ProcessIOStats._get_fd_by_timestamp(
                        fd_list[:midpoint], timestamp)
                else:
                    return ProcessIOStats._get_fd_by_timestamp(
                        fd_list[midpoint + 1:], timestamp)

    def get_fd(self, fd, timestamp=None):
        if fd not in self.fds or not self.fds[fd]:
            return None

        if timestamp is None:
            fd_stats = self._get_current_fd(fd)
        else:
            fd_stats = ProcessIOStats._get_fd_by_timestamp(self.fds[fd],
                                                           timestamp)

        return fd_stats

    def reset(self):
        self.disk_read = 0
        self.disk_write = 0
        self.net_read = 0
        self.net_write = 0
        self.unk_read = 0
        self.unk_write = 0
        self.block_read = 0
        self.block_write = 0
        self.rq_list = []

        for fd in self.fds:
            fd_stats = self.get_fd(fd)
            if fd_stats is not None:
                fd_stats.reset()


class FDStats():
    def __init__(self, fd, filename, fd_type, cloexec, family, open_ts):
        self.fd = fd
        self.filename = filename
        self.fd_type = fd_type
        self.cloexec = cloexec
        self.family = family
        self.open_ts = open_ts
        self.close_ts = None

        # Number of bytes read or written
        self.read = 0
        self.write = 0
        # IO Requests that acted upon the FD
        self.rq_list = []

    @classmethod
    def new_from_fd(cls, fd, open_ts):
        return cls(fd.fd, fd.filename, fd.fd_type, fd.cloexec, fd.family,
                   open_ts)

    def update_stats(self, req):
        if req.operation is sv.IORequest.OP_READ:
            self.read += req.returned_size
        elif req.operation is sv.IORequest.OP_WRITE:
            self.write += req.returned_size
        elif req.operation is sv.IORequest.OP_READ_WRITE:
            if self.fd == req.fd_in:
                self.read += req.returned_size
            elif self.fd == req.fd_out:
                self.write += req.returned_size

        self.rq_list.append(req)

    def reset(self):
        self.read = 0
        self.write = 0
        self.rq_list = []


class FileStats():
    GENERIC_NAMES = ['pipe', 'socket', 'anon_inode', 'unknown']

    def __init__(self, filename, fd, pid):
        self.filename = filename
        # Number of bytes read or written
        self.read = 0
        self.write = 0
        # Dict of file descriptors representing this file, indexed by
        # parent pid
        self.fd_by_pid = {pid: fd}

    def update_stats(self, fd_stats, proc_stats):
        self.read += fd_stats.read
        self.write += fd_stats.write

        if proc_stats.pid is not None:
            pid = proc_stats.pid
        else:
            pid = proc_stats.tid

        if pid not in self.fd_by_pid:
            self.fd_by_pid[pid] = fd_stats.fd

    def reset(self):
        self.read = 0
        self.write = 0

    @staticmethod
    def is_generic_name(filename):
        for generic_name in FileStats.GENERIC_NAMES:
            if filename.startswith(generic_name):
                return True

        return False
