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

import socket
from . import common


class StateVariable:
    pass


class Process():
    def __init__(self, tid=None, pid=None, comm='', prio=None):
        self.tid = tid
        self.pid = pid
        self.comm = comm
        self.prio = prio
        # indexed by fd
        self.fds = {}
        self.current_syscall = None
        # the process scheduled before this one
        self.prev_tid = None
        self.last_wakeup = None
        self.last_waker = None


class CPU():
    def __init__(self, cpu_id):
        self.cpu_id = cpu_id
        self.current_tid = None
        self.current_hard_irq = None
        # softirqs use a dict because multiple ones can be raised before
        # handling. They are indexed by vec, and each entry is a list,
        # ordered chronologically
        self.current_softirqs = {}


class MemoryManagement():
    def __init__(self):
        self.page_count = 0


class SyscallEvent():
    def __init__(self, name, begin_ts):
        self.name = name
        self.begin_ts = begin_ts
        self.end_ts = None
        self.ret = None
        self.duration = None
        # Only applicable to I/O syscalls
        self.io_rq = None

    def process_exit(self, event):
        self.end_ts = event.timestamp
        self.ret = event['ret']
        self.duration = self.end_ts - self.begin_ts

    @classmethod
    def new_from_entry(cls, event):
        name = common.get_syscall_name(event)
        return cls(name, event.timestamp)


class Disk():
    def __init__(self):
        # pending block IO Requests, indexed by sector
        self.pending_requests = {}


class FDType():
    unknown = 0
    disk = 1
    net = 2
    # not 100% sure they are network FDs (assumed when net_dev_xmit is
    # called during a write syscall and the type in unknown).
    maybe_net = 3

    @staticmethod
    def get_fd_type(name, family):
        if name in SyscallConsts.NET_OPEN_SYSCALLS:
            if family in SyscallConsts.INET_FAMILIES:
                return FDType.net
            if family in SyscallConsts.DISK_FAMILIES:
                return FDType.disk

        if name in SyscallConsts.DISK_OPEN_SYSCALLS:
            return FDType.disk

        return FDType.unknown


class FD():
    def __init__(self, fd, filename='unknown', fd_type=FDType.unknown,
                 cloexec=False, family=None):
        self.fd = fd
        self.filename = filename
        self.fd_type = fd_type
        self.cloexec = cloexec
        self.family = family

    @classmethod
    def new_from_fd(cls, fd):
        return cls(fd.fd, fd.filename, fd.fd_type, fd.cloexec, fd.family)

    @classmethod
    def new_from_open_rq(cls, io_rq):
        return cls(io_rq.fd, io_rq.filename, io_rq.fd_type, io_rq.cloexec,
                   io_rq.family)


class IRQ():
    def __init__(self, id, cpu_id, begin_ts=None):
        self.id = id
        self.cpu_id = cpu_id
        self.begin_ts = begin_ts
        self.end_ts = None

    @property
    def duration(self):
        if not self.end_ts or not self.begin_ts:
            return None

        return self.end_ts - self.begin_ts


class HardIRQ(IRQ):
    def __init__(self, id, cpu_id, begin_ts):
        super().__init__(id, cpu_id, begin_ts)
        self.ret = None

    @classmethod
    def new_from_irq_handler_entry(cls, event):
        id = event['irq']
        cpu_id = event['cpu_id']
        begin_ts = event.timestamp
        return cls(id, cpu_id, begin_ts)


class SoftIRQ(IRQ):
    def __init__(self, id, cpu_id, raise_ts=None, begin_ts=None):
        super().__init__(id, cpu_id, begin_ts)
        self.raise_ts = raise_ts

    @classmethod
    def new_from_softirq_raise(cls, event):
        id = event['vec']
        cpu_id = event['cpu_id']
        raise_ts = event.timestamp
        return cls(id, cpu_id, raise_ts)

    @classmethod
    def new_from_softirq_entry(cls, event):
        id = event['vec']
        cpu_id = event['cpu_id']
        begin_ts = event.timestamp
        return cls(id, cpu_id, begin_ts=begin_ts)


class IORequest():
    # I/O operations
    OP_OPEN = 1
    OP_READ = 2
    OP_WRITE = 3
    OP_CLOSE = 4
    OP_SYNC = 5
    # Operation used for requests that both read and write,
    # e.g. splice and sendfile
    OP_READ_WRITE = 6

    def __init__(self, begin_ts, size, tid, operation):
        self.begin_ts = begin_ts
        self.end_ts = None
        self.duration = None
        # request size in bytes
        self.size = size
        self.operation = operation
        # tid of process that triggered the rq
        self.tid = tid
        # Error number if request failed
        self.errno = None

    @staticmethod
    def is_equivalent_operation(left_op, right_op):
        """Predicate used to compare equivalence of IO_OPERATION.

        This method is employed because OP_READ_WRITE behaves like a
        set containing both OP_READ and OP_WRITE and is therefore
        equivalent to these operations as well as itself
        """
        if left_op == IORequest.OP_READ_WRITE:
            return right_op in [IORequest.OP_READ, IORequest.OP_WRITE,
                                IORequest.OP_READ_WRITE]
        if left_op == IORequest.OP_READ:
            return right_op in [IORequest.OP_READ, IORequest.OP_READ_WRITE]
        if left_op == IORequest.OP_WRITE:
            return right_op in [IORequest.OP_WRITE, IORequest.OP_READ_WRITE]

        return left_op == right_op


class SyscallIORequest(IORequest):
    def __init__(self, begin_ts, size, tid, operation, syscall_name):
        super().__init__(begin_ts, None, tid, operation)
        self.fd = None
        self.syscall_name = syscall_name
        # Number of pages alloc'd/freed/written to disk during the rq
        self.pages_allocated = 0
        self.pages_freed = 0
        self.pages_written = 0
        # Whether kswapd was forced to wakeup during the rq
        self.woke_kswapd = False

    def update_from_exit(self, event):
        self.end_ts = event.timestamp
        self.duration = self.end_ts - self.begin_ts
        if event['ret'] < 0:
            self.errno = -event['ret']


class OpenIORequest(SyscallIORequest):
    def __init__(self, begin_ts, tid, syscall_name, filename,
                 fd_type):
        super().__init__(begin_ts, None, tid, IORequest.OP_OPEN, syscall_name)
        # FD set on syscall exit
        self.fd = None
        self.filename = filename
        self.fd_type = fd_type
        self.family = None
        self.cloexec = False

    def update_from_exit(self, event):
        super().update_from_exit(event)
        if event['ret'] >= 0:
            self.fd = event['ret']

    @classmethod
    def new_from_disk_open(cls, event, tid):
        begin_ts = event.timestamp
        name = common.get_syscall_name(event)
        filename = event['filename']

        req = cls(begin_ts, tid, name, filename, FDType.disk)
        req.cloexec = event['flags'] & common.O_CLOEXEC == common.O_CLOEXEC

        return req

    @classmethod
    def new_from_accept(cls, event, tid):
        # Handle both accept and accept4
        begin_ts = event.timestamp
        name = common.get_syscall_name(event)
        req = cls(begin_ts, tid, name, 'socket', FDType.net)

        if 'family' in event:
            req.family = event['family']
            # Set filename to ip:port if INET socket
            if req.family == socket.AF_INET:
                req.filename = '%s:%d' % (common.get_v4_addr_str(
                    event['v4addr']), event['sport'])

        return req

    @classmethod
    def new_from_socket(cls, event, tid):
        begin_ts = event.timestamp
        req = cls(begin_ts, tid, 'socket', 'socket', FDType.net)

        if 'family' in event:
            req.family = event['family']

        return req

    @classmethod
    def new_from_old_fd(cls, event, tid, old_fd):
        begin_ts = event.timestamp
        name = common.get_syscall_name(event)
        if old_fd is None:
            filename = 'unknown'
            fd_type = FDType.unknown
        else:
            filename = old_fd.filename
            fd_type = old_fd.fd_type

        return cls(begin_ts, tid, name, filename, fd_type)


class CloseIORequest(SyscallIORequest):
    def __init__(self, begin_ts, tid, fd):
        super().__init__(begin_ts, None, tid, IORequest.OP_CLOSE, 'close')
        self.fd = fd


class ReadWriteIORequest(SyscallIORequest):
    def __init__(self, begin_ts, size, tid, operation, syscall_name):
        super().__init__(begin_ts, size, tid, operation, syscall_name)
        # The size returned on syscall exit, in bytes. May differ from
        # the size initially requested
        self.returned_size = None
        # Unused if fd is set
        self.fd_in = None
        self.fd_out = None

    def update_from_exit(self, event):
        super().update_from_exit(event)
        ret = event['ret']
        if ret >= 0:
            self.returned_size = ret
            # Set the size to the returned one if none was set at
            # entry, as with recvmsg or sendmsg
            if self.size is None:
                self.size = ret

    @classmethod
    def new_from_splice(cls, event, tid):
        begin_ts = event.timestamp
        size = event['len']

        req = cls(begin_ts, size, tid, IORequest.OP_READ_WRITE, 'splice')
        req.fd_in = event['fd_in']
        req.fd_out = event['fd_out']

        return req

    @classmethod
    def new_from_sendfile64(cls, event, tid):
        begin_ts = event.timestamp
        size = event['count']

        req = cls(begin_ts, size, tid, IORequest.OP_READ_WRITE, 'sendfile64')
        req.fd_in = event['in_fd']
        req.fd_out = event['out_fd']

        return req

    @classmethod
    def new_from_fd_event(cls, event, tid, size_key):
        begin_ts = event.timestamp
        # Some events, like recvmsg or sendmsg, only have size info on return
        if size_key is not None:
            size = event[size_key]
        else:
            size = None

        syscall_name = common.get_syscall_name(event)
        if syscall_name in SyscallConsts.READ_SYSCALLS:
            operation = IORequest.OP_READ
        else:
            operation = IORequest.OP_WRITE

        req = cls(begin_ts, size, tid, operation, syscall_name)
        req.fd = event['fd']

        return req


class SyncIORequest(SyscallIORequest):
    def __init__(self, begin_ts, size, tid, syscall_name):
        super().__init__(begin_ts, size, tid, IORequest.OP_SYNC, syscall_name)

    @classmethod
    def new_from_sync(cls, event, tid):
        begin_ts = event.timestamp
        size = None

        return cls(begin_ts, size, tid, 'sync')

    @classmethod
    def new_from_fsync(cls, event, tid):
        # Also handle fdatasync
        begin_ts = event.timestamp
        size = None
        syscall_name = common.get_syscall_name(event)

        req = cls(begin_ts, size, tid, syscall_name)
        req.fd = event['fd']

        return req

    @classmethod
    def new_from_sync_file_range(cls, event, tid):
        begin_ts = event.timestamp
        size = event['nbytes']

        req = cls(begin_ts, size, tid, 'sync_file_range')
        req.fd = event['fd']

        return req


class BlockIORequest(IORequest):
    # Logical sector size in bytes, according to the kernel
    SECTOR_SIZE = 512

    def __init__(self, begin_ts, tid, operation, dev, sector, nr_sector):
        size = nr_sector * BlockIORequest.SECTOR_SIZE
        super().__init__(begin_ts, size, tid, operation)
        self.dev = dev
        self.sector = sector
        self.nr_sector = nr_sector

    def update_from_rq_complete(self, event):
        self.end_ts = event.timestamp
        self.duration = self.end_ts - self.begin_ts

    @classmethod
    def new_from_rq_issue(cls, event):
        begin_ts = event.timestamp
        dev = event['dev']
        sector = event['sector']
        nr_sector = event['nr_sector']
        tid = event['tid']
        # An even rwbs indicates read operation, odd indicates write
        if event['rwbs'] % 2 == 0:
            operation = IORequest.OP_READ
        else:
            operation = IORequest.OP_WRITE

        return cls(begin_ts, tid, operation, dev, sector, nr_sector)


class BlockRemapRequest():
    def __init__(self, dev, sector, old_dev, old_sector):
        self.dev = dev
        self.sector = sector
        self.old_dev = old_dev
        self.old_sector = old_sector


class SyscallConsts():
    # TODO: decouple socket/family logic from this class
    INET_FAMILIES = [socket.AF_INET, socket.AF_INET6]
    DISK_FAMILIES = [socket.AF_UNIX]
    # list nof syscalls that open a FD on disk (in the exit_syscall event)
    DISK_OPEN_SYSCALLS = ['open', 'openat']
    # list of syscalls that open a FD on the network
    # (in the exit_syscall event)
    NET_OPEN_SYSCALLS = ['socket']
    # list of syscalls that can duplicate a FD
    DUP_OPEN_SYSCALLS = ['fcntl', 'dup', 'dup2', 'dup3']
    SYNC_SYSCALLS = ['sync', 'sync_file_range', 'fsync', 'fdatasync']
    # merge the 3 open lists
    OPEN_SYSCALLS = DISK_OPEN_SYSCALLS + NET_OPEN_SYSCALLS + DUP_OPEN_SYSCALLS
    # list of syscalls that close a FD (in the 'fd =' field)
    CLOSE_SYSCALLS = ['close']
    # list of syscall that read on a FD, value in the exit_syscall following
    READ_SYSCALLS = ['read', 'recvmsg', 'recvfrom', 'readv', 'pread',
                     'pread64', 'preadv']
    # list of syscall that write on a FD, value in the exit_syscall following
    WRITE_SYSCALLS = ['write', 'sendmsg', 'sendto', 'writev', 'pwrite',
                      'pwrite64', 'pwritev']
    # list of syscalls that both read and write on two FDs
    READ_WRITE_SYSCALLS = ['splice', 'sendfile64']
    # All I/O related syscalls
    IO_SYSCALLS = OPEN_SYSCALLS + CLOSE_SYSCALLS + READ_SYSCALLS + \
        WRITE_SYSCALLS + SYNC_SYSCALLS + READ_WRITE_SYSCALLS
