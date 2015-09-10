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

from . import sp, sv


class BlockStateProvider(sp.StateProvider):
    def __init__(self, state):
        cbs = {
            'block_rq_complete': self._process_block_rq_complete,
            'block_rq_issue': self._process_block_rq_issue,
            'block_bio_remap': self._process_block_bio_remap,
            'block_bio_backmerge': self._process_block_bio_backmerge,
        }

        self._state = state
        self._remap_requests = []
        self._register_cbs(cbs)

    def process_event(self, ev):
        self._process_event_cb(ev)

    def _process_block_bio_remap(self, event):
        dev = event['dev']
        sector = event['sector']
        old_dev = event['old_dev']
        old_sector = event['old_sector']

        for req in self._remap_requests:
            if req.dev == old_dev and req.sector == old_sector:
                req.dev = dev
                req.sector = sector
                return

        req = sv.BlockRemapRequest(dev, sector, old_dev, old_sector)
        self._remap_requests.append(req)

    # For backmerge requests, just remove the request from the
    # _remap_requests queue, because we rely later on the nr_sector
    # which has all the info we need
    def _process_block_bio_backmerge(self, event):
        dev = event['dev']
        sector = event['sector']
        for remap_req in self._remap_requests:
            if remap_req.dev == dev and remap_req.sector == sector:
                self._remap_requests.remove(remap_req)

    def _process_block_rq_issue(self, event):
        dev = event['dev']
        sector = event['sector']
        nr_sector = event['nr_sector']

        if nr_sector == 0:
            return

        req = sv.BlockIORequest.new_from_rq_issue(event)

        for remap_req in self._remap_requests:
            if remap_req.dev == dev and remap_req.sector == sector:
                dev = remap_req.old_dev
                break

        if dev not in self._state.disks:
            self._state.disks[dev] = sv.Disk()

        self._state.disks[dev].pending_requests[sector] = req

    def _process_block_rq_complete(self, event):
        dev = event['dev']
        sector = event['sector']
        nr_sector = event['nr_sector']

        if nr_sector == 0:
            return

        for remap_req in self._remap_requests:
            if remap_req.dev == dev and remap_req.sector == sector:
                dev = remap_req.old_dev
                self._remap_requests.remove(remap_req)
                break

        if dev not in self._state.disks:
            self._state.disks[dev] = sv.Disk()

        disk = self._state.disks[dev]

        # Ignore rq_complete without matching rq_issue
        if sector not in disk.pending_requests:
            return

        req = disk.pending_requests[sector]
        # Ignore rq_complete if nr_sector does not match rq_issue's
        if req.nr_sector != nr_sector:
            return

        if event.timestamp - req.begin_ts > 15000000000:
            print(event.timestamp)

        req.update_from_rq_complete(event)
        if req.tid in self._state.tids.keys():
            proc = self._state.tids[req.tid]
        else:
            proc = None
        self._state.send_notification_cb('block_rq_complete', req=req,
                                         proc=proc)
        del disk.pending_requests[sector]
