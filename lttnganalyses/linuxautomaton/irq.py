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


class IrqStateProvider(sp.StateProvider):
    def __init__(self, state):
        cbs = {
            'irq_handler_entry': self._process_irq_handler_entry,
            'irq_handler_exit': self._process_irq_handler_exit,
            'softirq_raise': self._process_softirq_raise,
            'softirq_entry': self._process_softirq_entry,
            'softirq_exit': self._process_softirq_exit
        }

        super().__init__(state, cbs)

    def _get_cpu(self, cpu_id):
        if cpu_id not in self._state.cpus:
            self._state.cpus[cpu_id] = sv.CPU(cpu_id)

        return self._state.cpus[cpu_id]

    # Hard IRQs
    def _process_irq_handler_entry(self, event):
        cpu = self._get_cpu(event['cpu_id'])
        irq = sv.HardIRQ.new_from_irq_handler_entry(event)
        cpu.current_hard_irq = irq

        self._state.send_notification_cb('irq_handler_entry',
                                         id=irq.id,
                                         irq_name=event['name'])

    def _process_irq_handler_exit(self, event):
        cpu = self._get_cpu(event['cpu_id'])
        if cpu.current_hard_irq is None or \
           cpu.current_hard_irq.id != event['irq']:
            cpu.current_hard_irq = None
            return

        cpu.current_hard_irq.end_ts = event.timestamp
        cpu.current_hard_irq.ret = event['ret']

        self._state.send_notification_cb('irq_handler_exit',
                                         hard_irq=cpu.current_hard_irq)
        cpu.current_hard_irq = None

    # SoftIRQs
    def _process_softirq_raise(self, event):
        cpu = self._get_cpu(event['cpu_id'])
        vec = event['vec']

        if vec not in cpu.current_softirqs:
            cpu.current_softirqs[vec] = []

        # Don't append a SoftIRQ object if one has already been raised,
        # because they are level-triggered. The only exception to this
        # is if the first SoftIRQ object already had a begin_ts which
        # means this raise was triggered after its entry, and will be
        # handled in the following softirq_entry
        if cpu.current_softirqs[vec] and \
           cpu.current_softirqs[vec][0].begin_ts is None:
            return

        irq = sv.SoftIRQ.new_from_softirq_raise(event)
        cpu.current_softirqs[vec].append(irq)

    def _process_softirq_entry(self, event):
        cpu = self._get_cpu(event['cpu_id'])
        vec = event['vec']

        if cpu.current_softirqs[vec]:
            cpu.current_softirqs[vec][0].begin_ts = event.timestamp
        else:
            # SoftIRQ entry without a corresponding raise
            irq = sv.SoftIRQ.new_from_softirq_entry(event)
            cpu.current_softirqs[vec].append(irq)

    def _process_softirq_exit(self, event):
        cpu = self._get_cpu(event['cpu_id'])
        vec = event['vec']

        if vec not in cpu.current_softirqs:
            return

        cpu.current_softirqs[vec][0].end_ts = event.timestamp
        self._state.send_notification_cb('softirq_exit',
                                         softirq=cpu.current_softirqs[vec][0])
        del cpu.current_softirqs[vec][0]
