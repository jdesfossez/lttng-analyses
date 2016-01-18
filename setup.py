#!/usr/bin/env python3
#
# Copyright (C) 2015 - Michael Jeanson <mjeanson@efficios.com>
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

"""LTTnganalyses setup script"""

from setuptools import setup
import versioneer
import sys

if sys.version_info[0:2] < (3, 4):
    raise RuntimeError("Python version >= 3.4 required.")

if 'install' in sys.argv:
    try:
        __import__('babeltrace')
    except ImportError:
        print('lttnganalysescli needs the babeltrace package.\n \
        See https://www.efficios.com/babeltrace for more info.\n',
              file=sys.stderr)
        sys.exit(1)


def read_file(filename):
    """Read all contents of ``filename``."""
    with open(filename, encoding='utf-8') as source:
        return source.read()

setup(
    name='lttnganalyses',
    version=versioneer.get_version(),
    cmdclass=versioneer.get_cmdclass(),

    description='LTTng analyses',
    long_description=read_file('README.rst'),

    url='https://github.com/lttng/lttng-analyses',

    author='Julien Desfossez',
    author_email='jdesfossez@efficios.com',

    license='MIT',

    classifiers=[
        'Development Status :: 4 - Beta',

        'Intended Audience :: Developers',
        'Intended Audience :: System Administrators',
        'Topic :: System :: Monitoring',

        'License :: OSI Approved :: MIT License',

        'Programming Language :: Python :: 3.4',
    ],

    keywords='lttng tracing',

    packages=[
        'lttnganalyses',
        'lttnganalyses.common',
        'lttnganalyses.core',
        'lttnganalyses.cli',
        'lttnganalyses.linuxautomaton',
        'lttnganalyses.ascii_graph'
        ],

    entry_points={
        'console_scripts': [
            # human-readable output
            'lttng-cputop = lttnganalyses.cli.cputop:run',
            'lttng-iolatencyfreq = lttnganalyses.cli.io:runfreq',
            'lttng-iolatencystats = lttnganalyses.cli.io:runstats',
            'lttng-iolatencytop = lttnganalyses.cli.io:runlatencytop',
            'lttng-iolog = lttnganalyses.cli.io:runlog',
            'lttng-iousagetop = lttnganalyses.cli.io:runusage',
            'lttng-irqfreq = lttnganalyses.cli.irq:runfreq',
            'lttng-irqlog = lttnganalyses.cli.irq:runlog',
            'lttng-irqstats = lttnganalyses.cli.irq:runstats',
            'lttng-memtop = lttnganalyses.cli.memtop:run',
            'lttng-syscallstats = lttnganalyses.cli.syscallstats:run',
            'lttng-schedlog = lttnganalyses.cli.sched:runlog',
            'lttng-schedtop = lttnganalyses.cli.sched:runtop',
            'lttng-schedstats = lttnganalyses.cli.sched:runstats',
            'lttng-schedfreq = lttnganalyses.cli.sched:runfreq',

            # MI mode
            'lttng-cputop-mi = lttnganalyses.cli.cputop:run_mi',
            'lttng-memtop-mi = lttnganalyses.cli.memtop:run_mi',
            'lttng-syscallstats-mi = lttnganalyses.cli.syscallstats:run_mi',
            'lttng-irqfreq-mi = lttnganalyses.cli.irq:runfreq_mi',
            'lttng-irqlog-mi = lttnganalyses.cli.irq:runlog_mi',
            'lttng-irqstats-mi = lttnganalyses.cli.irq:runstats_mi',
            'lttng-iolatencyfreq-mi = lttnganalyses.cli.io:runfreq_mi',
            'lttng-iolatencystats-mi = lttnganalyses.cli.io:runstats_mi',
            'lttng-iolatencytop-mi = lttnganalyses.cli.io:runlatencytop_mi',
            'lttng-iolog-mi = lttnganalyses.cli.io:runlog_mi',
            'lttng-iousagetop-mi = lttnganalyses.cli.io:runusage_mi',
            'lttng-schedlog-mi = lttnganalyses.cli.sched:runlog_mi',
            'lttng-schedtop-mi = lttnganalyses.cli.sched:runtop_mi',
            'lttng-schedstats-mi = lttnganalyses.cli.sched:runstats_mi',
            'lttng-schedfreq-mi = lttnganalyses.cli.sched:runfreq_mi',
        ],
    },

    scripts=[
        'lttng-analyses-record',
        'lttng-track-process'
    ],

    extras_require={
        'progressbar':  ["progressbar"]
    },

    setup_requires=['pytest-runner'],
    tests_require=['pytest']
)
