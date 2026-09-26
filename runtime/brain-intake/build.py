#!/usr/bin/env python3
"""Build the private POSIX embedding candidate against this exact CPython.

This does not bundle Python, engine modules or licenses, install into a consumer,
or claim a standalone/static distribution. Runtime dependencies remain explicit.
"""
import argparse
import json
from pathlib import Path
import shlex
import subprocess
import sys
import sysconfig


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', required=True, type=Path)
    args = parser.parse_args()
    if args.output.exists():
        parser.error('output must be a new path')
    if sys.platform not in ('darwin', 'linux') or sys.implementation.name != 'cpython':
        parser.error('this candidate supports CPython on macOS or Linux only')
    root = Path(__file__).resolve().parent
    command = shlex.split(sysconfig.get_config_var('CC'))
    command += ['-std=c11', '-D_POSIX_C_SOURCE=200809L', '-fPIC', '-O2', '-Wall', '-Wextra', '-Werror',
                '-I' + str(root / 'include'), '-I' + sysconfig.get_path('include'),
                '-DBRAIN_PYTHON_PROGRAM=' + json.dumps(sys.executable),
                str(root / 'src/brain_intake.c'), '-o', str(args.output), '-pthread']
    library = sysconfig.get_config_var('LIBDIR')
    command += ['-dynamiclib' if sys.platform == 'darwin' else '-shared', '-L' + library,
                '-Wl,-rpath,' + library, '-lpython' + sysconfig.get_config_var('LDVERSION')]
    command += shlex.split(sysconfig.get_config_var('LIBS') or '')
    command += shlex.split(sysconfig.get_config_var('SYSLIBS') or '')
    subprocess.run(command, check=True)
    print(json.dumps({'output': str(args.output), 'python': sys.version.split()[0], 'command': command}))


if __name__ == '__main__':
    main()
