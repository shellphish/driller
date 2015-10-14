from distutils.core import setup
import subprocess

import pip
r = pip.req.RequirementSet(pip.locations.build_prefix, pip.locations.src_prefix, download_dir=None)
r.add_requirement(pip.req.InstallRequirement.from_line('git+ssh://git@git.seclab.cs.ucsb.edu:/cgc/fuzzer.git#egg=fuzzer'))
r.add_requirement(pip.req.InstallRequirement.from_line('git+ssh://git@git.seclab.cs.ucsb.edu:/cgc/tracer.git#egg=tracer'))
r.prepare_files(pip.index.PackageFinder([], None))
r.install([], [])

setup(
        name='driller',
        version='1.0',
        packages=['driller'],
        data_files=[
            ('bin/driller', ('bin/driller/listen.py',),),
        ],
        install_requires=[
            'cle',
            'angr',
            'redis',
            'celery',
            'simuvex',
            'archinfo',
            'dpkt-fix',
            'termcolor',
        ],
)
