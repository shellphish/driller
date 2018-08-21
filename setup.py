from distutils.core import setup
import subprocess

#TRACER_URL = 'git+ssh://git@git.seclab.cs.ucsb.edu:/cgc/tracer.git#egg=tracer'
#FUZZER_URL = 'git+ssh://git@git.seclab.cs.ucsb.edu:/cgc/fuzzer.git#egg=fuzzer'
#
#if subprocess.call(['pip', 'install', TRACER_URL]) != 0:
#   raise LibError("Unable to install tracer")
#
#if subprocess.call(['pip', 'install', FUZZER_URL]) != 0:
#   raise LibError("Unable to install fuzzer")

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
            'archinfo',
            'dpkt',
            'termcolor',
        ],
)
