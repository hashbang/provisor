#!/usr/bin/env python
from distutils.core import setup

setup(
    name='provisor',
    version='0.2',
    scripts=['bin/provisor-server','bin/provisor-create'],
    data_files=[('/etc',['provisor.conf'])],
    author='Lance R. Vick',
    author_email='lance@lrvick.net',
    license='GPL 3.0',
    description='Server that provisions new users on a Linux system',
    long_description=open('README.md').read(),
    install_requires=['flask']
)
