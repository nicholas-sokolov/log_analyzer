#!/usr/bin/env python
# -*- encoding: utf-8 -*-
from __future__ import absolute_import
from __future__ import print_function

import io
import re
from glob import glob
from os.path import basename
from os.path import dirname
from os.path import join
from os.path import splitext

from setuptools import find_packages
from setuptools import setup


def read(*names, **kwargs):
    return io.open(
        join(dirname(__file__), *names),
        encoding=kwargs.get('encoding', 'utf8')
    ).read()


setup(
    name='log_analyzer',
    version='0.1.0',
    license='BSD 2-Clause License',
    description='Log analyzer for nginx',
    long_description='%s\n' % (
        re.compile('^.. start-badges.*^.. end-badges', re.M | re.S).sub('', read('README.md'))
    ),
    author='Sokolov Nikolay Valerevich',
    author_email='sokolov.nicholas@gmail.com',
    url='https://github.com/nicholas-sokolov/log_analyzer',
    packages=find_packages('src'),
    zip_safe=False,
    classifiers=[
        'Development Status :: 5 - Production/Stable',
        'Intended Audience :: Developers',
        'License :: OSI Approved :: BSD License',
        'Operating System :: Unix',
        'Operating System :: POSIX',
        'Operating System :: Microsoft :: Windows',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.4',
        'Programming Language :: Python :: 3.5',
        'Programming Language :: Python :: 3.6',
        'Programming Language :: Python :: 3.7',
    ],
)
