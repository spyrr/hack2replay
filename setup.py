#!/usr/bin/env python3
import io
from glob import glob
from os.path import basename, splitext
from setuptools import find_packages, setup


setup(
    name='remchk',
    version='0.0.1',
    description='Remediation checker for vulnerability',
    author='Hosub Lee',
    author_email='spyrr83@gmail.com',
    install_requires=[
        'click==8.1.3',
        'Cerberus==1.3.4',
        'click==8.1.3',
        'colorama==0.4.5',
        'PyYAML==6.0',
        'requests==2.28.1',
    ],
    packages=find_packages(where='remchk'),
    package_dir={'': 'remchk'},
    py_modules=[splitext(basename(path))[0] for path in glob('remchk/*.py')],
    keywords=['vulnerability', 'remediation', 'checker'],
    python_requires='>=3.6',
    # include_package_data=True,
    # package_data={
    #     '': ['template.xlsm',],
    # },
    entry_points={
        'console_scripts': [
            'remchk = remchk:main', 
        ],
    },
    zip_safe=False,
    classifiers=[
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.6',
        'Programming Language :: Python :: 3.7',
        'Programming Language :: Python :: 3.8',
        'Programming Language :: Python :: 3.9',
    ]
)
