# -*- coding: utf-8 -*-

from setuptools import setup


setup(
    name='black-dnsync',
    version='0.1.0',
    license='GPL',
    description='dns syncer',
    zip_safe=False,
    include_package_data=True,
    author='Maple',
    author_email='maplevalley8@gmail.com',
    platforms='any',
    packages=['black_dnsync'],
    entry_points="""
    [console_scripts]
    blackdnsync = black_dnsync.main:main
    """,
    install_requires=[
        'configparser',
        'paramiko',
        'requests',
        'termcolor',
    ],
    classifiers=[
        'Intended Audience :: Developers',
        'Operating System :: OS Independent',
        'Programming Language :: Python',
        "Programming Language :: Python :: 2",
        'Programming Language :: Python :: 2.7',
    ]
)
