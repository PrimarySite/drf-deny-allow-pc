from setuptools import setup, find_packages
from setuptools.command.test import test as TestCommand
import sys, os

class PyTest(TestCommand):
    def finalize_options(self):
        TestCommand.finalize_options(self)
        self.test_args = []
        self.test_suite = True

    def run_tests(self):
        # import here, cause outside the eggs aren't loaded
        import pytest
        errno = pytest.main(self.test_args)
        sys.exit(errno)

version = '0.1'

setup(name='drfdapc',
    version=version,
    description="DRF Deny All - Allow Specific Permission Classes.",
    long_description=(open("README.rst").read() + "\n"),
    classifiers=[
        'Framework :: Django',
        'Framework :: Django :: 1.6',
        'Framework :: Django :: 1.8',
        'Programming Language :: Python :: 2.7'
        'Programming Language :: Python :: 2'
        'Programming Language :: Python :: 3'
        'Programming Language :: Python :: 3.4'
    ], # Get strings from http://pypi.python.org/pypi?%3Aaction=list_classifiers
    keywords='django permission restframework',
    author='Christian Ledermann',
    author_email='christian.ledermann@gmail.com',
    url='https://github.com/PrimarySite/drfdapc/',
    license='MIT',
    packages=find_packages(exclude=['ez_setup', 'examples', 'tests']),
    include_package_data=True,
    zip_safe=False,
    install_requires=[
        # -*- Extra requirements: -*-
        'Django',
        'djangorestframework',
    ],
    tests_require=['pytest'],
    cmdclass={'test': PyTest},
    entry_points="""
    # -*- Entry points: -*-
    """,
    )
