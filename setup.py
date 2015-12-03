from setuptools import setup, find_packages
import sys, os

version = '0.1'

setup(name='drfdapc',
      version=version,
      description="DRF Deny All - Allow Specific Permission Classes.",
      long_description="""\
""",
      classifiers=[], # Get strings from http://pypi.python.org/pypi?%3Aaction=list_classifiers
      keywords='django permission drf',
      author='Christian Ledermann',
      author_email='christian.ledermann@gmail.com',
      url='https://github.com/PrimarySite/drfdapc/',
      license='MIT',
      packages=find_packages(exclude=['ez_setup', 'examples', 'tests']),
      include_package_data=True,
      zip_safe=False,
      install_requires=[
          # -*- Extra requirements: -*-
      ],
      entry_points="""
      # -*- Entry points: -*-
      """,
      )
