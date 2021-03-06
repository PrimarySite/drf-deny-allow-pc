An alternate approach to building permission classes with permission
chaining using an 'OR' logic


In Django rest Framework the permission classes work as:

    If any permission check fails an [...] exception will be raised,
    and the main body of the view will not run. They all
    have to allow access for the permission to work ('AND').

This implementation of permission classes takes a list of functions that
determine if the access is allowed. If **any** of the functions returns True,
the access is **allowed**, if **none** of the permission checks passes the access
will be **denied**. This enables to write small, reusable and chainable permissions.
You have to be explicit which users have access.

.. image:: https://travis-ci.org/PrimarySite/drf-deny-allow-pc.svg?branch=master
    :target: https://travis-ci.org/PrimarySite/drf-deny-allow-pc

.. image:: https://codecov.io/github/PrimarySite/drf-deny-allow-pc/coverage.svg?branch=master
    :target: https://codecov.io/github/PrimarySite/drf-deny-allow-pc

.. image:: https://readthedocs.org/projects/drfdapc/badge/?version=latest
    :target: http://drfdapc.readthedocs.org/en/latest/?badge=latest
    :alt: Documentation Status

To build the sphinx documentation execute `make html` in the docs directory.
