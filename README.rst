An alternate approach to building permission classes

In Django rest Framework the permission classes work as:

    If any permission check fails an [...] exception will be raised,
    and the main body of the view will not run.

This implementation of permission classes takes a list of functions that
determine if the access is allowed. If any of the functions returns True,
the access is allowed, if none of the permission checks passes the access
will be denied. This enables to write small, reusable and chainable permissions

.. image:: https://travis-ci.org/PrimarySite/drf-deny-allow-pc.svg?branch=master
    :target: https://travis-ci.org/PrimarySite/drf-deny-allow-pc

.. image:: https://codecov.io/github/PrimarySite/drf-deny-allow-pc/coverage.svg?branch=master
    :target: https://codecov.io/github/PrimarySite/drf-deny-allow-pc
