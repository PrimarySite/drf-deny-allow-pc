# -*- coding: utf-8 -*-
"""
DRF Deny All - Allow Specific Permission Classes.

In Django rest Framework the permission classes work as:

    *If any permission check fails an [...] exception will be raised,
    and the main body of the view will not run.*

This implementation of permission classes takes a list of functions that
determine if the access is allowed. If **any** of the functions returns True,
the access is *allowed*, if **none** of the permission checks passes the access
will be *denied*. This enables to write small, reusable and chainable permissions

"""
from __future__ import unicode_literals

from functools import wraps

from rest_framework import permissions


def authenticated_users(func):
    """
    This decorator is used to abstract common authentication checking
    functionality out of permission checks.
    """

    @wraps(func)
    def func_wrapper(*args, **kwargs):
        if args:
            request = args[0]
        elif kwargs.get('request'):
            request = kwargs.get('request')
        else:
            return False

        if not(request.user and request.user.is_authenticated()):
            return False

        return func(*args, **kwargs)

    return func_wrapper


def deny_all(*args, **kwargs):
    """
    Deny Access to everyone.

    This permission is not strictly required, since you can achieve the same
    result by using an empty  tuple for the permissions setting, but you may
    find it useful to specify this class because it makes the intention
    explicit.

    This permission on it's own is not useful as *nobody* will ever be able
    to access a view protected with it.

    """
    return False


@authenticated_users
def allow_superuser(request, *args, **kwargs):
    """
    Superuser access.

    This permission allows access to any user that has the `is_superuser`
    flag set.

    """
    return request.user.is_superuser


@authenticated_users
def allow_staff(request, *args, **kwargs):
    """
    Staff access.

    This permission allows access to any user that has the `is_staff` flag set.

    """
    return request.user.is_staff


@authenticated_users
def allow_authenticated(request, *args, **kwargs):
    """
    Authenticated user access.

    This permission class will deny permission to any unauthenticated user,
    and allow permission to any authenticated user.

    """
    return True


def allow_all(*args, **kwargs):
    """
    Allow anyone.

    This permission will allow unrestricted access, regardless of
    the request being authenticated or unauthenticated.

    """
    return True


class DABasePermission(permissions.BasePermission):

    """
    Deny Allow Base Permisson.

    Permissions subclassed from this Base class will run all
    permission checks specified in the `rw_permissions` tuple.

    It does not check if it is a read or a write access and treat
    **all** access methods in the same way
    """

    message = 'Permission denied.'
    rw_permissions = (deny_all,)

    def has_permission(self, request, view):
        for permission in self.rw_permissions:
            if permission(request, view):
                return True
        return False


class DARWBasePermission(DABasePermission):

    """
    Deny Allow Base Read/Write specific Permisson.

    Permissions subclassed from this Base class will run all
    permission checks specified in the `rw_permissions` tuple
    for all read and write access methods.

    If none of the `rw_permissions` passed it will check the
    permissions based on the http access methods.

    For read access (`options`, `head`, `get`) methods
    all permissions in the `read_permissions` methods are checked.

    For write access (`post`, `put`, `patch`, `delete`) methods
    all permissions in the `write_permissions` methods are checked.

    """

    read_permissions = (deny_all,)
    write_permissions = (deny_all,)

    def has_permission(self, request, view):
        if super(DARWBasePermission, self).has_permission(request, view):
            # Check permissions for all read or write requests
            return True
        if request.method in permissions.SAFE_METHODS:
            # Check permissions for read-only requests
            for permission in self.read_permissions:
                if permission(request, view):
                    return True
        else:
            # Check permissions for write requests
            for permission in self.write_permissions:
                if permission(request, view):
                    return True
        return False
