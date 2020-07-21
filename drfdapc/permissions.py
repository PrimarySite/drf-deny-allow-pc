# -*- coding: utf-8 -*-
"""
DRF Deny All - Allow Specific Permission Classes.

In Django rest Framework the permission classes work as:

    *If any permission check fails an [...] exception will be raised,
    and the main body of the view will not run.*

This implementation of permission classes takes a list of functions that
determine if the access is allowed. If **any** of the functions return `True`,
the access is *allowed*, if **none** of the permission checks passes the access
will be *denied*. This enables to write small, reusable and chainable
permissions

The BasePermission classes provide the `has_permission(self, request, view)`
and `has_object_permission(self, request, view, obj)` methods.

The **Default** is `deny_all` which means when you subclass `DABasePermission`,
`DARWBasePermission` or `DACrudBasePermission` you have to set `*_permissions`
explicitly on your class to allow access.

If you only need view level security you may set
`object_rw_permissions = (allow_all, )` otherwise your view will reject users
when `.get_object()` is called through REST framework's view machinery.

"""
# Standard Library
from functools import wraps
from unittest.mock import Mock

# Django
from django.core.exceptions import ImproperlyConfigured
from django.db.models import Model
from django.http import HttpRequest

# 3rd-party
from rest_framework import permissions


def authenticated_users(func):
    """
    Abstract common authentication checks as a decorator.

    `request` is required either as the first positional argument
    or as a Keyword argument
    """

    @wraps(func)
    def func_wrapper(*args, **kwargs):
        """
        Determine if the user is authenticated.

        It is recommended to always pass the request as a named argument.
        """
        if kwargs.get("request"):
            request = kwargs.get("request")
        elif args:
            request = args[0]
        else:
            raise TypeError("authenticated_users() missing 1 required argument: `request`")

        if not request.user.is_authenticated:
            return False

        return func(*args, **kwargs)

    return func_wrapper


def deny_all(*args, **kwargs) -> bool:
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
def allow_superuser(request: HttpRequest, *args, **kwargs) -> bool:
    """
    Superuser access.

    This permission allows access to any user that has the `is_superuser`
    flag set.
    """
    return request.user.is_superuser


@authenticated_users
def allow_staff(request: HttpRequest, *args, **kwargs) -> bool:
    """
    Allow staff access.

    This permission allows access to any user that has the `is_staff` flag set.
    """
    return request.user.is_staff


@authenticated_users
def allow_authenticated(request: HttpRequest, *args, **kwargs) -> bool:
    """
    Allow authenticated users.

    This permission class will deny permission to any unauthenticated user,
    and allow permission to any authenticated user.
    """
    return True


def allow_all(*args, **kwargs) -> bool:
    """
    Allow anyone.

    This permission will allow unrestricted access, regardless of
    the request being authenticated or unauthenticated.
    """
    return True


def allow_authorized_key(request: HttpRequest, view: Mock, *args, **kwargs) -> bool:
    """
    Allow access with a shared secret.

    The request must contain a authentication header that matches one of the API Keys.

    The API Keys are set in the authorized_keys attribute of the view.
    This is useful for authorization between services that communicate via drf
    where you'd rather have the keys as configuration and connect without
    authentication.
    """
    key = request.META.get("HTTP_AUTHORIZATION")
    if not isinstance(view.authorized_keys, (tuple, list)):
        raise ImproperlyConfigured("authorized_keys must be a tuple or a list")
    if key in view.authorized_keys:
        return True
    return False


class DABasePermission(permissions.BasePermission):
    """
    Deny Allow Base Permisson.

    Permissions subclassed from this Base class will run all
    permission checks specified in the `rw_permissions` tuple.

    It does not check if it is a read or a write access and treat
    **all** access methods in the same way.
    """

    message = "Permission denied."
    rw_permissions = (deny_all,)
    object_rw_permissions = (deny_all,)

    def has_permission(self, request: HttpRequest, view: None) -> bool:
        """
        Check permissions.

        Before running the main body of the view each permission in
        `rw_permissions` is checked.

        All request methods are treated in the same way.
        """
        for permission in self.rw_permissions:
            if permission(request=request, view=view):
                return True
        return False

    def has_object_permission(self, request: HttpRequest, view: None, obj: Mock) -> bool:
        """Object level permissions.

        All request methods are checked against the `object_rw_permissions`.
        If None of those permissions returns True the access is denied.

        This is run by REST framework's generic views when `.get_object()` is
        called. If you're writing your own views and want to enforce object
        level permissions, or if you override the get_object method on a
        generic view, then you'll need to explicitly call the
        `.check_object_permissions(request, obj)` method on the view at the
        point at which you've retrieved the object.
        """
        for permission in self.object_rw_permissions:
            if permission(request=request, view=view, obj=obj):
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
    """

    read_permissions = (deny_all,)
    write_permissions = (deny_all,)
    object_read_permissions = (deny_all,)
    object_write_permissions = (deny_all,)

    def has_permission(self, request: HttpRequest, view: None) -> bool:
        """
        Check permissions.

        Before running the main body of the view each permission in
        `rw_permissions` is checked.
        If None of these permissions allows access then the permissions in
        `read_permissions` are checked for the (`options`, `head`, `get`)
        methods.
        For write access (`post`, `put`, `patch`, `delete`) methods
        all permissions in the `write_permissions` methods are checked.

        """
        if super(DARWBasePermission, self).has_permission(request=request, view=view):
            # Check permissions for all read or write requests
            return True
        if request.method in permissions.SAFE_METHODS:
            # Check permissions for read-only requests
            for permission in self.read_permissions:
                if permission(request=request, view=view):
                    return True
        else:
            # Check permissions for write requests
            for permission in self.write_permissions:
                if permission(request=request, view=view):
                    return True
        return False

    def has_object_permission(self, request: HttpRequest, view: None, obj: Mock) -> bool:
        """Object level permissions.

        All request methods are checked against the `object_rw_permissions`.
        If None of those Permissions returns True the permissions are checked
        against `object_read_permissions` if the request method is a `get`,
        `head` or `options`,
        or against `object_write_permissions` for `put`, `patch`, `post` and
        `delete` methods.

        This is run by REST framework's generic views when .get_object() is
        called. If you're writing your own views and want to enforce object
        level permissions, or if you override the get_object method on a
        generic view, then you'll need to explicitly call the
        `.check_object_permissions(request, obj)` method on the view at the
        point at which you've retrieved the object.
        """
        if super(DARWBasePermission, self).has_object_permission(
            request=request, view=view, obj=obj,
        ):
            # Check permissions for all read or write requests
            return True
        if request.method in permissions.SAFE_METHODS:
            # Check permissions for read-only requests
            for permission in self.object_read_permissions:
                if permission(request=request, view=view, obj=obj):
                    return True
        else:
            # Check permissions for write requests
            for permission in self.object_write_permissions:
                if permission(request=request, view=view, obj=obj):
                    return True
        return False


class DACrudBasePermission(DABasePermission):
    """
    Deny Allow Base Read/Write specific Permisson.

    Permissions subclassed from this Base class will run all
    permission checks specified in the `rw_permissions` tuple
    for all read and write access methods.

    If none of the `rw_permissions` passed it will check the
    permissions based on the http access methods.

    For read access (`options`, `head`, `get`) methods
    all permissions in the `read_permissions` methods are checked.

    For create access (`post`) all permissions in the `add_permissions` are
    checked.

    For update access (`put`) all permissions in the `change_permissions` are
    checked.

    For delete access (`delete`) all permissions in the `delete_permissions`
    are checked.
    """

    read_permissions = (deny_all,)
    add_permissions = (deny_all,)
    change_permissions = (deny_all,)
    delete_permissions = (deny_all,)
    object_read_permissions = (deny_all,)
    object_add_permissions = (deny_all,)
    object_change_permissions = (deny_all,)
    object_delete_permissions = (deny_all,)

    def has_permission(self, request: HttpRequest, view: None) -> bool:
        """
        Check permissions.

        Before running the main body of the view each permission in
        `rw_permissions` is checked.
        If None of these permissions allows access then the permissions in
        `read_permissions` are checked for the (`options`, `head`, `get`)
        methods.
        For the `post` method all permissions in the `add_permissions` are
        checked.
        For `put` and `patch` methods all permissions in the
        `change_permissions` are checked.
        For the `delete` method all permissions in the `delete_permissions`
        are checked.

        """
        if super(DACrudBasePermission, self).has_permission(request=request, view=view):
            # Check permissions for all read or write requests
            return True

        if request.method in permissions.SAFE_METHODS:
            # Check permissions for read-only requests
            for permission in self.read_permissions:
                if permission(request=request, view=view):
                    return True
            return False

        elif request.method in ["PUT", "PATCH"]:
            # Update
            for permission in self.change_permissions:
                if permission(request=request, view=view):
                    return True
            return False

        elif request.method == "POST":
            # Create
            for permission in self.add_permissions:
                if permission(request=request, view=view):
                    return True
            return False

        elif request.method == "DELETE":
            # Delete
            for permission in self.delete_permissions:
                if permission(request=request, view=view):
                    return True
        return False

    def has_object_permission(self, request: HttpRequest, view: None, obj: Mock) -> bool:
        """Object level permissions.

        All request methods are checked against the `object_rw_permissions`.
        If None of those Permissions returns True the permissions are checked
        against `object_read_permissions` if the request method is a `get`,
        `head` or `options`,
        or against `object_change_permissions` for `put`and `patch`,
        against `object_add_permissions` for `post` and
        against `object_delete_permissions` for `delete` methods.

        This is run by REST framework's generic views when .get_object() is
        called. If you're writing your own views and want to enforce object
        level permissions, or if you override the get_object method on a
        generic view, then you'll need to explicitly call the
        `.check_object_permissions(request, obj)` method on the view at the
        point at which you've retrieved the object.
        """
        if super(DACrudBasePermission, self).has_object_permission(
            request=request, view=view, obj=obj,
        ):
            # Check permissions for all read or write requests
            return True

        if request.method in permissions.SAFE_METHODS:
            for permission in self.object_read_permissions:
                if permission(request=request, view=view, obj=obj):
                    return True
            return False

        elif request.method in ["PUT", "PATCH"]:
            for permission in self.object_change_permissions:
                if permission(request=request, view=view, obj=obj):
                    return True
            return False

        elif request.method == "POST":
            for permission in self.object_add_permissions:
                if permission(request=request, view=view, obj=obj):
                    return True
            return False

        elif request.method == "DELETE":
            for permission in self.object_delete_permissions:
                if permission(request=request, view=view, obj=obj):
                    return True
        return False
