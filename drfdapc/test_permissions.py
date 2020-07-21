# -*- coding: utf-8 -*-
"""Test DRF Deny All - Allow Specific Permission Classes."""
# Standard Library
from unittest import mock

# Django
from django.contrib.auth.models import AnonymousUser
from django.contrib.auth.models import User
from django.core.exceptions import ImproperlyConfigured

# 3rd-party
from rest_framework.test import APIRequestFactory
from rest_framework.test import APITransactionTestCase

# Local
from .permissions import DABasePermission
from .permissions import DACrudBasePermission
from .permissions import DARWBasePermission
from .permissions import allow_all
from .permissions import allow_authenticated
from .permissions import allow_authorized_key
from .permissions import allow_staff
from .permissions import allow_superuser
from .permissions import deny_all


class BaseTestCase(APITransactionTestCase):
    """Common Functionality for all Test cases."""

    def setUp(self):
        """Set common stuff up."""
        self.user = User.objects.create_user("christian", "me@test.com", "pw")
        self.factory = APIRequestFactory()
        self.request = self.factory.get("/")

    def tearDown(self):
        """Delete all created objects."""
        models = [User]
        for model in models:
            model.objects.all().delete()

    def has_access(self, request, view=None, obj=None, *args, **kwargs):  # noqa: D401
        """A Dummy Object Permission for easy to mock objects."""
        try:
            return bool(obj.allows_access)
        except AttributeError:
            return False

    def check_permission(self, permission, request):
        """
        Test the permission for a request for anonymous, staff and superuser.

        Assuming that only staff has the permission.
        """
        request.user = AnonymousUser()
        assert not permission.has_permission(request, None)

        self.user.is_superuser = False
        self.user.is_staff = True
        self.user.save()
        request.user = self.user
        assert permission.has_permission(request, None)

        self.user.is_superuser = True
        self.user.is_staff = False
        self.user.save()
        request.user = self.user
        assert not permission.has_permission(request, None)

    def check_object_permission(self, permission, request):
        """
        Test the permission for a request for anonymous, staff and superuser.

        Assuming that only staff can access the object when the object itself
        forbids access.
        """
        obj = mock.Mock()
        # allow access
        obj.allows_access = True
        request.user = AnonymousUser()
        assert permission.has_object_permission(request, None, obj)

        self.user.is_superuser = False
        self.user.is_staff = True
        self.user.save()
        request.user = self.user
        assert permission.has_object_permission(request, None, obj)

        self.user.is_superuser = True
        self.user.is_staff = False
        self.user.save()
        request.user = self.user
        assert permission.has_object_permission(request, None, obj)

        # restrict access
        obj.allows_access = False
        request.user = AnonymousUser()
        assert not permission.has_object_permission(request, None, obj)

        self.user.is_superuser = False
        self.user.is_staff = True
        self.user.save()
        request.user = self.user
        assert permission.has_object_permission(request, None, obj)

        self.user.is_superuser = True
        self.user.is_staff = False
        self.user.save()
        request.user = self.user
        assert not permission.has_object_permission(request, None, obj)

    def _test_rw_staff(self):
        """Staff can read and write."""
        permission = self.permission()
        permission.rw_permissions = (allow_staff,)
        request = self.factory.get("/")
        self.check_permission(permission, request)

        request = self.factory.post("/")
        self.check_permission(permission, request)

        request = self.factory.put("/")
        self.check_permission(permission, request)

        request = self.factory.delete("/")
        self.check_permission(permission, request)

    def _test_rw_object_staff(self):
        """Staff can read and write."""
        permission = self.permission()
        permission.object_rw_permissions = (allow_staff, self.has_access)
        request = self.factory.get("/")
        self.check_object_permission(permission, request)

        request = self.factory.post("/")
        self.check_object_permission(permission, request)

        request = self.factory.put("/")
        self.check_object_permission(permission, request)

        request = self.factory.delete("/")
        self.check_object_permission(permission, request)


class PermissionFunctionTestCase(BaseTestCase):
    """Test Permission functions."""

    def test_deny_all(self):
        """Even the most powerfull user will be rejected."""
        self.user.is_superuser = True
        self.user.is_staff = True
        self.user.save()
        self.request.user = self.user
        assert not deny_all(self.request)

    def test_allow_all(self):
        """No authentication is required."""
        assert allow_all(self.request)

    def test_allow_superuser(self):
        """Superuser has access, nobody else."""
        self.request.user = AnonymousUser()
        assert not allow_superuser(self.request)

        self.request.user = self.user
        assert not allow_superuser(self.request)

        self.request.user = self.user
        self.user.is_superuser = False
        self.user.is_staff = True
        self.user.save()
        assert not allow_superuser(self.request)

        self.user.is_superuser = True
        self.user.is_staff = False
        self.user.save()
        self.request.user = self.user
        assert allow_superuser(self.request)

    def test_allow_staff(self):
        """Staff user has access, nobody else, not even superuser."""
        self.request.user = AnonymousUser()
        assert not allow_staff(self.request)

        self.request.user = self.user
        assert not allow_staff(self.request)

        self.request.user = self.user
        self.user.is_superuser = False
        self.user.is_staff = True
        self.user.save()
        assert allow_staff(self.request)

        self.user.is_superuser = True
        self.user.is_staff = False
        self.user.save()
        self.request.user = self.user
        assert not allow_staff(self.request)

    def test_allow_authenticated(self):
        """Any authenticated user has access."""
        self.request.user = AnonymousUser()
        assert not allow_authenticated(self.request)

        self.request.user = self.user
        assert allow_authenticated(self.request)

    def test_allow_authenticated_request_kwarg(self):
        """Any authenticated user has access."""
        self.request.user = AnonymousUser()
        assert not allow_authenticated(request=self.request)

        self.request.user = self.user
        assert allow_authenticated(request=self.request)

    def test_allow_authenticated_no_request(self):
        """Without a request we cannot get the user."""
        with self.assertRaises(TypeError):  # noqa: PT009, T003
            allow_authenticated()

    def test_allow_authorized_key_valid_key(self):
        """Valid Keys pass."""
        view = mock.Mock()
        view.authorized_keys = ("aa11bb22", "cc33dd44")
        request = self.factory.get("/", HTTP_AUTHORIZATION="aa11bb22")
        assert allow_authorized_key(request, view)
        request = self.factory.get("/", HTTP_AUTHORIZATION="cc33dd44")
        assert allow_authorized_key(request, view)

    def test_allow_authorized_key_invalid_key(self):
        """Invalid Keys get rejected."""
        view = mock.Mock()
        view.authorized_keys = ("aa11bb22", "cc33dd44")
        request = self.factory.get("/", HTTP_AUTHORIZATION="aa11bb")
        assert not allow_authorized_key(request, view)
        request = self.factory.get("/", HTTP_AUTHORIZATION="cc33dd44xxx")
        assert not allow_authorized_key(request, view)

    def test_allow_authorized_key_invalid_authorized_keys_raises_improperly_configured_error(self):
        """Invalid configuration raises assertion error."""
        view = mock.Mock()
        view.authorized_keys = "aa11bb22"
        request = self.factory.get("/", HTTP_AUTHORIZATION="aa11bb22")
        with self.assertRaises(ImproperlyConfigured):   # noqa: PT009, T003
            allow_authorized_key(request, view)

    def test_has_access(self):
        """Make sure our Object Test Function works as expected."""
        obj = mock.Mock()
        # allow access
        obj.allows_access = True
        assert self.has_access(request=self.request, obj=obj)

        obj.allows_access = False
        assert not self.has_access(request=self.request, obj=obj)

        del obj.allows_access
        assert not self.has_access(request=self.request, obj=obj)

        assert not self.has_access(request=self.request, obj=None)


class DABasePermissionTestCase(BaseTestCase):
    """Test DABasePermission."""

    permission = DABasePermission

    def test_staff_and_superuser(self):
        """Assign 2 permissions and check that both have access."""
        permission = self.permission()
        permission.rw_permissions = (allow_staff, allow_superuser)
        self.request.user = AnonymousUser()
        assert not permission.has_permission(self.request, None)

        self.request.user = self.user
        assert not permission.has_permission(self.request, None)

        self.request.user = self.user
        self.request.user = self.user
        self.user.is_superuser = False
        self.user.is_staff = True
        self.user.save()
        assert permission.has_permission(self.request, None)

        self.user.is_superuser = True
        self.user.is_staff = False
        self.user.save()
        self.request.user = self.user
        assert permission.has_permission(self.request, None)

    def test_staff_and_superuser_object(self):
        """Assign 2 permissions and check that both have access to a certain object."""
        permission = self.permission()
        permission.object_rw_permissions = (allow_staff, allow_superuser, self.has_access)
        obj = mock.Mock()
        obj.allows_access = True
        self.request.user = AnonymousUser()
        assert permission.has_object_permission(self.request, None, obj)

        self.request.user = self.user
        assert permission.has_object_permission(self.request, None, obj)

        self.request.user = self.user
        self.request.user = self.user
        self.user.is_superuser = False
        self.user.is_staff = True
        self.user.save()
        assert permission.has_object_permission(self.request, None, obj)

        self.user.is_superuser = True
        self.user.is_staff = False
        self.user.save()
        self.request.user = self.user
        assert permission.has_object_permission(self.request, None, obj)

        # now the object does not allow access
        obj.allows_access = False
        self.request.user = AnonymousUser()
        assert not permission.has_object_permission(self.request, None, obj)

        self.user.is_superuser = False
        self.user.is_staff = False
        self.user.save()
        self.request.user = self.user
        assert not permission.has_object_permission(self.request, None, obj)

        self.request.user = self.user
        self.request.user = self.user
        self.user.is_superuser = False
        self.user.is_staff = True
        self.user.save()
        assert permission.has_object_permission(self.request, None, obj)

        self.user.is_superuser = True
        self.user.is_staff = False
        self.user.save()
        self.request.user = self.user
        assert permission.has_object_permission(self.request, None, obj)

    def test_rw_staff(self):
        """Staff can read and write."""
        self._test_rw_staff()

    def test_rw_object_staff(self):
        """Staff can read and write."""
        self._test_rw_object_staff()


class DARWBasePermissionTestCase(BaseTestCase):
    """Test DARWBasePermission."""

    permission = DARWBasePermission

    def test_rw_staff_and_superuser(self):
        """Assign 2 permissions to rw_permissions and check that both have access."""
        self.post_request = self.factory.post("/")
        permission = self.permission()
        permission.rw_permissions = (allow_staff, allow_superuser)
        self.request.user = AnonymousUser()
        assert not permission.has_permission(self.request, None)

        self.post_request.user = AnonymousUser()
        assert not permission.has_permission(self.post_request, None)

        self.request.user = self.user
        assert not permission.has_permission(self.request, None)

        self.post_request.user = self.user
        assert not permission.has_permission(self.post_request, None)

        self.request.user = self.user
        self.request.user = self.user
        self.user.is_superuser = False
        self.user.is_staff = True
        self.user.save()
        assert permission.has_permission(self.request, None)

        self.post_request.user = self.user
        assert permission.has_permission(self.post_request, None)

        self.user.is_superuser = True
        self.user.is_staff = False
        self.user.save()
        self.request.user = self.user
        assert permission.has_permission(self.request, None)

        self.post_request.user = self.user
        assert permission.has_permission(self.post_request, None)

    def test_w_staff_and_superuser(self):
        """Assign 2 permissions to write_permissions and check that both have access."""
        self.post_request = self.factory.post("/")
        permission = self.permission()
        permission.write_permissions = (allow_staff, allow_superuser)
        self.request.user = AnonymousUser()
        assert not permission.has_permission(self.request, None)

        self.post_request.user = AnonymousUser()
        assert not permission.has_permission(self.post_request, None)

        self.request.user = self.user
        assert not permission.has_permission(self.request, None)

        self.post_request.user = self.user
        assert not permission.has_permission(self.post_request, None)

        self.request.user = self.user
        self.user.is_superuser = False
        self.user.is_staff = True
        self.user.save()
        assert not permission.has_permission(self.request, None)

        self.post_request.user = self.user
        assert permission.has_permission(self.post_request, None)

        self.user.is_superuser = True
        self.user.is_staff = False
        self.user.save()
        self.request.user = self.user
        assert not permission.has_permission(self.request, None)

        self.post_request.user = self.user
        assert permission.has_permission(self.post_request, None)

    def test_r_staff_and_superuser(self):
        """Assign 2 permissions to rw_permissions and check that both have access."""
        self.post_request = self.factory.post("/")
        permission = self.permission()
        permission.read_permissions = (allow_staff, allow_superuser)
        self.request.user = AnonymousUser()
        assert not permission.has_permission(self.request, None)

        self.post_request.user = AnonymousUser()
        assert not permission.has_permission(self.post_request, None)

        self.request.user = self.user
        assert not permission.has_permission(self.request, None)

        self.post_request.user = self.user
        assert not permission.has_permission(self.post_request, None)

        self.request.user = self.user
        self.request.user = self.user
        self.user.is_superuser = False
        self.user.is_staff = True
        self.user.save()
        assert permission.has_permission(self.request, None)

        self.post_request.user = self.user
        assert not permission.has_permission(self.post_request, None)

        self.user.is_superuser = True
        self.user.is_staff = False
        self.user.save()
        self.request.user = self.user
        assert permission.has_permission(self.request, None)

        self.post_request.user = self.user
        assert not permission.has_permission(self.post_request, None)

    def test_r_staff_and_w_superuser(self):
        """Assign a permission to read_permissions another to write_permissions."""
        self.post_request = self.factory.post("/")
        permission = self.permission()
        permission.read_permissions = (allow_staff,)
        permission.write_permissions = (allow_superuser,)
        self.request.user = AnonymousUser()
        assert not permission.has_permission(self.request, None)

        self.post_request.user = AnonymousUser()
        assert not permission.has_permission(self.post_request, None)

        self.request.user = self.user
        assert not permission.has_permission(self.request, None)

        self.post_request.user = self.user
        assert not permission.has_permission(self.post_request, None)

        self.request.user = self.user
        self.request.user = self.user
        self.user.is_superuser = False
        self.user.is_staff = True
        self.user.save()
        assert permission.has_permission(self.request, None)

        self.post_request.user = self.user
        assert not permission.has_permission(self.post_request, None)

        self.user.is_superuser = True
        self.user.is_staff = False
        self.user.save()
        self.request.user = self.user
        assert not permission.has_permission(self.request, None)

        self.post_request.user = self.user
        assert permission.has_permission(self.post_request, None)

    def test_read_staff(self):
        """Only Staff can read."""
        request = self.factory.get("/")
        permission = self.permission()
        permission.read_permissions = (allow_staff,)
        self.check_permission(permission, request)

    def test_write_staff(self):
        """Only Staff can update."""
        request = self.factory.post("/")
        permission = self.permission()
        permission.write_permissions = (allow_staff,)
        self.check_permission(permission, request)

    def test_read_object_staff(self):
        """Only Staff can read."""
        request = self.factory.get("/")
        permission = self.permission()
        permission.object_read_permissions = (allow_staff, self.has_access)
        request.user = AnonymousUser()
        self.check_object_permission(permission, request)

    def test_write_object_staff(self):
        """Only Staff can create."""
        request = self.factory.post("/")
        permission = self.permission()
        permission.object_write_permissions = (allow_staff, self.has_access)
        self.check_object_permission(permission, request)

    def test_rw_staff(self):
        """Staff can read and write."""
        self._test_rw_staff()

    def test_rw_object_staff(self):
        """Staff can read and write."""
        self._test_rw_object_staff()


class DACrudBasePermissionTestCase(BaseTestCase):
    """
    Test DACrudBasePermission.

    We test here only the combination of anonymous, staff and superuser
    as permutations are covered in the above test cases.
    """

    permission = DACrudBasePermission

    def test_read_staff(self):
        """Only Staff can read."""
        request = self.factory.get("/")
        permission = self.permission()
        permission.read_permissions = (allow_staff,)
        self.check_permission(permission, request)

    def test_create_staff(self):
        """Only Staff can create."""
        request = self.factory.post("/")
        permission = self.permission()
        permission.add_permissions = (allow_staff,)
        self.check_permission(permission, request)

    def test_update_staff(self):
        """Only Staff can update."""
        request = self.factory.put("/")
        permission = self.permission()
        permission.change_permissions = (allow_staff,)
        self.check_permission(permission, request)

    def test_delete_staff(self):
        """Only Staff can delete."""
        request = self.factory.delete("/")
        permission = self.permission()
        permission.delete_permissions = (allow_staff,)
        self.check_permission(permission, request)

    def test_read_object_staff(self):
        """Only Staff can read."""
        request = self.factory.get("/")
        permission = self.permission()
        permission.object_read_permissions = (allow_staff, self.has_access)
        request.user = AnonymousUser()
        self.check_object_permission(permission, request)

    def test_create_object_staff(self):
        """Only Staff can create."""
        request = self.factory.post("/")
        permission = self.permission()
        permission.object_add_permissions = (allow_staff, self.has_access)
        self.check_object_permission(permission, request)

    def test_update_object_staff(self):
        """Only Staff can update."""
        request = self.factory.put("/")
        permission = self.permission()
        permission.object_change_permissions = (allow_staff, self.has_access)
        self.check_object_permission(permission, request)

    def test_delete_object_staff(self):
        """Only Staff can delete."""
        request = self.factory.delete("/")
        permission = self.permission()
        permission.object_delete_permissions = (allow_staff, self.has_access)
        self.check_object_permission(permission, request)

    def test_rw_staff(self):
        """Staff can read and write."""
        self._test_rw_staff()

    def test_rw_object_staff(self):
        """Staff can read and write."""
        self._test_rw_object_staff()
