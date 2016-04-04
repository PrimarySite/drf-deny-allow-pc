# -*- coding: utf-8 -*-
"""Test DRF Deny All - Allow Specific Permission Classes."""
from .permissions import (DABasePermission, DARWBasePermission, DACrudBasePermission,
                          allow_all, allow_authenticated,
                          allow_staff, allow_superuser, deny_all)
from django.contrib.auth.models import AnonymousUser, User
from rest_framework.test import (APIRequestFactory,
                                 APITransactionTestCase)


class BaseTestCase(APITransactionTestCase):

    """Common Functionality for all Test cases."""

    def setUp(self):
        """Set common stuff up."""
        self.user = User.objects.create_user('christian', 'me@test.com', 'pw')
        self.factory = APIRequestFactory()
        self.request = self.factory.get('/')

    def tearDown(self):
        """Delete all created objects."""
        models = [User]
        for model in models:
            model.objects.all().delete()


class PermissionFunctionTestCase(BaseTestCase):

    """Test Permission functions."""

    def test_deny_all(self):
        """Even the most powerfull user will be rejected."""
        self.user.is_superuser = True
        self.user.is_staff = True
        self.user.save()
        self.request.user = self.user
        self.assertFalse(deny_all(self.request))

    def test_allow_all(self):
        """No authentication is required."""
        self.assertTrue(allow_all(self.request))

    def test_allow_superuser(self):
        """Superuser has access, nobody else."""
        self.request.user = AnonymousUser()
        self.assertFalse(allow_superuser(self.request))
        self.request.user = self.user
        self.assertFalse(allow_superuser(self.request))
        self.request.user = self.user
        self.user.is_superuser = False
        self.user.is_staff = True
        self.user.save()
        self.assertFalse(allow_superuser(self.request))
        self.user.is_superuser = True
        self.user.is_staff = False
        self.user.save()
        self.request.user = self.user
        self.assertTrue(allow_superuser(self.request))

    def test_allow_staff(self):
        """Staff user has access, nobody else, not even superuser."""
        self.request.user = AnonymousUser()
        self.assertFalse(allow_staff(self.request))
        self.request.user = self.user
        self.assertFalse(allow_staff(self.request))
        self.request.user = self.user
        self.user.is_superuser = False
        self.user.is_staff = True
        self.user.save()
        self.assertTrue(allow_staff(self.request))
        self.user.is_superuser = True
        self.user.is_staff = False
        self.user.save()
        self.request.user = self.user
        self.assertFalse(allow_staff(self.request))

    def test_allow_authenticated(self):
        """Any authenticated user has access."""
        self.request.user = AnonymousUser()
        self.assertFalse(allow_authenticated(self.request))
        self.request.user = self.user
        self.assertTrue(allow_authenticated(self.request))

    def test_allow_authenticated_request_kwarg(self):
        """Any authenticated user has access."""
        self.request.user = AnonymousUser()
        self.assertFalse(allow_authenticated(request=self.request))
        self.request.user = self.user
        self.assertTrue(allow_authenticated(request=self.request))

    def test_allow_authenticated_no_request(self):
        """Without a request we cannot get the user."""
        with self.assertRaises(TypeError):
            allow_authenticated()


class DABasePermissionTestCase(BaseTestCase):

    """Test DABasePermission."""

    def test_staff_and_superuser(self):
        """Assign 2 permissions and check that both have access."""
        permission = DABasePermission()
        permission.rw_permissions = (allow_staff, allow_superuser)
        self.request.user = AnonymousUser()
        self.assertFalse(permission.has_permission(self.request, None))
        self.request.user = self.user
        self.assertFalse(permission.has_permission(self.request, None))
        self.request.user = self.user
        self.request.user = self.user
        self.user.is_superuser = False
        self.user.is_staff = True
        self.user.save()
        self.assertTrue(permission.has_permission(self.request, None))
        self.user.is_superuser = True
        self.user.is_staff = False
        self.user.save()
        self.request.user = self.user
        self.assertTrue(permission.has_permission(self.request, None))


class DARWBasePermissionTestCase(BaseTestCase):

    """Test DARWBasePermission."""

    def test_rw_staff_and_superuser(self):
        """Assign 2 permissions to rw_permissions and check that both have access."""
        self.post_request = self.factory.post('/')
        permission = DARWBasePermission()
        permission.rw_permissions = (allow_staff, allow_superuser)
        self.request.user = AnonymousUser()
        self.assertFalse(permission.has_permission(self.request, None))
        self.post_request.user = AnonymousUser()
        self.assertFalse(permission.has_permission(self.post_request, None))
        self.request.user = self.user
        self.assertFalse(permission.has_permission(self.request, None))
        self.post_request.user = self.user
        self.assertFalse(permission.has_permission(self.post_request, None))
        self.request.user = self.user
        self.request.user = self.user
        self.user.is_superuser = False
        self.user.is_staff = True
        self.user.save()
        self.assertTrue(permission.has_permission(self.request, None))
        self.post_request.user = self.user
        self.assertTrue(permission.has_permission(self.post_request, None))
        self.user.is_superuser = True
        self.user.is_staff = False
        self.user.save()
        self.request.user = self.user
        self.assertTrue(permission.has_permission(self.request, None))
        self.post_request.user = self.user
        self.assertTrue(permission.has_permission(self.post_request, None))

    def test_w_staff_and_superuser(self):
        """Assign 2 permissions to rw_permissions and check that both have access."""
        self.post_request = self.factory.post('/')
        permission = DARWBasePermission()
        permission.write_permissions = (allow_staff, allow_superuser)
        self.request.user = AnonymousUser()
        self.assertFalse(permission.has_permission(self.request, None))
        self.post_request.user = AnonymousUser()
        self.assertFalse(permission.has_permission(self.post_request, None))
        self.request.user = self.user
        self.assertFalse(permission.has_permission(self.request, None))
        self.post_request.user = self.user
        self.assertFalse(permission.has_permission(self.post_request, None))
        self.request.user = self.user
        self.request.user = self.user
        self.user.is_superuser = False
        self.user.is_staff = True
        self.user.save()
        self.assertFalse(permission.has_permission(self.request, None))
        self.post_request.user = self.user
        self.assertTrue(permission.has_permission(self.post_request, None))
        self.user.is_superuser = True
        self.user.is_staff = False
        self.user.save()
        self.request.user = self.user
        self.assertFalse(permission.has_permission(self.request, None))
        self.post_request.user = self.user
        self.assertTrue(permission.has_permission(self.post_request, None))

    def test_r_staff_and_superuser(self):
        """Assign 2 permissions to rw_permissions and check that both have access."""
        self.post_request = self.factory.post('/')
        permission = DARWBasePermission()
        permission.read_permissions = (allow_staff, allow_superuser)
        self.request.user = AnonymousUser()
        self.assertFalse(permission.has_permission(self.request, None))
        self.post_request.user = AnonymousUser()
        self.assertFalse(permission.has_permission(self.post_request, None))
        self.request.user = self.user
        self.assertFalse(permission.has_permission(self.request, None))
        self.post_request.user = self.user
        self.assertFalse(permission.has_permission(self.post_request, None))
        self.request.user = self.user
        self.request.user = self.user
        self.user.is_superuser = False
        self.user.is_staff = True
        self.user.save()
        self.assertTrue(permission.has_permission(self.request, None))
        self.post_request.user = self.user
        self.assertFalse(permission.has_permission(self.post_request, None))
        self.user.is_superuser = True
        self.user.is_staff = False
        self.user.save()
        self.request.user = self.user
        self.assertTrue(permission.has_permission(self.request, None))
        self.post_request.user = self.user
        self.assertFalse(permission.has_permission(self.post_request, None))

    def test_r_staff_and_w_superuser(self):
        """Assign a permission to read_permissions another to write_permissions."""
        self.post_request = self.factory.post('/')
        permission = DARWBasePermission()
        permission.read_permissions = (allow_staff, )
        permission.write_permissions = (allow_superuser, )
        self.request.user = AnonymousUser()
        self.assertFalse(permission.has_permission(self.request, None))
        self.post_request.user = AnonymousUser()
        self.assertFalse(permission.has_permission(self.post_request, None))
        self.request.user = self.user
        self.assertFalse(permission.has_permission(self.request, None))
        self.post_request.user = self.user
        self.assertFalse(permission.has_permission(self.post_request, None))
        self.request.user = self.user
        self.request.user = self.user
        self.user.is_superuser = False
        self.user.is_staff = True
        self.user.save()
        self.assertTrue(permission.has_permission(self.request, None))
        self.post_request.user = self.user
        self.assertFalse(permission.has_permission(self.post_request, None))
        self.user.is_superuser = True
        self.user.is_staff = False
        self.user.save()
        self.request.user = self.user
        self.assertFalse(permission.has_permission(self.request, None))
        self.post_request.user = self.user
        self.assertTrue(permission.has_permission(self.post_request, None))


class DACrudBasePermissionTestCase(BaseTestCase):

    """
    Test DACrudBasePermission.

    We Test here only the combination of anonymous, staff and superuser
    as permutations are covered in the above test cases.
    """

    def check_permission(self, permission, request):
        """
        Test the permission for a request for anonymous, staff and superuser.

        Assuming that only staff has the permission.
        """
        request.user = AnonymousUser()
        self.assertFalse(permission.has_permission(request, None))
        self.user.is_superuser = False
        self.user.is_staff = True
        self.user.save()
        request.user = self.user
        self.assertTrue(permission.has_permission(request, None))
        self.user.is_superuser = True
        self.user.is_staff = False
        self.user.save()
        request.user = self.user
        self.assertFalse(permission.has_permission(request, None))

    def test_rw_staff(self):
        """Staff can read and write."""
        permission = DACrudBasePermission()
        permission.rw_permissions = (allow_staff, )
        request = self.factory.get('/')
        self.check_permission(permission, request)
        request = self.factory.post('/')
        self.check_permission(permission, request)
        request = self.factory.put('/')
        self.check_permission(permission, request)
        request = self.factory.delete('/')
        self.check_permission(permission, request)

    def test_read_staff(self):
        """Only Staff can read."""
        request = self.factory.get('/')
        permission = DACrudBasePermission()
        permission.read_permissions = (allow_staff, )
        request.user = AnonymousUser()
        self.check_permission(permission, request)

    def test_create_staff(self):
        """Only Staff can create."""
        request = self.factory.post('/')
        permission = DACrudBasePermission()
        permission.add_permissions = (allow_staff, )
        self.check_permission(permission, request)

    def test_update_staff(self):
        """Only Staff can update."""
        request = self.factory.put('/')
        permission = DACrudBasePermission()
        permission.change_permissions = (allow_staff, )
        self.check_permission(permission, request)

    def test_delete_staff(self):
        """Only Staff can delete."""
        request = self.factory.delete('/')
        permission = DACrudBasePermission()
        permission.delete_permissions = (allow_staff, )
        self.check_permission(permission, request)
