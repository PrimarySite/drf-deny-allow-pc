# -*- coding: utf-8 -*-

import os, sys
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'test_settings')
sys.path.insert(0, 'tests')

from django.core.management import call_command

if __name__ == '__main__':
    import django
    django.setup()
    args = sys.argv[1:]
    call_command('test', *args, verbosity=2, failfast=True)
