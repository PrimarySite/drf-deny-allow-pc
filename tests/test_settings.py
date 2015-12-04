# -*- coding: utf-8 -*-

DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.sqlite3'
    },
}

SECRET_KEY = "django_tests_secret_key"
#TIME_ZONE = 'UTC'
#LANGUAGE_CODE = 'en'
#ADMIN_MEDIA_PREFIX = '/static/admin/'
#STATICFILES_DIRS = ()


INSTALLED_APPS = (
    'django.contrib.auth',
    'django.contrib.contenttypes',
    #'django.contrib.sessions',
    #'django.contrib.messages',
    #'django.contrib.admin',
    #'django.contrib.staticfiles',
    #'django.contrib.sitemaps',
    'rest_framework',
)
