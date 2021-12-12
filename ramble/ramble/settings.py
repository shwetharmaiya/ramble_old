"""
Django settings for ramble project.

Generated by 'django-admin startproject' using Django 2.1.4.

For more information on this file, see
https://docs.djangoproject.com/en/2.1/topics/settings/

For the full list of settings and their values, see
https://docs.djangoproject.com/en/2.1/ref/settings/
"""

import os
from .config import * #SRM

# Build paths inside the project like this: os.path.join(BASE_DIR, ...)
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

MEDIA_ROOT = os.path.join(os.path.pardir, BASE_DIR, 'userdata')
MEDIA_URL = '/media/'


# Quick-start development settings - unsuitable for production
# See https://docs.djangoproject.com/en/2.1/howto/deployment/checklist/

# SECURITY WARNING: keep the secret key used in production secret!
SECRET_KEY = '!gw*9u^uy%$1d)jh=e5#cd9k9^q9g6a9#llzitr=5ez3bzmg7b'

# SECURITY WARNING: don't run with debug turned on in production!
DEBUG = True

ALLOWED_HOSTS = ['ramble.shwetharmaiya.repl.co','3cfd9715-c805-4599-a422-d42520609b49.id.repl.co','0.0.0.0', 'localhost', '127.0.0.1', '111.222.333.444', 'www.ramble.today']


# Application definition

INSTALLED_APPS = [
    'social_django',
    'django.contrib.auth',
    'taggit',
    'rambleapp.apps.RambleappConfig',
    'django.contrib.admin',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.messages',
    'django.contrib.staticfiles',
    'django.contrib.sites',
    'crispy_forms',
    'postman',
    'actstream',
    'magiclink',
]
SITE_ID = 1
POSTMAN_AUTO_MODERATE_AS = True 
POSTMAN_QUICKREPLY_QUOTE_BODY = True

MIDDLEWARE = [
    'social_django.middleware.SocialAuthExceptionMiddleware',
    'django.middleware.security.SecurityMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.middleware.common.CommonMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
]

ROOT_URLCONF = 'ramble.urls'

#SECURE_SSL_REDIRECT = True
SESSION_COOKIE_SECURE = False
CSRF_COOKIE_SECURE = False
SECURE_SSL_REDIRECT = False

TEMPLATES = [
    {
        'BACKEND': 'django.template.backends.django.DjangoTemplates',
        'DIRS': [os.path.join(BASE_DIR, 'templates')],
        'APP_DIRS': True,
        'OPTIONS': {
            'context_processors': [
                'social_django.context_processors.backends',
                'social_django.context_processors.login_redirect',
                'django.template.context_processors.debug',
                'django.template.context_processors.request',
                'django.contrib.auth.context_processors.auth',
                'django.contrib.messages.context_processors.messages',
            ],
        },
    },
]
CRISPY_TEMPLATE_PACK = 'bootstrap4'

WSGI_APPLICATION = 'ramble.wsgi.application'


# Database
# https://docs.djangoproject.com/en/2.1/ref/settings/#databases

DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.sqlite3',
        'NAME': os.path.join(BASE_DIR, 'db.sqlite3'),
    }
}


# Password validation
# https://docs.djangoproject.com/en/2.1/ref/settings/#auth-password-validators

AUTH_PASSWORD_VALIDATORS = [
    {
        'NAME': 'django.contrib.auth.password_validation.UserAttributeSimilarityValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.MinimumLengthValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.CommonPasswordValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.NumericPasswordValidator',
    },
]

AUTHENTICATION_BACKENDS = (
     'magiclink.backends.MagicLinkBackend',
    'social_core.backends.github.GithubOAuth2',
    'social_core.backends.twitter.TwitterOAuth',
    'social_core.backends.facebook.FacebookOAuth2',
    'social_core.backends.open_id.OpenIdAuth',
    'social_core.backends.google.GoogleOAuth2',
    'social_core.backends.google.GoogleOAuth',
   
    'django.contrib.auth.backends.ModelBackend',
)

LOGIN_URL = 'login'
LOGIN_REDIRECT_URL = 'index'
LOGOUT_URL = 'logout'

TAGGIT_CASE_INSENSITIVE = True

# Internationalization
# https://docs.djangoproject.com/en/2.1/topics/i18n/

LANGUAGE_CODE = 'en-us'

TIME_ZONE = 'UTC'

USE_I18N = True

USE_L10N = True

USE_TZ = True


# Static files (CSS, JavaScript, Images)
# https://docs.djangoproject.com/en/2.1/howto/static-files/

STATIC_URL = '/static/'

ACTSTREAM_SETTINGS = {
    'MANAGER': 'rambleapp.managers.MyActionManager',
    'FETCH_RELATIONS': True,
    'USE_PREFETCH': True,
    'USE_JSONFIELD': True,
    'GFK_FETCH_DEPTH': 1,
}
DEFAULT_AUTO_FIELD = 'django.db.models.AutoField'

# Set Djangos login URL to the magiclink login page
LOGIN_URL = 'magiclink:login'

MAGICLINK_LOGIN_TEMPLATE_NAME = 'magiclink/login_ml.html'
MAGICLINK_LOGIN_SENT_TEMPLATE_NAME = 'magiclink/login_sent.html'
MAGICLINK_LOGIN_FAILED_TEMPLATE_NAME = 'magiclink/login_failed.html'

# Optional:
# If this setting is set to False a user account will be created the first
# time a user requests a login link.
MAGICLINK_REQUIRE_SIGNUP = False
MAGICLINK_SIGNUP_TEMPLATE_NAME = 'magiclink/signup.html'
