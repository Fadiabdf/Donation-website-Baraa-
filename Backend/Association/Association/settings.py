"""
Django settings for Association project.

Generated by 'django-admin startproject' using Django 4.1.7.

For more information on this file, see
https://docs.djangoproject.com/en/4.1/topics/settings/

For the full list of settings and their values, see
https://docs.djangoproject.com/en/4.1/ref/settings/
"""

from pathlib import Path
import os

EPAY_SECRET_KEY = os.environ.get('secret_e5ecf09832590e31587758696c7368879b13853cba43258a3efe095b9ebf9d37')

# Build paths inside the project like this: BASE_DIR / 'subdir'.
BASE_DIR = Path(__file__).resolve().parent.parent

# Quick-start development settings - unsuitable for production
# See https://docs.djangoproject.com/en/4.1/howto/deployment/checklist/

# SECURITY WARNING: keep the secret key used in production secret!
SECRET_KEY = 'django-insecure-xr=l%$kwre5%kso184*dp!u#km(znwf!$%uys%9%1-9spj9had'

# SECURITY WARNING: don't run with debug turned on in production!
DEBUG = True

ALLOWED_HOSTS = []

PHONENUMBER_DEFAULT_REGION = 'DZ'

# Application definitions

SITE_ID=3

INSTALLED_APPS = [
    'django.contrib.admin',
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.messages',
    'corsheaders',
    'django.contrib.staticfiles', 
    'enumfields',
    'rest_framework',
    'rest_framework.authtoken',
    'django_countries',
    #'webapp',
    'webapp.apps.WebappConfig',
    'phonenumber_field',
    'django_filters', 
    'knox',
    'allauth',
    'allauth.account',
    'allauth.socialaccount',
    'allauth.socialaccount.providers.google',
    'django.contrib.sites',
    'chargily_epay_django',
    'social_django',
    'ckeditor',
   

]
CHARGILY_SECRET_KEY = 'secret_e5ecf09832590e31587758696c7368879b13853cba43258a3efe095b9ebf9d37'
CHARGILY_API_KEY = 'api_BN9DCaNUmTxRadEgZaAog4NrCLuPBKKAYnaWqQyoH4pCPfkwDAHfJYZzmV0ral1u'
CHARGILY_EPAY_ENDPOINT = 'https://api.chargily.com/v1/epay'
CHARGILY_CURRENCY = 'DZD'
CHARGILY_SOURCE = 'web'

SOCIALACCOUNT_PROVIDERS = {
    'google': {
        'SCOPE': [
            'profile',
            'email',
        ],
        'AUTH_PARAMS': {
            'access_type': 'online',
        }
    }
}

MIDDLEWARE = [
    'django.middleware.security.SecurityMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware',
     "corsheaders.middleware.CorsMiddleware",
    "django.middleware.common.CommonMiddleware", 
    'django.middleware.csrf.CsrfViewMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
    'django.middleware.clickjacking.XFrameOptionsMiddleware', 
    "social_django.middleware.SocialAuthExceptionMiddleware", 

]


ROOT_URLCONF = 'Association.urls'

TEMPLATES = [
    {
        'BACKEND': 'django.template.backends.django.DjangoTemplates',
        'DIRS': [os.path.join(BASE_DIR, 'templates')],
        'APP_DIRS': True,
        'OPTIONS': {
            'context_processors': [
                'django.template.context_processors.debug',
                'django.template.context_processors.request',
                'django.contrib.auth.context_processors.auth',
                'django.contrib.messages.context_processors.messages',
            ],
        },
    },
]

WSGI_APPLICATION = 'Association.wsgi.application'

# Database
# https://docs.djangoproject.com/en/4.1/ref/settings/#databases

DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.sqlite3',
        'NAME': BASE_DIR / 'db.sqlite3',
    }
}


# Password validation
# https://docs.djangoproject.com/en/4.1/ref/settings/#auth-password-validators

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

REST_FRAMEWORK = {
    'DEFAULT_AUTHENTICATION_CLASSES':[
    'rest_framework.authentication.TokenAuthentication',
    'knox.auth.TokenAuthentication',
    'rest_framework.authentication.BasicAuthentication',
    'rest_framework.authentication.SessionAuthentication',
    'rest_framework_simplejwt.authentication.JWTAuthentication'
    ],
   'DEFAULT_PERMISSION_CLASSES': [
    'rest_framework.permissions.AllowAny',
    'rest_framework.permissions.IsAuthenticated',
   ],
   'DEFAULT_PAGINATION_CLASS': 'rest_framework.pagination.LimitOffsetPagination',
   'PAGE_SIZE': 100
}

CORS_ORIGIN_WHITELIST = [
    'http://localhost:3000' # the URL of React frontend
]
CORS_ALLOWED_ORIGINS = [
    'http://localhost:3000',
]
CORS_ORIGIN_ALLOW_ALL = True
CORS_ALLOW_METHODS = [
    'DELETE',
    'GET',
    'OPTIONS',
    'PATCH',
    'POST',
    'PUT',
]
# Internationalization
# https://docs.djangoproject.com/en/4.1/topics/i18n/

LANGUAGE_CODE = 'en-us'

TIME_ZONE = 'UTC'

USE_I18N = True

USE_TZ = True

BASE_COUNTRY = "DZ"


# Static files (CSS, JavaScript, Images)
# https://docs.djangoproject.com/en/4.1/howto/static-files/

STATIC_URL = '/static/'
STATIC_ROOT = os.path.join(BASE_DIR, 'static')

# Default primary key field type
# https://docs.djangoproject.com/en/4.1/ref/settings/#default-auto-field

DEFAULT_AUTO_FIELD = 'django.db.models.BigAutoField'

#SMTP configuration

EMAIL_BACKEND = 'django.core.mail.backends.smtp.EmailBackend'
EMAIL_USE_TLS = True
EMAIL_HOST = 'smtp.gmail.com'
EMAIL_HOST_USER = 'baraaassociation595@gmail.com'
EMAIL_HOST_PASSWORD = 'agbdmmgxmwkqinfs'
EMAIL_PORT = 587

APPLICATION_EMAIL = 'baraaassociation595@gmail.com'
DEFAULT_FROM_EMAIL = 'baraaassociation595@gmail.com'
SMTP_USERNAME = 'Baraa_Association'
SMTP_PASSWORD = 'agbdmmgxmwkqinfs'
SMTP_SERVER = 'smtp.gmail.com'
SMTP_PORT = 587
SMTP_USE_TLS = True

AUTHENTICATION_BACKENDS = (
    'django.contrib.auth.backends.ModelBackend',
    'allauth.account.auth_backends.AuthenticationBackend',
    'social_core.backends.google.GoogleOAuth2',
)

# Define your Google OAuth2 credentials
SOCIAL_AUTH_GOOGLE_OAUTH2_KEY = '530160629274-8j10vopr5trlm78ldp27tskqb5bsv9rd.apps.googleusercontent.com'
SOCIAL_AUTH_GOOGLE_OAUTH2_SECRET = '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'

#LOGIN_REDIRECT_URLS =""
'''
LOGOUT_REDIRECT_URL =""
LOGIN_REDIRECT_URLS = {
    'password_change_done': '/change-password/done/',
}

'''
