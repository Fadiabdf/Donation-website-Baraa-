from django.contrib import admin
from django.urls import path,include
from rest_framework.authtoken.views import obtain_auth_token
from rest_auth.views import LogoutView
from django.conf.urls.static import static
from django.conf import settings

urlpatterns = [
    path('admin/', admin.site.urls),
    #**************************************
    path('api/', include('webapp.urls')),
    #**************************************
    path('api/auth/', include('rest_auth.urls')),
    path('api/auth/registration/', include('rest_auth.registration.urls')),
    path('api-auth/',include('rest_framework.urls')),
    path('api/auth/login/', obtain_auth_token, name='api_token_auth'),
    path('api/auth/logout/', LogoutView.as_view(), name='logout'),
    path("accounts/",include("allauth.urls")),
    path('password_reset/', include('django.contrib.auth.urls')),
] + static(settings.STATIC_URL, document_root=settings.STATIC_ROOT)
