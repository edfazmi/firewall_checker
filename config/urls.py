# config/urls.py
from django.contrib import admin
from django.urls import path, include

urlpatterns = [
    path('admin/', admin.site.urls),
    path('auth/', include('authentication.urls')),
    path('devices/', include('devices.urls')),
    path('compliance/', include('compliance.urls')),
    path('', include('dashboard.urls')),
    path('kelola-akun/', include('accounts.urls')),
]