# authentication/urls.py
from django.urls import path
from django.contrib.auth.views import LogoutView
from .views import CustomLoginView

app_name = 'authentication'

urlpatterns = [
    path('login/', CustomLoginView.as_view(), name='login'),
    # Mengarahkan user kembali ke halaman login setelah logout
    path('logout/', LogoutView.as_view(next_page='authentication:login'), name='logout'),
]