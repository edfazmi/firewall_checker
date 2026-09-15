# dashboard/urls.py
from django.urls import path
from . import views

app_name = 'dashboard'

urlpatterns = [
    path('', views.DashboardView.as_view(), name='index'),
    # Endpoint baru untuk detail policy dinamis
    path('api/device/<int:device_id>/policy/<int:policy_id>/', views.PolicyDetailAPI.as_view(), name='api_policy_detail'),
]