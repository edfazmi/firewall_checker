# devices/urls.py
from django.urls import path
from . import views

app_name = 'devices'

urlpatterns = [
    path('', views.DeviceListView.as_view(), name='list'),
    path('create/', views.DeviceCreateView.as_view(), name='create'),
    path('<int:pk>/update/', views.DeviceUpdateView.as_view(), name='update'),
    path('<int:pk>/delete/', views.DeviceDeleteView.as_view(), name='delete'),
    path('<int:pk>/sync/', views.SyncDeviceView.as_view(), name='sync'),
]