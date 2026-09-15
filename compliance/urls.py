# compliance/urls.py
from django.urls import path
from . import views

app_name = 'compliance'

urlpatterns = [
    path('scan/<int:device_id>/', views.ScanDeviceView.as_view(), name='scan'),
    path('scan/result/<int:scan_id>/', views.ScanResultView.as_view(), name='result'),
    path('rules/', views.RuleListView.as_view(), name='rule_list'),
    path('rules/create/', views.RuleCreateView.as_view(), name='rule_create'),
    path('rules/<int:pk>/update/', views.RuleUpdateView.as_view(), name='rule_update'),
    
    # Rute Notifikasi Baru (berdasarkan ID Notifikasi)
    path('notifications/', views.DeviceNotificationListView.as_view(), name='notification_devices'),
    path('notifications/read/<int:notif_id>/', views.ReadDeviceNotificationsView.as_view(), name='notification_read'),
    path('hapus-scan-otomatis//', views.hapus_hasil_scan_otomatis, name='hapus_scan_otomatis'),
]