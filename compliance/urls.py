from django.urls import path
from . import views

app_name = 'compliance'

urlpatterns = [
    path('scan/<int:device_id>/', views.ScanDeviceView.as_view(), name='scan'),
    path('scan/result/<int:scan_id>/', views.ScanResultView.as_view(), name='result'),
    path('rules/', views.RuleListView.as_view(), name='rule_list'),
    path('rules/create/', views.RuleCreateView.as_view(), name='rule_create'),
    path('rules/<int:pk>/update/', views.RuleUpdateView.as_view(), name='rule_update'),
    path('hapus-scan-otomatis//', views.hapus_hasil_scan_otomatis, name='hapus_scan_otomatis'),
    path('api/device/<int:device_id>/policy/<int:policy_id>/', views.PolicyDetailAPI.as_view(), name='api_policy_detail'),
    
]