# dashboard/views.py
import re
from django.views.generic import TemplateView
from django.views import View
from django.http import JsonResponse
from django.contrib.auth.mixins import LoginRequiredMixin
from django.core.paginator import Paginator
from django.utils import timezone
from devices.models import Device
from compliance.models import ScanHistory, Finding
import requests
from urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)

class DashboardView(LoginRequiredMixin, TemplateView):
    template_name = 'dashboard/index.html'

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        
        devices_list = Device.objects.select_related('statistics').all().order_by('-last_sync')
        paginator = Paginator(devices_list, 5)
        page_number = self.request.GET.get('page', 1)
        page_obj = paginator.get_page(page_number)
        
        context['devices'] = page_obj
        context['total_devices'] = devices_list.count()
        context['total_online'] = devices_list.filter(connection_status='CONNECTED').count()
        context['total_offline'] = devices_list.exclude(connection_status='CONNECTED').count()
        
        months_id = ['', 'Januari', 'Februari', 'Maret', 'April', 'Mei', 'Juni', 'Juli', 'Agustus', 'September', 'Oktober', 'November', 'Desember']
        now = timezone.now()
        context['current_month_year'] = f"{months_id[now.month]} {now.year}"
        
        return context

class PolicyDetailAPI(LoginRequiredMixin, View):
    """API dinamis untuk menarik seluruh detail 1 Policy langsung dari FortiGate."""
    def get(self, request, device_id, policy_id):
        try:
            device = Device.objects.get(id=device_id)
            token = device.get_token()
            
            if not token:
                return JsonResponse({'error': 'Token API tidak valid atau korup.'}, status=400)
            
            url = f"https://{device.ip_address}/api/v2/cmdb/firewall/policy/{policy_id}"
            headers = {'Authorization': f'Bearer {token}'}
            
            # Tembak API FortiGate
            response = requests.get(url, headers=headers, verify=False, timeout=10)
            
            if response.status_code == 200:
                data = response.json().get('results', [])
                if data:
                    p = data[0]
                    # Format ulang data agar mudah dibaca oleh Javascript Frontend
                    result = {
                        'id': p.get('policyid'),
                        'name': p.get('name', 'Tanpa Nama'),
                        'status': 'Enabled' if p.get('status') == 'enable' else 'Disabled',
                        'action': p.get('action', 'UNKNOWN').upper(),
                        'nat': 'Enabled' if p.get('nat') == 'enable' else 'Disabled',
                        'logtraffic': p.get('logtraffic', 'Disabled').replace('-', ' ').title(),
                        'comments': p.get('comments', 'Tidak ada catatan atau komentar pada policy ini di dalam perangkat.'),
                        'srcintf': [x.get('name') for x in p.get('srcintf', [])],
                        'dstintf': [x.get('name') for x in p.get('dstintf', [])],
                        'srcaddr': [x.get('name') for x in p.get('srcaddr', [])],
                        'dstaddr': [x.get('name') for x in p.get('dstaddr', [])],
                        'service': [x.get('name') for x in p.get('service', [])],
                        'schedule': p.get('schedule', 'N/A'),
                        'security_profiles': {
                            'Antivirus': p.get('av-profile', ''),
                            'Web Filter': p.get('webfilter-profile', ''),
                            'IPS Sensor': p.get('ips-sensor', ''),
                            'App Control': p.get('application-list', '')
                        },
                        'poolname': [x.get('name') for x in p.get('poolname', [])]
                    }
                    return JsonResponse(result)
                else:
                    return JsonResponse({'error': 'Data Policy tidak ditemukan di perangkat.'}, status=404)
            else:
                return JsonResponse({'error': f'Akses Ditolak (HTTP {response.status_code})'}, status=response.status_code)
                
        except Exception as e:
            return JsonResponse({'error': str(e)}, status=500)