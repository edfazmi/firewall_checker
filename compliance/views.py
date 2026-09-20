import requests
from urllib3.exceptions import InsecureRequestWarning

from django.contrib import messages
from django.contrib.auth.mixins import LoginRequiredMixin
from django.db.models import Case, When, Value, IntegerField
from django.http import Http404, HttpResponse, JsonResponse
from django.shortcuts import get_object_or_404, redirect, render
from django.urls import reverse_lazy
from django.views import View
from django.views.decorators.csrf import csrf_exempt
from django.views.generic import CreateView, DetailView, ListView, UpdateView

from devices.models import Device
from core.exceptions import BaseAppException
from .models import ScanHistory, ComplianceRule
from .services import ComplianceScanner
from .forms import ComplianceRuleForm

requests.packages.urllib3.disable_warnings(
    category=InsecureRequestWarning
)

class ScanDeviceView(LoginRequiredMixin, View):
    def get(self, request, device_id):
        device = get_object_or_404(Device, id=device_id)
        scanner = ComplianceScanner(device=device, user=request.user)
        try:
            scan_record = scanner.execute_scan()
            if scan_record.status == 'SUCCESS':
                return redirect('compliance:result', scan_id=scan_record.id)
            else:
                messages.error(request, f"Audit gagal: {scan_record.error_message}")
                return redirect('devices:list')
        except BaseAppException as e:
            messages.error(request, f"Audit gagal: {str(e)}")
            return redirect('devices:list')
        except Exception as e:
            messages.error(request, f"Terjadi kesalahan sistem: {str(e)}")
            return redirect('devices:list')

class ScanResultView(LoginRequiredMixin, DetailView):
    model = ScanHistory
    template_name = 'compliance/result.html'
    context_object_name = 'scan'
    pk_url_kwarg = 'scan_id'

    def get(self, request, *args, **kwargs):
        try:
            self.object = self.get_object()
        except Http404:
            return render(request, 'compliance/scan_deleted.html', status=404)

        context = self.get_context_data(object=self.object)
        return self.render_to_response(context)

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)

        context['findings'] = self.object.findings.select_related('rule').all().order_by('rule__severity')
        
        context['policy_risks'] = (
            self.object.policy_risks.all()
            .annotate(
                severity_order=Case(
                    When(severity='Critical', then=Value(4)),
                    When(severity='High', then=Value(3)),
                    When(severity='Medium', then=Value(2)),
                    When(severity='Low', then=Value(1)),
                    default=Value(0),
                    output_field=IntegerField(),
                )
            )
            .order_by('-severity_order')
        )
        
        return context

class RuleListView(LoginRequiredMixin, ListView):
    model = ComplianceRule
    template_name = 'compliance/rule_list.html'
    context_object_name = 'rules'
    ordering = ['category', '-severity']


class RuleCreateView(LoginRequiredMixin, CreateView):
    model = ComplianceRule
    form_class = ComplianceRuleForm
    template_name = 'compliance/rule_form.html'
    success_url = reverse_lazy('compliance:rule_list')

    def form_valid(self, form):
        messages.success(self.request, "Rule berhasil ditambahkan.")
        return super().form_valid(form)


class RuleUpdateView(LoginRequiredMixin, UpdateView):
    model = ComplianceRule
    form_class = ComplianceRuleForm
    template_name = 'compliance/rule_form.html'
    success_url = reverse_lazy('compliance:rule_list')

    def form_valid(self, form):
        messages.success(self.request, "Rule berhasil diperbarui.")
        return super().form_valid(form)

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

            response = requests.get(url, headers=headers, verify=False, timeout=10)
            
            if response.status_code == 200:
                data = response.json().get('results', [])
                if data:
                    p = data[0]
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

@csrf_exempt
def hapus_hasil_scan_otomatis(request):
    if request.method == 'POST':
        scan_id = request.POST.get('scan_id')
        if scan_id:
            ScanHistory.objects.filter(id=scan_id).delete()
    return HttpResponse(status=200)