# compliance/views.py
from django.views import View
from django.views.generic import DetailView, ListView, CreateView, UpdateView
from django.shortcuts import get_object_or_404, redirect
from django.contrib import messages
from django.contrib.auth.mixins import LoginRequiredMixin
from django.urls import reverse_lazy
from django.db.models import Case, When, Value, IntegerField

from devices.models import Device
from core.exceptions import BaseAppException
from .models import ScanHistory, ComplianceRule
from .services import ComplianceScanner
from .forms import ComplianceRuleForm

from django.http import HttpResponse
from django.views.decorators.csrf import csrf_exempt
from compliance.models import ScanHistory

from django.http import HttpResponse, Http404
from django.shortcuts import get_object_or_404, redirect, render



# --- SCANNER VIEWS ---

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
            # Mencoba memuat objek ScanHistory
            self.object = self.get_object()
        except Http404:
            # Jika data tidak ditemukan (karena terhapus otomatis), arahkan ke halaman khusus
            return render(request, 'compliance/scan_deleted.html', status=404)

        context = self.get_context_data(object=self.object)
        return self.render_to_response(context)

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        
        # Ambil temuan (findings)
        context['findings'] = self.object.findings.select_related('rule').all().order_by('rule__severity')
        
        # Ambil hasil penilaian risiko dengan kustom urutan severity
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


# --- RULE MANAGEMENT VIEWS ---

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

@csrf_exempt
def hapus_hasil_scan_otomatis(request):
    if request.method == 'POST':
        # Menarik ID dari payload Form, bukan dari URL
        scan_id = request.POST.get('scan_id')
        if scan_id:
            ScanHistory.objects.filter(id=scan_id).delete()
    return HttpResponse(status=200)