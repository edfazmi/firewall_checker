from django.views.generic import TemplateView
from django.contrib.auth.mixins import LoginRequiredMixin
from django.core.paginator import Paginator
from django.utils import timezone
from devices.models import Device

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

        from compliance.models import ComplianceRule

        context['total_active_rules'] = ComplianceRule.objects.filter(is_active=True).count()
        context['total_inactive_rules'] = ComplianceRule.objects.filter(is_active=False).count()
        
        return context