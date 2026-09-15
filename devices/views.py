# devices/views.py
from django.views.generic import ListView, CreateView, UpdateView, DeleteView
from django.views import View
from django.contrib.auth.mixins import LoginRequiredMixin
from django.urls import reverse_lazy
from django.shortcuts import get_object_or_404, redirect
from django.contrib import messages
from .models import Device, DeviceStatistic
from .forms import DeviceForm
from .services import FortiGateAPIService
from core.exceptions import FortiGateAPIError

class DeviceListView(LoginRequiredMixin, ListView):
    model = Device
    template_name = 'devices/list.html'
    context_object_name = 'devices'
    ordering = ['-created_at']

class DeviceCreateView(LoginRequiredMixin, CreateView):
    model = Device
    form_class = DeviceForm
    template_name = 'devices/form.html'
    success_url = reverse_lazy('devices:list')

    def form_valid(self, form):
        messages.success(self.request, "Perangkat berhasil ditambahkan.")
        return super().form_valid(form)

class DeviceUpdateView(LoginRequiredMixin, UpdateView):
    model = Device
    form_class = DeviceForm
    template_name = 'devices/form.html'
    success_url = reverse_lazy('devices:list')

    def form_valid(self, form):
        messages.success(self.request, "Perangkat berhasil diperbarui.")
        return super().form_valid(form)

class DeviceDeleteView(LoginRequiredMixin, DeleteView):
    model = Device
    template_name = 'devices/confirm_delete.html'
    success_url = reverse_lazy('devices:list')

    def delete(self, request, *args, **kwargs):
        messages.success(self.request, "Perangkat berhasil dihapus.")
        return super().delete(request, *args, **kwargs)

class SyncDeviceView(LoginRequiredMixin, View):
    def get(self, request, pk):
        device = get_object_or_404(Device, pk=pk)
        service = FortiGateAPIService(device=device, user=request.user)
        
        try:
            # 1. Test Koneksi
            service.test_connection()
            
            # 2. Ambil Statistik Monitoring
            stats = service.fetch_statistics()
            if stats:
                stat_obj, created = DeviceStatistic.objects.get_or_create(device=device)
                stat_obj.total_interfaces_up = stats['up_ports']
                stat_obj.total_policies = stats['total_policies']
                stat_obj.top_used_policy = stats['top_policy']
                stat_obj.never_used_policies_count = stats['never_used']
                stat_obj.save()

            messages.success(request, f"Koneksi ke {device.name} berhasil. Data monitoring telah diperbarui.")
        except FortiGateAPIError as e:
            messages.error(request, f"Gagal Sinkronisasi: {str(e)}")
        except Exception as e:
            messages.error(request, f"Kesalahan Sistem: {str(e)}")
            
        return redirect('devices:list')