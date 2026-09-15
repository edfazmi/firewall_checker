# compliance/management/commands/auto_monitor.py
import time
from django.core.management.base import BaseCommand
from devices.models import Device
from compliance.services import ComplianceScanner

class Command(BaseCommand):
    help = 'Background worker untuk memantau perubahan FortiGate secara real-time.'

    def handle(self, *args, **kwargs):
        self.stdout.write(self.style.SUCCESS('\n=== MEMULAI AUTO-MONITOR ==='))
        self.stdout.write(self.style.WARNING('Worker aktif. Memeriksa perubahan setiap 30 detik. Tekan CTRL+C untuk berhenti.\n'))
        
        while True:
            # Ambil semua perangkat yang berhasil dikoneksikan sebelumnya
            devices = Device.objects.filter(connection_status='CONNECTED')
            
            for device in devices:
                try:
                    scanner = ComplianceScanner(device)
                    # Hanya trigger jika hash berubah
                    if scanner.has_config_changed():
                        current_time = time.strftime('%X')
                        self.stdout.write(self.style.ERROR(f"[{current_time}] PERUBAHAN TERDETEKSI pada {device.name}!"))
                        self.stdout.write(self.style.WARNING(f"[{current_time}] Menjalankan Auto-Scan dan merekam Audit Risk..."))
                        
                        # Eksekusi full scan
                        scanner.execute_scan()
                        
                        self.stdout.write(self.style.SUCCESS(f"[{time.strftime('%X')}] Auto-Scan Selesai. Notifikasi dikirim."))
                except Exception as e:
                    self.stdout.write(self.style.ERROR(f"[Error pada {device.name}]: {str(e)}"))

            time.sleep(30) # Istirahat 30 detik