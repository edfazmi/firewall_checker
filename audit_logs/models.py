# audit_logs/models.py
from django.db import models
from django.conf import settings

class AuditLog(models.Model):
    """
    Model untuk mencatat segala aktivitas kritis di dalam aplikasi.
    Seperti: Login, Penambahan Device, Sinkronisasi API, dan Perubahan Konfigurasi.
    """
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL, 
        on_delete=models.SET_NULL, 
        null=True, 
        blank=True, 
        related_name='audit_logs',
        help_text="Pengguna yang melakukan aksi. Null jika aksi dilakukan oleh sistem."
    )
    action = models.CharField(
        max_length=150, 
        help_text="Aksi yang dilakukan (contoh: LOGIN, SCAN_FIREWALL, CREATE_DEVICE)"
    )
    target_type = models.CharField(
        max_length=100, 
        blank=True, 
        null=True, 
        help_text="Model/Objek yang terdampak (contoh: Device, ComplianceRule)"
    )
    target_id = models.IntegerField(
        blank=True, 
        null=True, 
        help_text="ID record dari tabel yang terdampak"
    )
    ip_address = models.GenericIPAddressField(
        blank=True, 
        null=True, 
        help_text="IP Address pengguna saat melakukan aksi"
    )
    timestamp = models.DateTimeField(
        auto_now_add=True, 
        db_index=True,
        help_text="Waktu kejadian"
    )
    details = models.JSONField(
        blank=True, 
        null=True, 
        help_text="Data tambahan atau perubahan yang terjadi (snapshot JSON sebelum/sesudah)"
    )

    class Meta:
        db_table = 'audit_logs'
        verbose_name = 'Audit Log'
        verbose_name_plural = 'Audit Logs'
        ordering = ['-timestamp'] # Selalu tampilkan yang terbaru di urutan pertama

    def __str__(self) -> str:
        user_display = self.user.username if self.user else "System"
        time_format = self.timestamp.strftime('%Y-%m-%d %H:%M:%S')
        return f"[{time_format}] {user_display} - {self.action}"