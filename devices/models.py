from django.db import models
from django.core.exceptions import ValidationError
from django.utils.translation import gettext_lazy as _
from core.utils import encrypt_token, decrypt_token
import ipaddress

def validate_non_loopback(value):
    try:
        ip = ipaddress.ip_address(value)
        if ip.is_loopback or ip.is_unspecified:
            raise ValidationError('Alamat IP loopback tidak diizinkan.')
    except ValueError:
        raise ValidationError('Format alamat IP tidak valid.')

class Device(models.Model):
    CONNECTION_STATUS_CHOICES = [
        ('CONNECTED', 'Connected'),
        ('DISCONNECTED', 'Disconnected'),
        ('ERROR', 'Connection Error'),
        ('UNTESTED', 'Untested'),
    ]

    name = models.CharField(max_length=100, unique=True)
    ip_address = models.GenericIPAddressField(validators=[validate_non_loopback])
    port = models.PositiveIntegerField(default=443)
    api_token_encrypted = models.TextField()
    os_version = models.CharField(max_length=50, blank=True, null=True)
    connection_status = models.CharField(max_length=20, choices=CONNECTION_STATUS_CHOICES, default='UNTESTED')
    last_sync = models.DateTimeField(blank=True, null=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    last_config_hash = models.CharField(max_length=64, null=True, blank=True)

    class Meta:
        db_table = 'firewall_devices'
        verbose_name = _('Firewall Device')
        verbose_name_plural = _('Firewall Devices')
        unique_together = ('ip_address', 'port')

    def __str__(self) -> str:
        return f"{self.name} ({self.ip_address})"

    def set_token(self, raw_token: str) -> None:
        if raw_token:
            self.api_token_encrypted = encrypt_token(raw_token)
        else:
            self.api_token_encrypted = ""

    def save(self, *args, **kwargs):
        from core.utils import encrypt_token
        
        raw_token = getattr(self, 'api_token', getattr(self, 'token', ''))

        if raw_token:
            encrypted = encrypt_token(str(raw_token))
            final_token = encrypted.decode('utf-8') if isinstance(encrypted, bytes) else encrypted
            
            self.api_token_encrypted = final_token
            
            if hasattr(self, 'api_token'):
                delattr(self, 'api_token')
            if hasattr(self, 'token'):
                delattr(self, 'token')
                
        super().save(*args, **kwargs)

    def get_token(self):
        from core.utils import decrypt_token
        
        db_token = self.api_token_encrypted
        
        if not db_token:
            return ""
            
        if isinstance(db_token, str) and db_token.startswith("b'") and db_token.endswith("'"):
            db_token = db_token[2:-1]
            
        try:
            decrypted = decrypt_token(db_token)
            return decrypted.decode('utf-8') if isinstance(decrypted, bytes) else decrypted
        except Exception:
            return ""
        
    def clean(self):
        super().clean()
        if not self.ip_address:
            raise ValidationError({'ip_address': 'IP Address wajib diisi.'})


class DeviceStatistic(models.Model):
    device = models.OneToOneField(Device, on_delete=models.CASCADE, related_name='statistics')
    total_interfaces_up = models.IntegerField(default=0)
    total_policies = models.IntegerField(default=0)
    never_used_policies_count = models.IntegerField(default=0, help_text="Jumlah policy dengan 0 hit")
    last_updated = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = 'device_statistics'