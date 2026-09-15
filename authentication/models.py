# authentication/models.py
from django.db import models
from django.contrib.auth.models import AbstractUser
from django.utils.translation import gettext_lazy as _

class Role(models.Model):
    """
    Model untuk Role Based Access Control (RBAC).
    Contoh data: Administrator, Operator, Viewer.
    """
    name = models.CharField(
        max_length=50, 
        unique=True, 
        help_text="Nama role (contoh: Administrator, Operator, Viewer)"
    )
    description = models.TextField(
        blank=True, 
        null=True, 
        help_text="Deskripsi hak akses role ini."
    )
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = 'roles'
        verbose_name = _('Role')
        verbose_name_plural = _('Roles')

    def __str__(self) -> str:
        return self.name


class User(AbstractUser):
    """
    Custom User model yang berelasi dengan tabel Role.
    Menggunakan email sebagai identifier tambahan jika diperlukan.
    """
    role = models.ForeignKey(
        Role, 
        on_delete=models.SET_NULL, 
        null=True, 
        blank=True, 
        related_name='users',
        help_text="Role yang menentukan tingkat akses pengguna dalam aplikasi."
    )

    class Meta:
        db_table = 'users'
        verbose_name = _('User')
        verbose_name_plural = _('Users')

    def __str__(self) -> str:
        role_name = self.role.name if self.role else "No Role"
        return f"{self.username} ({role_name})"

    @property
    def is_administrator(self) -> bool:
        """Helper function untuk mengecek apakah user adalah Administrator."""
        return self.role and self.role.name.lower() == 'administrator'

    @property
    def is_operator(self) -> bool:
        """Helper function untuk mengecek apakah user adalah Operator."""
        return self.role and self.role.name.lower() == 'operator'

    @property
    def is_viewer(self) -> bool:
        """Helper function untuk mengecek apakah user adalah Viewer."""
        return self.role and self.role.name.lower() == 'viewer'