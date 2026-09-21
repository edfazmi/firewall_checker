from django.db import models
from django.contrib.auth.models import AbstractUser
from django.utils.translation import gettext_lazy as _

class Role(models.Model):
    name = models.CharField(
        max_length=50, 
        unique=True, 
    )
    description = models.TextField(
        blank=True, 
        null=True, 
    )
    is_system_admin = models.BooleanField(
        default=False,
    )
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = 'roles'
        verbose_name = _('Role')
        verbose_name_plural = _('Roles')

    def __str__(self) -> str:
        return self.name

class User(AbstractUser):
    role = models.ForeignKey(
        Role, 
        on_delete=models.SET_NULL, 
        null=True, 
        blank=True, 
        related_name='users',
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
        return self.role is not None and self.role.is_system_admin