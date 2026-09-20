from django.db import models
from django.conf import settings 

class UserProfile(models.Model):
    user = models.OneToOneField(settings.AUTH_USER_MODEL, on_delete=models.CASCADE)
    jabatan = models.CharField(max_length=100, blank=True, null=True)
    divisi = models.CharField(max_length=100, blank=True, null=True)
    
    def __str__(self):
        return f"Profil dari {self.user.username}"