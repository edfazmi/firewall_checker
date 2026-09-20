from django.urls import path
from . import views

urlpatterns = [
    path('', views.kelola_akun, name='kelola_akun'),
    path('ubah-password/', views.ubah_password_ajax, name='ubah_password_ajax'),
    path('tambah-akun/', views.tambah_akun, name='tambah_akun'),
    path('hapus-akun/<int:id_akun>/', views.hapus_akun, name='hapus_akun'),
]