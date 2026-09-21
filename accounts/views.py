from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth.decorators import login_required, user_passes_test
from django.contrib.auth import get_user_model, update_session_auth_hash
from django.http import JsonResponse
from django.db import IntegrityError
from .models import UserProfile
import json

User = get_user_model()

def is_superadmin(user):
    return user.is_superuser

@login_required
def kelola_akun(request):
    profil, created = UserProfile.objects.get_or_create(user=request.user)

    if request.method == 'POST':
        nama_lengkap = request.POST.get('nama_lengkap', '').strip()
        nama_parts = nama_lengkap.split(' ', 1)
        first_name = nama_parts[0]
        last_name = nama_parts[1] if len(nama_parts) > 1 else ''

        username_baru = request.POST.get('username', '').strip()
        email_baru = request.POST.get('email', '').strip()

        user = request.user
        user.first_name = first_name
        user.last_name = last_name
        user.email = email_baru
        
        if user.username != username_baru:
            if User.objects.filter(username=username_baru).exists():
                return redirect('kelola_akun') 
            user.username = username_baru
            
        try:
            user.save()
            profil.jabatan = request.POST.get('jabatan', '').strip()
            profil.divisi = request.POST.get('divisi', '').strip()
            profil.save()
        except IntegrityError:
            return redirect('kelola_akun')

        return redirect('kelola_akun')

    semua_akun = User.objects.select_related('userprofile').order_by('-is_superuser', 'first_name')

    nama = request.user.first_name
    inisial = ''.join([n[0] for n in nama.split()[:2]]).upper() if nama else request.user.username[:2].upper()

    context = {
        'semua_akun': semua_akun,
        'inisial_profil': inisial,
    }
    return render(request, 'accounts/manage_account.html', context)

@login_required
def ubah_password_ajax(request):
    if request.method == 'POST':
        try:
            data = json.loads(request.body)
            action = data.get('action')
            user = request.user

            if action == 'cek_lama':
                password_lama = data.get('password_lama', '')
                if user.check_password(password_lama):
                    return JsonResponse({'status': 'success', 'pesan': 'Password valid.'})
                else:
                    return JsonResponse({'status': 'error', 'pesan': 'Password lama salah.'}, status=400)

            elif action == 'simpan_baru':
                password_baru = data.get('password_baru', '')
                konfirmasi_password = data.get('konfirmasi_password', '')

                if len(password_baru) < 8:
                    return JsonResponse({'status': 'error', 'pesan': 'Password minimal 8 karakter.'}, status=400)
                
                if password_baru != konfirmasi_password:
                    return JsonResponse({'status': 'error', 'pesan': 'Konfirmasi password tidak cocok.'}, status=400)

                user.set_password(password_baru)
                user.save()
                update_session_auth_hash(request, user)
                
                return JsonResponse({'status': 'success', 'pesan': 'Password berhasil diubah.'})

        except Exception as e:
            return JsonResponse({'status': 'error', 'pesan': 'Terjadi kesalahan internal.'}, status=500)
            
    return JsonResponse({'status': 'error', 'pesan': 'Metode tidak diizinkan.'}, status=405)

@login_required
@user_passes_test(is_superadmin) 
def tambah_akun(request):
    if request.method == 'POST':
        username = request.POST.get('username', '').strip()
        email = request.POST.get('email', '').strip()
        password = request.POST.get('password', '')
        
        if len(password) < 8:
            return redirect('kelola_akun')
            
        if User.objects.filter(username=username).exists():
            return redirect('kelola_akun')
            
        nama_lengkap = request.POST.get('nama_lengkap', '').strip()
        jabatan = request.POST.get('jabatan', '').strip()
        divisi = request.POST.get('divisi', '').strip()

        nama_parts = nama_lengkap.split(' ', 1)
        first_name = nama_parts[0]
        last_name = nama_parts[1] if len(nama_parts) > 1 else ''

        try:
            user_baru = User.objects.create_user(
                username=username,
                email=email,
                password=password,
                first_name=first_name,
                last_name=last_name
            )

            UserProfile.objects.create(
                user=user_baru,
                jabatan=jabatan,
                divisi=divisi
            )
        except IntegrityError:
            pass 

    return redirect('kelola_akun')

@login_required
@user_passes_test(is_superadmin) 
def hapus_akun(request, id_akun):
    if request.method == 'POST':
        akun_dihapus = get_object_or_404(User, id=id_akun)
        if akun_dihapus.id != request.user.id:
            akun_dihapus.delete()
            
    return redirect('kelola_akun')