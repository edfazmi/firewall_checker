from django.shortcuts import render, redirect
from django.contrib.auth.decorators import login_required
from django.contrib.auth import get_user_model
from .models import UserProfile
import json
from django.http import JsonResponse
from django.contrib.auth import update_session_auth_hash
from django.shortcuts import render, redirect, get_object_or_404

User = get_user_model()

@login_required
def kelola_akun(request):
    profil, created = UserProfile.objects.get_or_create(user=request.user)

    if request.method == 'POST':
        nama_lengkap = request.POST.get('nama_lengkap', '').strip()

        nama_parts = nama_lengkap.split(' ', 1)
        first_name = nama_parts[0]
        last_name = nama_parts[1] if len(nama_parts) > 1 else ''

        user = request.user
        user.first_name = first_name
        user.last_name = last_name
        user.username = request.POST.get('username')
        user.email = request.POST.get('email')
        user.save()

        profil.jabatan = request.POST.get('jabatan')
        profil.divisi = request.POST.get('divisi')
        profil.save()

        return redirect('kelola_akun')

    semua_akun = User.objects.select_related('userprofile').order_by('-is_superuser', 'first_name')

    nama = request.user.first_name
    inisial = ''.join([n[0] for n in nama.split()[:2]]).upper() if nama else request.user.username[:2].upper()

    context = {
        'semua_akun': semua_akun,
        'inisial_profil': inisial,
    }
    return render(request, 'accounts/manage_account.html', context)

def ubah_password_ajax(request):
    if request.method == 'POST':
        try:
            data = json.loads(request.body)
            action = data.get('action')
            user = request.user

            if action == 'cek_lama':
                password_lama = data.get('password_lama')
                if user.check_password(password_lama):
                    return JsonResponse({'status': 'success', 'pesan': 'Password valid.'})
                else:
                    return JsonResponse({'status': 'error', 'pesan': 'Password lama salah.'}, status=400)

            elif action == 'simpan_baru':
                password_baru = data.get('password_baru')
                konfirmasi_password = data.get('konfirmasi_password')

                if len(password_baru) < 8:
                    return JsonResponse({'status': 'error', 'pesan': 'Password minimal 8 karakter.'}, status=400)
                
                if password_baru != konfirmasi_password:
                    return JsonResponse({'status': 'error', 'pesan': 'Konfirmasi password tidak cocok.'}, status=400)

                user.set_password(password_baru)
                user.save()

                update_session_auth_hash(request, user)
                
                return JsonResponse({'status': 'success', 'pesan': 'Password berhasil diubah.'})

        except Exception as e:
            return JsonResponse({'status': 'error', 'pesan': str(e)}, status=500)
            
    return JsonResponse({'status': 'error', 'pesan': 'Metode tidak diizinkan.'}, status=405)

def tambah_akun(request):
    if request.method == 'POST':
        username = request.POST.get('username')
        email = request.POST.get('email')
        password = request.POST.get('password')
        nama_lengkap = request.POST.get('nama_lengkap', '').strip()
        jabatan = request.POST.get('jabatan')
        divisi = request.POST.get('divisi')

        nama_parts = nama_lengkap.split(' ', 1)
        first_name = nama_parts[0]
        last_name = nama_parts[1] if len(nama_parts) > 1 else ''

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
        
    return redirect('kelola_akun')

def hapus_akun(request, id_akun):
    if request.method == 'POST':
        akun_dihapus = get_object_or_404(User, id=id_akun)
        if akun_dihapus.id != request.user.id:
            akun_dihapus.delete()
            
    return redirect('kelola_akun')