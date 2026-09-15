# compliance/management/commands/seed_rules.py
from django.core.management.base import BaseCommand
from compliance.models import ComplianceRule

class Command(BaseCommand):
    help = 'Memasukkan data Rule Compliance dasar ke database.'

    def handle(self, *args, **kwargs):
        rules = [
            {
                'rule_code': 'POL_ANY_ANY',
                'name': 'Policy Allow Any-Any',
                'category': 'POLICY',
                'severity': 'CRITICAL',
                'description': 'Terdapat Firewall Policy yang mengizinkan lalu lintas dari source manapun ke destination manapun (Any -> Any).',
                'impact': 'Membuka celah keamanan besar dimana seluruh trafik diizinkan masuk ke jaringan internal tanpa filterisasi.',
                'recommendation': 'Spesifikasikan Source Address, Destination Address, dan Service pada policy ini.'
            },
            {
                'rule_code': 'POL_NO_LOG',
                'name': 'Logging Policy Disabled',
                'category': 'POLICY',
                'severity': 'MEDIUM',
                'description': 'Fitur pencatatan log pada policy tidak diaktifkan.',
                'impact': 'Menghambat proses investigasi (forensik) saat terjadi insiden keamanan karena tidak ada catatan trafik.',
                'recommendation': 'Aktifkan "Log Allowed Traffic" minimal untuk "Security Events".'
            },
            {
                'rule_code': 'POL_NO_DESC',
                'name': 'Policy without Description/Comment',
                'category': 'POLICY',
                'severity': 'LOW',
                'description': 'Policy tidak memiliki komentar atau deskripsi.',
                'impact': 'Menyulitkan proses audit dan pemeliharaan administrasi di masa depan.',
                'recommendation': 'Tambahkan komentar yang menjelaskan tujuan bisnis dari policy tersebut.'
            },
            {
                'rule_code': 'INTF_DOWN',
                'name': 'Interface is Administratively Down',
                'category': 'INTERFACE',
                'severity': 'INFO',
                'description': 'Terdapat interface yang statusnya down namun masih terkonfigurasi.',
                'impact': 'Bisa menjadi potensi blind spot konfigurasi.',
                'recommendation': 'Jika interface tidak digunakan, pertimbangkan untuk menghapus konfigurasinya.'
            },
            {
                'rule_code': 'ADM_NO_TRUSTHOST',
                'name': 'Admin tanpa Trusted Host',
                'category': 'ADMIN',
                'severity': 'HIGH',
                'description': 'Akun administrator dapat diakses dari IP manapun tanpa pembatasan.',
                'impact': 'Rentan terhadap serangan Brute Force dan pencurian kredensial.',
                'recommendation': 'Konfigurasikan Trusted Host (Restricted IP) untuk akun administrator.'
            }
        ]

        created_count = 0
        for rule_data in rules:
            obj, created = ComplianceRule.objects.get_or_create(
                rule_code=rule_data['rule_code'],
                defaults=rule_data
            )
            if created:
                created_count += 1
                self.stdout.write(self.style.SUCCESS(f"Berhasil membuat rule: {obj.rule_code}"))
            else:
                self.stdout.write(self.style.WARNING(f"Rule {obj.rule_code} sudah ada. Melewati..."))

        self.stdout.write(self.style.SUCCESS(f"Selesai! {created_count} rule baru ditambahkan."))