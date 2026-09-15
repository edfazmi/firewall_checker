# dashboard/context_processors.py
from django.db.utils import OperationalError, ProgrammingError

def notifications(request):
    """
    Menghitung jumlah notifikasi yang belum dibaca secara global
    agar bisa diakses oleh base.html dari halaman mana saja.
    """
    if request.user.is_authenticated:
        try:
            from compliance.models import ChangeNotification
            unread_count = ChangeNotification.objects.filter(is_read=False).count()
            return {'unread_notifications_count': unread_count}
        except (OperationalError, ProgrammingError, ImportError):
            # Mencegah error saat pertama kali migrate database
            pass
    return {'unread_notifications_count': 0}