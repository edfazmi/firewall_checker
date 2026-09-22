import logging
from cryptography.fernet import Fernet, InvalidToken
from django.conf import settings
from core.exceptions import EncryptionError

logger = logging.getLogger('application')

def get_cipher_suite() -> Fernet:
    try:
        key = getattr(settings, 'FIREWALL_KEY', None)
        
        if not key:
            logger.error("FIREWALL_KEY tidak ditemukan di settings atau environment.")
            raise EncryptionError("Konfigurasi enkripsi tidak valid.")

        return Fernet(key.encode('utf-8') if isinstance(key, str) else key)
    except ValueError as e:
        logger.error(f"Format FIREWALL_KEY tidak valid: {e}")
        raise EncryptionError("Sistem gagal menginisialisasi modul pengamanan data.")
    except Exception as e:
        logger.error(f"Gagal menginisialisasi cipher suite: {e}")
        raise EncryptionError("Sistem gagal menginisialisasi modul pengamanan data.")

def encrypt_token(plain_token: str) -> str:
    if not plain_token:
        return ""
    try:
        cipher = get_cipher_suite()
        encrypted_bytes = cipher.encrypt(plain_token.encode('utf-8'))
        return encrypted_bytes.decode('utf-8')
    except Exception as e:
        logger.error(f"Error internal saat mengenkripsi token: {e}")
        raise EncryptionError("Gagal memproses pengamanan data sistem.")

def decrypt_token(encrypted_token: str) -> str:
    if not encrypted_token:
        return ""
    try:
        cipher = get_cipher_suite()
        decrypted_bytes = cipher.decrypt(encrypted_token.encode('utf-8'))
        return decrypted_bytes.decode('utf-8')
    except InvalidToken:
        logger.warning("Upaya dekripsi gagal: Token tidak valid atau kunci enkripsi salah.")
        raise EncryptionError("Data rahasia tidak valid atau rusak.")
    except Exception as e:
        logger.error(f"Error tidak terduga saat mendekripsi token: {e}")
        raise EncryptionError("Gagal membaca pengamanan data sistem.")