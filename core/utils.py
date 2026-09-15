# core/utils.py
import base64
from cryptography.fernet import Fernet
from django.conf import settings
from core.exceptions import EncryptionError

def get_cipher_suite() -> Fernet:
    """Menginisialisasi algoritma Fernet menggunakan SECRET_KEY Django."""
    try:
        # Gunakan 32 karakter pertama dari SECRET_KEY sebagai material kunci
        key = settings.SECRET_KEY[:32].encode('utf-8')
        # Fernet membutuhkan URL-safe base64-encoded 32-byte key
        fernet_key = base64.urlsafe_b64encode(key)
        return Fernet(fernet_key)
    except Exception as e:
        raise EncryptionError(f"Gagal menginisialisasi cipher suite: {str(e)}")

def encrypt_token(plain_token: str) -> str:
    """Mengenripsi API token dalam bentuk string."""
    if not plain_token:
        return ""
    try:
        cipher = get_cipher_suite()
        encrypted_bytes = cipher.encrypt(plain_token.encode('utf-8'))
        return encrypted_bytes.decode('utf-8')
    except Exception as e:
        raise EncryptionError(f"Gagal mengenkripsi token: {str(e)}")

def decrypt_token(encrypted_token: str) -> str:
    """Mendekripsi API token yang terenkripsi."""
    if not encrypted_token:
        return ""
    try:
        cipher = get_cipher_suite()
        decrypted_bytes = cipher.decrypt(encrypted_token.encode('utf-8'))
        return decrypted_bytes.decode('utf-8')
    except Exception as e:
        raise EncryptionError(f"Gagal mendekripsi token: {str(e)}")