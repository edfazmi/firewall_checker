from typing import Optional

class BaseAppException(Exception):
    """Base exception untuk seluruh aplikasi."""
    def __init__(self, message: str, code: Optional[str] = None):
        super().__init__(message)
        self.message = message
        self.code = code

class FirewallAPIError(BaseAppException):
    """Dilempar ketika koneksi ke API FortiGate gagal atau mengembalikan error."""
    pass

class EncryptionError(BaseAppException):
    """Dilempar ketika proses enkripsi/dekripsi API Token gagal."""
    pass

class ComplianceEngineError(BaseAppException):
    """Dilempar ketika terjadi kesalahan internal pada rule engine saat evaluasi."""
    pass