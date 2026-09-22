import logging
import copy
from typing import Any, Dict, Optional

logger = logging.getLogger('application')

SENSITIVE_KEYS = {'token', 'password', 'secret', 'api_key', 'authorization', 'pass'}

class BaseService:  
    @classmethod
    def execute(cls, *args, **kwargs) -> Any:
        raise NotImplementedError("Setiap service harus mengimplementasikan method execute().")

    @staticmethod
    def _sanitize_string(text: str) -> str:
        """Mencegah Log Injection dengan menetralkan karakter newline/carriage return."""
        if not isinstance(text, str):
            return str(text)
        return text.replace('\n', '\\n').replace('\r', '\\r')

    @staticmethod
    def _redact_data(data: Dict) -> Dict:
        """Menyensor nilai dari key yang sensitif (Data Leakage Prevention)."""
        if not isinstance(data, dict):
            return data
        
        redacted = copy.deepcopy(data)
        for key, value in redacted.items():
            if any(sensitive in key.lower() for sensitive in SENSITIVE_KEYS):
                redacted[key] = "***REDACTED***"
            elif isinstance(value, dict):
                redacted[key] = BaseService._redact_data(value)
        return redacted

    @staticmethod
    def log_action(level: str, message: str, data: Optional[Dict] = None) -> None:
        safe_message = BaseService._sanitize_string(message)
        
        if data:
            safe_data = BaseService._redact_data(data)
            log_message = f"{safe_message} | Data: {safe_data}"
        else:
            log_message = safe_message

        if level == 'info':
            logger.info(log_message)
        elif level == 'error':
            logger.error(log_message)
        elif level == 'warning':
            logger.warning(log_message)
        else:
            logger.debug(log_message)