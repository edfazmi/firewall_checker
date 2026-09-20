import logging
from typing import Any, Dict, Optional

logger = logging.getLogger('application')

class BaseService:  
    @classmethod
    def execute(cls, *args, **kwargs) -> Any:
        raise NotImplementedError("Setiap service harus mengimplementasikan method execute().")

    @staticmethod
    def log_action(level: str, message: str, data: Optional[Dict] = None) -> None:
        """Helper untuk standarisasi logging di dalam service."""
        log_message = f"{message} | Data: {data}" if data else message
        if level == 'info':
            logger.info(log_message)
        elif level == 'error':
            logger.error(log_message)
        elif level == 'warning':
            logger.warning(log_message)
        else:
            logger.debug(log_message)