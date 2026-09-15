# devices/services.py
import requests
import urllib3
from typing import Dict, Any, Optional
from django.utils import timezone
from core.services import BaseService
from core.exceptions import FortiGateAPIError
from devices.models import Device
from audit_logs.models import AuditLog

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class FortiGateAPIService(BaseService):
    def __init__(self, device: Device, user=None):
        self.device = device
        self.user = user
        self.base_url = f"https://{self.device.ip_address}:{self.device.port}/api/v2/cmdb"
        self.monitor_url = f"https://{self.device.ip_address}:{self.device.port}/api/v2/monitor"
        
        raw_token = self.device.get_token()
        self.headers = {
            'Authorization': f'Bearer {raw_token}',
            'Accept': 'application/json'
        }
        self.timeout = 10 

    def _make_request(self, endpoint: str, is_monitor: bool = False) -> Dict[str, Any]:
        """HTTP Wrapper murni. Sama sekali tidak mengubah database (No Side-Effects)."""
        url_prefix = self.monitor_url if is_monitor else self.base_url
        url = f"{url_prefix}/{endpoint}"
        
        try:
            response = requests.get(url, headers=self.headers, verify=False, timeout=self.timeout)
            response.raise_for_status()
            data = response.json()
            
            if data.get('http_status') not in [200, 201] and 'results' not in data:
                 raise FortiGateAPIError(f"API Error: {data.get('error', 'Unknown Error')}")
                 
            return data.get('results', data)

        except requests.exceptions.Timeout:
            raise FortiGateAPIError(f"Timeout saat menghubungi {self.device.ip_address}")
        except requests.exceptions.ConnectionError:
            raise FortiGateAPIError(f"Gagal koneksi ke {self.device.ip_address}. Pastikan IP dan Port benar.")
        except requests.exceptions.HTTPError as err:
            if err.response.status_code == 401:
                raise FortiGateAPIError("Otentikasi gagal. API Token tidak valid atau tidak memiliki akses admin.")
            elif err.response.status_code == 403:
                raise FortiGateAPIError("Akses ditolak (Forbidden). Periksa izin API Profile di FortiGate.")
            raise FortiGateAPIError(f"HTTP Error: {str(err)}")
        except Exception as e:
            raise FortiGateAPIError(f"Terjadi kesalahan yang tidak terduga: {str(e)}")

    def _update_device_status(self, status: str, os_version: Optional[str] = None):
        self.device.connection_status = status
        if status == 'CONNECTED':
            self.device.last_sync = timezone.now()
            if os_version:
                self.device.os_version = os_version
        self.device.save(update_fields=['connection_status', 'last_sync', 'os_version'])

    def _create_audit_log(self, action: str, details: str):
        AuditLog.objects.create(
            user=self.user,
            action=action,
            target_type="Device",
            target_id=self.device.id,
            details={"message": details}
        )

    def test_connection(self) -> bool:
        """Satu-satunya fungsi yang berhak mengubah status device menjadi ERROR/CONNECTED secara paksa."""
        try:
            url = f"{self.monitor_url}/system/status"
            response = requests.get(url, headers=self.headers, verify=False, timeout=self.timeout)
            response.raise_for_status()
            raw_data = response.json()

            version = raw_data.get('version')
            if not version:
                results = raw_data.get('results', {})
                if isinstance(results, dict):
                    version = results.get('version')

            if version:
                version = str(version)
                 
            self._update_device_status('CONNECTED', os_version=version)
            self._create_audit_log("TEST_CONNECTION_SUCCESS", f"Berhasil terkoneksi ke {self.device.name}")
            return True
            
        except Exception as e:
            self._update_device_status('ERROR')
            raise FortiGateAPIError(f"Test Koneksi Gagal: {str(e)}")

    def fetch_statistics(self) -> dict:
        stats = {'up_ports': 0, 'total_policies': 0, 'top_policy': "Data tidak tersedia", 'never_used': 0}
        try:
            interfaces = self._make_request('system/interface')
            stats['up_ports'] = sum(1 for i in interfaces if str(i.get('status', '')).lower() == 'up' or str(i.get('link', '')).lower() == 'up')

            policies = self._make_request('firewall/policy')
            stats['total_policies'] = len(policies)
            
            policy_monitor = self._make_request('firewall/policy', is_monitor=True)
            
            never_used = 0
            max_hits = -1
            top_pol_id = None
            
            for pm in policy_monitor:
                hits = pm.get('hit_count', pm.get('packets', 0))
                if hits == 0:
                    never_used += 1
                if hits > max_hits:
                    max_hits = hits
                    top_pol_id = pm.get('policyid')
            
            stats['never_used'] = never_used
            
            if top_pol_id is not None and max_hits > 0:
                pol_name = f"ID: {top_pol_id}"
                for p in policies:
                    if str(p.get('policyid')) == str(top_pol_id):
                        pol_name = p.get('name', pol_name)
                        break
                stats['top_policy'] = f"{pol_name} ({max_hits} hits)"
                
        except Exception as e:
            self.log_action('warning', f"Gagal mengambil statistik monitoring: {str(e)}")
            
        return stats

    def get_recent_admin(self) -> str:
        try:
            logs = self._make_request('log/memory/event/system?count=15', is_monitor=True)
            for log in logs:
                msg = str(log.get('msg', '')).lower()
                if 'attribute configured' in msg or 'edit firewall policy' in msg or 'policy' in msg:
                    return log.get('user', 'Administrator')
        except:
            pass
        return "Sistem / Admin GUI"

    # --- Data Fetching Methods ---
    def get_firewall_policies(self) -> list:
        return self._make_request('firewall/policy')
    def get_interfaces(self) -> list:
        return self._make_request('system/interface')
    def get_address_objects(self) -> list:
        return self._make_request('firewall/address')
    def get_service_objects(self) -> list:
        return self._make_request('firewall.service/custom')
    def get_static_routes(self) -> list:
        return self._make_request('router/static')
    def get_administrators(self) -> list:
        return self._make_request('system/admin')
    def get_policy_monitor(self) -> list:
        try:
            return self._make_request('firewall/policy', is_monitor=True)
        except FortiGateAPIError:
            return []