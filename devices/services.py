import requests
import urllib3
from typing import Dict, Any, Optional
from django.utils import timezone
from core.services import BaseService
from core.exceptions import FirewallAPIError
from devices.models import Device

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

    def _make_request(self, endpoint: str, is_monitor: bool = False) -> Any:
        url_prefix = self.monitor_url if is_monitor else self.base_url
        url = f"{url_prefix}/{endpoint}"
        
        try:
            response = requests.get(url, headers=self.headers, verify=False, timeout=self.timeout)
            response.raise_for_status()
            data = response.json()
            
            if data.get('http_status') not in [200, 201] and 'results' not in data:
                 raise FirewallAPIError(f"API Error: {data.get('error', 'Unknown Error')}")
                 
            return data.get('results', data)

        except requests.exceptions.Timeout:
            raise FirewallAPIError(f"Timeout saat menghubungi {self.device.ip_address}")
        except requests.exceptions.ConnectionError:
            raise FirewallAPIError(f"Gagal koneksi ke {self.device.ip_address}. Pastikan IP dan Port benar.")
        except requests.exceptions.HTTPError as err:
            if err.response.status_code == 401:
                raise FirewallAPIError("Otentikasi gagal. API Token tidak valid atau tidak memiliki akses admin.")
            elif err.response.status_code == 403:
                raise FirewallAPIError("Akses ditolak (Forbidden). Periksa izin API Profile di FortiGate.")
            raise FirewallAPIError(f"HTTP Error: {str(err)}")
        except Exception as e:
            raise FirewallAPIError(f"Terjadi kesalahan yang tidak terduga: {str(e)}")

    def _update_device_status(self, status: str, os_version: Optional[str] = None):
        self.device.connection_status = status
        if status == 'CONNECTED':
            self.device.last_sync = timezone.now()
            if os_version:
                self.device.os_version = os_version
        self.device.save(update_fields=['connection_status', 'last_sync', 'os_version'])

    def test_connection(self) -> bool:
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
            return True
            
        except requests.exceptions.Timeout:
            self._update_device_status('ERROR')
            raise FirewallAPIError(f"Waktu habis (Timeout). Perangkat {self.device.ip_address} tidak merespons, pastikan perangkat aktif dan jaringan lancar.")
            
        except requests.exceptions.ConnectionError:
            self._update_device_status('ERROR')
            raise FirewallAPIError(f"Gagal terhubung. Pastikan alamat IP {self.device.ip_address} dan port sudah benar, serta perangkat dapat dijangkau.")
            
        except requests.exceptions.HTTPError as err:
            self._update_device_status('ERROR')
            if err.response.status_code in [401, 403]:
                raise FirewallAPIError("Akses ditolak. Token API tidak valid atau izin akses profil kurang.")
            raise FirewallAPIError("Gagal melakukan sinkronisasi dengan perangkat karena masalah autentikasi.")
            
        except Exception as e:
            self._update_device_status('ERROR')
            raise FirewallAPIError("Terjadi kendala saat memeriksa status perangkat. Silakan coba lagi beberapa saat.")

    def fetch_statistics(self) -> dict:
        stats = {'up_ports': 0, 'total_policies': 0, 'never_used': 0}
        
        try:
            interfaces = self._make_request('system/interface')
            stats['up_ports'] = sum(1 for i in interfaces if str(i.get('status', '')).lower() == 'up' or str(i.get('link', '')).lower() == 'up')
        except Exception:
            pass 

        try:
            policies = self._make_request('firewall/policy')
            stats['total_policies'] = len(policies)
        except Exception:
            pass

        try:
            policy_monitor = self._make_request('firewall/policy', is_monitor=True)
            never_used = 0
            for pm in policy_monitor:
                hits = pm.get('hit_count', pm.get('packets', 0))
                if hits == 0:
                    never_used += 1
            stats['never_used'] = never_used
        except Exception:
            pass
            
        return stats

    def get_firewall_policies(self) -> list:
        res = self._make_request('firewall/policy')
        return res if isinstance(res, list) else [res] if res else []

    def get_interfaces(self) -> list:
        res = self._make_request('system/interface')
        return res if isinstance(res, list) else [res] if res else []

    def get_address_objects(self) -> list:
        res = self._make_request('firewall/address')
        return res if isinstance(res, list) else [res] if res else []

    def get_service_objects(self) -> list:
        res = self._make_request('firewall.service/custom')
        return res if isinstance(res, list) else [res] if res else []

    def get_static_routes(self) -> list:
        res = self._make_request('router/static')
        return res if isinstance(res, list) else [res] if res else []

    def get_policy_monitor(self) -> list:
        res = self._make_request('firewall/policy', is_monitor=True)
        return res if isinstance(res, list) else [res] if res else []