import json
import hashlib
import requests
from typing import List, Dict, Any
from compliance.models import ConfigurationSnapshot

class ConfigurationDiffService:
    def __init__(self, device):
        self.device = device

    def has_config_changed(self) -> bool:
        url = f"https://{self.device.ip_address}/api/v2/cmdb/firewall/policy"
        headers = {"Authorization": f"Bearer {self.device.api_token_encrypted}"}
        
        try:
            response = requests.get(url, headers=headers, verify=False, timeout=5)
            if response.status_code != 200:
                return False

            data = response.json().get('results', [])

            for policy in data:
                policy.pop('uuid', None)
                policy.pop('hit_count', None)
                policy.pop('bytes', None)
                policy.pop('last_used', None)

            policy_string = json.dumps(data, sort_keys=True)
            current_hash = hashlib.sha256(policy_string.encode('utf-8')).hexdigest()

            if self.device.last_config_hash != current_hash:
                self.device.last_config_hash = current_hash
                self.device.save(update_fields=['last_config_hash'])
                return True 

            return False
            
        except requests.exceptions.RequestException:
            return False

    def detect_changes(self, raw_policies: List[Dict[str, Any]], scan_record, recent_admin: str):
        current_dict = {}
        for index, pol in enumerate(raw_policies):
            pol_id = str(pol.get('policyid', 'Unknown'))
            current_dict[pol_id] = {
                'name': pol.get('name', ''),
                'action': str(pol.get('action', '')).strip().lower(),
                'status': str(pol.get('status', 'enable')).strip().lower(),
                'comments': pol.get('comments', ''),
                'srcintf': sorted([str(i.get('name', '')).strip() for i in pol.get('srcintf', []) if isinstance(i, dict)]),
                'dstintf': sorted([str(i.get('name', '')).strip() for i in pol.get('dstintf', []) if isinstance(i, dict)]),
                'srcaddr': sorted([str(i.get('name', '')).strip() for i in pol.get('srcaddr', []) if isinstance(i, dict)]),
                'dstaddr': sorted([str(i.get('name', '')).strip() for i in pol.get('dstaddr', []) if isinstance(i, dict)]),
                'service': sorted([str(i.get('name', '')).strip() for i in pol.get('service', []) if isinstance(i, dict)]),
                'index': index 
            }
            
        snapshot, created = ConfigurationSnapshot.objects.get_or_create(device=self.device)
        
        if created or not snapshot.policies_json:
            snapshot.policies_json = current_dict
            snapshot.save()
            return
            
        old_dict = snapshot.policies_json
        changes = {'added': [], 'removed': [], 'modified': [], 'author': recent_admin}
        
        old_ids = set(old_dict.keys())
        new_ids = set(current_dict.keys())
        
        for pid in old_ids - new_ids:
            changes['removed'].append({'id': pid, 'name': old_dict[pid].get('name', 'Unknown')})
            
        for pid in new_ids - old_ids:
            changes['added'].append({'id': pid, 'name': current_dict[pid].get('name', 'Unknown')})
            
        for pid in old_ids.intersection(new_ids):
            old_p = old_dict[pid]
            new_p = current_dict[pid]
            diffs = []
            
            if old_p.get('index', -1) != new_p['index']:
                diffs.append(f"Urutan eksekusi bergeser dari posisi #{old_p.get('index', 'N/A')} ke #{new_p['index']}")
                
            for key in ['name', 'action', 'status', 'srcintf', 'dstintf', 'srcaddr', 'dstaddr', 'service']:
                val_old = old_p.get(key)
                val_new = new_p.get(key)
                if val_old != val_new:
                    diffs.append(f"Parameter [{key}] diubah dari '{val_old}' menjadi '{val_new}'")
            
            if diffs:
                changes['modified'].append({'id': pid, 'name': new_p['name'], 'diffs': diffs})
                
        if changes['added'] or changes['removed'] or changes['modified']:
            scan_record.changes_detail = changes
            scan_record.save(update_fields=['changes_detail'])
            
        snapshot.policies_json = current_dict
        snapshot.save()