import ipaddress
from typing import List, Dict, Any
from django.utils import timezone
from core.services import BaseService
from core.exceptions import ComplianceEngineError, FortiGateAPIError
from devices.models import Device
from devices.services import FortiGateAPIService
from compliance.models import ComplianceRule, ScanHistory, Finding, PolicyRiskAssessment, ConfigurationSnapshot
import logging
import hashlib
import json
import requests

logger = logging.getLogger('application')

class ComplianceScanner(BaseService):
    def __init__(self, device: Device, user=None):
        self.device = device
        self.user = user
        self.api_service = FortiGateAPIService(device=self.device, user=self.user)
        self.scan_record = None
        self.findings_to_create = []
        self.risks_to_create = []
        self.active_rules = self._load_active_rules()
        self.address_map = {}
        self.parsed_policies_for_diff = []

    def _load_active_rules(self) -> Dict[str, ComplianceRule]:
        core_rules = [
            ('POL_OVERLY_PERMISSIVE', 'Overly Permissive Policy (ANY/ALL)', 'Policy mengizinkan trafik dengan cakupan Source atau Destination terbuka sangat luas (ANY/ALL).', 'HIGH', 'Ganti objek "all" dengan spesifik IP Address, Subnet, atau Address Group.'),
            ('POL_ANY_INTF', 'Overly Permissive Interface (ANY)', 'Policy mengizinkan trafik dengan cakupan Incoming atau Outgoing Interface terbuka untuk semua (ANY).', 'HIGH', 'Spesifikasikan Incoming dan Outgoing interface yang diizinkan untuk melewati policy ini.'),
            ('POL_ANY_SVC', 'Overly Permissive Service (ALL)', 'Policy mengizinkan trafik untuk semua layanan/port (ALL).', 'HIGH', 'Spesifikasikan layanan atau port yang benar-benar dibutuhkan.'),
            ('POL_UNUSED', 'Potentially Unused Policy', 'Firewall policy dalam status aktif namun tercatat memiliki 0 Hit (tidak pernah dilalui traffic).', 'INFO', 'Lakukan review bisnis. Policy ini mungkin perlu dinonaktifkan.'),
            ('POL_SHADOWED', 'Shadowed Policy (Tertimpa Urutan)', 'Policy spesifik diletakkan di bawah policy umum yang memiliki Action berlawanan, sehingga tidak akan pernah dieksekusi.', 'CRITICAL', 'Pindahkan letak Policy ini ke urutan di atas Policy yang membayanginya.'),
            ('POL_REDUNDANT', 'Potentially Redundant Policy', 'Subnet jaringan sepenuhnya tercakup di dalam policy lain yang memiliki action yang sama.', 'MEDIUM', 'Hapus Policy ini karena traffic-nya sudah diizinkan/diblokir secara lebih luas oleh policy lain.'),
            ('POL_CONFLICT', 'Conflicting Policy', 'Terdapat bentrokan parsial (overlap) pada cakupan IP address dengan policy lain yang memiliki Action berlawanan.', 'MEDIUM', 'Pisahkan subnet yang bentrok menjadi policy independen.'),
            ('POL_DUPLICATE', 'Duplicate Policy', 'Terdapat duplikasi identik dengan policy lain (Source, Dest, Service, dan Action sama).', 'MEDIUM', 'Hapus salah satu policy yang menduplikat.'),
            ('POL_NO_DESC', 'Policy without Description/Comment', 'Policy tidak memiliki komentar atau deskripsi.', 'LOW', 'Tambahkan komentar yang menjelaskan tujuan bisnis dari policy tersebut.'),
            ('INTF_DOWN', 'Interface Down', 'Interface dalam keadaan admin down.', 'INFO', 'Verifikasi apakah interface ini masih dibutuhkan.'),
            ('INTF_NO_IP', 'Interface Active Without IP', 'Interface berstatus UP namun tidak memiliki konfigurasi IP.', 'LOW', 'Berikan IP Address atau nonaktifkan interface jika tidak digunakan.'),
            ('ADM_NO_TRUSTHOST', 'Admin tanpa Trusted Host', 'Akun administrator dapat diakses dari IP manapun tanpa pembatasan.', 'HIGH', 'Konfigurasi Trusted Host (Restricted IP) untuk akun administrator.'),
            ('ROUTE_NO_DEFAULT', 'Missing Default Route', 'Tidak ada static route default (0.0.0.0/0) yang aktif.', 'MEDIUM', 'Pastikan firewall memiliki rute keluar (gateway) yang valid.'),
            ('ADDR_DUP_SUBNET', 'Duplicate Address Object', 'Terdapat objek address berbeda yang menunjuk ke subnet yang sama persis.', 'LOW', 'Gabungkan atau hapus objek address yang berulang.'),
            ('SVC_WIDE_PORT', 'Wide Port Range Service', 'Service membuka rentang port yang sangat besar (1-65535).', 'LOW', 'Persempit rentang port sesuai kebutuhan aplikasi.'),
        ]
        
        for code, name, desc, sev, rec in core_rules:
            ComplianceRule.objects.get_or_create(
                rule_code=code,
                defaults={
                    'name': name,
                    'description': desc,
                    'severity': sev,
                    'recommendation': rec,
                    'is_active': True
                }
            )
        
        rules = ComplianceRule.objects.filter(is_active=True)
        return {rule.rule_code.strip(): rule for rule in rules}

    def _add_finding(self, rule_code: str, element_name: str, details: dict):
        rule = self.active_rules.get(rule_code)
        if not rule: return
        self.findings_to_create.append(
            Finding(scan=self.scan_record, rule=rule, element_name=element_name, element_details=details)
        )

    # -------------------------------------------------------------------------
    # RULE LOGIC FUNCTIONS (1 Rule = 1 Function)
    # -------------------------------------------------------------------------

    def _rule_intf_down(self, intf, intf_name, status):
        if status == 'down' and 'INTF_DOWN' in self.active_rules:
            self._add_finding('INTF_DOWN', f"Interface {intf_name}", intf)

    def _rule_intf_no_ip(self, intf, intf_name, status):
        if intf.get('ip', '0.0.0.0 0.0.0.0') == '0.0.0.0 0.0.0.0' and status == 'up' and 'INTF_NO_IP' in self.active_rules:
            self._add_finding('INTF_NO_IP', f"Interface {intf_name}", intf)

    def _rule_adm_no_trusthost(self, admin, admin_name):
        if admin.get('trusthost1', '0.0.0.0 0.0.0.0') == '0.0.0.0 0.0.0.0' and 'ADM_NO_TRUSTHOST' in self.active_rules:
            self._add_finding('ADM_NO_TRUSTHOST', f"Admin {admin_name}", admin)

    def _rule_route_no_default(self, routes):
        if not any(r.get('dst', '') == '0.0.0.0 0.0.0.0' and r.get('status', 'enable') == 'enable' for r in routes):
            if 'ROUTE_NO_DEFAULT' in self.active_rules:
                self._add_finding('ROUTE_NO_DEFAULT', "Static Route", {"message": "Tidak ada Default Route."})

    def _rule_addr_dup_subnet(self, addr, addr_name, subnet, subnets_seen):
        if subnet in subnets_seen and 'ADDR_DUP_SUBNET' in self.active_rules:
            self._add_finding('ADDR_DUP_SUBNET', f"Address {addr_name}", {"conflict_with": subnets_seen[subnet]})
        else:
            subnets_seen[subnet] = addr_name

    def _rule_svc_wide_port(self, svc, svc_name):
        if svc.get('tcp-portrange', '') == '1-65535' or svc.get('udp-portrange', '') == '1-65535':
            if 'SVC_WIDE_PORT' in self.active_rules:
                self._add_finding('SVC_WIDE_PORT', f"Service {svc_name}", svc)

    def _rule_pol_no_desc(self, pol, target_name):
        if not pol.get('comments') and 'POL_NO_DESC' in self.active_rules:
            self._add_finding('POL_NO_DESC', target_name, pol)

    def _rule_pol_overly_permissive(self, action, src_addrs_str, dst_addrs_str, target_name):
        if action == 'accept' and 'POL_OVERLY_PERMISSIVE' in self.active_rules:
            has_any_src = any(addr.lower() == 'all' for addr in src_addrs_str)
            has_any_dst = any(addr.lower() == 'all' for addr in dst_addrs_str)
            if has_any_src or has_any_dst:
                self._add_finding('POL_OVERLY_PERMISSIVE', target_name, {
                    "message": "Policy mengizinkan trafik dengan cakupan Source atau Destination sangat luas (ANY/ALL)."
                })

    def _rule_pol_any_intf(self, action, src_intf_set, dst_intf_set, target_name):
        if action == 'accept' and 'POL_ANY_INTF' in self.active_rules:
            has_any_src = any(intf.lower() == 'any' for intf in src_intf_set)
            has_any_dst = any(intf.lower() == 'any' for intf in dst_intf_set)
            if has_any_src or has_any_dst:
                self._add_finding('POL_ANY_INTF', target_name, {
                    "message": "Policy mengizinkan trafik dengan Incoming atau Outgoing interface sangat luas (ANY)."
                })

    def _rule_pol_any_svc(self, action, services_set, target_name):
        if action == 'accept' and 'POL_ANY_SVC' in self.active_rules:
            has_all_svc = any(svc.lower() == 'all' for svc in services_set)
            if has_all_svc:
                self._add_finding('POL_ANY_SVC', target_name, {
                    "message": "Policy mengizinkan trafik dengan cakupan Service terbuka untuk semua (ALL)."
                })

    def _rule_pol_unused(self, pol, pol_id, hit_dict):
        if 'POL_UNUSED' not in self.active_rules: return
        if str(pol.get('status', 'enable')).strip().lower() == 'disable': return
        
        hit_data = hit_dict.get(pol_id, {})
        hit_count = hit_data.get('hit_count', hit_data.get('packets', 0))
        if hit_count == 0:
            self._add_finding('POL_UNUSED', f"Policy ID {pol_id} ({pol.get('name', '')})", {
                "message": "Policy aktif namun 0 hits.", "hit_count": 0, "last_used": hit_data.get('last_used', 'N/A')
            })

    def _rule_pol_duplicate(self, pol_a, pol_b, action_a, action_b, combined_rel, target_b_name, info_json):
        if combined_rel == 'EXACT' and action_a == action_b and 'POL_DUPLICATE' in self.active_rules:
            info_json["message"] = "Duplikasi identik terdeteksi."
            info_json["related_policy_id"] = pol_a['id']
            info_json["related_policy_name"] = pol_a['name']
            self._add_finding('POL_DUPLICATE', target_b_name, info_json)

    def _rule_pol_shadowed(self, pol_a, pol_b, action_a, action_b, combined_rel, target_b_name, info_json):
        if 'POL_SHADOWED' not in self.active_rules: return
        
        if combined_rel == 'EXACT' and action_a != action_b:
            info_json["message"] = f"Shadowed secara penuh! Action bertentangan dengan Policy ID {pol_a['id']}."
            info_json["related_policy_id"] = pol_a['id']
            info_json["related_policy_name"] = pol_a['name']
            self._add_finding('POL_SHADOWED', target_b_name, info_json)
        elif combined_rel == 'SUPERSET' and action_a != action_b:
            info_json["message"] = f"Shadowed. Policy tertimpa oleh Policy luas (ID {pol_a['id']}) di atasnya."
            info_json["related_policy_id"] = pol_a['id']
            info_json["related_policy_name"] = pol_a['name']
            self._add_finding('POL_SHADOWED', target_b_name, info_json)

    def _rule_pol_redundant(self, pol_a, pol_b, action_a, action_b, combined_rel, target_a_name, target_b_name, info_json):
        if 'POL_REDUNDANT' not in self.active_rules: return
        
        if combined_rel == 'SUPERSET' and action_a == action_b:
            info_json["message"] = f"Redundant. Traffic dicakup penuh oleh Policy ID {pol_a['id']} yang lebih luas."
            info_json["related_policy_id"] = pol_a['id']
            info_json["related_policy_name"] = pol_a['name']
            self._add_finding('POL_REDUNDANT', target_b_name, info_json)
        elif combined_rel == 'SUBSET' and action_a == action_b:
            info_json["message"] = f"Redundant. Action sama dengan Policy general ID {pol_b['id']} di bawahnya."
            info_json["related_policy_id"] = pol_b['id']
            info_json["related_policy_name"] = pol_b['name']
            self._add_finding('POL_REDUNDANT', target_a_name, info_json)

    def _rule_pol_conflict(self, pol_a, pol_b, action_a, action_b, combined_rel, target_b_name, info_json):
        if combined_rel == 'OVERLAP' and action_a != action_b and 'POL_CONFLICT' in self.active_rules:
            info_json["message"] = f"Partial Conflict. Sebagian IP range bentrok dengan Policy ID {pol_a['id']}."
            info_json["related_policy_id"] = pol_a['id']
            info_json["related_policy_name"] = pol_a['name']
            self._add_finding('POL_CONFLICT', target_b_name, info_json)


    # -------------------------------------------------------------------------
    # RUNNER FUNCTIONS (Iterators / Logic Connectors)
    # -------------------------------------------------------------------------

    def _check_interfaces(self, interfaces: List[Dict[str, Any]]):
        for intf in interfaces:
            intf_name = intf.get('name', 'Unknown')
            status = intf.get('status', 'down')

            self._rule_intf_down(intf, intf_name, status)
            self._rule_intf_no_ip(intf, intf_name, status)

    def _check_administrators(self, admins: List[Dict[str, Any]]):
        for admin in admins:
            admin_name = admin.get('name', 'Unknown')
            self._rule_adm_no_trusthost(admin, admin_name)

    def _check_routing(self, routes: List[Dict[str, Any]]):
        self._rule_route_no_default(routes)

    def _check_address_objects(self, addresses: List[Dict[str, Any]]):
        subnets_seen = {}
        for addr in addresses:
            subnet = addr.get('subnet', '')
            addr_name = addr.get('name', '')
            if addr.get('type', '') == 'ipmask' and subnet != '0.0.0.0 0.0.0.0':
                self._rule_addr_dup_subnet(addr, addr_name, subnet, subnets_seen)

    def _check_service_objects(self, services: List[Dict[str, Any]]):
        for svc in services:
            svc_name = svc.get('name', '')
            self._rule_svc_wide_port(svc, svc_name)

    def _check_unused_policies(self, policies: List[Dict[str, Any]], policy_hits: List[Dict[str, Any]]):
        hit_dict = {str(p.get('policyid')): p for p in policy_hits}
        for pol in policies:
            pol_id = str(pol.get('policyid', 'Unknown'))
            self._rule_pol_unused(pol, pol_id, hit_dict)

    def _check_policies_and_relationships(self, policies: List[Dict[str, Any]]) -> List[Dict]:
        parsed_policies = []

        for pol in policies:
            pol_id = str(pol.get('policyid', 'Unknown'))
            pol_name = pol.get('name', '')
            action = str(pol.get('action', '')).strip().lower()
            status = str(pol.get('status', 'enable')).strip().lower()
            if status == 'disable': continue

            src_intf = self._extract_names(pol.get('srcintf'))
            dst_intf = self._extract_names(pol.get('dstintf'))
            src_addrs_str = list(self._extract_names(pol.get('srcaddr')))
            dst_addrs_str = list(self._extract_names(pol.get('dstaddr')))
            services = self._extract_names(pol.get('service'))

            target_name = f"Policy ID {pol_id} ({pol_name})"

            self._rule_pol_no_desc(pol, target_name)
            self._rule_pol_overly_permissive(action, src_addrs_str, dst_addrs_str, target_name)
            self._rule_pol_any_intf(action, src_intf, dst_intf, target_name)
            self._rule_pol_any_svc(action, services, target_name)

            src_nets = self._get_networks_from_names(src_addrs_str)
            dst_nets = self._get_networks_from_names(dst_addrs_str)

            parsed_policies.append({
                'id': pol_id, 'name': pol_name, 'action': action,
                'src_intf': src_intf, 'dst_intf': dst_intf, 'services': services,
                'src_nets': src_nets, 'dst_nets': dst_nets, 'raw': pol
            })

        for i, pol_a in enumerate(parsed_policies):
            for j, pol_b in enumerate(parsed_policies):
                if i >= j: continue 

                rel_src_intf = self._compare_sets(pol_a['src_intf'], pol_b['src_intf'], 'any')
                rel_dst_intf = self._compare_sets(pol_a['dst_intf'], pol_b['dst_intf'], 'any')
                rel_svc = self._compare_sets(pol_a['services'], pol_b['services'], 'all')
                rel_src_net = self._compare_networks(pol_a['src_nets'], pol_b['src_nets'])
                rel_dst_net = self._compare_networks(pol_a['dst_nets'], pol_b['dst_nets'])

                combined_rel = self._combine_relations([rel_src_intf, rel_dst_intf, rel_svc, rel_src_net, rel_dst_net])
                if combined_rel == 'NONE': continue

                action_a = pol_a['action']
                action_b = pol_b['action']
                target_b_name = f"Policy ID {pol_b['id']} ({pol_b['name']})"
                target_a_name = f"Policy ID {pol_a['id']} ({pol_a['name']})"
                
                info_json = {"reason": f"Policy A ({pol_a['id']}) ditempatkan sebelum Policy B ({pol_b['id']})."}

                self._rule_pol_duplicate(pol_a, pol_b, action_a, action_b, combined_rel, target_b_name, dict(info_json))
                self._rule_pol_shadowed(pol_a, pol_b, action_a, action_b, combined_rel, target_b_name, dict(info_json))
                self._rule_pol_redundant(pol_a, pol_b, action_a, action_b, combined_rel, target_a_name, target_b_name, dict(info_json))
                self._rule_pol_conflict(pol_a, pol_b, action_a, action_b, combined_rel, target_b_name, dict(info_json))
                        
        return parsed_policies


    # -------------------------------------------------------------------------
    # CORE ENGINE & HELPER METHODS
    # -------------------------------------------------------------------------

    def has_config_changed(self):
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
                self.device.save()
                return True 

            return False
            
        except requests.exceptions.RequestException:
            return False

    def execute_scan(self) -> ScanHistory:
        ScanHistory.objects.filter(device=self.device).delete()
        self.scan_record = ScanHistory.objects.create(device=self.device, status='RUNNING')

        try:
            policies = self.api_service.get_firewall_policies()
            interfaces = self.api_service.get_interfaces()
            admins = self.api_service.get_administrators()
            routes = self.api_service.get_static_routes()
            addresses = self.api_service.get_address_objects()
            services = self.api_service.get_service_objects()
            policy_hits = self.api_service.get_policy_monitor()

            self._build_address_map(addresses)
            
            self.parsed_policies_for_diff = self._check_policies_and_relationships(policies)
            self._check_unused_policies(policies, policy_hits)
            self._check_interfaces(interfaces)
            self._check_administrators(admins)
            self._check_routing(routes)
            self._check_address_objects(addresses)
            self._check_service_objects(services)

            self._assess_policy_risks(self.parsed_policies_for_diff)
            self._detect_changes(policies)

            self._finalize_scan()
            return self.scan_record

        except FortiGateAPIError as e:
            self.scan_record.status = 'FAILED'
            self.scan_record.error_message = str(e)
            self.scan_record.save()
            raise ComplianceEngineError(f"API Error: {str(e)}")
        except Exception as e:
            self.scan_record.status = 'FAILED'
            self.scan_record.error_message = f"Internal Error: {str(e)}"
            self.scan_record.save()
            logger.error(f"Engine Error: {str(e)}", exc_info=True)
            raise ComplianceEngineError("Terjadi kesalahan internal sistem saat scanning.")

    def _detect_changes(self, raw_policies: List[Dict[str, Any]]):
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
        changes = {'added': [], 'removed': [], 'modified': [], 'author': self.api_service.get_recent_admin()}
        
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
            self.scan_record.changes_detail = changes
            self.scan_record.save(update_fields=['changes_detail'])
            
        snapshot.policies_json = current_dict
        snapshot.save()

    def _build_address_map(self, addresses: List[Dict[str, Any]]):
        for addr in addresses:
            name = str(addr.get('name', '')).strip()
            obj_type = addr.get('type', 'ipmask')
            subnet_str = addr.get('subnet', '0.0.0.0 0.0.0.0')
            if obj_type == 'ipmask':
                try:
                    ip, mask = subnet_str.split(' ')
                    if ip == '0.0.0.0' and mask == '0.0.0.0':
                        self.address_map[name] = ipaddress.IPv4Network('0.0.0.0/0')
                    else:
                        self.address_map[name] = ipaddress.IPv4Network(f"{ip}/{mask}", strict=False)
                except ValueError:
                    self.address_map[name] = None 
            else:
                self.address_map[name] = None

    def _get_networks_from_names(self, names_list: List[str]) -> List[ipaddress.IPv4Network]:
        networks = []
        for name in names_list:
            if name.lower() == 'all':
                networks.append(ipaddress.IPv4Network('0.0.0.0/0'))
            elif name in self.address_map and self.address_map[name] is not None:
                networks.append(self.address_map[name])
        return networks

    def _compare_networks(self, nets_a: List[ipaddress.IPv4Network], nets_b: List[ipaddress.IPv4Network]) -> str:
        if not nets_a or not nets_b: return 'NONE'
        a_super_b = True 
        for net_b in nets_b:
            if not any(net_b.subnet_of(net_a) for net_a in nets_a):
                a_super_b = False; break
        b_super_a = True 
        for net_a in nets_a:
            if not any(net_a.subnet_of(net_b) for net_b in nets_b):
                b_super_a = False; break
        has_overlap = False
        if not a_super_b and not b_super_a:
            for net_a in nets_a:
                for net_b in nets_b:
                    if net_a.overlaps(net_b):
                        has_overlap = True; break
                if has_overlap: break
        if a_super_b and b_super_a: return 'EXACT'
        if a_super_b: return 'SUPERSET'
        if b_super_a: return 'SUBSET'
        if has_overlap: return 'OVERLAP'
        return 'NONE'

    def _compare_sets(self, set_a: set, set_b: set, univ_kw: str = 'any') -> str:
        if not set_a or not set_b: return 'NONE'
        has_univ_a = any(univ_kw in s.lower() for s in set_a)
        has_univ_b = any(univ_kw in s.lower() for s in set_b)
        if has_univ_a and has_univ_b: return 'EXACT'
        if has_univ_a: return 'SUPERSET'
        if has_univ_b: return 'SUBSET'
        a_sup_b = set_b.issubset(set_a)
        b_sup_a = set_a.issubset(set_b)
        overlap = bool(set_a.intersection(set_b))
        if a_sup_b and b_sup_a: return 'EXACT'
        if a_sup_b: return 'SUPERSET'
        if b_sup_a: return 'SUBSET'
        if overlap: return 'OVERLAP'
        return 'NONE'

    def _combine_relations(self, rels: List[str]) -> str:
        if 'NONE' in rels: return 'NONE'
        if all(r == 'EXACT' for r in rels): return 'EXACT'
        if all(r in ['SUPERSET', 'EXACT'] for r in rels): return 'SUPERSET'
        if all(r in ['SUBSET', 'EXACT'] for r in rels): return 'SUBSET'
        return 'OVERLAP'

    def _extract_names(self, data) -> set:
        if not data or not isinstance(data, list): return set()
        return set([str(item.get('name', '')).strip() for item in data if isinstance(item, dict)])

    def _assess_policy_risks(self, parsed_policies: List[Dict]):
        for pol in parsed_policies:
            factors = []
            severities_found = []
            
            target_name = f"Policy ID {pol['id']} ({pol['name']})"
            related_findings = [f for f in self.findings_to_create if f.element_name == target_name]
            
            for f in related_findings:
                if f.rule.name not in factors:
                    factors.append(f.rule.name)
                severities_found.append(f.rule.severity)

            if 'CRITICAL' in severities_found:
                severity = 'CRITICAL'
            elif 'HIGH' in severities_found:
                severity = 'HIGH'
            elif 'MEDIUM' in severities_found:
                severity = 'MEDIUM'
            elif 'LOW' in severities_found:
                severity = 'LOW'
            elif 'INFO' in severities_found:
                severity = 'INFO'
            else:
                severity = 'INFO'

            if not factors:
                factors.append("Konfigurasi beroperasi normal tanpa temuan konflik.")

            self.risks_to_create.append(PolicyRiskAssessment(
                scan=self.scan_record,
                policy_id=pol['id'],
                policy_name=pol['name'],
                severity=severity,
                contributing_factors=factors
            ))

    def _finalize_scan(self):
        if self.findings_to_create:
            Finding.objects.bulk_create(self.findings_to_create)
        if self.risks_to_create:
            PolicyRiskAssessment.objects.bulk_create(self.risks_to_create)

        self.scan_record.status = 'SUCCESS'
        self.scan_record.save(update_fields=['status'])
        
        self.device.last_sync = timezone.now()
        self.device.save(update_fields=['last_sync'])
        
        if hasattr(self, 'log_action'):
            self.log_action('info', "Scan sukses diselesaikan.")