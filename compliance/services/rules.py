from typing import List, Dict, Any, Tuple
from compliance.models import Finding
from . import network_utils

class RuleEngine:
    def __init__(self, scan_record, active_rules: Dict[str, Any]):
        self.scan_record = scan_record
        self.active_rules = active_rules
        self.findings_to_create = []

    def _add_finding(self, rule_code: str, element_name: str, details: dict):
        rule = self.active_rules.get(rule_code)
        if not rule: return
        self.findings_to_create.append(
            Finding(scan=self.scan_record, rule=rule, element_name=element_name, element_details=details)
        )

    # -------------------------------------------------------------------------
    # RULE LOGIC FUNCTIONS
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
    # RUNNER FUNCTIONS (Iterators)
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

    def _check_policies_and_relationships(self, policies: List[Dict[str, Any]], address_map: Dict[str, Any]) -> List[Dict]:
        parsed_policies = []

        for pol in policies:
            pol_id = str(pol.get('policyid', 'Unknown'))
            pol_name = pol.get('name', '')
            action = str(pol.get('action', '')).strip().lower()
            status = str(pol.get('status', 'enable')).strip().lower()
            if status == 'disable': continue

            src_intf = network_utils.extract_names(pol.get('srcintf'))
            dst_intf = network_utils.extract_names(pol.get('dstintf'))
            src_addrs_str = list(network_utils.extract_names(pol.get('srcaddr')))
            dst_addrs_str = list(network_utils.extract_names(pol.get('dstaddr')))
            services = network_utils.extract_names(pol.get('service'))

            target_name = f"Policy ID {pol_id} ({pol_name})"

            self._rule_pol_no_desc(pol, target_name)
            self._rule_pol_overly_permissive(action, src_addrs_str, dst_addrs_str, target_name)
            self._rule_pol_any_intf(action, src_intf, dst_intf, target_name)
            self._rule_pol_any_svc(action, services, target_name)

            src_nets = network_utils.get_networks_from_names(src_addrs_str, address_map)
            dst_nets = network_utils.get_networks_from_names(dst_addrs_str, address_map)

            parsed_policies.append({
                'id': pol_id, 'name': pol_name, 'action': action,
                'src_intf': src_intf, 'dst_intf': dst_intf, 'services': services,
                'src_nets': src_nets, 'dst_nets': dst_nets, 'raw': pol
            })

        for i, pol_a in enumerate(parsed_policies):
            for j, pol_b in enumerate(parsed_policies):
                if i >= j: continue 

                rel_src_intf = network_utils.compare_sets(pol_a['src_intf'], pol_b['src_intf'], 'any')
                rel_dst_intf = network_utils.compare_sets(pol_a['dst_intf'], pol_b['dst_intf'], 'any')
                rel_svc = network_utils.compare_sets(pol_a['services'], pol_b['services'], 'all')
                rel_src_net = network_utils.compare_networks(pol_a['src_nets'], pol_b['src_nets'])
                rel_dst_net = network_utils.compare_networks(pol_a['dst_nets'], pol_b['dst_nets'])

                combined_rel = network_utils.combine_relations([rel_src_intf, rel_dst_intf, rel_svc, rel_src_net, rel_dst_net])
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
        
    def run_all_checks(self, policies, interfaces, admins, routes, addresses, services, policy_hits) -> Tuple[List[Finding], List[Dict]]:
        address_map = network_utils.build_address_map(addresses)

        parsed_policies = self._check_policies_and_relationships(policies, address_map)
        self._check_unused_policies(policies, policy_hits)
        self._check_interfaces(interfaces)
        self._check_administrators(admins)
        self._check_routing(routes)
        self._check_address_objects(addresses)
        self._check_service_objects(services)
        
        return self.findings_to_create, parsed_policies