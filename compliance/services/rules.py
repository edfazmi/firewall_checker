from typing import Any, Dict, List, Optional, Tuple

from compliance.models import Finding
from . import network_utils


class RuleEngine:
    def __init__(self, scan_record, active_rules: Dict[str, Any]):
        self.scan_record = scan_record
        self.active_rules = active_rules or {}
        self.findings_to_create: List[Finding] = []

    def _add_finding(self, rule_code: str, element_name: str, details: Dict[str, Any]) -> None:
        rule = self.active_rules.get(rule_code)
        if rule:
            self.findings_to_create.append(
                Finding(
                    scan=self.scan_record,
                    rule=rule,
                    element_name=element_name,
                    element_details=details,
                )
            )

    def _rule_intf_down(self, intf: Dict[str, Any], intf_name: str, status: str) -> None:
        if status == "down" and "INTF_DOWN" in self.active_rules:
            self._add_finding("INTF_DOWN", f"Interface {intf_name}", intf)

    def _rule_intf_no_ip(self, intf: Dict[str, Any], intf_name: str, status: str) -> None:
        if (
            "INTF_NO_IP" in self.active_rules
            and status == "up"
            and str(intf.get("ip", "0.0.0.0 0.0.0.0")).strip() == "0.0.0.0 0.0.0.0"
        ):
            self._add_finding("INTF_NO_IP", f"Interface {intf_name}", intf)

    def _rule_addr_dup_subnet(self, addr_name: str, subnet_key: str, subnets_seen: Dict[str, str]) -> None:
        if "ADDR_DUP_SUBNET" not in self.active_rules:
            return
        previous_name = subnets_seen.get(subnet_key)
        if previous_name:
            self._add_finding(
                "ADDR_DUP_SUBNET",
                f"Address {addr_name}",
                {"conflict_with": previous_name, "subnet": subnet_key},
            )
        else:
            subnets_seen[subnet_key] = addr_name

    def _rule_svc_wide_port(self, svc: Dict[str, Any], svc_name: str) -> None:
        if "SVC_WIDE_PORT" not in self.active_rules:
            return
        ranges = []
        for key in ("tcp-portrange", "tcp_portrange", "udp-portrange", "udp_portrange", "sctp-portrange", "sctp_portrange"):
            ranges.extend(network_utils._parse_port_ranges(svc.get(key)))
        if any(start == 0 and end == 65535 or start == 1 and end == 65535 for start, end in ranges):
            self._add_finding("SVC_WIDE_PORT", f"Service {svc_name}", svc)

    def _rule_pol_no_desc(self, pol: Dict[str, Any], target_name: str) -> None:
        if "POL_NO_DESC" in self.active_rules and not str(pol.get("comments", "")).strip():
            self._add_finding("POL_NO_DESC", target_name, pol)

    def _rule_pol_broad_scope(self, src_addrs: set, dst_addrs: set, target_name: str) -> None:
        if "POL_BROAD_SCOPE" not in self.active_rules:
            return
        source_all = any(str(addr).strip().lower() == "all" for addr in src_addrs)
        destination_all = any(str(addr).strip().lower() == "all" for addr in dst_addrs)
        if source_all or destination_all:
            self._add_finding(
                "POL_BROAD_SCOPE",
                target_name,
                {
                    "message": "Policy memiliki cakupan Source atau Destination ALL.",
                    "source_all": source_all,
                    "destination_all": destination_all,
                },
            )

    def _rule_pol_overly_permissive(self, src_addrs: set, dst_addrs: set, target_name: str) -> None:
        if "POL_OVERLY_PERMISSIVE" not in self.active_rules:
            return
        if any(str(addr).strip().lower() == "all" for addr in src_addrs) or any(
            str(addr).strip().lower() == "all" for addr in dst_addrs
        ):
            self._add_finding(
                "POL_OVERLY_PERMISSIVE",
                target_name,
                {"message": "Policy memiliki cakupan Source atau Destination sangat luas (ANY/ALL)."},
            )

    def _rule_pol_any_intf(self, src_intf_set: set, dst_intf_set: set, target_name: str) -> None:
        if "POL_ANY_INTF" not in self.active_rules:
            return
        if any(str(intf).strip().lower() == "any" for intf in src_intf_set) or any(
            str(intf).strip().lower() == "any" for intf in dst_intf_set
        ):
            self._add_finding(
                "POL_ANY_INTF",
                target_name,
                {"message": "Policy menggunakan Incoming atau Outgoing interface ANY sehingga cakupan interface sangat luas."},
            )

    def _rule_pol_any_svc(self, services_set: set, target_name: str) -> None:
        if "POL_ANY_SVC" not in self.active_rules:
            return
        if any(str(service).strip().lower() == "all" for service in services_set):
            self._add_finding(
                "POL_ANY_SVC",
                target_name,
                {"message": "Policy menggunakan Service ALL sehingga mencakup semua service."},
            )

    def _rule_pol_unused(self, pol: Dict[str, Any], pol_id: str, hit_dict: Dict[str, Dict[str, Any]]) -> None:
        if "POL_UNUSED" not in self.active_rules or str(pol.get("status", "enable")).strip().lower() == "disable":
            return
        hit_data = hit_dict.get(pol_id)
        if not isinstance(hit_data, dict):
            return
        raw_hit_count = hit_data.get("hit_count", hit_data.get("hit-count", hit_data.get("packets")))
        try:
            hit_count = int(raw_hit_count or 0)
        except (TypeError, ValueError):
            return
        if hit_count == 0:
            self._add_finding(
                "POL_UNUSED",
                f"Policy ID {pol_id} ({pol.get('name', '')})",
                {
                    "message": "Policy aktif namun 0 hits.",
                    "hit_count": 0,
                    "last_used": hit_data.get("last_used", "N/A"),
                },
            )

    def _rule_pol_no_log(self, pol: Dict[str, Any], target_name: str) -> None:
        if "POL_NO_LOG" not in self.active_rules:
            return
        log_status = str(pol.get("logtraffic", "disable")).strip().lower()
        if log_status in {"disable", "", "none", "false", "disabled"}:
            self._add_finding(
                "POL_NO_LOG",
                target_name,
                {"message": "Fitur logging dimatikan pada policy ini.", "logtraffic_value": log_status},
            )

    @staticmethod
    def _relation_details(relations: Dict[str, str]) -> Dict[str, Any]:
        return {
            "source_interface": relations.get("source_interface", "NONE"),
            "destination_interface": relations.get("destination_interface", "NONE"),
            "service": relations.get("service", "NONE"),
            "source_network": relations.get("source_network", "NONE"),
            "destination_network": relations.get("destination_network", "NONE"),
        }

    def _rule_pol_duplicate(
        self,
        pol_a: Dict[str, Any],
        action_a: str,
        action_b: str,
        relations: Dict[str, str],
        target_b_name: str,
        info_json: Dict[str, Any],
    ) -> None:
        if "POL_DUPLICATE" in self.active_rules and action_a == action_b and network_utils.traffic_exact(relations):
            self._add_finding(
                "POL_DUPLICATE",
                target_b_name,
                {
                    **info_json,
                    "message": "Duplikasi identik terdeteksi.",
                    "related_policy_id": pol_a["id"],
                    "related_policy_name": pol_a["name"],
                },
            )

    def _rule_pol_shadowed(
        self,
        pol_a: Dict[str, Any],
        action_a: str,
        action_b: str,
        relations: Dict[str, str],
        target_b_name: str,
        info_json: Dict[str, Any],
    ) -> None:
        if "POL_SHADOWED" not in self.active_rules or action_a == action_b:
            return
        if not network_utils.traffic_covers(relations):
            return
        relationship = "EXACT" if network_utils.traffic_exact(relations) else "SUPERSET"
        message = (
            f"Shadowed secara penuh. Policy sebelumnya (ID {pol_a['id']}) memiliki cakupan identik dengan action berbeda."
            if relationship == "EXACT"
            else f"Shadowed. Policy sebelumnya (ID {pol_a['id']}) mencakup seluruh trafik Policy B dengan action berbeda."
        )
        self._add_finding(
            "POL_SHADOWED",
            target_b_name,
            {
                **info_json,
                "message": message,
                "related_policy_id": pol_a["id"],
                "related_policy_name": pol_a["name"],
            },
        )

    def _rule_pol_redundant(
        self,
        pol_a: Dict[str, Any],
        pol_b: Dict[str, Any],
        action_a: str,
        action_b: str,
        relations: Dict[str, str],
        target_a_name: str,
        target_b_name: str,
        info_json: Dict[str, Any],
    ) -> None:
        if "POL_REDUNDANT" not in self.active_rules or action_a != action_b:
            return
        if network_utils.traffic_covers(relations) and not network_utils.traffic_exact(relations):
            self._add_finding(
                "POL_REDUNDANT",
                target_b_name,
                {
                    **info_json,
                    "message": f"Redundant. Policy B dicakup penuh oleh Policy ID {pol_a['id']} yang lebih luas dengan action yang sama.",
                    "related_policy_id": pol_a["id"],
                    "related_policy_name": pol_a["name"],
                },
            )

    def _rule_pol_conflict(
        self,
        pol_a: Dict[str, Any],
        action_a: str,
        action_b: str,
        relations: Dict[str, str],
        target_b_name: str,
        info_json: Dict[str, Any],
    ) -> None:
        if "POL_CONFLICT" not in self.active_rules or action_a == action_b:
            return
        if network_utils.traffic_intersects(relations) and not network_utils.traffic_covers(relations):
            self._add_finding(
                "POL_CONFLICT",
                target_b_name,
                {
                    **info_json,
                    "message": f"Policy memiliki sebagian trafik yang beririsan dengan action berbeda dari Policy ID {pol_a['id']}.",
                    "related_policy_id": pol_a["id"],
                    "related_policy_name": pol_a["name"],
                },
            )

    def _rule_pol_potentially_merge(
        self,
        pol_a: Dict[str, Any],
        pol_b: Dict[str, Any],
        action_a: str,
        action_b: str,
        relations: Dict[str, str],
        target_a_name: str,
        target_b_name: str,
        info_json: Dict[str, Any],
    ) -> None:
        if "POL_POTENTIALLY_MERGE" not in self.active_rules or action_a != action_b:
            return
        if not (
            relations.get("source_interface") == "EXACT"
            and relations.get("destination_interface") == "EXACT"
            and relations.get("source_network") == "EXACT"
            and relations.get("destination_network") == "EXACT"
        ):
            return
        service_relation = relations.get("service")
        if service_relation != "OVERLAP":
            return
        if network_utils.traffic_exact(relations):
            return
        self._add_finding(
            "POL_POTENTIALLY_MERGE",
            target_b_name,
            {
                **info_json,
                "message": "Berpotensi digabung. Source, Destination, dan interface sama, sedangkan cakupan service berbeda atau beririsan.",
                "related_policy_id": pol_a["id"],
                "related_policy_name": pol_a["name"],
                "merge_with_policy_id": pol_b["id"],
                "merge_with_policy_name": pol_b["name"],
                "service_relationship": service_relation,
                "suggested_action": "Pertimbangkan menggabungkan service kedua policy menjadi satu policy setelah memastikan kebutuhan akses tetap terpenuhi.",
            },
        )

    def _check_interfaces(self, interfaces: List[Dict[str, Any]]) -> None:
        if not isinstance(interfaces, list):
            return
        for intf in interfaces:
            if not isinstance(intf, dict):
                continue
            intf_name = str(intf.get("name", "Unknown")).strip() or "Unknown"
            status = str(intf.get("status", "")).strip().lower()
            if not status:
                status = str(intf.get("link", "down")).strip().lower()
            if status not in {"up", "down"}:
                status = "down"
            self._rule_intf_down(intf, intf_name, status)
            self._rule_intf_no_ip(intf, intf_name, status)

    def _check_address_objects(self, addresses: List[Dict[str, Any]]) -> None:
        if not isinstance(addresses, list) or "ADDR_DUP_SUBNET" not in self.active_rules:
            return
        subnets_seen: Dict[str, str] = {}
        for addr in addresses:
            if not isinstance(addr, dict):
                continue
            obj_type = str(addr.get("type", "")).strip().lower()
            if obj_type not in {"ipmask", "subnet", "interface-subnet"}:
                continue
            network = network_utils._parse_subnet(addr.get("subnet"))
            if network is None or network == network_utils.ipaddress.IPv4Network("0.0.0.0/0"):
                continue
            self._rule_addr_dup_subnet(
                str(addr.get("name", "")).strip() or "Unknown",
                str(network),
                subnets_seen,
            )

    def _check_service_objects(self, services: List[Dict[str, Any]]) -> None:
        if not isinstance(services, list):
            return
        for svc in services:
            if isinstance(svc, dict):
                self._rule_svc_wide_port(svc, str(svc.get("name", "Unknown")).strip() or "Unknown")

    def _check_unused_policies(self, policies: List[Dict[str, Any]], policy_hits: List[Dict[str, Any]]) -> None:
        if not isinstance(policies, list) or "POL_UNUSED" not in self.active_rules:
            return
        hit_dict = {
            str(hit["policyid"]): hit
            for hit in policy_hits
            if isinstance(hit, dict) and hit.get("policyid") is not None
        }
        for pol in policies:
            if isinstance(pol, dict):
                self._rule_pol_unused(pol, self._policy_id(pol), hit_dict)

    @staticmethod
    def _policy_name(pol: Dict[str, Any]) -> str:
        return str(pol.get("name", "")).strip()

    @staticmethod
    def _policy_id(pol: Dict[str, Any]) -> str:
        return str(pol.get("policyid", pol.get("policy-id", "Unknown"))).strip()

    @staticmethod
    def _policy_action(pol: Dict[str, Any]) -> str:
        return str(pol.get("action", "")).strip().lower()

    @staticmethod
    def _policy_enabled(pol: Dict[str, Any]) -> bool:
        return str(pol.get("status", "enable")).strip().lower() != "disable"

    def _prepare_policy(
        self,
        pol: Dict[str, Any],
        address_map: Dict[str, network_utils.Scope],
        service_map: Dict[str, network_utils.Scope],
    ) -> Optional[Dict[str, Any]]:
        if not isinstance(pol, dict) or not self._policy_enabled(pol):
            return None
        pol_id = self._policy_id(pol)
        pol_name = self._policy_name(pol)
        action = self._policy_action(pol)
        src_intf = network_utils.extract_names(pol.get("srcintf"))
        dst_intf = network_utils.extract_names(pol.get("dstintf"))
        src_addrs = network_utils.extract_names(pol.get("srcaddr"))
        dst_addrs = network_utils.extract_names(pol.get("dstaddr"))
        services = network_utils.extract_names(pol.get("service"))
        src_scopes = network_utils.get_address_scopes_from_names(src_addrs, address_map)
        dst_scopes = network_utils.get_address_scopes_from_names(dst_addrs, address_map)
        svc_scopes = network_utils.get_service_scopes_from_names(services, service_map)
        target_name = f"Policy ID {pol_id} ({pol_name})"
        self._rule_pol_no_desc(pol, target_name)
        self._rule_pol_no_log(pol, target_name)
        if "POL_BROAD_SCOPE" in self.active_rules:
            self._rule_pol_broad_scope(src_addrs, dst_addrs, target_name)
        else:
            self._rule_pol_overly_permissive(src_addrs, dst_addrs, target_name)
        self._rule_pol_any_intf(src_intf, dst_intf, target_name)
        self._rule_pol_any_svc(services, target_name)
        return {
            "id": pol_id,
            "name": pol_name,
            "action": action,
            "src_intf": src_intf,
            "dst_intf": dst_intf,
            "services": services,
            "src_scopes": src_scopes,
            "dst_scopes": dst_scopes,
            "svc_scopes": svc_scopes,
            "raw": pol,
        }

    @staticmethod
    def _compare_policy_pair(pol_a: Dict[str, Any], pol_b: Dict[str, Any]) -> Optional[Dict[str, str]]:
        relations = network_utils.compare_traffic_dimensions(
            pol_a["src_intf"],
            pol_b["src_intf"],
            pol_a["dst_intf"],
            pol_b["dst_intf"],
            pol_a["src_scopes"],
            pol_b["src_scopes"],
            pol_a["dst_scopes"],
            pol_b["dst_scopes"],
            pol_a["svc_scopes"],
            pol_b["svc_scopes"],
        )
        if not network_utils.traffic_intersects(relations):
            return None
        return relations

    def _process_policy_pair(
        self,
        pol_a: Dict[str, Any],
        pol_b: Dict[str, Any],
        relations: Dict[str, str],
    ) -> None:
        name_a = f"Policy ID {pol_a['id']} ({pol_a['name']})"
        name_b = f"Policy ID {pol_b['id']} ({pol_b['name']})"
        act_a = pol_a["action"]
        act_b = pol_b["action"]
        combined = network_utils.combine_relations(list(relations.values()))
        info = {
            "reason": f"Policy A (ID {pol_a['id']}) berada sebelum Policy B (ID {pol_b['id']}) dalam urutan analisis.",
            "relations": {
                **self._relation_details(relations),
                "combined": combined,
            },
        }
        self._rule_pol_potentially_merge(pol_a, pol_b, act_a, act_b, relations, name_a, name_b, info)
        self._rule_pol_duplicate(pol_a, act_a, act_b, relations, name_b, info)
        self._rule_pol_shadowed(pol_a, act_a, act_b, relations, name_b, info)
        self._rule_pol_redundant(pol_a, pol_b, act_a, act_b, relations, name_a, name_b, info)
        self._rule_pol_conflict(pol_a, act_a, act_b, relations, name_b, info)

    def _check_policies_and_relationships(
        self,
        policies: List[Dict[str, Any]],
        address_map: Dict[str, network_utils.Scope],
        service_map: Dict[str, network_utils.Scope],
    ) -> List[Dict[str, Any]]:
        if not isinstance(policies, list):
            return []
        parsed = [
            prepared
            for pol in policies
            if (prepared := self._prepare_policy(pol, address_map, service_map)) is not None
        ]
        for idx_a, pol_a in enumerate(parsed[:-1]):
            for pol_b in parsed[idx_a + 1:]:
                relations = self._compare_policy_pair(pol_a, pol_b)
                if relations:
                    self._process_policy_pair(pol_a, pol_b, relations)
        return parsed

    def run_all_checks(
        self,
        policies,
        interfaces,
        addresses,
        services,
        policy_hits,
    ) -> Tuple[List[Finding], List[Dict[str, Any]]]:
        policies = policies if isinstance(policies, list) else []
        interfaces = interfaces if isinstance(interfaces, list) else []
        addresses = addresses if isinstance(addresses, list) else []
        services = services if isinstance(services, list) else []
        policy_hits = policy_hits if isinstance(policy_hits, list) else []
        address_map = network_utils.build_address_map(addresses)
        service_map = network_utils.build_service_map(services)
        parsed_policies = self._check_policies_and_relationships(policies, address_map, service_map)
        self._check_unused_policies(policies, policy_hits)
        self._check_interfaces(interfaces)
        self._check_address_objects(addresses)
        self._check_service_objects(services)
        return self.findings_to_create, parsed_policies
