from datetime import datetime
import time
from typing import Any, Dict, List, Optional, Tuple
from django.utils import timezone
from compliance.models import Finding
from . import network_utils

class RuleEngine:
    def __init__(self, scan_record, active_rules: Dict[str, Any], finding_sink=None, finding_batch_size: int = 500, pair_batch_size: int = 250, pair_batch_pause: float = 0.05):
        self.scan_record = scan_record
        self.active_rules = active_rules or {}
        self.finding_sink = finding_sink
        self.finding_batch_size = max(1, int(finding_batch_size or 500))
        self.pair_batch_size = max(1, int(pair_batch_size or 250))
        self.pair_batch_pause = max(0.0, float(pair_batch_pause or 0.0))
        self.findings_to_create: List[Finding] = []
        self.risk_index: Dict[str, Dict[str, Any]] = {}

    def _add_finding(self, rule_code: str, element_name: str, details: Dict[str, Any]) -> None:
        rule = self.active_rules.get(rule_code)
        if not rule:
            return
        finding = Finding(
            scan=self.scan_record,
            rule=rule,
            element_name=element_name,
            element_details=details,
        )
        self.findings_to_create.append(finding)
        risk = self.risk_index.setdefault(
            element_name,
            {"factors": [], "severities": []},
        )
        rule_name = getattr(rule, "name", rule_code)
        severity = str(getattr(rule, "severity", "INFO")).upper()
        if rule_name not in risk["factors"]:
            risk["factors"].append(rule_name)
        risk["severities"].append(severity)
        if self.finding_sink and len(self.findings_to_create) >= self.finding_batch_size:
            self.flush_findings()

    def flush_findings(self) -> None:
        if not self.finding_sink or not self.findings_to_create:
            return
        batch = self.findings_to_create
        self.findings_to_create = []
        self.finding_sink(batch)

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
        raw_last_used = None
        for key in ("last_used", "last-used", "last_hit", "last-hit", "last_hit_time", "last-hit-time", "last_used_time", "last-used-time"):
            if hit_data.get(key) not in (None, ""):
                raw_last_used = hit_data.get(key)
                break
        if hit_count == 0 and self._parse_last_used(raw_last_used) is None:
            self._add_finding(
                "POL_UNUSED",
                f"Policy ID {pol_id} ({pol.get('name', '')})",
                {
                    "message": "Policy aktif tidak memiliki catatan penggunaan yang tersedia dan counter hit bernilai 0.",
                    "hit_count": 0,
                    "last_used": "N/A",
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
            "schedule": relations.get("schedule", "NONE"),
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
        if network_utils.traffic_exact(relations):
            return
        if not network_utils.traffic_covers(relations):
            return
        self._add_finding(
            "POL_SHADOWED",
            target_b_name,
            {
                **info_json,
                "message": f"Policy B tertimpa oleh Policy ID {pol_a['id']} yang berada lebih awal dan mencakup seluruh trafik Policy B dengan action berbeda.",
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
        covering_relations = {
            relations.get("source_interface"),
            relations.get("destination_interface"),
            relations.get("source_network"),
            relations.get("destination_network"),
            relations.get("service"),
        }
        if covering_relations.issubset({network_utils.EXACT, network_utils.SUPERSET}) and not network_utils.traffic_exact(relations):
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
        if not network_utils.traffic_intersects(relations):
            return
        if network_utils.traffic_exact(relations):
            conflict_type = "EXACT_SCOPE_DIFFERENT_ACTION"
            message = f"Policy memiliki cakupan trafik identik dengan action berbeda dari Policy ID {pol_a['id']}."
        elif network_utils.traffic_covers(relations):
            return
        elif all(
            relation in {network_utils.EXACT, network_utils.SUBSET}
            for relation in relations.values()
        ):
            return
        else:
            conflict_type = "PARTIAL_OVERLAP_DIFFERENT_ACTION"
            message = f"Policy memiliki sebagian cakupan trafik yang beririsan dengan action berbeda dari Policy ID {pol_a['id']} tanpa hubungan cakupan penuh antara kedua policy."
        self._add_finding(
            "POL_CONFLICT",
            target_b_name,
            {
                **info_json,
                "message": message,
                "related_policy_id": pol_a["id"],
                "related_policy_name": pol_a["name"],
                "conflict_type": conflict_type,
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
            relations.get("schedule") == network_utils.EXACT
            and relations.get("source_interface") == network_utils.EXACT
            and relations.get("destination_interface") == network_utils.EXACT
        ):
            return
        network_relations = {
            relations.get("source_network"),
            relations.get("destination_network"),
        }
        if network_utils.NONE in network_relations:
            return
        if not network_relations.issubset({
            network_utils.EXACT,
            network_utils.SUPERSET,
            network_utils.SUBSET,
            network_utils.OVERLAP,
        }):
            return
        service_relation = relations.get("service")
        if service_relation not in {
            network_utils.SUPERSET,
            network_utils.SUBSET,
            network_utils.OVERLAP,
            network_utils.NONE,
        }:
            return
        self._add_finding(
            "POL_POTENTIALLY_MERGE",
            target_b_name,
            {
                **info_json,
                "message": "Berpotensi digabung. Interface sama, cakupan Source dan Destination identik, saling mencakup, atau beririsan, sedangkan cakupan service berbeda atau beririsan.",
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

    def _parse_last_used(self, value: Any) -> Optional[datetime]:
        if value in (None, ""):
            return None
        if isinstance(value, datetime):
            return value
        text = str(value).strip()
        if not text:
            return None
        candidates = [text, text.replace("Z", "+00:00")]
        for candidate in candidates:
            try:
                parsed = datetime.fromisoformat(candidate)
                if parsed.tzinfo is None:
                    parsed = timezone.make_aware(parsed, timezone.get_current_timezone())
                return parsed
            except ValueError:
                continue
        return None

    def _rule_pol_not_used_1month(self, pol: Dict[str, Any], pol_id: str, hit_dict: Dict[str, Dict[str, Any]]) -> None:
        if "POL_NOT_USED_1MONTH" not in self.active_rules or not self._policy_enabled(pol):
            return
        hit_data = hit_dict.get(pol_id)
        if not isinstance(hit_data, dict):
            return
        raw_last_used = None
        for key in ("last_used", "last-used", "last_hit", "last-hit", "last_hit_time", "last-hit-time", "last_used_time", "last-used-time"):
            if hit_data.get(key) not in (None, ""):
                raw_last_used = hit_data.get(key)
                break
        last_used = self._parse_last_used(raw_last_used)
        if last_used is None:
            return
        if last_used.tzinfo is None:
            last_used = timezone.make_aware(last_used, timezone.get_current_timezone())
        elapsed = timezone.now() - last_used
        if elapsed.total_seconds() >= 30 * 24 * 60 * 60:
            self._add_finding(
                "POL_NOT_USED_1MONTH",
                f"Policy ID {pol_id} ({pol.get('name', '')})",
                {
                    "message": "Policy aktif tidak digunakan selama minimal 30 hari berdasarkan waktu terakhir digunakan.",
                    "last_used": str(raw_last_used),
                    "elapsed_days": round(elapsed.total_seconds() / 86400, 2),
                },
            )

    def _check_unused_policies(self, policies: List[Dict[str, Any]], policy_hits: List[Dict[str, Any]]) -> None:
        if not isinstance(policies, list):
            return
        if not any(code in self.active_rules for code in ("POL_UNUSED", "POL_NOT_USED_1MONTH")):
            return
        hit_dict = {
            str(hit["policyid"]): hit
            for hit in policy_hits
            if isinstance(hit, dict) and hit.get("policyid") is not None
        }
        for pol in policies:
            if not isinstance(pol, dict):
                continue
            pol_id = self._policy_id(pol)
            self._rule_pol_unused(pol, pol_id, hit_dict)
            self._rule_pol_not_used_1month(pol, pol_id, hit_dict)

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

    @staticmethod
    def _value_enabled(value: Any) -> bool:
        if value is None:
            return False
        if isinstance(value, bool):
            return value
        if isinstance(value, (list, tuple, set, dict)):
            return bool(value)
        text = str(value).strip().lower()
        return text not in {"", "0", "false", "no", "off", "disable", "disabled", "none", "null"}

    @classmethod
    def _unsupported_relational_features(cls, pol: Dict[str, Any]) -> List[str]:
        reasons: List[str] = []
        negate_fields = ("srcaddr-negate", "srcaddr_negate", "dstaddr-negate", "dstaddr_negate", "service-negate", "service_negate")
        for key in negate_fields:
            if key in pol and cls._value_enabled(pol.get(key)):
                reasons.append(key)
        ipv6_fields = ("srcaddr6", "srcaddr6-negate", "srcaddr6_negate", "dstaddr6", "dstaddr6-negate", "dstaddr6_negate", "ipv6")
        for key in ipv6_fields:
            if key in pol and cls._value_enabled(pol.get(key)):
                reasons.append(key)
        ip_version = str(pol.get("ip-version", pol.get("ip_version", ""))).strip().lower()
        if ip_version in {"6", "ipv6", "ipv6-only"}:
            reasons.append("ip-version")
        unsupported_fields = (
            "internet-service",
            "internet-service-name",
            "internet-service-src",
            "internet-service-dst",
            "application-list",
            "application_list",
            "users",
            "groups",
            "fsso-groups",
            "fsso_groups",
        )
        for key in unsupported_fields:
            if key in pol and cls._value_enabled(pol.get(key)):
                reasons.append(key)
        return sorted(set(reasons))

    @staticmethod
    def _schedule_names(pol: Dict[str, Any]) -> set:
        schedule = network_utils.extract_names(pol.get("schedule"))
        return schedule or {"always"}

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
        schedule = self._schedule_names(pol)
        src_scopes = network_utils.get_address_scopes_from_names(src_addrs, address_map)
        dst_scopes = network_utils.get_address_scopes_from_names(dst_addrs, address_map)
        svc_scopes = network_utils.get_service_scopes_from_names(services, service_map)
        unsupported = self._unsupported_relational_features(pol)
        if not src_intf or not dst_intf or not src_scopes or not dst_scopes or not svc_scopes:
            unsupported.append("unresolved-traffic-scope")
        target_name = f"Policy ID {pol_id} ({pol_name})"
        self._rule_pol_no_desc(pol, target_name)
        self._rule_pol_no_log(pol, target_name)
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
            "schedule": schedule,
            "src_scopes": src_scopes,
            "dst_scopes": dst_scopes,
            "svc_scopes": svc_scopes,
            "src_atoms": tuple(atom for scope in src_scopes for atom in network_utils._flatten_scope(scope)),
            "dst_atoms": tuple(atom for scope in dst_scopes for atom in network_utils._flatten_scope(scope)),
            "svc_atoms": tuple(atom for scope in svc_scopes for atom in network_utils._flatten_service_scope(scope)),
            "raw": pol,
            "relational_supported": not unsupported,
            "unsupported_relational_features": unsupported,
        }

    @staticmethod
    def _compare_policy_pair(pol_a: Dict[str, Any], pol_b: Dict[str, Any]) -> Optional[Dict[str, str]]:
        if not pol_a.get("relational_supported", False) or not pol_b.get("relational_supported", False):
            return None
        relations = network_utils.compare_traffic_dimensions(
            pol_a["src_intf"],
            pol_b["src_intf"],
            pol_a["dst_intf"],
            pol_b["dst_intf"],
            pol_a.get("src_atoms", pol_a["src_scopes"]),
            pol_b.get("src_atoms", pol_b["src_scopes"]),
            pol_a.get("dst_atoms", pol_a["dst_scopes"]),
            pol_b.get("dst_atoms", pol_b["dst_scopes"]),
            pol_a.get("svc_atoms", pol_a["svc_scopes"]),
            pol_b.get("svc_atoms", pol_b["svc_scopes"]),
            pol_a["schedule"],
            pol_b["schedule"],
        )
        if relations.get("schedule") == network_utils.NONE:
            return None
        for key in ("source_interface", "destination_interface", "source_network", "destination_network"):
            if relations.get(key) == network_utils.NONE:
                return None
        if relations.get("service") == network_utils.NONE:
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
        pair_count = 0
        for idx_a, pol_a in enumerate(parsed[:-1]):
            if not pol_a.get("relational_supported"):
                continue
            for pol_b in parsed[idx_a + 1:]:
                if not pol_b.get("relational_supported"):
                    continue
                relations = self._compare_policy_pair(pol_a, pol_b)
                if relations:
                    self._process_policy_pair(pol_a, pol_b, relations)
                pair_count += 1
                if pair_count % self.pair_batch_size == 0:
                    self.flush_findings()
                    if self.pair_batch_pause > 0:
                        time.sleep(self.pair_batch_pause)
        self.flush_findings()
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
        self.flush_findings()
        return self.findings_to_create, parsed_policies