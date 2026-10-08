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
            self._add_finding(
                "INTF_DOWN",
                f"Interface {intf_name}",
                {
                    "message": f"Interface {intf_name} berstatus DOWN sehingga tidak aktif meneruskan trafik.",
                    "interface": intf,
                    "status": status,
                },
            )

    def _rule_intf_no_ip(self, intf: Dict[str, Any], intf_name: str, status: str) -> None:
        if "INTF_NO_IP" not in self.active_rules or status != "up":
            return
        raw_ip = intf.get("ip", intf.get("ipv4", intf.get("address")))
        if raw_ip is None:
            return
        if isinstance(raw_ip, (list, tuple, set)):
            values = [str(value).strip() for value in raw_ip if str(value).strip()]
            ip_text = values[0] if values else ""
        else:
            ip_text = str(raw_ip).strip()
        if not ip_text:
            self._add_finding(
                "INTF_NO_IP",
                f"Interface {intf_name}",
                {
                    "message": f"Interface {intf_name} berstatus UP tetapi tidak memiliki alamat IP yang terkonfigurasi.",
                    "interface": intf,
                    "ip": None,
                },
            )
            return
        first_value = ip_text.replace("/", " ").split()[0]
        if first_value == "0.0.0.0":
            self._add_finding(
                "INTF_NO_IP",
                f"Interface {intf_name}",
                {
                    "message": f"Interface {intf_name} berstatus UP tetapi alamat IP yang terdeteksi adalah 0.0.0.0.",
                    "interface": intf,
                    "ip": ip_text,
                },
            )

    def _rule_addr_dup_subnet(self, addr_name: str, subnet_key: str, subnets_seen: Dict[str, str]) -> None:
        if "ADDR_DUP_SUBNET" not in self.active_rules:
            return
        previous_name = subnets_seen.get(subnet_key)
        if previous_name:
            self._add_finding(
                "ADDR_DUP_SUBNET",
                f"Address {addr_name}",
                {
                    "message": f"Address {addr_name} menggunakan subnet {subnet_key} yang sama dengan Address {previous_name}.",
                    "conflict_with": previous_name,
                    "subnet": subnet_key,
                },
            )
        else:
            subnets_seen[subnet_key] = addr_name

    def _rule_svc_wide_port(self, svc: Dict[str, Any], svc_name: str) -> None:
        if "SVC_WIDE_PORT" not in self.active_rules:
            return
        ranges = []
        for key in ("tcp-portrange", "tcp_portrange", "udp-portrange", "udp_portrange", "sctp-portrange", "sctp_portrange"):
            ranges.extend(network_utils._parse_port_ranges(svc.get(key)))
        wide_ranges = [
            (start, end)
            for start, end in ranges
            if (start == 0 and end == 65535) or (start == 1 and end == 65535)
        ]
        if wide_ranges:
            protocols = []
            for key, protocol in (
                ("tcp-portrange", "TCP"),
                ("tcp_portrange", "TCP"),
                ("udp-portrange", "UDP"),
                ("udp_portrange", "UDP"),
                ("sctp-portrange", "SCTP"),
                ("sctp_portrange", "SCTP"),
            ):
                if network_utils._parse_port_ranges(svc.get(key)):
                    protocols.append(protocol)
            protocols = sorted(set(protocols))
            protocol_text = ", ".join(protocols) if protocols else "protocol tidak diketahui"
            range_text = ", ".join(f"{start}-{end}" for start, end in wide_ranges)
            self._add_finding(
                "SVC_WIDE_PORT",
                f"Service {svc_name}",
                {
                    "message": f"Service {svc_name} membuka seluruh port {range_text} pada {protocol_text} sehingga cakupan port sangat luas.",
                    "wide_port_ranges": wide_ranges,
                    "protocols": protocols,
                    "service": svc,
                },
            )

    def _rule_pol_no_desc(self, pol: Dict[str, Any], target_name: str) -> None:
        if "POL_NO_DESC" in self.active_rules and not str(pol.get("comments") or "").strip():
            self._add_finding(
                "POL_NO_DESC",
                target_name,
                {
                    "message": f"{target_name} tidak memiliki deskripsi pada field comments.",
                },
            )

    def _rule_pol_overly_permissive(self, src_addrs: set, dst_addrs: set, target_name: str) -> None:
        if "POL_OVERLY_PERMISSIVE" not in self.active_rules:
            return
        problems = []
        src_all = sorted({str(addr).strip() for addr in src_addrs if str(addr).strip().lower() == "all"}, key=str.lower)
        dst_all = sorted({str(addr).strip() for addr in dst_addrs if str(addr).strip().lower() == "all"}, key=str.lower)
        if src_all:
            problems.append(f"Source [{', '.join(src_all)}]")
        if dst_all:
            problems.append(f"Destination [{', '.join(dst_all)}]")
        if not problems:
            return
        self._add_finding(
            "POL_OVERLY_PERMISSIVE",
            target_name,
            {
                "message": f"{target_name} memiliki cakupan address sangat luas pada {' dan '.join(problems)}.",
                "problematic_addresses": problems,
            },
        )

    def _rule_pol_any_intf(self, src_intf_set: set, dst_intf_set: set, target_name: str) -> None:
        if "POL_ANY_INTF" not in self.active_rules:
            return
        problems = []
        src_any = sorted({str(value).strip() for value in src_intf_set if str(value).strip().lower() == "any"}, key=str.lower)
        dst_any = sorted({str(value).strip() for value in dst_intf_set if str(value).strip().lower() == "any"}, key=str.lower)
        if src_any:
            problems.append(f"Source Interface [{', '.join(src_any)}]")
        if dst_any:
            problems.append(f"Destination Interface [{', '.join(dst_any)}]")
        if not problems:
            return
        self._add_finding(
            "POL_ANY_INTF",
            target_name,
            {
                "message": f"{target_name} menggunakan interface ANY pada {' dan '.join(problems)}, sehingga cakupan interface menjadi sangat luas.",
                "problematic_interfaces": problems,
            },
        )

    def _rule_pol_any_svc(self, services_set: set, target_name: str) -> None:
        if "POL_ANY_SVC" not in self.active_rules:
            return
        any_services = sorted({str(service).strip() for service in services_set if str(service).strip().lower() == "all"}, key=str.lower)
        if not any_services:
            return
        self._add_finding(
            "POL_ANY_SVC",
            target_name,
            {
                "message": f"{target_name} menggunakan Service [{', '.join(any_services)}] sehingga mencakup seluruh service.",
                "problematic_services": any_services,
            },
        )

    def _rule_pol_unused(self, pol: Dict[str, Any], pol_id: str, hit_dict: Dict[str, Dict[str, Any]]) -> None:
        if "POL_UNUSED" not in self.active_rules or not self._policy_enabled(pol):
            return
        hit_data = hit_dict.get(pol_id)
        if not isinstance(hit_data, dict):
            return
        raw_hit_count = None
        for key in ("hit_count", "hit-count", "packets"):
            if key in hit_data and hit_data.get(key) not in (None, ""):
                raw_hit_count = hit_data.get(key)
                break
        if raw_hit_count is None:
            return
        try:
            hit_count = int(str(raw_hit_count).strip())
        except (TypeError, ValueError):
            return
        if hit_count < 0:
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
                    "message": f"Policy ID {pol_id} ({pol.get('name', '')}) aktif, tetapi counter hit bernilai 0 dan tidak memiliki waktu penggunaan terakhir yang valid.",
                    "hit_count": 0,
                    "last_used": "N/A",
                },
            )

    def _rule_pol_no_log(self, pol: Dict[str, Any], target_name: str) -> None:
        if "POL_NO_LOG" not in self.active_rules:
            return
        raw_log_status = pol.get("logtraffic", "disable")
        log_status = str(raw_log_status).strip().lower()
        if log_status in {"disable", "", "none", "false", "disabled", "0", "off", "no"}:
            self._add_finding(
                "POL_NO_LOG",
                target_name,
                {
                    "message": f"{target_name} tidak mengaktifkan logging; nilai logtraffic terdeteksi sebagai [{raw_log_status}].",
                    "logtraffic_value": raw_log_status,
                },
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

    @staticmethod
    def _compact_names(values: Any, limit: int = 4) -> str:
        if isinstance(values, (set, list, tuple)):
            items = sorted({str(value).strip() for value in values if str(value).strip()}, key=str.lower)
        else:
            text = str(values).strip()
            items = [text] if text else []
        if not items:
            return "-"
        if len(items) <= limit:
            return ", ".join(items)
        return f"{', '.join(items[:limit])}, +{len(items) - limit} lainnya"

    @classmethod
    def _dimension_label(cls, dimension: str) -> str:
        return {
            "schedule": "Schedule",
            "source_interface": "Source Interface",
            "destination_interface": "Destination Interface",
            "source_network": "Source",
            "destination_network": "Destination",
            "service": "Service",
        }.get(dimension, dimension)

    @classmethod
    def _dimension_values(cls, pol: Dict[str, Any], dimension: str) -> Any:
        mapping = {
            "schedule": "schedule",
            "source_interface": "src_intf",
            "destination_interface": "dst_intf",
            "source_network": "src_addrs",
            "destination_network": "dst_addrs",
            "service": "services",
        }
        return pol.get(mapping[dimension], set())

    @classmethod
    def _format_relation_detail(
        cls,
        pol_a: Dict[str, Any],
        pol_b: Dict[str, Any],
        dimension: str,
        relation: str,
    ) -> Optional[str]:
        if relation == network_utils.EXACT:
            return None
        label = cls._dimension_label(dimension)
        values_a = cls._compact_names(cls._dimension_values(pol_a, dimension))
        values_b = cls._compact_names(cls._dimension_values(pol_b, dimension))
        if relation == network_utils.SUBSET:
            return f"{label}: cakupan Policy A [{values_a}] lebih sempit dan tercakup oleh Policy B [{values_b}]"
        if relation == network_utils.SUPERSET:
            return f"{label}: cakupan Policy A [{values_a}] lebih luas dan mencakup Policy B [{values_b}]"
        if relation == network_utils.OVERLAP:
            return f"{label}: cakupan Policy A [{values_a}] beririsan dengan Policy B [{values_b}]"
        return None

    @classmethod
    def _format_exact_details(cls, pol_a: Dict[str, Any], relations: Dict[str, Any]) -> List[str]:
        details = []
        for dimension in network_utils.TRAFFIC_DIMENSIONS:
            if relations.get(dimension) != network_utils.EXACT:
                continue
            label = cls._dimension_label(dimension)
            values = cls._compact_names(cls._dimension_values(pol_a, dimension))
            details.append(f"{label}: [{values}]")
        return details

    @classmethod
    def _format_shadow_details(
        cls,
        pol_a: Dict[str, Any],
        pol_b: Dict[str, Any],
        relations: Dict[str, Any],
        full_scope: bool,
    ) -> List[str]:
        details = []
        for dimension in network_utils.TRAFFIC_DIMENSIONS:
            relation = relations.get(dimension, network_utils.NONE)
            label = cls._dimension_label(dimension)
            values_a = cls._compact_names(cls._dimension_values(pol_a, dimension))
            values_b = cls._compact_names(cls._dimension_values(pol_b, dimension))
            if relation == network_utils.SUPERSET:
                details.append(f"{label}: [{values_a}] mencakup [{values_b}]")
            elif relation == network_utils.OVERLAP:
                details.append(f"{label}: [{values_a}] beririsan dengan [{values_b}]")
            elif relation == network_utils.SUBSET and not full_scope:
                details.append(f"{label}: bagian [{values_a}] beririsan dengan cakupan [{values_b}]")
        return details

    @classmethod
    def _format_conflict_details(
        cls,
        pol_a: Dict[str, Any],
        pol_b: Dict[str, Any],
        relations: Dict[str, Any],
        exact_overlap: bool,
    ) -> List[str]:
        details = []
        for dimension in network_utils.TRAFFIC_DIMENSIONS:
            relation = relations.get(dimension, network_utils.NONE)
            if exact_overlap and relation == network_utils.EXACT:
                label = cls._dimension_label(dimension)
                values = cls._compact_names(cls._dimension_values(pol_a, dimension))
                details.append(f"{label}: [{values}]")
            elif not exact_overlap and relation in {
                network_utils.SUBSET,
                network_utils.SUPERSET,
                network_utils.OVERLAP,
            } and relation != network_utils.EXACT:
                detail = cls._format_relation_detail(pol_a, pol_b, dimension, relation)
                if detail:
                    details.append(detail)
        return details

    @classmethod
    def _redundancy_scope_details(
        cls,
        pol_a: Dict[str, Any],
        pol_b: Dict[str, Any],
        relations: Dict[str, str],
    ) -> List[str]:
        details: List[str] = []
        for dimension in network_utils.TRAFFIC_DIMENSIONS:
            relation = relations.get(dimension)
            if relation not in {network_utils.SUBSET, network_utils.SUPERSET}:
                continue
            label = cls._dimension_label(dimension)
            values_a = cls._compact_names(cls._dimension_values(pol_a, dimension))
            values_b = cls._compact_names(cls._dimension_values(pol_b, dimension))
            if relation == network_utils.SUBSET:
                details.append(f"{label}: [{values_a}] tercakup oleh [{values_b}]")
            else:
                details.append(f"{label}: [{values_a}] mencakup [{values_b}]")
        return details

    def _rule_pol_duplicate(
        self,
        pol_a: Dict[str, Any],
        action_a: str,
        action_b: str,
        relations: Dict[str, str],
        target_b_name: str,
        info_json: Dict[str, Any],
    ) -> None:
        if "POL_DUPLICATE" not in self.active_rules or action_a != action_b:
            return
        if not network_utils.traffic_exact(relations):
            return
        details = self._format_exact_details(pol_a, relations)
        message = (
            f"Policy ini merupakan duplikasi penuh dari Policy ID {pol_a['id']} ({pol_a['name']}) "
            f"dengan action yang sama ({action_a.upper()})."
        )
        if details:
            message += " Cakupan yang identik: " + "; ".join(details) + "."
        self._add_finding(
            "POL_DUPLICATE",
            target_b_name,
            {
                **info_json,
                "message": message,
                "related_policy_id": pol_a["id"],
                "related_policy_name": pol_a["name"],
                "duplicate_dimensions": details,
            },
        )

    def _rule_pol_shadowed(
        self,
        pol_a: Dict[str, Any],
        pol_b: Dict[str, Any],
        action_a: str,
        action_b: str,
        relations: Dict[str, Any],
        target_b_name: str,
        info_json: Dict[str, Any],
    ) -> None:
        if "POL_SHADOWED" not in self.active_rules or action_a == action_b:
            return
        profile = relations.get("_traffic_profile") or {}
        if profile.get("conflict_overlap") or not profile.get("b_specific_overlap"):
            return
        full_scope = network_utils.traffic_covers(relations)
        shadow_type = "FULL_SCOPE" if full_scope else "PARTIAL_SCOPE"
        scope_word = "seluruh" if full_scope else "sebagian"
        message = (
            f"{scope_word.capitalize()} trafik Policy ID {pol_b['id']} ({pol_b['name']}) "
            f"tertimpa oleh Policy ID {pol_a['id']} ({pol_a['name']}) yang berada lebih awal. "
            f"Action berbeda: Policy ID {pol_a['id']} = {action_a.upper()}, Policy ID {pol_b['id']} = {action_b.upper()}."
        )
        details = self._format_shadow_details(pol_a, pol_b, relations, full_scope)
        if details:
            message += " Penyebab cakupan: " + "; ".join(details) + "."
        self._add_finding(
            "POL_SHADOWED",
            target_b_name,
            {
                **info_json,
                "message": message,
                "related_policy_id": pol_a["id"],
                "related_policy_name": pol_a["name"],
                "shadow_type": shadow_type,
                "shadow_dimensions": details,
            },
        )

    def _rule_pol_redundant(
        self,
        pol_a: Dict[str, Any],
        pol_b: Dict[str, Any],
        action_a: str,
        action_b: str,
        relations: Dict[str, Any],
        target_a_name: str,
        target_b_name: str,
        info_json: Dict[str, Any],
        intermediate_policies: Optional[List[Dict[str, Any]]] = None,
    ) -> Optional[str]:
        if "POL_REDUNDANT" not in self.active_rules or action_a != action_b:
            return None
        if network_utils.traffic_exact(relations):
            return None
        if network_utils.traffic_covers(relations):
            redundant_name = target_b_name
            message_prefix = (
                f"Policy ID {pol_b['id']} ({pol_b['name']}) dapat dipertimbangkan dihapus karena "
                f"seluruh trafiknya sudah dicakup Policy ID {pol_a['id']} ({pol_a['name']}) "
                f"yang berada lebih awal dengan action yang sama ({action_a.upper()})."
            )
            direction = "LATER_POLICY_COVERED_BY_EARLIER"
        elif network_utils.traffic_is_subset(relations):
            blocked = False
            if intermediate_policies:
                for middle in intermediate_policies:
                    if middle.get("action") == action_a:
                        continue
                    middle_relations = self._compare_policy_pair(pol_a, middle)
                    if middle_relations:
                        blocked = True
                        break
            if blocked:
                return None
            redundant_name = target_a_name
            message_prefix = (
                f"Policy ID {pol_a['id']} ({pol_a['name']}) dapat dipertimbangkan dihapus karena "
                f"seluruh trafiknya sudah dicakup Policy ID {pol_b['id']} ({pol_b['name']}) "
                f"yang berada lebih akhir dengan action yang sama ({action_a.upper()})."
            )
            direction = "EARLIER_POLICY_COVERED_BY_LATER"
        else:
            return None
        details = self._redundancy_scope_details(pol_a, pol_b, relations)
        message = message_prefix
        if details:
            message += " Penyebab cakupan: " + "; ".join(details) + "."
        self._add_finding(
            "POL_REDUNDANT",
            redundant_name,
            {
                **info_json,
                "message": message,
                "related_policy_id": pol_b["id"] if direction == "EARLIER_POLICY_COVERED_BY_LATER" else pol_a["id"],
                "related_policy_name": pol_b["name"] if direction == "EARLIER_POLICY_COVERED_BY_LATER" else pol_a["name"],
                "redundancy_direction": direction,
                "redundant_policy_id": pol_a["id"] if direction == "EARLIER_POLICY_COVERED_BY_LATER" else pol_b["id"],
                "redundant_policy_name": pol_a["name"] if direction == "EARLIER_POLICY_COVERED_BY_LATER" else pol_b["name"],
                "redundant_dimensions": details,
            },
        )
        return direction

    def _rule_pol_conflict(
        self,
        pol_a: Dict[str, Any],
        pol_b: Dict[str, Any],
        action_a: str,
        action_b: str,
        relations: Dict[str, Any],
        target_b_name: str,
        info_json: Dict[str, Any],
    ) -> None:
        if "POL_CONFLICT" not in self.active_rules or action_a == action_b:
            return
        profile = relations.get("_traffic_profile") or {}
        if not profile.get("conflict_overlap"):
            return
        exact_overlap = bool(profile.get("exact_overlap"))
        if exact_overlap:
            conflict_type = "EXACT_SCOPE_DIFFERENT_ACTION"
        elif profile.get("mixed_specificity_overlap"):
            conflict_type = "MIXED_SPECIFICITY_OVERLAP"
        else:
            conflict_type = "PARTIAL_OVERLAP_DIFFERENT_ACTION"
        details = self._format_conflict_details(
            pol_a,
            pol_b,
            relations,
            exact_overlap,
        )
        message = (
            f"Policy ID {pol_b['id']} ({pol_b['name']}) memiliki konflik dengan "
            f"Policy ID {pol_a['id']} ({pol_a['name']}) karena action berbeda: "
            f"Policy A = {action_a.upper()}, Policy B = {action_b.upper()}."
        )
        if details:
            message += " Bagian yang menyebabkan irisan: " + "; ".join(details) + "."
        self._add_finding(
            "POL_CONFLICT",
            target_b_name,
            {
                **info_json,
                "message": message,
                "related_policy_id": pol_a["id"],
                "related_policy_name": pol_a["name"],
                "conflict_type": conflict_type,
                "conflict_dimensions": details,
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
        required_exact = (
            "schedule",
            "source_interface",
            "destination_interface",
            "source_network",
            "destination_network",
        )
        if not all(relations.get(key) == network_utils.EXACT for key in required_exact):
            return
        if relations.get("service") != network_utils.OVERLAP:
            return
        service_a = self._compact_names(pol_a.get("services", set()))
        service_b = self._compact_names(pol_b.get("services", set()))
        message = (
            f"Policy ID {pol_a['id']} ({pol_a['name']}) dan Policy ID {pol_b['id']} ({pol_b['name']}) "
            f"memiliki action yang sama ({action_a.upper()}) dan cakupan Source, Destination, "
            f"Interface, serta Schedule yang identik. Perbedaan yang menyebabkan potensi merge "
            f"terdapat pada Service: Policy A [{service_a}] dan Policy B [{service_b}] beririsan."
        )
        self._add_finding(
            "POL_POTENTIALLY_MERGE",
            target_b_name,
            {
                **info_json,
                "message": message,
                "related_policy_id": pol_a["id"],
                "related_policy_name": pol_a["name"],
                "merge_with_policy_id": pol_b["id"],
                "merge_with_policy_name": pol_b["name"],
                "service_relationship": relations.get("service"),
                "service_policy_a": service_a,
                "service_policy_b": service_b,
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
                status = str(intf.get("link", intf.get("link-status", ""))).strip().lower()
            if status not in {"up", "down"}:
                continue
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
        try:
            numeric = float(text)
            if numeric >= 0:
                return datetime.fromtimestamp(numeric, tz=timezone.get_current_timezone())
        except (TypeError, ValueError, OverflowError, OSError):
            pass
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
            elapsed_days = round(elapsed.total_seconds() / 86400, 2)
            self._add_finding(
                "POL_NOT_USED_1MONTH",
                f"Policy ID {pol_id} ({pol.get('name', '')})",
                {
                    "message": f"Policy ID {pol_id} ({pol.get('name', '')}) aktif tetapi tidak digunakan selama {elapsed_days} hari sejak penggunaan terakhir.",
                    "last_used": str(raw_last_used),
                    "elapsed_days": elapsed_days,
                },
            )

    def _check_unused_policies(self, policies: List[Dict[str, Any]], policy_hits: List[Dict[str, Any]]) -> None:
        if not isinstance(policies, list):
            return
        if not any(code in self.active_rules for code in ("POL_UNUSED", "POL_NOT_USED_1MONTH")):
            return
        hit_dict = {}
        for hit in policy_hits:
            if not isinstance(hit, dict):
                continue
            raw_id = hit.get("policyid", hit.get("policy-id"))
            if raw_id is not None and str(raw_id).strip():
                hit_dict[str(raw_id).strip()] = hit
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
            "src_addrs": src_addrs,
            "dst_addrs": dst_addrs,
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
    def _compare_policy_pair(pol_a: Dict[str, Any], pol_b: Dict[str, Any]) -> Optional[Dict[str, Any]]:
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
        profile = network_utils.traffic_overlap_profile(
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
        if not profile.get("intersects"):
            return None
        relations["_traffic_profile"] = profile
        return relations

    def _process_policy_pair(
        self,
        pol_a: Dict[str, Any],
        pol_b: Dict[str, Any],
        relations: Dict[str, str],
        intermediate_policies: Optional[List[Dict[str, Any]]] = None,
    ) -> None:
        name_a = f"Policy ID {pol_a['id']} ({pol_a['name']})"
        name_b = f"Policy ID {pol_b['id']} ({pol_b['name']})"
        act_a = pol_a["action"]
        act_b = pol_b["action"]
        combined = network_utils.combine_relations(
            [relations.get(key, network_utils.NONE) for key in network_utils.TRAFFIC_DIMENSIONS]
        )
        info = {
            "reason": f"Policy A (ID {pol_a['id']}) berada sebelum Policy B (ID {pol_b['id']}) dalam urutan analisis.",
            "relations": {
                **self._relation_details(relations),
                "combined": combined,
            },
        }
        self._rule_pol_potentially_merge(pol_a, pol_b, act_a, act_b, relations, name_a, name_b, info)
        self._rule_pol_duplicate(pol_a, act_a, act_b, relations, name_b, info)
        self._rule_pol_shadowed(pol_a, pol_b, act_a, act_b, relations, name_b, info)
        self._rule_pol_redundant(pol_a, pol_b, act_a, act_b, relations, name_a, name_b, info, intermediate_policies)
        self._rule_pol_conflict(pol_a, pol_b, act_a, act_b, relations, name_b, info)

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
            for idx_b in range(idx_a + 1, len(parsed)):
                pol_b = parsed[idx_b]
                if not pol_b.get("relational_supported"):
                    continue
                relations = self._compare_policy_pair(pol_a, pol_b)
                if relations:
                    self._process_policy_pair(pol_a, pol_b, relations, parsed[idx_a + 1:idx_b])
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
