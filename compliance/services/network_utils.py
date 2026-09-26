import ipaddress
from typing import List, Dict, Any, Set

def build_address_map(addresses: List[Dict[str, Any]]) -> Dict[str, Any]:
    address_map: Dict[str, Any] = {}
    if not isinstance(addresses, list):
        return address_map
    for addr in addresses:
        if not isinstance(addr, dict):
            continue
        name = str(addr.get("name", "")).strip()
        if not name:
            continue
        obj_type = str(addr.get("type", "ipmask")).strip().lower()
        subnet_str = str(addr.get("subnet", "0.0.0.0 0.0.0.0")).strip()
        if obj_type != "ipmask":
            address_map[name] = None
            continue
        try:
            parts = subnet_str.split()
            if len(parts) != 2:
                address_map[name] = None
                continue
            ip = parts[0]
            mask = parts[1]
            network = ipaddress.IPv4Network(f"{ip}/{mask}", strict=False)
            address_map[name] = network
        except (ValueError, TypeError):
            address_map[name] = None
    return address_map

def get_networks_from_names(names_list: List[str], address_map: Dict[str, Any]) -> List[ipaddress.IPv4Network]:
    networks: List[ipaddress.IPv4Network] = []
    if not isinstance(names_list, (list, tuple, set)):
        return networks
    if not isinstance(address_map, dict):
        return networks
    for name in names_list:
        if name is None:
            continue
        clean_name = str(name).strip()
        if not clean_name:
            continue
        if clean_name.lower() == "all":
            networks.append(ipaddress.IPv4Network("0.0.0.0/0"))
            continue
        network = address_map.get(clean_name)
        if network is None:
            continue
        if isinstance(network, ipaddress.IPv4Network):
            networks.append(network)
    return networks

def compare_networks(nets_a: List[ipaddress.IPv4Network], nets_b: List[ipaddress.IPv4Network]) -> str:
    if not nets_a or not nets_b:
        return "NONE"
    a_super_b = True
    for net_b in nets_b:
        covered_by_a = False
        for net_a in nets_a:
            try:
                if net_b.subnet_of(net_a):
                    covered_by_a = True
                    break
            except (TypeError, ValueError):
                continue
        if not covered_by_a:
            a_super_b = False
            break
    b_super_a = True
    for net_a in nets_a:
        covered_by_b = False
        for net_b in nets_b:
            try:
                if net_a.subnet_of(net_b):
                    covered_by_b = True
                    break
            except (TypeError, ValueError):
                continue
        if not covered_by_b:
            b_super_a = False
            break
    if a_super_b and b_super_a:
        return "EXACT"
    if a_super_b:
        return "SUPERSET"
    if b_super_a:
        return "SUBSET"
    for net_a in nets_a:
        for net_b in nets_b:
            try:
                if net_a.overlaps(net_b):
                    return "OVERLAP"
            except (TypeError, ValueError):
                continue
    return "NONE"

def compare_sets(set_a: set, set_b: set, univ_kw: str = "any") -> str:
    if not isinstance(set_a, (set, list, tuple)):
        return "NONE"
    if not isinstance(set_b, (set, list, tuple)):
        return "NONE"
    normalized_a: Set[str] = {str(value).strip() for value in set_a if value is not None and str(value).strip()}
    normalized_b: Set[str] = {str(value).strip() for value in set_b if value is not None and str(value).strip()}
    if not normalized_a or not normalized_b:
        return "NONE"
    universal = str(univ_kw).strip().lower()
    has_univ_a = any(value.lower() == universal for value in normalized_a)
    has_univ_b = any(value.lower() == universal for value in normalized_b)
    if has_univ_a and has_univ_b:
        return "EXACT"
    if has_univ_a:
        return "SUPERSET"
    if has_univ_b:
        return "SUBSET"
    a_sup_b = normalized_b.issubset(normalized_a)
    b_sup_a = normalized_a.issubset(normalized_b)
    if a_sup_b and b_sup_a:
        return "EXACT"
    if a_sup_b:
        return "SUPERSET"
    if b_sup_a:
        return "SUBSET"
    if normalized_a.intersection(normalized_b):
        return "OVERLAP"
    return "NONE"

def combine_relations(rels: List[str]) -> str:
    if not isinstance(rels, (list, tuple)):
        return "NONE"
    normalized_rels = []
    valid_relations = {"EXACT", "SUPERSET", "SUBSET", "OVERLAP", "NONE"}
    for rel in rels:
        if rel is None:
            return "NONE"
        relation = str(rel).strip().upper()
        if relation not in valid_relations:
            return "NONE"
        normalized_rels.append(relation)
    if not normalized_rels:
        return "NONE"
    if "NONE" in normalized_rels:
        return "NONE"
    if all(rel == "EXACT" for rel in normalized_rels):
        return "EXACT"
    if all(rel in {"EXACT", "SUPERSET"} for rel in normalized_rels):
        return "SUPERSET"
    if all(rel in {"EXACT", "SUBSET"} for rel in normalized_rels):
        return "SUBSET"
    return "OVERLAP"

def extract_names(data) -> set:
    if not data:
        return set()
    if not isinstance(data, list):
        return set()
    names = set()
    for item in data:
        if not isinstance(item, dict):
            continue
        name = str(item.get("name", "")).strip()
        if name:
            names.add(name)
    return names