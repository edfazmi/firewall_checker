import ipaddress
from typing import Any, Dict, Iterable, List, Optional, Set, Tuple, Union

Relation = str

EXACT = "EXACT"
SUPERSET = "SUPERSET"
SUBSET = "SUBSET"
OVERLAP = "OVERLAP"
INCOMPARABLE = "INCOMPARABLE"
NONE = "NONE"

VALID_RELATIONS = {EXACT, SUPERSET, SUBSET, OVERLAP, INCOMPARABLE, NONE}

Network = ipaddress.IPv4Network


def _clean_name(value: Any) -> str:
    return str(value).strip() if value is not None else ""


def build_address_map(addresses: List[Dict[str, Any]]) -> Dict[str, Optional[Network]]:
    address_map: Dict[str, Optional[Network]] = {}

    if not isinstance(addresses, list):
        return address_map

    for addr in addresses:
        if not isinstance(addr, dict):
            continue

        name = _clean_name(addr.get("name"))
        if not name:
            continue

        obj_type = _clean_name(addr.get("type", "ipmask")).lower()
        if obj_type != "ipmask":
            address_map[name] = None
            continue

        subnet_value = addr.get("subnet", "0.0.0.0 0.0.0.0")
        parts = str(subnet_value).strip().split()
        if len(parts) != 2:
            address_map[name] = None
            continue

        try:
            address_map[name] = ipaddress.IPv4Network(
                f"{parts[0]}/{parts[1]}",
                strict=False,
            )
        except (ValueError, TypeError):
            address_map[name] = None

    return address_map


def get_networks_from_names(
    names_list: Iterable[str],
    address_map: Dict[str, Optional[Network]],
) -> List[Network]:
    if not isinstance(address_map, dict):
        return []

    if not isinstance(names_list, (list, tuple, set)):
        return []

    networks: List[Network] = []
    seen: Set[Network] = set()
    all_network = ipaddress.IPv4Network("0.0.0.0/0")

    for name in names_list:
        clean_name = _clean_name(name)
        if not clean_name:
            continue

        if clean_name.lower() == "all":
            if all_network not in seen:
                networks.append(all_network)
                seen.add(all_network)
            continue

        network = address_map.get(clean_name)
        if isinstance(network, ipaddress.IPv4Network) and network not in seen:
            networks.append(network)
            seen.add(network)

    return networks


def normalize_networks(networks: Iterable[Network]) -> List[Network]:
    if not isinstance(networks, (list, tuple, set)):
        return []

    valid = [
        net for net in networks
        if isinstance(net, ipaddress.IPv4Network)
    ]

    if not valid:
        return []

    return list(ipaddress.collapse_addresses(valid))


def _covers_all(source: List[Network], targets: List[Network]) -> bool:
    if not source or not targets:
        return False

    for target in targets:
        if not any(target.subnet_of(candidate) for candidate in source):
            return False
    return True


def networks_intersect(nets_a: List[Network], nets_b: List[Network]) -> bool:
    a = normalize_networks(nets_a)
    b = normalize_networks(nets_b)

    if not a or not b:
        return False

    for net_a in a:
        for net_b in b:
            if net_a.overlaps(net_b):
                return True
    return False


def compare_networks(nets_a: List[Network], nets_b: List[Network]) -> Relation:
    a = normalize_networks(nets_a)
    b = normalize_networks(nets_b)

    if not a or not b:
        return NONE

    a_covers_b = _covers_all(a, b)
    b_covers_a = _covers_all(b, a)

    if a_covers_b and b_covers_a:
        return EXACT
    if a_covers_b:
        return SUPERSET
    if b_covers_a:
        return SUBSET
    if networks_intersect(a, b):
        return OVERLAP
    return NONE


def normalize_names(values: Iterable[Any]) -> Set[str]:
    if not isinstance(values, (set, list, tuple)):
        return set()
    return {
        str(value).strip()
        for value in values
        if value is not None and str(value).strip()
    }


def _has_universal(values: Set[str], universal: str) -> bool:
    return universal in {value.lower() for value in values}


def sets_intersect(
    set_a: Iterable[str],
    set_b: Iterable[str],
    univ_kw: str = "any",
) -> bool:
    a = normalize_names(set_a)
    b = normalize_names(set_b)
    if not a or not b:
        return False

    universal = _clean_name(univ_kw).lower()
    if _has_universal(a, universal) or _has_universal(b, universal):
        return True

    return bool({value.lower() for value in a}.intersection(value.lower() for value in b))


def compare_sets(
    set_a: Iterable[str],
    set_b: Iterable[str],
    univ_kw: str = "any",
) -> Relation:
    a = normalize_names(set_a)
    b = normalize_names(set_b)

    if not a or not b:
        return NONE

    universal = _clean_name(univ_kw).lower()
    has_univ_a = _has_universal(a, universal)
    has_univ_b = _has_universal(b, universal)

    if has_univ_a and has_univ_b:
        return EXACT
    if has_univ_a:
        return SUPERSET
    if has_univ_b:
        return SUBSET

    a_lower = {value.lower() for value in a}
    b_lower = {value.lower() for value in b}

    a_covers_b = b_lower.issubset(a_lower)
    b_covers_a = a_lower.issubset(b_lower)

    if a_covers_b and b_covers_a:
        return EXACT
    if a_covers_b:
        return SUPERSET
    if b_covers_a:
        return SUBSET
    if a_lower.intersection(b_lower):
        return OVERLAP
    return NONE


def combine_relations(rels: List[Relation]) -> Relation:
    if not isinstance(rels, (list, tuple)) or not rels:
        return NONE

    normalized: List[Relation] = []
    for rel in rels:
        relation = _clean_name(rel).upper()
        if relation not in VALID_RELATIONS:
            return NONE
        normalized.append(relation)

    if NONE in normalized:
        return NONE
    if all(rel == EXACT for rel in normalized):
        return EXACT
    if all(rel in {EXACT, SUPERSET} for rel in normalized):
        return SUPERSET
    if all(rel in {EXACT, SUBSET} for rel in normalized):
        return SUBSET

    if OVERLAP in normalized:
        return OVERLAP

    return INCOMPARABLE


def extract_names(data: Any) -> Set[str]:
    if not isinstance(data, list):
        return set()

    names: Set[str] = set()
    for item in data:
        if not isinstance(item, dict):
            continue
        name = _clean_name(item.get("name"))
        if name:
            names.add(name)
    return names