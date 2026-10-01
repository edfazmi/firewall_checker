import ipaddress
import re
from typing import Any, Dict, Iterable, List, Optional, Set, Tuple

Relation = str
EXACT = "EXACT"
SUPERSET = "SUPERSET"
SUBSET = "SUBSET"
OVERLAP = "OVERLAP"
INCOMPARABLE = "INCOMPARABLE"
NONE = "NONE"
VALID_RELATIONS = {EXACT, SUPERSET, SUBSET, OVERLAP, INCOMPARABLE, NONE}
Network = ipaddress.IPv4Network
Scope = Dict[str, Any]
_WILDCARD_EXPANSION_LIMIT = 4096
_MAC_RE = re.compile(r"^[0-9a-f]{12}$")

def _clean_name(value: Any) -> str:
    return str(value).strip() if value is not None else ""

def _lower(value: Any) -> str:
    return _clean_name(value).lower()

def _split_values(value: Any) -> List[str]:
    if value is None:
        return []
    if isinstance(value, (list, tuple, set)):
        result = []
        for item in value:
            result.extend(_split_values(item))
        return result
    return [item.strip() for item in re.split(r"[,;\n]+", _clean_name(value)) if item.strip()]

def _parse_subnet(value: Any) -> Optional[Network]:
    parts = _clean_name(value).replace("/", " ").split()
    if len(parts) != 2:
        return None
    try:
        return ipaddress.IPv4Network(f"{parts[0]}/{parts[1]}", strict=False)
    except (ValueError, TypeError):
        return None

def _parse_ip(value: Any) -> Optional[ipaddress.IPv4Address]:
    try:
        return ipaddress.IPv4Address(_clean_name(value))
    except (ValueError, TypeError):
        return None

def _parse_ip_range(addr: Dict[str, Any]) -> List[Network]:
    candidates = [
        (addr.get("start-ip"), addr.get("end-ip")),
        (addr.get("start_ip"), addr.get("end_ip")),
        (addr.get("startip"), addr.get("endip")),
    ]
    start = end = None
    for raw_start, raw_end in candidates:
        start = _parse_ip(raw_start)
        end = _parse_ip(raw_end)
        if start is not None and end is not None:
            break
    if start is None or end is None:
        raw_range = addr.get("iprange", addr.get("ip-range", ""))
        text = _clean_name(raw_range).replace(" ", "")
        if "-" in text:
            left, right = text.split("-", 1)
            start = _parse_ip(left)
            end = _parse_ip(right)
    if start is None or end is None or int(start) > int(end):
        return []
    return list(ipaddress.summarize_address_range(start, end))

def _parse_wildcard(value: Any) -> Optional[Tuple[int, int]]:
    parts = _clean_name(value).replace("/", " ").split()
    if len(parts) != 2:
        return None
    try:
        return int(ipaddress.IPv4Address(parts[0])), int(ipaddress.IPv4Address(parts[1]))
    except (ValueError, TypeError):
        return None

def _wildcard_matches_ip(base: int, wildcard: int, ip_value: int) -> bool:
    fixed_mask = (~wildcard) & 0xFFFFFFFF
    return (ip_value & fixed_mask) == (base & fixed_mask)

def _wildcard_compatible_with_network(base: int, wildcard: int, network: Network) -> bool:
    fixed_mask = (~wildcard) & 0xFFFFFFFF
    common_fixed = fixed_mask & int(network.netmask)
    return (base & common_fixed) == (int(network.network_address) & common_fixed)

def _wildcard_network_relation(base: int, wildcard: int, network: Network) -> Relation:
    fixed_mask = (~wildcard) & 0xFFFFFFFF
    network_mask = int(network.netmask)
    network_host_mask = int(network.hostmask)
    if not _wildcard_compatible_with_network(base, wildcard, network):
        return NONE
    if wildcard == network_host_mask:
        return EXACT
    if fixed_mask & network_host_mask == 0:
        return SUBSET
    if network_mask & wildcard == 0:
        return SUPERSET
    return OVERLAP

def _wildcard_relation(base_a: int, wildcard_a: int, base_b: int, wildcard_b: int) -> Relation:
    fixed_a = (~wildcard_a) & 0xFFFFFFFF
    fixed_b = (~wildcard_b) & 0xFFFFFFFF
    common_fixed = fixed_a & fixed_b
    if (base_a & common_fixed) != (base_b & common_fixed):
        return NONE
    a_covers_b = (fixed_a & wildcard_b) == 0
    b_covers_a = (fixed_b & wildcard_a) == 0
    if a_covers_b and b_covers_a:
        return EXACT
    if a_covers_b:
        return SUPERSET
    if b_covers_a:
        return SUBSET
    return OVERLAP

def _wildcard_to_networks(base: int, wildcard: int, limit: int = _WILDCARD_EXPANSION_LIMIT) -> List[Network]:
    variable_positions = [bit for bit in range(32) if wildcard & (1 << bit)]
    count = 1 << len(variable_positions)
    if count > limit:
        return []
    addresses = []
    fixed = base & ((~wildcard) & 0xFFFFFFFF)
    for combination in range(count):
        value = fixed
        for index, bit in enumerate(variable_positions):
            if combination & (1 << index):
                value |= 1 << bit
        addresses.append(ipaddress.IPv4Address(value))
    return list(ipaddress.collapse_addresses(ipaddress.ip_network(f"{address}/32") for address in addresses))

def _normalize_mac(value: Any) -> Optional[int]:
    text = re.sub(r"[^0-9A-Fa-f]", "", _clean_name(value))
    if not _MAC_RE.fullmatch(text):
        return None
    return int(text, 16)

def _parse_mac_range(addr: Dict[str, Any]) -> Optional[Tuple[int, int]]:
    start = _normalize_mac(addr.get("start-mac", addr.get("start_mac")))
    end = _normalize_mac(addr.get("end-mac", addr.get("end_mac")))
    if start is None:
        start = _normalize_mac(addr.get("mac"))
    if end is None:
        end = start
    if start is None or end is None or start > end:
        return None
    return start, end

def _canonical_domain(value: Any) -> str:
    text = _lower(value).rstrip(".")
    if text.startswith("*."):
        return "*." + text[2:].strip(".")
    return text

def _fqdn_relation(value_a: str, value_b: str) -> Relation:
    a = _canonical_domain(value_a)
    b = _canonical_domain(value_b)
    if not a or not b:
        return NONE
    if a == b:
        return EXACT
    a_wild = a.startswith("*.")
    b_wild = b.startswith("*.")
    if a_wild and not b_wild:
        suffix = a[1:]
        return SUPERSET if b.endswith(suffix) and b != suffix[1:] else NONE
    if b_wild and not a_wild:
        suffix = b[1:]
        return SUBSET if a.endswith(suffix) and a != suffix[1:] else NONE
    if a_wild and b_wild:
        suffix_a = a[1:]
        suffix_b = b[1:]
        if suffix_b.endswith(suffix_a) and suffix_b != suffix_a:
            return SUPERSET
        if suffix_a.endswith(suffix_b) and suffix_a != suffix_b:
            return SUBSET
    return NONE

def _make_scope(kind: str, value: Any = None, **extra: Any) -> Scope:
    scope = {"kind": kind}
    if value is not None:
        scope["value"] = value
    scope.update(extra)
    return scope

def _scope_from_address(addr: Dict[str, Any]) -> Scope:
    obj_type = _lower(addr.get("type", "ipmask"))
    if obj_type in {"ipmask", "subnet", "interface-subnet"}:
        network = _parse_subnet(addr.get("subnet"))
        if network is not None:
            return _make_scope("network", network)
        return _make_scope("opaque", ("subnet", _clean_name(addr.get("name"))))
    if obj_type == "iprange":
        networks = _parse_ip_range(addr)
        if networks:
            return _make_scope("network-set", tuple(normalize_networks(networks)))
        return _make_scope("opaque", ("iprange", _clean_name(addr.get("name"))))
    if obj_type in {"fqdn", "wildcard-fqdn"}:
        values = _split_values(addr.get("fqdn") if obj_type == "fqdn" else addr.get("wildcard-fqdn"))
        if not values:
            values = _split_values(addr.get("fqdn")) or _split_values(addr.get("wildcard-fqdn"))
        atoms = [_make_scope("fqdn", _canonical_domain(value)) for value in values if _canonical_domain(value)]
        if atoms:
            return _make_scope("atom-set", atoms=tuple(atoms))
        return _make_scope("opaque", ("fqdn", _clean_name(addr.get("name"))))
    if obj_type == "geography":
        countries = {_lower(value) for value in _split_values(addr.get("country", addr.get("geography")))}
        if countries:
            return _make_scope("geography", tuple(sorted(countries)))
        return _make_scope("opaque", ("geography", _clean_name(addr.get("name"))))
    if obj_type == "wildcard":
        wildcard = _parse_wildcard(addr.get("wildcard"))
        if wildcard is not None:
            return _make_scope("wildcard", wildcard)
        return _make_scope("opaque", ("wildcard", _clean_name(addr.get("name"))))
    if obj_type == "mac":
        mac_range = _parse_mac_range(addr)
        if mac_range is not None:
            return _make_scope("mac", mac_range)
        return _make_scope("opaque", ("mac", _clean_name(addr.get("name"))))
    if obj_type == "ipam":
        network = _parse_subnet(addr.get("subnet"))
        if network is not None and network != ipaddress.IPv4Network("0.0.0.0/0"):
            return _make_scope("network", network)
        return _make_scope("opaque", ("ipam", _clean_name(addr.get("name"))))
    if obj_type == "dynamic":
        network = _parse_subnet(addr.get("subnet"))
        if network is not None and network != ipaddress.IPv4Network("0.0.0.0/0"):
            return _make_scope("network", network)
        identity = (
            _lower(addr.get("sub-type")),
            _lower(addr.get("obj-type")),
            _lower(addr.get("obj-tag")),
            _lower(addr.get("sdn")),
            _lower(addr.get("sdn-tag")),
            _lower(addr.get("interface")),
            _lower(addr.get("organization")),
            _lower(addr.get("tenant")),
        )
        return _make_scope("dynamic", identity)
    canonical = tuple(sorted((str(key), str(value).strip()) for key, value in addr.items() if key not in {"name", "uuid"} and value not in (None, "", [], {})))
    return _make_scope("opaque", (obj_type, canonical))

def build_address_map(addresses: List[Dict[str, Any]]) -> Dict[str, Scope]:
    address_map: Dict[str, Scope] = {}
    if not isinstance(addresses, list):
        return address_map
    for addr in addresses:
        if not isinstance(addr, dict):
            continue
        name = _clean_name(addr.get("name"))
        if name:
            address_map[name] = _scope_from_address(addr)
    return address_map

def _universal_scope() -> Scope:
    return _make_scope("network", ipaddress.IPv4Network("0.0.0.0/0"))

def get_address_scopes_from_names(names_list: Iterable[str], address_map: Dict[str, Scope]) -> List[Scope]:
    if not isinstance(address_map, dict):
        return []
    if not isinstance(names_list, (list, tuple, set)):
        return []
    scopes: List[Scope] = []
    seen: Set[str] = set()
    for name in names_list:
        clean_name = _clean_name(name)
        if not clean_name:
            continue
        if clean_name.lower() == "all":
            key = "network:0.0.0.0/0"
            if key not in seen:
                scopes.append(_universal_scope())
                seen.add(key)
            continue
        scope = address_map.get(clean_name)
        if not scope:
            continue
        key = repr(scope)
        if key not in seen:
            scopes.append(scope)
            seen.add(key)
    return scopes

def _flatten_scope(scope: Scope) -> List[Scope]:
    if not isinstance(scope, dict):
        return []
    if scope.get("kind") == "atom-set":
        return list(scope.get("atoms", ()))
    if scope.get("kind") == "network-set":
        return [_make_scope("network", net) for net in scope.get("value", ())]
    return [scope]

def _atom_intersection(atom_a: Scope, atom_b: Scope) -> bool:
    kind_a = atom_a.get("kind")
    kind_b = atom_b.get("kind")
    if kind_a == "network" and atom_a["value"] == ipaddress.IPv4Network("0.0.0.0/0"):
        return True
    if kind_b == "network" and atom_b["value"] == ipaddress.IPv4Network("0.0.0.0/0"):
        return True
    if kind_a == "network" and kind_b == "network":
        return atom_a["value"].overlaps(atom_b["value"])
    if kind_a == "network" and kind_b == "wildcard":
        return _wildcard_compatible_with_network(atom_b["value"][0], atom_b["value"][1], atom_a["value"])
    if kind_a == "wildcard" and kind_b == "network":
        return _wildcard_compatible_with_network(atom_a["value"][0], atom_a["value"][1], atom_b["value"])
    if kind_a == "wildcard" and kind_b == "wildcard":
        return _wildcard_relation(*atom_a["value"], *atom_b["value"]) != NONE
    if kind_a == "fqdn" and kind_b == "fqdn":
        return _fqdn_relation(atom_a["value"], atom_b["value"]) != NONE
    if kind_a == "geography" and kind_b == "geography":
        return bool(set(atom_a["value"]).intersection(atom_b["value"]))
    if kind_a == "mac" and kind_b == "mac":
        start_a, end_a = atom_a["value"]
        start_b, end_b = atom_b["value"]
        return max(start_a, start_b) <= min(end_a, end_b)
    if kind_a == "dynamic" and kind_b == "dynamic":
        return atom_a["value"] == atom_b["value"]
    if kind_a == "opaque" and kind_b == "opaque":
        return atom_a["value"] == atom_b["value"]
    return False

def _atom_covers(atom_a: Scope, atom_b: Scope) -> bool:
    kind_a = atom_a.get("kind")
    kind_b = atom_b.get("kind")
    if kind_a == "network" and atom_a["value"] == ipaddress.IPv4Network("0.0.0.0/0"):
        return True
    if kind_a == "network" and kind_b == "network":
        return atom_b["value"].subnet_of(atom_a["value"])
    if kind_a == "network" and kind_b == "wildcard":
        relation = _wildcard_network_relation(atom_b["value"][0], atom_b["value"][1], atom_a["value"])
        return relation in {SUPERSET, EXACT}
    if kind_a == "wildcard" and kind_b == "network":
        relation = _wildcard_network_relation(atom_a["value"][0], atom_a["value"][1], atom_b["value"])
        return relation in {SUBSET, EXACT}
    if kind_a == "wildcard" and kind_b == "wildcard":
        return _wildcard_relation(*atom_a["value"], *atom_b["value"]) in {EXACT, SUPERSET}
    if kind_a == "fqdn" and kind_b == "fqdn":
        return _fqdn_relation(atom_a["value"], atom_b["value"]) in {EXACT, SUPERSET}
    if kind_a == "geography" and kind_b == "geography":
        return set(atom_b["value"]).issubset(atom_a["value"])
    if kind_a == "mac" and kind_b == "mac":
        start_a, end_a = atom_a["value"]
        start_b, end_b = atom_b["value"]
        return start_a <= start_b and end_b <= end_a
    if kind_a == "dynamic" and kind_b == "dynamic":
        return atom_a["value"] == atom_b["value"]
    if kind_a == "opaque" and kind_b == "opaque":
        return atom_a["value"] == atom_b["value"]
    return False

def compare_address_scopes(scopes_a: Iterable[Scope], scopes_b: Iterable[Scope]) -> Relation:
    a: List[Scope] = []
    b: List[Scope] = []
    if isinstance(scopes_a, (list, tuple, set)):
        for scope in scopes_a:
            a.extend(_flatten_scope(scope))
    if isinstance(scopes_b, (list, tuple, set)):
        for scope in scopes_b:
            b.extend(_flatten_scope(scope))
    if not a or not b:
        return NONE
    a_covers_b = all(any(_atom_covers(atom_a, atom_b) for atom_a in a) for atom_b in b)
    b_covers_a = all(any(_atom_covers(atom_b, atom_a) for atom_b in b) for atom_a in a)
    if a_covers_b and b_covers_a:
        return EXACT
    if a_covers_b:
        return SUPERSET
    if b_covers_a:
        return SUBSET
    if any(_atom_intersection(atom_a, atom_b) for atom_a in a for atom_b in b):
        return OVERLAP
    return NONE

def get_networks_from_names(names_list: Iterable[str], address_map: Dict[str, Scope]) -> List[Network]:
    scopes = get_address_scopes_from_names(names_list, address_map)
    networks: List[Network] = []
    for scope in scopes:
        for atom in _flatten_scope(scope):
            if atom.get("kind") == "network":
                networks.append(atom["value"])
            elif atom.get("kind") == "wildcard":
                networks.extend(_wildcard_to_networks(*atom["value"]))
    return normalize_networks(networks)

def normalize_networks(networks: Iterable[Network]) -> List[Network]:
    if not isinstance(networks, (list, tuple, set)):
        return []
    valid = [net for net in networks if isinstance(net, ipaddress.IPv4Network)]
    if not valid:
        return []
    return list(ipaddress.collapse_addresses(valid))

def _covers_all(source: List[Network], targets: List[Network]) -> bool:
    if not source or not targets:
        return False
    return all(any(target.subnet_of(candidate) for candidate in source) for target in targets)

def networks_intersect(nets_a: List[Network], nets_b: List[Network]) -> bool:
    a = normalize_networks(nets_a)
    b = normalize_networks(nets_b)
    if not a or not b:
        return False
    return any(net_a.overlaps(net_b) for net_a in a for net_b in b)

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
    return {str(value).strip() for value in values if value is not None and str(value).strip()}

def _has_universal(values: Set[str], universal: str) -> bool:
    return universal in {value.lower() for value in values}

def sets_intersect(set_a: Iterable[str], set_b: Iterable[str], univ_kw: str = "any") -> bool:
    a = normalize_names(set_a)
    b = normalize_names(set_b)
    if not a or not b:
        return False
    universal = _clean_name(univ_kw).lower()
    if _has_universal(a, universal) or _has_universal(b, universal):
        return True
    return bool({value.lower() for value in a}.intersection(value.lower() for value in b))

def compare_sets(set_a: Iterable[str], set_b: Iterable[str], univ_kw: str = "any") -> Relation:
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
    return {str(item.get("name")).strip() for item in data if isinstance(item, dict) and item.get("name") is not None and str(item.get("name")).strip()}