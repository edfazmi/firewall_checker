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
TRAFFIC_DIMENSIONS = ("schedule", "source_interface", "destination_interface", "source_network", "destination_network", "service")
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
        result: List[str] = []
        for item in value:
            result.extend(_split_values(item))
        return result
    return [item.strip() for item in re.split(r"[,;\n]+", _clean_name(value)) if item.strip()]


def _parse_subnet(value: Any) -> Optional[Network]:
    text = _clean_name(value).replace("/", " ").split()
    if len(text) != 2:
        return None
    try:
        return ipaddress.IPv4Network(f"{text[0]}/{text[1]}", strict=False)
    except (ValueError, TypeError):
        return None


def _parse_ip(value: Any) -> Optional[ipaddress.IPv4Address]:
    try:
        return ipaddress.IPv4Address(_clean_name(value))
    except (ValueError, TypeError):
        return None


def _parse_ip_range(addr: Dict[str, Any]) -> List[Network]:
    pairs = [
        (addr.get("start-ip"), addr.get("end-ip")),
        (addr.get("start_ip"), addr.get("end_ip")),
        (addr.get("startip"), addr.get("endip")),
    ]
    start = end = None
    for raw_start, raw_end in pairs:
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


def _wildcard_fixed(base: int, wildcard: int) -> int:
    return (~wildcard) & 0xFFFFFFFF


def _wildcard_intersects(base_a: int, wildcard_a: int, base_b: int, wildcard_b: int) -> bool:
    fixed_a = _wildcard_fixed(base_a, wildcard_a)
    fixed_b = _wildcard_fixed(base_b, wildcard_b)
    common = fixed_a & fixed_b
    return (base_a & common) == (base_b & common)


def _wildcard_covers(base_a: int, wildcard_a: int, base_b: int, wildcard_b: int) -> bool:
    fixed_a = _wildcard_fixed(base_a, wildcard_a)
    fixed_b = _wildcard_fixed(base_b, wildcard_b)
    if (base_a & fixed_a) != (base_b & fixed_a):
        return False
    return (fixed_a & fixed_b) == fixed_a


def _wildcard_network_relation(base: int, wildcard: int, network: Network) -> Relation:
    network_base = int(network.network_address)
    network_wildcard = int(network.hostmask)
    return _relation_from_set_operations(
        _wildcard_covers(base, wildcard, network_base, network_wildcard),
        _wildcard_covers(network_base, network_wildcard, base, wildcard),
        _wildcard_intersects(base, wildcard, network_base, network_wildcard),
    )


def _wildcard_relation(base_a: int, wildcard_a: int, base_b: int, wildcard_b: int) -> Relation:
    return _relation_from_set_operations(
        _wildcard_covers(base_a, wildcard_a, base_b, wildcard_b),
        _wildcard_covers(base_b, wildcard_b, base_a, wildcard_a),
        _wildcard_intersects(base_a, wildcard_a, base_b, wildcard_b),
    )


def _relation_from_set_operations(a_covers_b: bool, b_covers_a: bool, intersects: bool) -> Relation:
    if a_covers_b and b_covers_a:
        return EXACT
    if a_covers_b:
        return SUPERSET
    if b_covers_a:
        return SUBSET
    if intersects:
        return OVERLAP
    return NONE


def _wildcard_to_networks(base: int, wildcard: int, limit: int = _WILDCARD_EXPANSION_LIMIT) -> List[Network]:
    variable_positions = [bit for bit in range(32) if wildcard & (1 << bit)]
    count = 1 << len(variable_positions)
    if count > limit:
        return []
    addresses = []
    fixed = base & _wildcard_fixed(base, wildcard)
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


def _fqdn_covers(value_a: str, value_b: str) -> bool:
    a = _canonical_domain(value_a)
    b = _canonical_domain(value_b)
    if not a or not b:
        return False
    if a == b:
        return True
    if a.startswith("*."):
        suffix = a[1:]
        return b.endswith(suffix) and b != suffix[1:]
    return False


def _fqdn_intersects(value_a: str, value_b: str) -> bool:
    a = _canonical_domain(value_a)
    b = _canonical_domain(value_b)
    if not a or not b:
        return False
    return _fqdn_covers(a, b) or _fqdn_covers(b, a)


def _fqdn_relation(value_a: str, value_b: str) -> Relation:
    return _relation_from_set_operations(
        _fqdn_covers(value_a, value_b),
        _fqdn_covers(value_b, value_a),
        _fqdn_intersects(value_a, value_b),
    )


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


def _group_members(obj: Dict[str, Any]) -> List[str]:
    members = obj.get("member", obj.get("members", obj.get("member-list", obj.get("member_list"))))
    if isinstance(members, (list, tuple, set)):
        result: List[str] = []
        for item in members:
            if isinstance(item, dict):
                value = item.get("name")
                if value is not None and _clean_name(value):
                    result.append(_clean_name(value))
            else:
                result.extend(_split_values(item))
        return result
    return _split_values(members)


def _is_address_group(obj: Dict[str, Any]) -> bool:
    obj_type = _lower(obj.get("type"))
    return obj_type in {"addrgrp", "address-group", "address_group", "group"} or any(
        key in obj for key in ("member", "members", "member-list", "member_list")
    ) and obj_type not in {"ipmask", "subnet", "interface-subnet", "iprange", "fqdn", "wildcard-fqdn", "geography", "wildcard", "mac", "ipam", "dynamic"}


def build_address_map(addresses: List[Dict[str, Any]]) -> Dict[str, Scope]:
    address_map: Dict[str, Scope] = {}
    if not isinstance(addresses, list):
        return address_map
    groups: List[Dict[str, Any]] = []
    for addr in addresses:
        if not isinstance(addr, dict):
            continue
        name = _clean_name(addr.get("name"))
        if not name:
            continue
        if _is_address_group(addr):
            groups.append(addr)
        else:
            address_map[name] = _scope_from_address(addr)
    pending = list(groups)
    for _ in range(len(groups) + 1):
        progressed = False
        remaining: List[Dict[str, Any]] = []
        for group in pending:
            name = _clean_name(group.get("name"))
            members = _group_members(group)
            if not members:
                remaining.append(group)
                continue
            atoms: List[Scope] = []
            resolved = True
            for member in members:
                scope = address_map.get(member)
                if scope is None:
                    lower_member = member.lower()
                    scope = next((value for key, value in address_map.items() if key.lower() == lower_member), None)
                if scope is None:
                    resolved = False
                    break
                atoms.extend(_flatten_scope(scope))
            if resolved and atoms:
                unique: List[Scope] = []
                seen: Set[str] = set()
                for atom in atoms:
                    key = repr(atom)
                    if key not in seen:
                        unique.append(atom)
                        seen.add(key)
                address_map[name] = _make_scope("atom-set", atoms=tuple(unique), name=name)
                progressed = True
            else:
                remaining.append(group)
        pending = remaining
        if not pending or not progressed:
            break
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
        if scope is None:
            scope = address_map.get(next((key for key in address_map if key.lower() == clean_name.lower()), ""))
        if scope is None:
            continue
        key = repr(scope)
        if key not in seen:
            scopes.append(scope)
            seen.add(key)
    return scopes


def _flatten_scope(scope: Scope) -> List[Scope]:
    if not isinstance(scope, dict):
        return []
    kind = scope.get("kind")
    if kind == "atom-set":
        return list(scope.get("atoms", ()))
    if kind == "network-set":
        return [_make_scope("network", net) for net in scope.get("value", ())]
    return [scope]


def _atom_intersection(atom_a: Scope, atom_b: Scope) -> bool:
    kind_a = atom_a.get("kind")
    kind_b = atom_b.get("kind")
    if kind_a == "network" and atom_a.get("value") == ipaddress.IPv4Network("0.0.0.0/0"):
        return True
    if kind_b == "network" and atom_b.get("value") == ipaddress.IPv4Network("0.0.0.0/0"):
        return True
    if kind_a == "network" and kind_b == "network":
        return atom_a["value"].overlaps(atom_b["value"])
    if kind_a == "network" and kind_b == "wildcard":
        return _wildcard_intersects(atom_b["value"][0], atom_b["value"][1], int(atom_a["value"].network_address), int(atom_a["value"].hostmask))
    if kind_a == "wildcard" and kind_b == "network":
        return _wildcard_intersects(atom_a["value"][0], atom_a["value"][1], int(atom_b["value"].network_address), int(atom_b["value"].hostmask))
    if kind_a == "wildcard" and kind_b == "wildcard":
        return _wildcard_intersects(*atom_a["value"], *atom_b["value"])
    if kind_a == "fqdn" and kind_b == "fqdn":
        return _fqdn_intersects(atom_a["value"], atom_b["value"])
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
    if kind_a == "network" and atom_a.get("value") == ipaddress.IPv4Network("0.0.0.0/0"):
        return True
    if kind_a == "network" and kind_b == "network":
        return atom_b["value"].subnet_of(atom_a["value"])
    if kind_a == "network" and kind_b == "wildcard":
        return _wildcard_covers(int(atom_a["value"].network_address), int(atom_a["value"].hostmask), *atom_b["value"])
    if kind_a == "wildcard" and kind_b == "network":
        return _wildcard_covers(*atom_a["value"], int(atom_b["value"].network_address), int(atom_b["value"].hostmask))
    if kind_a == "wildcard" and kind_b == "wildcard":
        return _wildcard_covers(*atom_a["value"], *atom_b["value"])
    if kind_a == "fqdn" and kind_b == "fqdn":
        return _fqdn_covers(atom_a["value"], atom_b["value"])
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


def _normalize_address_atoms(scopes: Iterable[Scope]) -> List[Scope]:
    atoms: List[Scope] = []
    for scope in scopes or ():
        if isinstance(scope, dict) and scope.get("kind") in {"atom-set", "network-set"}:
            atoms.extend(_flatten_scope(scope))
        elif isinstance(scope, dict):
            atoms.append(scope)
    if not atoms:
        return []
    networks = [atom["value"] for atom in atoms if atom.get("kind") == "network" and isinstance(atom.get("value"), ipaddress.IPv4Network)]
    countries: Set[str] = set()
    mac_ranges: List[Tuple[int, int]] = []
    other: List[Scope] = []
    for atom in atoms:
        kind = atom.get("kind")
        if kind == "network":
            continue
        if kind == "geography":
            countries.update(atom.get("value", ()))
            continue
        if kind == "mac" and isinstance(atom.get("value"), tuple) and len(atom["value"]) == 2:
            mac_ranges.append(tuple(atom["value"]))
            continue
        other.append(atom)
    normalized: List[Scope] = [_make_scope("network", net) for net in ipaddress.collapse_addresses(networks)]
    if countries:
        normalized.append(_make_scope("geography", tuple(sorted(countries))))
    if mac_ranges:
        mac_ranges.sort()
        merged: List[List[int]] = []
        for start, end in mac_ranges:
            if not merged or start > merged[-1][1] + 1:
                merged.append([start, end])
            else:
                merged[-1][1] = max(merged[-1][1], end)
        normalized.extend(_make_scope("mac", (start, end)) for start, end in merged)
    normalized.extend(other)
    unique: List[Scope] = []
    seen: Set[str] = set()
    for atom in normalized:
        key = repr(atom)
        if key not in seen:
            unique.append(atom)
            seen.add(key)
    return unique


def compare_address_scopes(scopes_a: Iterable[Scope], scopes_b: Iterable[Scope]) -> Relation:
    raw_a = tuple(scopes_a or ())
    raw_b = tuple(scopes_b or ())
    if not raw_a or not raw_b:
        return NONE
    if len(raw_a) == len(raw_b) and {repr(atom) for atom in raw_a} == {repr(atom) for atom in raw_b}:
        return EXACT
    a = _normalize_address_atoms(raw_a)
    b = _normalize_address_atoms(raw_b)
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
    intersects = any(_atom_intersection(atom_a, atom_b) for atom_a in a for atom_b in b)
    return _relation_from_set_operations(False, False, intersects)

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
    return list(ipaddress.collapse_addresses(valid)) if valid else []


def networks_intersect(nets_a: List[Network], nets_b: List[Network]) -> bool:
    a = normalize_networks(nets_a)
    b = normalize_networks(nets_b)
    return bool(a and b and any(net_a.overlaps(net_b) for net_a in a for net_b in b))


def compare_networks(nets_a: List[Network], nets_b: List[Network]) -> Relation:
    a = normalize_networks(nets_a)
    b = normalize_networks(nets_b)
    if not a or not b:
        return NONE
    a_covers_b = all(any(target.subnet_of(candidate) for candidate in a) for target in b)
    b_covers_a = all(any(target.subnet_of(candidate) for candidate in b) for target in a)
    return _relation_from_set_operations(a_covers_b, b_covers_a, networks_intersect(a, b))


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
    a_lower = {value.lower() for value in a}
    b_lower = {value.lower() for value in b}
    if a_lower == b_lower:
        return EXACT
    if has_univ_a and has_univ_b:
        return EXACT
    if has_univ_a:
        return SUPERSET
    if has_univ_b:
        return SUBSET
    a_covers_b = b_lower.issubset(a_lower)
    b_covers_a = a_lower.issubset(b_lower)
    if a_covers_b and b_covers_a:
        return EXACT
    if a_covers_b:
        return SUPERSET
    if b_covers_a:
        return SUBSET
    return _relation_from_set_operations(False, False, bool(a_lower.intersection(b_lower)))


def _parse_port_ranges(value: Any) -> List[Tuple[int, int]]:
    if value is None:
        return []
    if isinstance(value, (list, tuple, set)):
        values = []
        for item in value:
            values.extend(_parse_port_ranges(item))
        return _merge_ranges(values)
    result: List[Tuple[int, int]] = []
    text = _clean_name(value)
    if not text:
        return []
    for token in re.split(r"[,;\s]+", text):
        token = token.strip()
        if not token:
            continue
        token = token.split(":", 1)[0].strip()
        if not token:
            continue
        for part in token.split("/"):
            part = part.strip()
            if not part:
                continue
            if "-" in part:
                left, right = part.split("-", 1)
            else:
                left = right = part
            try:
                start = int(left)
                end = int(right)
            except (ValueError, TypeError):
                continue
            if 0 <= start <= 65535 and 0 <= end <= 65535:
                if start > end:
                    start, end = end, start
                result.append((start, end))
    return _merge_ranges(result)


def _merge_ranges(ranges: Iterable[Tuple[int, int]]) -> List[Tuple[int, int]]:
    valid: List[Tuple[int, int]] = []
    for start, end in ranges:
        try:
            start_int = int(start)
            end_int = int(end)
        except (TypeError, ValueError):
            continue
        if 0 <= start_int <= end_int <= 65535:
            valid.append((start_int, end_int))
    valid.sort()
    merged: List[List[int]] = []
    for start, end in valid:
        if not merged or start > merged[-1][1] + 1:
            merged.append([start, end])
        else:
            merged[-1][1] = max(merged[-1][1], end)
    return [(start, end) for start, end in merged]


def _protocol_tokens(service: Dict[str, Any]) -> Set[str]:
    values: Set[str] = set()
    for key in ("protocol", "protocols"):
        raw = service.get(key)
        for value in _split_values(raw):
            for token in re.split(r"[/\s,]+", _lower(value)):
                if token:
                    values.add(token)
    return values


def _protocol_number(service: Dict[str, Any]) -> Optional[int]:
    for key in ("protocol-number", "protocol_number"):
        raw = service.get(key)
        if raw in (None, ""):
            continue
        try:
            number = int(str(raw).strip())
        except (TypeError, ValueError):
            continue
        if 0 <= number <= 255:
            return number
    return None


def _service_protocols(service: Dict[str, Any]) -> Tuple[Set[str], bool]:
    tokens = _protocol_tokens(service)
    number = _protocol_number(service)
    tcp_ranges = _parse_port_ranges(service.get("tcp-portrange", service.get("tcp_portrange")))
    udp_ranges = _parse_port_ranges(service.get("udp-portrange", service.get("udp_portrange")))
    sctp_ranges = _parse_port_ranges(service.get("sctp-portrange", service.get("sctp_portrange")))
    aliases = {6: "tcp", 17: "udp", 132: "sctp", 1: "icmp", 58: "icmp6"}
    explicit = {token for token in tokens if token in {"tcp", "udp", "sctp", "icmp", "icmp6", "ip", "any", "all"}}
    ranged = set()
    if tcp_ranges:
        ranged.add("tcp")
    if udp_ranges:
        ranged.add("udp")
    if sctp_ranges:
        ranged.add("sctp")
    if number in aliases:
        explicit.add(aliases[number])
    if "any" in explicit or "all" in explicit or "ip" in explicit:
        return {"any"}, False
    web_aliases = {
        "http": "tcp",
        "https": "tcp",
        "ftp": "tcp",
        "connect": "tcp",
        "socks-tcp": "tcp",
        "socks-udp": "udp",
    }
    for token, protocol in web_aliases.items():
        if token in tokens:
            explicit.add(protocol)
    compound = len(explicit.intersection({"tcp", "udp", "sctp"})) > 1
    if ranged:
        if compound:
            protocols = ranged
        else:
            protocols = explicit.intersection({"tcp", "udp", "sctp"}) | ranged
    else:
        protocols = set(explicit)
    return protocols, compound


def _protocol_values(service: Dict[str, Any]) -> Set[str]:
    protocols, _ = _service_protocols(service)
    return protocols


def _service_scope_from_object(service: Dict[str, Any]) -> Scope:
    name = _clean_name(service.get("name"))
    protocols, compound = _service_protocols(service)
    tcp_ranges = _parse_port_ranges(service.get("tcp-portrange", service.get("tcp_portrange")))
    udp_ranges = _parse_port_ranges(service.get("udp-portrange", service.get("udp_portrange")))
    sctp_ranges = _parse_port_ranges(service.get("sctp-portrange", service.get("sctp_portrange")))
    atoms: List[Tuple[str, int, int]] = []
    if "any" in protocols:
        atoms.append(("any", 0, 65535))
    else:
        if "tcp" in protocols:
            if tcp_ranges:
                atoms.extend(("tcp", start, end) for start, end in tcp_ranges)
            elif not compound:
                atoms.append(("tcp", 0, 65535))
        if "udp" in protocols:
            if udp_ranges:
                atoms.extend(("udp", start, end) for start, end in udp_ranges)
            elif not compound:
                atoms.append(("udp", 0, 65535))
        if "sctp" in protocols:
            if sctp_ranges:
                atoms.extend(("sctp", start, end) for start, end in sctp_ranges)
            elif not compound:
                atoms.append(("sctp", 0, 65535))
        if "icmp" in protocols:
            atoms.append(("icmp", 0, 255))
        if "icmp6" in protocols:
            atoms.append(("icmp6", 0, 255))
        known = {"tcp", "udp", "sctp", "icmp", "icmp6", "any"}
        for protocol in protocols - known:
            atoms.append((protocol, 0, 65535))
    return _make_scope("service-set", atoms=tuple(sorted(set(atoms))), name=name)

def _is_service_group(service: Dict[str, Any]) -> bool:
    obj_type = _lower(service.get("type", service.get("category", "")))
    if obj_type in {"service-group", "service_group", "svcgrp", "group"}:
        return True
    return any(key in service for key in ("member", "members", "member-list", "member_list")) and not any(
        service.get(key) for key in ("tcp-portrange", "tcp_portrange", "udp-portrange", "udp_portrange", "sctp-portrange", "sctp_portrange")
    )


def build_service_map(services: List[Dict[str, Any]]) -> Dict[str, Scope]:
    service_map: Dict[str, Scope] = {}
    if not isinstance(services, list):
        return service_map
    groups: List[Dict[str, Any]] = []
    for service in services:
        if not isinstance(service, dict):
            continue
        name = _clean_name(service.get("name"))
        if not name:
            continue
        if _is_service_group(service):
            groups.append(service)
        else:
            service_map[name] = _service_scope_from_object(service)
    pending = list(groups)
    for _ in range(len(groups) + 1):
        progressed = False
        remaining: List[Dict[str, Any]] = []
        for group in pending:
            name = _clean_name(group.get("name"))
            members = _group_members(group)
            atoms: List[Tuple[str, int, int]] = []
            resolved = True
            for member in members:
                scope = service_map.get(member)
                if scope is None:
                    scope = service_map.get(next((key for key in service_map if key.lower() == member.lower()), ""))
                if scope is None:
                    resolved = False
                    break
                atoms.extend(_flatten_service_scope(scope))
            if members and resolved and atoms:
                service_map[name] = _make_scope("service-set", atoms=tuple(sorted(set(atoms))), name=name)
                progressed = True
            else:
                remaining.append(group)
        pending = remaining
        if not pending or not progressed:
            break
    return service_map

def _universal_service() -> Scope:
    return _make_scope("service-set", atoms=(("any", 0, 65535),), name="all")


def get_service_scopes_from_names(names: Iterable[str], service_map: Dict[str, Scope]) -> List[Scope]:
    if not isinstance(names, (list, tuple, set)) or not isinstance(service_map, dict):
        return []
    scopes: List[Scope] = []
    seen: Set[str] = set()
    for name in names:
        clean = _clean_name(name)
        if not clean:
            continue
        if clean.lower() == "all":
            scope = _universal_service()
        else:
            scope = service_map.get(clean)
            if scope is None:
                scope = service_map.get(next((key for key in service_map if key.lower() == clean.lower()), ""))
            if scope is None:
                continue
        key = repr(scope)
        if key not in seen:
            scopes.append(scope)
            seen.add(key)
    return scopes


def _flatten_service_scope(scope: Scope) -> List[Tuple[str, int, int]]:
    if not isinstance(scope, dict):
        return []
    return list(scope.get("atoms", ())) if scope.get("kind") == "service-set" else []


def _service_atom_intersection(atom_a: Tuple[str, int, int], atom_b: Tuple[str, int, int]) -> bool:
    protocol_a, start_a, end_a = atom_a
    protocol_b, start_b, end_b = atom_b
    if protocol_a != "any" and protocol_b != "any" and protocol_a != protocol_b:
        return False
    return max(start_a, start_b) <= min(end_a, end_b)


def _service_atom_covers(atom_a: Tuple[str, int, int], atom_b: Tuple[str, int, int]) -> bool:
    protocol_a, start_a, end_a = atom_a
    protocol_b, start_b, end_b = atom_b
    protocol_ok = protocol_a == "any" or protocol_a == protocol_b
    return protocol_ok and start_a <= start_b and end_b <= end_a


def _normalize_service_atoms(scopes: Iterable[Scope]) -> List[Tuple[str, int, int]]:
    atoms: List[Tuple[str, int, int]] = []
    for scope in scopes or ():
        if isinstance(scope, dict):
            if scope.get("kind") == "service-set":
                atoms.extend(_flatten_service_scope(scope))
            elif scope.get("kind") == "service-atom" and isinstance(scope.get("value"), tuple):
                atoms.append(scope["value"])
        elif isinstance(scope, tuple) and len(scope) == 3:
            atoms.append(scope)
    if not atoms:
        return []
    if any(protocol == "any" and start == 0 and end == 65535 for protocol, start, end in atoms):
        return [("any", 0, 65535)]
    grouped: Dict[str, List[Tuple[int, int]]] = {}
    for protocol, start, end in atoms:
        grouped.setdefault(str(protocol).lower(), []).append((int(start), int(end)))
    normalized: List[Tuple[str, int, int]] = []
    for protocol, ranges in grouped.items():
        for start, end in _merge_ranges(ranges):
            normalized.append((protocol, start, end))
    return sorted(set(normalized))


def compare_service_scopes(scopes_a: Iterable[Scope], scopes_b: Iterable[Scope]) -> Relation:
    raw_a = tuple(scopes_a or ())
    raw_b = tuple(scopes_b or ())
    if not raw_a or not raw_b:
        return NONE
    if len(raw_a) == len(raw_b) and {repr(atom) for atom in raw_a} == {repr(atom) for atom in raw_b}:
        return EXACT
    a = _normalize_service_atoms(raw_a)
    b = _normalize_service_atoms(raw_b)
    if not a or not b:
        return NONE
    a_covers_b = all(any(_service_atom_covers(atom_a, atom_b) for atom_a in a) for atom_b in b)
    b_covers_a = all(any(_service_atom_covers(atom_b, atom_a) for atom_b in b) for atom_a in a)
    if a_covers_b and b_covers_a:
        return EXACT
    if a_covers_b:
        return SUPERSET
    if b_covers_a:
        return SUBSET
    intersects = any(_service_atom_intersection(atom_a, atom_b) for atom_a in a for atom_b in b)
    return _relation_from_set_operations(False, False, intersects)

def compare_traffic_dimensions(
    src_intf_a: Iterable[str],
    src_intf_b: Iterable[str],
    dst_intf_a: Iterable[str],
    dst_intf_b: Iterable[str],
    src_addr_a: Iterable[Scope],
    src_addr_b: Iterable[Scope],
    dst_addr_a: Iterable[Scope],
    dst_addr_b: Iterable[Scope],
    svc_a: Iterable[Scope],
    svc_b: Iterable[Scope],
    schedule_a: Iterable[str] = ("always",),
    schedule_b: Iterable[str] = ("always",),
) -> Dict[str, Relation]:
    schedule = compare_sets(schedule_a, schedule_b, "always")
    if schedule == NONE:
        return {"schedule": NONE}
    source_interface = compare_sets(src_intf_a, src_intf_b, "any")
    if source_interface == NONE:
        return {"schedule": schedule, "source_interface": NONE}
    destination_interface = compare_sets(dst_intf_a, dst_intf_b, "any")
    if destination_interface == NONE:
        return {"schedule": schedule, "source_interface": source_interface, "destination_interface": NONE}
    source_network = compare_address_scopes(src_addr_a, src_addr_b)
    if source_network == NONE:
        return {
            "schedule": schedule,
            "source_interface": source_interface,
            "destination_interface": destination_interface,
            "source_network": NONE,
        }
    destination_network = compare_address_scopes(dst_addr_a, dst_addr_b)
    if destination_network == NONE:
        return {
            "schedule": schedule,
            "source_interface": source_interface,
            "destination_interface": destination_interface,
            "source_network": source_network,
            "destination_network": NONE,
        }
    service = compare_service_scopes(svc_a, svc_b)
    return {
        "schedule": schedule,
        "source_interface": source_interface,
        "destination_interface": destination_interface,
        "source_network": source_network,
        "destination_network": destination_network,
        "service": service,
    }


def traffic_intersects(relations: Dict[str, Relation]) -> bool:
    return all(relations.get(key) != NONE for key in TRAFFIC_DIMENSIONS)


def traffic_covers(relations: Dict[str, Relation]) -> bool:
    return all(relations.get(key) in {EXACT, SUPERSET} for key in TRAFFIC_DIMENSIONS)


def traffic_exact(relations: Dict[str, Relation]) -> bool:
    return all(relations.get(key) == EXACT for key in TRAFFIC_DIMENSIONS)


def extract_names(data: Any) -> Set[str]:
    if isinstance(data, str):
        return {item.strip() for item in re.split(r"[,;\n]+", data) if item.strip()}
    if not isinstance(data, (list, tuple, set)):
        return set()
    result: Set[str] = set()
    for item in data:
        if isinstance(item, dict):
            value = item.get("name")
        else:
            value = item
        if value is not None and str(value).strip():
            result.add(str(value).strip())
    return result


def combine_relations(rels: List[Relation]) -> Relation:
    if not isinstance(rels, (list, tuple)) or not rels:
        return NONE
    normalized = [_clean_name(rel).upper() for rel in rels]
    if any(rel not in VALID_RELATIONS for rel in normalized):
        return NONE
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
