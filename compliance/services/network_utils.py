import ipaddress
from typing import List, Dict, Any, Set

def build_address_map(addresses: List[Dict[str, Any]]) -> Dict[str, Any]:
    address_map = {}
    for addr in addresses:
        name = str(addr.get('name', '')).strip()
        obj_type = addr.get('type', 'ipmask')
        subnet_str = addr.get('subnet', '0.0.0.0 0.0.0.0')
        if obj_type == 'ipmask':
            try:
                ip, mask = subnet_str.split(' ')
                if ip == '0.0.0.0' and mask == '0.0.0.0':
                    address_map[name] = ipaddress.IPv4Network('0.0.0.0/0')
                else:
                    address_map[name] = ipaddress.IPv4Network(f"{ip}/{mask}", strict=False)
            except ValueError:
                address_map[name] = None 
        else:
            address_map[name] = None
    return address_map

def get_networks_from_names(names_list: List[str], address_map: Dict[str, Any]) -> List[ipaddress.IPv4Network]:
    networks = []
    for name in names_list:
        if name.lower() == 'all':
            networks.append(ipaddress.IPv4Network('0.0.0.0/0'))
        elif name in address_map and address_map[name] is not None:
            networks.append(address_map[name])
    return networks

def compare_networks(nets_a: List[ipaddress.IPv4Network], nets_b: List[ipaddress.IPv4Network]) -> str:
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

def compare_sets(set_a: set, set_b: set, univ_kw: str = 'any') -> str:
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

def combine_relations(rels: List[str]) -> str:
    if 'NONE' in rels: return 'NONE'
    if all(r == 'EXACT' for r in rels): return 'EXACT'
    if all(r in ['SUPERSET', 'EXACT'] for r in rels): return 'SUPERSET'
    if all(r in ['SUBSET', 'EXACT'] for r in rels): return 'SUBSET'
    return 'OVERLAP'

def extract_names(data) -> set:
    if not data or not isinstance(data, list): return set()
    return set([str(item.get('name', '')).strip() for item in data if isinstance(item, dict)])