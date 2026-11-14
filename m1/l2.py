"""Bounded-time correlation candidates; no assertion of attacker identity."""
import re
from collections import Counter, defaultdict
from datetime import datetime
from urllib.parse import urlparse


def normalized_route(value):
    path = urlparse(str(value or '')).path
    path = re.sub(r'/[0-9]+(?=/|$)', '/{id}', path)
    return re.sub(r'/[0-9a-fA-F]{8}-[0-9a-fA-F-]{27,}(?=/|$)', '/{uuid}', path)


def family(event):
    rules = set(event.get('rule_hits', []))
    if rules & {'scanner', 'multi_path_scan'}: return 'reconnaissance'
    if rules & {'sql_injection', 'xss', 'path_traversal', 'command_injection', 'java_deserialization', 'file_inclusion', 'file_upload', 'csrf'}:
        return 'web_exploitation'
    return 'ioc' if 'ioc_match' in rules else 'unclassified'


def identity(event):
    # Never infer the same actor solely from a shared proxy/NAT address.
    return (event.get('src_ip'), event.get('victim_asset_id') or event.get('dst_ip'),
            event.get('protocol'), event.get('dst_port'), event.get('domain'),
            event.get('session_id') if event.get('source_identity_shared') else None)


def time_groups(events, key_for, seconds):
    """Data-anchored bounded windows, independent of wall-clock boundaries."""
    if seconds <= 0: raise ValueError('correlation window must be positive')
    groups = defaultdict(list)
    for event in events:
        if not event.get('timestamp') or not event.get('src_ip') or not event.get('dst_ip'):
            yield key_for(event), [event]
            continue
        groups[key_for(event)].append(event)
    for key, items in groups.items():
        items.sort(key=lambda item: datetime.fromisoformat(item['timestamp']))
        current, start = [], None
        for item in items:
            stamp = datetime.fromisoformat(item['timestamp']).timestamp()
            if current and stamp - start > seconds:
                yield key, current
                current = []
            if not current: start = stamp
            current.append(item)
        if current: yield key, current


SENSITIVE = re.compile(r'(?:^|/)(?:\.env(?:\.|/|$)|\.git(?:/|$)|wp-admin(?:/|$)|wp-login\.php$|phpmyadmin(?:/|$)|actuator(?:/|$)|server-status$|etc/passwd$|web\.config$)', re.I)


def detect_scans(events, config):
    """Sliding window on accepted events before filtering/aggregation.

    Mark the union of qualifying intervals in linear time after sorting.
    Numeric product IDs, ordinary browsing and shared exits are conservative.
    """
    seconds = int(config.get('scan_window_seconds', 60))
    minimum = int(config.get('scan_min_unique_paths', 5))
    sensitive_min = int(config.get('scan_min_sensitive_paths', 2))
    if seconds <= 0 or minimum < 2 or sensitive_min < 1:
        raise ValueError('invalid scan thresholds')
    groups = defaultdict(list)
    shared = set(config.get('shared_egress_ips', []))
    for event in events:
        path = normalized_route(event.get('url_path'))
        if not path or not event.get('timestamp') or not event.get('src_ip') or not event.get('dst_ip'):
            continue
        key = (event['src_ip'], event['dst_ip'], event.get('protocol'), event.get('dst_port'), event.get('domain'),
               event.get('src_port') if event['src_ip'] in shared else None)
        if event['src_ip'] in shared and event.get('src_port') is None: continue
        groups[key].append((datetime.fromisoformat(event['timestamp']).timestamp(), path, event))
    for rows in groups.values():
        rows.sort(key=lambda row: row[0])
        counts, sensitive = Counter(), Counter()
        delta = [0] * (len(rows) + 1)
        left = 0
        for right, (stamp, path, _) in enumerate(rows):
            counts[path] += 1
            if SENSITIVE.search(path): sensitive[path] += 1
            while rows[left][0] < stamp - seconds:
                old = rows[left][1]
                counts[old] -= 1
                if not counts[old]: del counts[old]
                if old in sensitive:
                    sensitive[old] -= 1
                    if not sensitive[old]: del sensitive[old]
                left += 1
            if len(counts) >= minimum and len(sensitive) >= sensitive_min:
                delta[left] += 1
                delta[right + 1] -= 1
        active = 0
        for i, (_, _, event) in enumerate(rows):
            active += delta[i]
            if not active: continue
            event['rule_hits'] = sorted(set(event.get('rule_hits', [])) | {'multi_path_scan'})
            event.setdefault('evidence', []).append({'type': 'behavior', 'name': 'multi_path_scan',
                'window_seconds': seconds, 'min_unique_paths': minimum, 'min_sensitive_paths': sensitive_min})
            event['risk_score'] = max(event.get('risk_score', 15), 45)

