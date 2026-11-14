"""Public feed snapshots, atomic SQLite publication and offline indexed matching."""
import argparse
import hashlib
import ipaddress
import json
import os
import sqlite3
from contextlib import closing
from datetime import datetime, timezone, timedelta
from pathlib import Path
from urllib.parse import urlsplit
from urllib.request import Request, urlopen
from urllib.parse import urlencode
from uuid import uuid4

SOURCES = [
    ('spamhaus_drop_v4', 'https://www.spamhaus.org/drop/drop_v4.json', 'cidr'),
    ('spamhaus_drop_v6', 'https://www.spamhaus.org/drop/drop_v6.json', 'cidr'),
    ('openphish_community', 'https://openphish.com/feed.txt', 'url'),
]


def parse_feed(text, kind):
    values = set()
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith('#'): continue
        if kind == 'cidr':
            record = json.loads(line)
            if 'cidr' in record:
                values.add(str(ipaddress.ip_network(record['cidr'], strict=True)))
        else:
            parsed = urlsplit(line)
            if parsed.scheme in ('http', 'https') and parsed.hostname:
                values.add(line)
    if not values: raise ValueError('empty_or_invalid_feed')
    return sorted(values)


def update(workspace):
    root = Path(workspace) / 'm1/local_ioc'
    root.mkdir(parents=True, exist_ok=True)
    database = root / 'ioc.sqlite3'
    staging = root / (uuid4().hex + '.sqlite3')
    conn = sqlite3.connect(staging)
    try:
        if database.exists():
            with closing(sqlite3.connect(database)) as previous:
                previous.backup(conn)
        conn.execute('CREATE TABLE IF NOT EXISTS indicators (kind TEXT, value TEXT, source TEXT, fetched_at TEXT, expires_at TEXT, PRIMARY KEY(kind,value,source))')
        conn.execute('CREATE TABLE IF NOT EXISTS sources (source TEXT PRIMARY KEY, url TEXT, fetched_at TEXT, last_modified TEXT, sha256 TEXT, count INTEGER)')
        report = {'updated_at': datetime.now(timezone.utc).isoformat(), 'sources': []}
        for name, url, kind in SOURCES:
            try:
                with urlopen(Request(url, headers={'User-Agent': 'M1-LocalIOC/1.0'}), timeout=30) as response:
                    raw = response.read(10_000_001)
                    modified = response.headers.get('Last-Modified')
                if len(raw) > 10_000_000: raise ValueError('feed_too_large')
                values = parse_feed(raw.decode('utf-8-sig'), kind)
                fetched = datetime.now(timezone.utc)
                expires = fetched + timedelta(hours=72)
                with conn:
                    conn.execute('DELETE FROM indicators WHERE source=?', (name,))
                    conn.executemany('INSERT INTO indicators VALUES (?,?,?,?,?)', ((kind, value, name, fetched.isoformat(), expires.isoformat()) for value in values))
                    conn.execute('INSERT OR REPLACE INTO sources VALUES (?,?,?,?,?,?)', (name, url, fetched.isoformat(), modified, hashlib.sha256(raw).hexdigest(), len(values)))
                report['sources'].append({'source': name, 'url': url, 'status': 'updated', 'count': len(values), 'expires_at': expires.isoformat()})
            except Exception as exc:
                report['sources'].append({'source': name, 'status': 'failed_kept_previous', 'error': type(exc).__name__})
        # OTX is the third public IOC source. Keep the sync bounded to 25 subscribed
        # pulses per run (each pulse needs one indicator request), preserve old rows
        # on failure, and honor the local proxy setting used by other intelligence.
        key = os.getenv('OTX_KEY') or os.getenv('NETGUARD_OTX_KEY')
        if not key:
            env_file = Path(__file__).resolve().parents[1] / '.env'
            if env_file.is_file():
                for line in env_file.read_text(encoding='utf-8', errors='replace').splitlines():
                    if line.startswith(('OTX_KEY=', 'NETGUARD_OTX_KEY=')):
                        key = line.split('=', 1)[1].strip().strip('"').strip("'")
                        if key: break
        if key:
            name = 'alienvault_otx_subscribed'
            try:
                import urllib.request
                proxy = os.getenv('NETGUARD_INTEL_PROXY') or os.getenv('HTTPS_PROXY') or ''
                opener = urllib.request.build_opener(urllib.request.ProxyHandler({'http': proxy, 'https': proxy}) if proxy else urllib.request.ProxyHandler({}))
                def get_json(url):
                    request = Request(url, headers={'User-Agent': 'M1-LocalIOC/1.0', 'X-OTX-API-KEY': key})
                    with opener.open(request, timeout=30) as response:
                        return json.loads(response.read().decode('utf-8'))
                pulse_page = get_json('https://otx.alienvault.com/api/v1/pulses/subscribed?' + urlencode({'page': 1, 'limit': 25}))
                indicators = set()
                for pulse in (pulse_page.get('results') or [])[:25]:
                    pulse_id = pulse.get('id')
                    if not pulse_id: continue
                    payload = get_json('https://otx.alienvault.com/api/v1/pulses/' + str(pulse_id) + '/indicators')
                    for indicator in payload.get('results') or []:
                        value = str(indicator.get('indicator') or '').strip()
                        kind = str(indicator.get('type') or '').upper()
                        if kind in {'IPv4', 'IPv6'}:
                            try: indicators.add(('cidr', str(ipaddress.ip_network(value, strict=False))))
                            except ValueError: continue
                        elif kind in {'DOMAIN', 'HOSTNAME'} and '.' in value and len(value) <= 253:
                            indicators.add(('domain', value.lower().rstrip('.')))
                        elif kind in {'URL', 'URI'}:
                            try:
                                parsed = urlsplit(value)
                                if parsed.scheme in {'http', 'https'} and parsed.hostname: indicators.add(('url', value))
                            except ValueError: pass
                fetched = datetime.now(timezone.utc); expires = fetched + timedelta(hours=72)
                with conn:
                    conn.execute('DELETE FROM indicators WHERE source=?', (name,))
                    conn.executemany('INSERT INTO indicators VALUES (?,?,?,?,?)', ((kind, value, name, fetched.isoformat(), expires.isoformat()) for kind, value in indicators))
                    conn.execute('INSERT OR REPLACE INTO sources VALUES (?,?,?,?,?,?)', (name, 'https://otx.alienvault.com/api/v1/pulses/subscribed?page=1&limit=25', fetched.isoformat(), None, None, len(indicators)))
                report['sources'].append({'source': name, 'status': 'updated', 'count': len(indicators), 'pulses': min(25, len(pulse_page.get('results') or [])), 'expires_at': expires.isoformat()})
            except Exception as exc:
                report['sources'].append({'source': name, 'status': 'failed_kept_previous', 'error': type(exc).__name__})
        else:
            report['sources'].append({'source': 'alienvault_otx_subscribed', 'status': 'skipped_no_api_key'})
        conn.close()
        staging.replace(database)
        (root / 'update_status.json').write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding='utf-8')
        return report
    finally:
        conn.close()
        staging.unlink(missing_ok=True)


class LocalIOC:
    def __init__(self, workspace):
        self.urls = {}
        self.domains = {}
        self.networks = {}
        self.count = 0
        self.expired = 0
        path = Path(workspace) / 'm1/local_ioc/ioc.sqlite3'
        self.status = 'missing' if not path.exists() else 'ready'
        if not path.exists(): return
        now = datetime.now(timezone.utc).isoformat()
        with closing(sqlite3.connect(path)) as conn:
            for kind, value, source, fetched, expires in conn.execute('SELECT * FROM indicators'):
                if expires <= now:
                    self.expired += 1
                    continue
                info = {'type': kind, 'value': value, 'source': source, 'fetched_at': fetched, 'expires_at': expires}
                if kind == 'url': self.urls.setdefault(value, []).append(info)
                elif kind == 'domain': self.domains.setdefault(value.lower(), []).append(info)
                else:
                    net = ipaddress.ip_network(value)
                    self.networks.setdefault((net.version, net.prefixlen), {}).setdefault(int(net.network_address), []).append(info)
                self.count += 1
        if not self.count: self.status = 'empty_or_expired'

    def match(self, event):
        matches = []
        for field in ('src_ip', 'dst_ip'):
            try: address = ipaddress.ip_address(event.get(field))
            except (ValueError, TypeError): continue
            for (version, prefix), table in self.networks.items():
                if version != address.version: continue
                shift = address.max_prefixlen - prefix
                key = (int(address) >> shift) << shift
                matches.extend({**info, 'matched_field': field} for info in table.get(key, []))
        matches.extend({**info, 'matched_field': 'url_path'} for info in self.urls.get(event.get('url_path'), []))
        domain = str(event.get('domain') or '').lower().rstrip('.')
        if domain:
            for name, indicators in self.domains.items():
                if domain == name or domain.endswith('.' + name):
                    matches.extend({**info, 'matched_field': 'domain'} for info in indicators)
        return matches


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--workspace', type=Path, required=True)
    args = parser.parse_args()
    result = update(args.workspace)
    print(json.dumps(result, ensure_ascii=True, indent=2))
    raise SystemExit(0 if all(s['status'] == 'updated' for s in result['sources']) else 1)
