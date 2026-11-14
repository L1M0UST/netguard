"""Bounded SimHash candidate retrieval with exact token-set verification.

Only review groups use this representation; it never deletes events or scores them.
"""
import hashlib
import re
from urllib.parse import urlsplit

VERSION = 'payload-simhash-v1'


def payload_features(event):
    fields = [('query', urlsplit(str(event.get('url_path') or '')).query)]
    fields += [(key, str(event.get(key) or '')) for key in ('request_body','message','user_agent')]
    digest = hashlib.sha256()
    tokens = set()
    bounded = True
    for name, value in fields:
        # Do not decode, lowercase or replace numeric literals: those changes can
        # erase security semantics. Only whitespace is normalized for review.
        value = re.sub(r'\s+', ' ', value).strip()
        raw = value.encode('utf-8')
        digest.update(name.encode()); digest.update(len(raw).to_bytes(8,'big')); digest.update(raw)
        if len(value)>4096: bounded=False
        words = re.findall(r'\w+|[^\w\s]',value[:4096])
        units = [' '.join(words[i:i+3]) for i in range(max(1,len(words)-2))] if words else []
        for unit in units:
            tokens.add(int.from_bytes(hashlib.blake2b((name+':'+unit).encode(),digest_size=8).digest(),'big'))
            if len(tokens)>256:
                bounded=False
                break
    if not bounded: tokens=set()  # Full digest only; never merge on truncated evidence.
    counts=[0]*64
    for token in tokens:
        for bit in range(64): counts[bit]+=1 if token & (1<<bit) else -1
    signature=sum(1<<bit for bit,total in enumerate(counts) if total>0)
    return {'digest':digest.hexdigest(),'tokens':frozenset(tokens),'signature':signature,
            'approximate':bounded and len(tokens)>=8}


def session_features(events):
    unique={e['_payload']['digest']:e['_payload'] for e in events if '_payload' in e}
    if len(unique)==1: return next(iter(unique.values()))
    if not unique: return None
    # Mixed payload sessions must not be represented solely by their first/highest event.
    digest=hashlib.sha256(''.join(sorted(unique)).encode()).hexdigest()
    return {'digest':digest,'tokens':frozenset(),'signature':0,'approximate':False}


def clusters(rows, stats):
    exact, bands, groups = {}, {}, []
    for row in sorted(rows,key=lambda r:r['session_id']):
        feature=row.get('_payload')
        if not feature:
            feature=payload_features({**row,**(row.get('semantic_evidence') or {})})
            # Legacy bounded excerpts cannot establish complete payload equality.
            feature['digest']=row['session_id'];feature['approximate']=False
        fingerprint=feature['digest']
        index=exact.get(fingerprint)
        if index is None and feature['approximate']:
            candidates=set()
            for band in range(4):
                bucket=(band,(feature['signature']>>(band*16))&65535)
                candidates.update(bands.get(bucket,[]))
            for candidate in sorted(candidates)[:64]:
                exemplar=groups[candidate][0].get('_payload')
                if not exemplar: continue
                stats['candidate_comparisons']+=1
                a,b=feature['tokens'],exemplar['tokens']
                similarity=len(a&b)/len(a|b)
                if similarity>=0.9:
                    index=candidate;stats['approximate_assignments']+=1;break
        if index is None:
            index=len(groups);groups.append([])
            if feature['approximate']:
                for band in range(4):
                    bucket=(band,(feature['signature']>>(band*16))&65535)
                    entries=bands.setdefault(bucket,[])
                    if len(entries)<64: entries.append(index)
        exact[fingerprint]=index
        groups[index].append(row)
    return groups
