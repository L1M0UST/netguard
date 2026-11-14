"""Review queues and human-labelled, session-level quality evaluation."""
import argparse
import csv
import hashlib
import json
import random
from collections import defaultdict, Counter
from pathlib import Path
from m1.handoff import read_batch
from m1.l2 import normalized_route
from m1.similarity import clusters, VERSION


def pattern_key(row):
    if row.get('review_group_id'): return ('review_group', row['review_group_id'])
    return base_pattern_key(row)


def base_pattern_key(row):
    # A review pattern is deliberately not an incident or attacker identity.
    return (tuple(sorted(row.get('rule_hits', []))), row.get('protocol'),
            row.get('method'), normalized_route(row.get('url_path')),
            tuple(sorted((m.get('type'), m.get('value')) for m in row.get('ioc_matches', []))))


def review_groups(rows, stats=None):
    if stats is None: stats=Counter()
    groups = defaultdict(list)
    for row in rows:
        groups[base_pattern_key(row)].append(row)
    result = []
    partitions=((key,members) for key,items in groups.items() for members in clusters(items,stats))
    for key, members in partitions:
        representative = max(members, key=lambda r: r['risk_score'])
        group_id = hashlib.sha256(json.dumps((VERSION,key,sorted(r['session_id'] for r in members))).encode()).hexdigest()[:24]
        for row in members:
            row['review_group_id'] = group_id
        result.append({'review_group_id': group_id, 'correlation_status': 'review_pattern_only',
            'representative_session_id': representative['session_id'],
            'related_session_ids': [r['session_id'] for r in members],
            'session_count': len(members), 'event_count': sum(r['event_count'] for r in members),
            'target_count': len({r.get('dst_ip') for r in members}),
            'source_count': len({r.get('src_ip') for r in members}),
            'rule_hits': list(key[0]), 'route_template': key[3],
            'similarity_version': VERSION,
            'risk_score': representative['risk_score']})
    return sorted(result, key=lambda r: (-r['risk_score'], -r['session_count']))


def read_rows(directory, batch, name):
    path = directory / batch['artifacts'][name]
    if path.suffix == '.parquet':
        import pyarrow.parquet as pq
        for chunk in pq.ParquetFile(path).iter_batches(batch_size=1000):
            yield from chunk.to_pylist()
    else:
        with path.open(encoding='utf-8') as stream:
            for line in stream:
                if line.strip(): yield json.loads(line)


def sample(directory, output, per_class=100):
    if per_class < 1: raise ValueError('per-class must be positive')
    batch = read_batch(directory)
    suspicious = {r['session_id'] for r in read_rows(directory, batch, 'suspicious_events')}
    rng = random.Random(42)
    pools, counts = defaultdict(list), Counter()
    for row in read_rows(directory, batch, 'all_sessions'):
        predicted = int(row['session_id'] in suspicious)
        counts[predicted] += 1
        pool = pools[predicted]
        if len(pool) < per_class: pool.append(row)
        else:
            index = rng.randrange(counts[predicted])
            if index < per_class: pool[index] = row
    output.parent.mkdir(parents=True, exist_ok=True)
    with output.open('x', encoding='utf-8-sig', newline='') as stream:
        writer = csv.DictWriter(stream, fieldnames=['consumption_key','session_id','predicted','population','sample_size','src_ip','dst_ip','rule_hits','label','notes'])
        writer.writeheader()
        for predicted, pool in sorted(pools.items()):
            for row in pool:
                writer.writerow({'consumption_key':batch['consumption_key'], 'session_id':row['session_id'],
                    'predicted':predicted, 'population':counts[predicted], 'sample_size':len(pool),
                    'src_ip':row.get('src_ip'), 'dst_ip':row.get('dst_ip'),
                    'rule_hits':','.join(row.get('rule_hits',[])), 'label':'', 'notes':''})
    return {'sampled':sum(map(len,pools.values())), 'population':dict(counts)}


def evaluate(directory, labels):
    batch = read_batch(directory)
    suspicious = {r['session_id'] for r in read_rows(directory,batch,'suspicious_events')}
    known = {r['session_id'] for r in read_rows(directory,batch,'all_sessions')}
    confusion, seen = Counter(), set()
    pending = 0
    with labels.open(encoding='utf-8-sig',newline='') as stream:
        for row in csv.DictReader(stream):
            sid = row['session_id']
            if row['consumption_key'] != batch['consumption_key'] or sid not in known or sid in seen:
                raise ValueError('wrong batch, unknown or duplicate session')
            seen.add(sid)
            label = row['label'].strip().lower()
            if label in ('','unknown'):
                pending += 1
                continue
            if label not in ('malicious','benign'): raise ValueError('label must be malicious, benign or unknown')
            confusion[('TP' if sid in suspicious else 'FN') if label == 'malicious' else ('FP' if sid in suspicious else 'TN')] += 1
    def ratio(a,b): return a/b if b else None
    tp,fp,tn,fn = (confusion[k] for k in ('TP','FP','TN','FN'))
    return {'scope':'labelled_sample_only_not_population_estimate', 'labelled':tp+fp+tn+fn,
        'pending_or_unknown':pending, 'confusion':{k:confusion[k] for k in ('TP','FP','TN','FN')},
        'precision':ratio(tp,tp+fp), 'recall':ratio(tp,tp+fn),
        'false_positive_rate':ratio(fp,fp+tn), 'accuracy':ratio(tp+tn,tp+tn+fp+fn)}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('action',choices=['sample','evaluate'])
    parser.add_argument('--batch',type=Path,required=True)
    parser.add_argument('--labels',type=Path,required=True)
    parser.add_argument('--per-class',type=int,default=100)
    args = parser.parse_args()
    result = sample(args.batch,args.labels,args.per_class) if args.action == 'sample' else evaluate(args.batch,args.labels)
    print(json.dumps(result,ensure_ascii=False,indent=2))


if __name__ == '__main__': main()
