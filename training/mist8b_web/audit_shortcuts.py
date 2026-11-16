"""Check simple metadata-to-label shortcuts in the competition split."""
from __future__ import annotations

import collections
import json
import re
from pathlib import Path

DATA = Path(r'E:\platform_taishi\mist8b-web-data\20261115_v3')
FIELDS = ('源IP','目的IP','User-Agent','方法','时间')


def field(text: str, name: str) -> str:
    match=re.search(r'(?m)^'+re.escape(name)+r': ([^\r\n]*)',text)
    return match.group(1) if match else ''


def main():
    splits={}
    for split in ('train','dev','test'):
        with (DATA/(split+'.jsonl')).open(encoding='utf-8') as stream:
            splits[split]=[row for line in stream if (row:=json.loads(line))['_meta']['source']=='D0_competition']
    report={}
    for name in FIELDS:
        labels=collections.defaultdict(collections.Counter)
        for row in splits['train']:
            value=field(row['input'],name)
            if value not in ('','未知'):
                labels[value][row['_meta']['label']]+=1
        group={}
        for split in ('dev','test'):
            covered=correct=0
            for row in splits[split]:
                counter=labels.get(field(row['input'],name))
                if counter:
                    covered+=1
                    prediction=counter.most_common(1)[0][0]
                    correct+=prediction==row['_meta']['label']
            group[split]={'samples':len(splits[split]),'seen_in_train':covered,
                          'coverage':covered/len(splits[split]),
                          'majority_label_accuracy_all':correct/len(splits[split]),
                          'majority_label_accuracy_when_seen':correct/covered if covered else None}
        report[name]={'distinct_train_values':len(labels),'holdouts':group}
    path=DATA/'metadata_shortcut_audit.json'
    path.write_text(json.dumps(report,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
    print(json.dumps(report,ensure_ascii=False,indent=2))


if __name__=='__main__':
    main()
