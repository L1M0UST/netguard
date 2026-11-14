"""Persist an offline review batch using local configuration and IOC snapshot."""
import json
import shutil
from pathlib import Path
from uuid import uuid4
from m1.run import process
from m1.quality import sample, read_rows
from m1.handoff import read_batch


def main():
    source = Path('shared-workspace').resolve()
    root = Path('work/quality-audit') / uuid4().hex
    root.mkdir(parents=True)
    (root/'m1').mkdir()
    config = json.loads((source/'m1/config.json').read_text(encoding='utf-8'))
    # No secrets or external calls in the audit workspace.
    for key in ('llm','mapping_llm','threatbook'):
        config[key]={'enabled':False}
    config['enable_l3_semantic_judge']=False
    (root/'m1/config.json').write_text(json.dumps(config,indent=2),encoding='utf-8')
    local = source/'m1/local_ioc/ioc.sqlite3'
    if local.exists():
        (root/'m1/local_ioc').mkdir()
        shutil.copy2(local,root/'m1/local_ioc/ioc.sqlite3')
    manifest = root/'manifest.json'
    manifest.write_text(json.dumps({'task_id':'quality-audit','input_files':[str(source/'incoming/web_alerts.xlsx')]}),encoding='utf-8')
    ready = process(root.resolve(),manifest.resolve())
    batch = read_batch(ready)
    sessions = list(read_rows(ready,batch,'suspicious_events'))
    groups = list(read_rows(ready,batch,'review_groups'))
    members = [sid for group in groups for sid in group['related_session_ids']]
    assert len(members)==len(set(members))==len(sessions)
    assert set(members)=={r['session_id'] for r in sessions}
    labels = root/'review_labels.csv'
    sampling = sample(ready,labels)
    report = {'batch':str(ready.relative_to(Path.cwd())), 'labels':str(labels),
        'metrics':batch['status']['metrics'],'quality':batch['status']['quality'],
        'local_ioc':batch['status']['local_ioc'],'sampling':sampling,
        'llm_calls':batch['status']['llm_calls'],'review_references_valid':True}
    (root/'report.json').write_text(json.dumps(report,indent=2),encoding='utf-8')
    print(json.dumps(report,indent=2))


if __name__ == '__main__': main()
