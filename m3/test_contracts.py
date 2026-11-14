import json
from pathlib import Path
from contracts import CandidateAlert, AttackChain, ProgressEvent

def test_candidate_fixture_matches_contract():
    line = Path('fixtures/candidates.jsonl').read_text(encoding='utf-8').splitlines()[0]
    alert = CandidateAlert.model_validate(json.loads(line))
    assert alert.alert_id and alert.severity == 'high'

def test_chain_and_progress_contracts():
    chain = AttackChain.model_validate(json.loads(Path('fixtures/attack_chains.json').read_text(encoding='utf-8')))
    assert chain.evidence_ids == ['A-fixture-001']
    progress = ProgressEvent(task_id='T-fixture-001', status='completed', progress=100, stage='done')
    assert progress.progress == 100
