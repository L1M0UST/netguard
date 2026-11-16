"""Create a small reproducible payload for the isolated GPU work directory."""
from pathlib import Path
from zipfile import ZIP_DEFLATED, ZipFile
import hashlib

ROOT = Path(__file__).resolve().parent
OUT = ROOT / 'pipeline-payload.zip'
NAMES = ('configs/smoke.yaml', 'configs/profile.yaml', 'configs/round1.yaml', 'run_pipeline.sh')
with ZipFile(OUT, 'x', compression=ZIP_DEFLATED) as archive:
    for name in NAMES:
        archive.write(ROOT / name, name)
with ZipFile(OUT) as archive:
    assert archive.testzip() is None and set(archive.namelist()) == set(NAMES)
print('bytes', OUT.stat().st_size, 'sha256', hashlib.sha256(OUT.read_bytes()).hexdigest())
