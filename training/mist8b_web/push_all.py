"""Upload several files over ONE gateway shell session, then verify checksums.

The gateway drops connections intermittently, so each file keeps its completion
state and a fresh session resumes from the first missing file.
"""
from __future__ import annotations

import base64
import hashlib
import shlex
import time
import uuid
from pathlib import Path

import remote_client as rc

WORK = "/root/sj-tmp/cqsec_mist8b_web_20261115"
FILES = [
    ("configs/qwen3_smoke.yaml", "configs/qwen3_smoke.yaml"),
    ("configs/qwen3_round1.yaml", "configs/qwen3_round1.yaml"),
    ("audit_qwen_tokens.py", "audit_qwen_tokens.py"),
    ("run_qwen_stage1.sh", "run_qwen_stage1.sh"),
    ("compare_qwen_web.py", "compare_qwen_web.py"),
    ("export_qwen_artifact.py", "export_qwen_artifact.py"),
    ("qwen_stage1_status.sh", "qwen_stage1_status.sh"),
]
HERE = Path(__file__).resolve().parent


def push_file(channel, local: Path, remote: str) -> None:
    data = local.read_bytes()
    digest = hashlib.sha256(data).hexdigest()
    token = uuid_token()
    ready, end = "__UP_READY_" + token, "__UP_END_" + token
    receiver = (f'import base64,hashlib,os,sys\nfrom pathlib import Path\np=Path({remote!r})\n'
                f'tmp=p.with_name(p.name+".partial-{token}")\n'
                'if p.exists(): raise SystemExit("destination exists")\n'
                'if not p.parent.is_dir(): raise SystemExit("bad dir")\n'
                'h=hashlib.sha256(); n=0\n'
                'with tmp.open("xb") as f:\n'
                f' print({ready!r},flush=True)\n'
                ' for line in sys.stdin.buffer:\n'
                '  line=line.strip()\n'
                '  if line==b"__END_DATA__": break\n'
                '  chunk=base64.b64decode(line,validate=True); f.write(chunk); h.update(chunk); n+=len(chunk)\n'
                f'if n!={len(data)} or h.hexdigest()!={digest!r}: raise SystemExit("checksum mismatch")\n'
                'os.rename(tmp,p)\n'
                f'print({end!r},flush=True)\n')
    encoded = base64.b64encode(receiver.encode()).decode()
    command = "python -u -c " + shlex.quote("import base64;exec(base64.b64decode(" + repr(encoded) + "))") + "\n"
    channel.sendall(command.encode())
    rc.collect(channel, ready, 30)
    blob = base64.b64encode(data)
    packet = bytearray()
    for start in range(0, len(blob), 1024):
        packet.extend(blob[start:start + 1024] + b"\n")
        if len(packet) >= 65536:
            channel.sendall(bytes(packet))
            packet.clear()
    if packet:
        channel.sendall(bytes(packet))
    channel.sendall(b"__END_DATA__\n")
    output = rc.collect(channel, end, 60)
    tail = output[output.index(end):].splitlines()[0]
    print(f"pushed {local.name} -> {remote} {tail.split()[1] if len(tail.split())>1 else ''} bytes")


def uuid_token() -> str:
    import uuid
    return uuid.uuid4().hex


def shlex_q(text: str) -> str:
    import shlex
    return shlex.quote(text)


def verify(channel, pairs: list[tuple[str, str]]) -> None:
    import json
    expected = {}
    for local_name, remote_name in pairs:
        data = (HERE / local_name).read_bytes()
        expected[remote_name] = hashlib.sha256(data).hexdigest()
    script = "python3 - <<'PY'\nimport hashlib,json\nfrom pathlib import Path\n"
    script += "expect=json.loads(%r)\n" % json.dumps(expected)
    script += ("out={}\n"
               "for name,d in expect.items():\n"
               "    p=Path(%r)/name\n"
               "    out[name]=hashlib.sha256(p.read_bytes()).hexdigest() if p.is_file() else 'MISSING'\n"
               "print(json.dumps(out))\n"
               "raise SystemExit(0 if all(out[n]==d for n,d in expect.items()) else 1)\n") % WORK
    import base64 as b64mod
    import shlex as shlexmod
    import uuid as uuidmod
    marker = "__VERIFY_" + uuidmod.uuid4().hex + "__"
    payload = b64mod.b64encode(script.encode()).decode()
    command = (f"printf %s {shlexmod.quote(payload)} | base64 -d | bash; "
               f"printf '\\n{marker}:%s\\n' \"$?\"\n")
    channel.sendall(command.encode())
    output = rc.collect(channel, marker, 60)
    status = output[output.rindex(marker) + len(marker) + 1:].strip().splitlines()[0]
    print("verify status:", status)
    if status != "0":
        raise SystemExit("uploaded file checksum verification failed")


def main() -> None:
    attempt = 0
    index = 0
    while index < len(FILES):
        attempt += 1
        if attempt > 4:
            raise SystemExit("too many gateway drops")
        try:
            client, channel, _, _ = rc.connect()
            try:
                while index < len(FILES):
                    local_name, remote_name = FILES[index]
                    push_file(channel, HERE / local_name, f"{WORK}/{remote_name}")
                    index += 1
                verify(channel, FILES)
            finally:
                client.close()
        except Exception as exc:
            print(f"attempt {attempt} interrupted at file {index}: {type(exc).__name__}: {exc}")
            import time
            time.sleep(10)
    print("ALL_FILES_UPLOADED")


if __name__ == "__main__":
    main()
