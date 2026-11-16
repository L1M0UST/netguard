"""Interactive-shell delivery diagnosis: which command forms reach the shell."""
from __future__ import annotations

import base64
import shlex
import time
import uuid

import remote_client as rc


def drain(channel, seconds: float) -> str:
    out = ""
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        if channel.recv_ready():
            out += channel.recv(65536).decode("utf-8", errors="replace")
        else:
            time.sleep(0.05)
    return out


def main() -> None:
    client, channel, user, password = rc.connect()
    try:
        print("[1] direct echo:", repr(drain(channel, 2.0) or "(nothing)"))
        channel.sendall(b"echo HELLO_DIRECT_$((1+1))\n")
        print("[2] after echo cmd:", repr(drain(channel, 3.0) or "(nothing)"))

        token = uuid.uuid4().hex
        ready = "__UPDIAG_READY_" + token
        receiver = (f'import sys\nprint({ready!r},flush=True)\n'
                    'for line in sys.stdin.buffer:\n'
                    '    if line.strip()==b"__END__": break\n'
                    'print("got",line,flush=True)\n')
        encoded = base64.b64encode(receiver.encode()).decode()
        command = "python -u -c " + shlex.quote(
            "import base64;exec(base64.b64decode(" + repr(encoded) + "))") + "\n"
        print("[3] command repr head:", repr(command[:120]))
        channel.sendall(command.encode())
        got = drain(channel, 5.0)
        print("[4] after python -u -c:", repr(got[:300] or "(nothing)"))
        if ready in got:
            channel.sendall(b"__END__\n")
            print("[5] after END:", repr(drain(channel, 3.0) or "(nothing)"))

        # [6] replicate remote_client.upload's receiver: file open BEFORE ready print.
        token2 = uuid.uuid4().hex
        remote = "/root/qwen_work/_updiag_file.txt"
        ready2 = "__UPDIAG_FILE_READY_" + token2
        receiver2 = (f'import base64,hashlib,os,sys\nfrom pathlib import Path\np=Path({remote!r})\n'
                     f'tmp=p.with_name(p.name+".partial-{token2}")\n'
                     'if p.exists(): raise SystemExit("destination exists")\n'
                     'if not p.parent.is_dir(): raise SystemExit("destination directory does not exist")\n'
                     'h=hashlib.sha256(); n=0\n'
                     'with tmp.open("xb") as f:\n'
                     f' print({ready2!r},flush=True)\n'
                     ' for line in sys.stdin.buffer:\n'
                     '  line=line.strip()\n'
                     '  if line==b"__END_DATA__": break\n'
                     '  chunk=base64.b64decode(line,validate=True); f.write(chunk); h.update(chunk); n+=len(chunk)\n'
                     'if n!=14 or h.hexdigest()!="7ec0fc6b04f79f46fea23a1c5f63ff5c": raise SystemExit("upload checksum mismatch")\n'
                     'os.rename(tmp,p)\n'
                     'print("FILE_DONE",flush=True)\n')
        encoded2 = base64.b64encode(receiver2.encode()).decode()
        command2 = "python -u -c " + shlex.quote(
            "import base64;exec(base64.b64decode(" + repr(encoded2) + "))") + "\n"
        channel.sendall(command2.encode())
        got2 = drain(channel, 5.0)
        print("[6] file receiver:", repr(got2[:300] or "(nothing)"))
        if ready2 in got2:
            channel.sendall(base64.b64encode(b"hello upload\n") + b"\n")
            channel.sendall(b"__END_DATA__\n")
            print("[7] after data:", repr(drain(channel, 3.0) or "(nothing)"))
    finally:
        client.close()


if __name__ == "__main__":
    main()
