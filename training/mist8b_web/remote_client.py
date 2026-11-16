"""Run auditable commands in the selected GPU instance without storing credentials.

The provider's gateway requires the menu digit and Enter as separate SSH writes.
This helper is intentionally limited to shell commands and verified file transfer;
credentials are read locally from an existing env file and are never logged.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import os
from pathlib import Path
import re
import shlex
import sys
import time
import uuid

import paramiko

HOST = "xn-a.suanjiayun.com"
PORT = 2020
ENV_FILE = Path(r"E:\platform_taishi\vps.env")
KNOWN_HOSTS = Path(__file__).with_name(".gateway_known_hosts")


def credentials() -> tuple[str, str]:
    values = {}
    for raw in ENV_FILE.read_text(encoding="utf-8-sig").splitlines():
        line = raw.strip()
        if line and not line.startswith("#") and "=" in line:
            name, value = line.split("=", 1)
            values[name.strip().lower()] = value.strip().strip("\"'")
    if not values.get("user") or not values.get("pass"):
        raise ValueError("connection file requires user and pass")
    return values["user"], values["pass"]


def collect(channel, until: str, timeout: float) -> str:
    out = ""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if channel.recv_ready():
            out += channel.recv(65536).decode("utf-8", errors="replace")
            if until in out:
                return out
        elif channel.closed:
            raise RuntimeError("SSH shell closed before expected marker")
        else:
            time.sleep(0.05)
    raise TimeoutError(f"remote marker not received within {timeout:g}s")


def connect() -> tuple[paramiko.SSHClient, paramiko.Channel, str, str]:
    user, password = credentials()
    client = paramiko.SSHClient()
    client.load_system_host_keys()
    if KNOWN_HOSTS.exists():
        client.load_host_keys(str(KNOWN_HOSTS))
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    client.connect(HOST, port=PORT, username=user, password=password,
                   allow_agent=False, look_for_keys=False, timeout=20,
                   banner_timeout=20, auth_timeout=20)
    client.save_host_keys(str(KNOWN_HOSTS))
    channel = client.invoke_shell(term="xterm-256color", width=180, height=45)
    collect(channel, "输入服务器序号>", 20)
    channel.sendall(b"0")
    time.sleep(0.35)
    channel.sendall(b"\r")
    time.sleep(0.35)
    channel.sendall(b"\n")
    collect(channel, "root@", 30)
    # Wait for the shell to execute stty, rather than racing the login banner.
    # Otherwise the shell may echo a command containing the response marker.
    ready = "__MIST_ECHO_OFF_" + uuid.uuid4().hex + "__"
    channel.sendall(b"stty -echo\n")
    channel.sendall(f"printf '\\n{ready}\\n'\n".encode())
    output = ""
    deadline = time.monotonic() + 20
    ready_pattern = re.compile(r"(?:^|[\r\n])" + re.escape(ready) + r"[\r]*\n")
    while not ready_pattern.search(output) and time.monotonic() < deadline:
        if channel.recv_ready():
            output += channel.recv(65536).decode("utf-8", errors="replace")
        elif channel.closed:
            raise RuntimeError("SSH shell closed before echo was disabled")
        else:
            time.sleep(0.05)
    if not ready_pattern.search(output):
        raise TimeoutError("remote shell did not confirm echo was disabled")
    # Settle: let trailing login output arrive, then drain once, so commands sent
    # right after connect() are not interleaved with leftover banner data.
    time.sleep(1.0)
    while channel.recv_ready():
        channel.recv(65536)
    return client, channel, user, password


def run_script(channel: paramiko.Channel, script: str, timeout: float) -> tuple[str, int]:
    marker = "__MIST_CMD_" + uuid.uuid4().hex + "__"
    payload = base64.b64encode(script.encode("utf-8")).decode("ascii")
    command = f"printf %s {shlex.quote(payload)} | base64 -d | bash; printf '\\n{marker}:%s\\n' \"$?\"\n"
    channel.sendall(command.encode())
    output = ""
    deadline = time.monotonic() + timeout
    status_pattern = re.compile(re.escape(marker) + r":(\d+)(?:\r?\n|$)")
    while not status_pattern.search(output) and time.monotonic() < deadline:
        if channel.recv_ready():
            output += channel.recv(65536).decode("utf-8", errors="replace")
        elif channel.closed:
            raise RuntimeError("SSH shell closed before exit status")
        else:
            time.sleep(0.05)
    match = status_pattern.search(output)
    if not match:
        raise RuntimeError("remote exit status missing")
    return output[:match.start()].strip(), int(match.group(1))


def upload(channel: paramiko.Channel, local: Path, remote: str, timeout: float) -> None:
    data = local.read_bytes()
    digest = hashlib.sha256(data).hexdigest()
    token = uuid.uuid4().hex
    ready, end = "__UPLOAD_READY_" + token, "__UPLOAD_END_" + token
    # A unique .partial is created exclusively; no existing destination is overwritten.
    receiver = f'''import base64,hashlib,os,sys\nfrom pathlib import Path\np=Path({remote!r})\ntmp=p.with_name(p.name+".partial-{token}")\nif p.exists(): raise SystemExit("destination exists")\nif not p.parent.is_dir(): raise SystemExit("destination directory does not exist")\nh=hashlib.sha256(); n=0\nwith tmp.open("xb") as f:\n print({ready!r},flush=True)\n for line in sys.stdin.buffer:\n  line=line.strip()\n  if line==b"__END_DATA__": break\n  chunk=base64.b64decode(line,validate=True); f.write(chunk); h.update(chunk); n+=len(chunk)\nif n!={len(data)} or h.hexdigest()!={digest!r}: raise SystemExit("upload checksum mismatch")\nos.rename(tmp,p)\nprint({end!r},n,h.hexdigest(),flush=True)\n'''
    encoded_receiver = base64.b64encode(receiver.encode()).decode()
    command = "python -u -c " + shlex.quote("import base64;exec(base64.b64decode(" + repr(encoded_receiver) + "))") + "\n"
    channel.sendall(command.encode())
    try:
        collect(channel, ready, 20)
    except TimeoutError:
        # Dump whatever the remote side produced so the failure is diagnosable.
        extra = ""
        deadline = time.monotonic() + 3
        while time.monotonic() < deadline:
            if channel.recv_ready():
                extra += channel.recv(65536).decode("utf-8", errors="replace")
            else:
                time.sleep(0.05)
        raise TimeoutError(f"upload ready marker missing; raw tail: {extra[-2000:]!r}") from None
    encoded = base64.b64encode(data)
    # Keep each terminal input line well below its canonical-mode size limit.
    packet = bytearray()
    for start in range(0, len(encoded), 1024):
        packet.extend(encoded[start:start + 1024] + b"\n")
        if len(packet) >= 65536:
            channel.sendall(bytes(packet))
            packet.clear()
    if packet:
        channel.sendall(bytes(packet))
    channel.sendall(b"__END_DATA__\n")
    output = collect(channel, end, timeout)
    print(output[output.index(end):].splitlines()[0])


def download(channel: paramiko.Channel, remote: str, local: Path, timeout: float) -> None:
    if local.exists():
        raise FileExistsError("local destination already exists")
    if not local.parent.is_dir():
        raise FileNotFoundError("local destination directory does not exist")
    token = uuid.uuid4().hex
    start, end = "__DOWNLOAD_START_" + token, "__DOWNLOAD_END_" + token
    sender = f'''import base64,hashlib,sys\nfrom pathlib import Path\np=Path({remote!r})\nif not p.is_file(): raise SystemExit("file missing")\nh=hashlib.sha256(); n=0\nprint({start!r},p.stat().st_size,flush=True)\nwith p.open("rb") as f:\n while True:\n  chunk=f.read(768)\n  if not chunk: break\n  h.update(chunk); n+=len(chunk)\n  sys.stdout.buffer.write(base64.b64encode(chunk)+b"\\n")\nsys.stdout.buffer.flush()\nprint({end!r},n,h.hexdigest(),flush=True)\n'''
    encoded = base64.b64encode(sender.encode()).decode()
    command = "python -u -c " + shlex.quote("import base64;exec(base64.b64decode(" + repr(encoded) + "))") + "\n"
    channel.sendall(command.encode())
    partial = local.with_name(local.name + ".partial-" + token)
    digest = hashlib.sha256()
    written = 0
    expected = None
    buf = b""
    deadline = time.monotonic() + timeout
    with partial.open("xb") as stream:
        while time.monotonic() < deadline:
            if b"\n" not in buf:
                if channel.recv_ready():
                    buf += channel.recv(65536)
                elif channel.closed:
                    raise RuntimeError("SSH shell closed during download")
                else:
                    time.sleep(.01)
                continue
            raw, buf = buf.split(b"\n", 1)
            line = raw.strip()
            if expected is None:
                index = line.find(start.encode())
                if index >= 0:
                    expected = int(line[index:].decode().split()[1])
                continue
            if line.startswith(end.encode()):
                parts = line.decode().split()
                if len(parts) != 3 or int(parts[1]) != written or written != expected or parts[2] != digest.hexdigest():
                    raise RuntimeError("download checksum or size mismatch")
                break
            data = base64.b64decode(line, validate=True)
            stream.write(data)
            digest.update(data)
            written += len(data)
        else:
            raise TimeoutError("download timed out")
    os.rename(partial, local)
    print("downloaded", written, digest.hexdigest(), "to", local)


def main() -> int:
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest="action", required=True)
    run = sub.add_parser("run")
    run.add_argument("script", type=Path)
    run.add_argument("--timeout", type=float, default=60)
    up = sub.add_parser("upload")
    up.add_argument("local", type=Path)
    up.add_argument("remote")
    up.add_argument("--timeout", type=float, default=180)
    down = sub.add_parser("download")
    down.add_argument("remote")
    down.add_argument("local", type=Path)
    down.add_argument("--timeout", type=float, default=1800)
    args = parser.parse_args()
    client = None
    user = password = ""
    try:
        client, channel, user, password = connect()
        if args.action == "run":
            output, status = run_script(channel, args.script.read_text(encoding="utf-8"), args.timeout)
            print(output.replace(password, "[REDACTED]").replace(user, "[USER]"))
            return status
        if args.action == "upload":
            upload(channel, args.local, args.remote, args.timeout)
        else:
            download(channel, args.remote, args.local, args.timeout)
        return 0
    except Exception as exc:
        message = str(exc)
        if password:
            message = message.replace(password, "[REDACTED]")
        if user:
            message = message.replace(user, "[USER]")
        print(f"{type(exc).__name__}: {message}", file=sys.stderr)
        return 1
    finally:
        if client:
            client.close()


if __name__ == "__main__":
    raise SystemExit(main())
