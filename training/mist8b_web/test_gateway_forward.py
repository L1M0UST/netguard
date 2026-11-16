"""Check whether the selected instance shares the gateway loopback namespace."""
from remote_client import connect, run_script


def main():
    client, channel, _, _ = connect()
    transport = client.get_transport()
    try:
        def handle(remote_channel, origin, server):
            remote_channel.sendall(b"forward-ok")
            remote_channel.close()
        port = transport.request_port_forward("127.0.0.1", 0, handler=handle)
        script = f'''python - <<'PY'
import socket
s=socket.socket()
s.settimeout(4)
try:
 s.connect(("127.0.0.1",{port}))
 print("INSTANCE_TO_GATEWAY_LOOPBACK", s.recv(20).decode())
except Exception as exc:
 print("INSTANCE_TO_GATEWAY_LOOPBACK", type(exc).__name__)
finally:
 s.close()
PY
'''
        print(run_script(channel, script, 15)[0])
    except Exception as exc:
        print("GATEWAY_FORWARD", type(exc).__name__)
    finally:
        client.close()


if __name__ == "__main__":
    main()
