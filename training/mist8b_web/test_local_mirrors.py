"""Test reachability and a bounded public model range without printing redirects."""
import concurrent.futures
import socket
import time
import urllib.request

URLS = {
    "huggingface": "https://huggingface.co/dreamgroup/MiST-8B/resolve/9ba377df00b9e830849fce8ebbe568a9a84774f2/model.safetensors",
    "hf-mirror": "https://hf-mirror.com/dreamgroup/MiST-8B/resolve/9ba377df00b9e830849fce8ebbe568a9a84774f2/model.safetensors",
}


def check(item):
    name, url = item
    start = time.monotonic()
    try:
        request = urllib.request.Request(url, headers={"Range": "bytes=0-1048575"})
        with urllib.request.urlopen(request, timeout=25) as response:
            data = response.read(1048576)
            print(name, "status", response.status, "bytes", len(data), "seconds", round(time.monotonic()-start, 1))
    except Exception as exc:
        print(name, type(exc).__name__, "seconds", round(time.monotonic()-start, 1))


if __name__ == "__main__":
    with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
        list(pool.map(check, URLS.items()))
    for port in (7890, 7897, 1080, 10808):
        with socket.socket() as sock:
            sock.settimeout(.3)
            if sock.connect_ex(("127.0.0.1", port)) == 0:
                print("local proxy port active", port)
