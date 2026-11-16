import time
import urllib.request

url = "https://huggingface.co/dreamgroup/MiST-8B/resolve/9ba377df00b9e830849fce8ebbe568a9a84774f2/model.safetensors"
for name, proxy in [("system", None), ("local_proxy_7890", "http://127.0.0.1:7890")]:
    start = time.monotonic()
    try:
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({"https": proxy})) if proxy else urllib.request.build_opener()
        request = urllib.request.Request(url, headers={"Range": "bytes=0-16777215"})
        total = 0
        with opener.open(request, timeout=45) as response:
            while True:
                chunk = response.read(262144)
                if not chunk:
                    break
                total += len(chunk)
        elapsed = time.monotonic() - start
        print(name, "bytes", total, "seconds", round(elapsed,1), "MiB/s", round(total/1048576/elapsed,2), flush=True)
    except Exception as exc:
        print(name, type(exc).__name__, "elapsed", round(time.monotonic()-start,1), flush=True)
