import io
import urllib.error

import intel_lookup


def test_normalize_deep_answer_accepts_inline_sections():
    answer = intel_lookup._normalize_deep_answer(
        "【定性】可疑外联，中置信度。【依据】本地未命中，缺少流量证据。"
        "【处置】核查目的地址与进程，并保留流量日志。"
    )
    assert "【定性】可疑外联" in answer
    assert "【依据】本地未命中" in answer
    assert "【处置】核查目的地址" in answer


def test_normalize_deep_answer_accepts_json_aliases():
    answer = intel_lookup._normalize_deep_answer(
        '{"classification":"疑似恶意","evidence":["命中本地 IOC"],'
        '"recommendation":"隔离主机并核查告警"}'
    )
    assert "【定性】疑似恶意" in answer
    assert "【依据】命中本地 IOC" in answer
    assert "【处置】隔离主机" in answer


def test_otx_reads_nested_pulses(monkeypatch):
    monkeypatch.setattr(intel_lookup, "_env_or_dotenv", lambda key, default="": "test-key" if key == "OTX_KEY" else "")
    monkeypatch.setattr(intel_lookup, "_fetch", lambda *args, **kwargs: {
        "pulse_info": {"pulses": [{"name": "fixture pulse"}]}
    })
    intel_lookup._reputation_cache.clear()

    result = intel_lookup._reputation("8.8.8.8", "ip")

    assert result["hit"] is True
    assert result["sources"] == ["AlienVault OTX"]
    assert result["detail"][0]["matched"] == "fixture pulse"


def test_otx_400_message_describes_bad_indicator_not_proxy(monkeypatch):
    def fail(*args, **kwargs):
        raise urllib.error.HTTPError("https://otx.invalid", 400, "Bad Request", {}, io.BytesIO(b"bad indicator"))

    monkeypatch.setattr(intel_lookup, "_env_or_dotenv", lambda key, default="": "test-key" if key == "OTX_KEY" else "")
    monkeypatch.setattr(intel_lookup, "_fetch", fail)
    intel_lookup._reputation_cache.clear()

    result = intel_lookup._reputation("not-an-ip", "ip")

    assert "不接受该指标格式或类型" in result["detail"][0]["matched"]
    assert "代理" not in result["detail"][0]["matched"]
