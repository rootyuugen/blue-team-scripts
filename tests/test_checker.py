import checker


def test_classify():
    assert checker.classify("8.8.8.8") == "ip"
    assert checker.classify("2001:4860:4860::8888") == "ip"
    assert checker.classify("evil.com") == "domain"
    assert checker.classify("https://evil.com/x") == "url"
    assert checker.classify("44d88612fea8a8f36de82e1278abb02f") == "md5"
    assert checker.classify("a" * 40) == "sha1"
    assert checker.classify("a" * 64) == "sha256"
    assert checker.classify("not an ioc") is None


def test_refang_input():
    assert checker.refang("185.220.101[.]47") == "185.220.101.47"
    assert checker.refang("hxxps://evil[.]com") == "https://evil.com"


def test_private_ip():
    assert checker.is_private_ip("192.168.0.1")
    assert not checker.is_private_ip("8.8.8.8")


def test_verdict_rules():
    r = checker.Result("x", "ip")
    assert checker.compute_verdict(r) == "UNKNOWN"
    r.vt_malicious, r.abuse_score = 0, 0
    assert checker.compute_verdict(r) == "CLEAN"
    r.abuse_score = 30
    assert checker.compute_verdict(r) == "SUSPICIOUS"
    r.vt_malicious = 10
    assert checker.compute_verdict(r) == "MALICIOUS"


def test_no_api_keys_returns_error(monkeypatch):
    for key in ("VT_API_KEY", "ABUSEIPDB_API_KEY", "OTX_API_KEY"):
        monkeypatch.delenv(key, raising=False)
    assert checker.main(["8.8.8.8", "-q"]) == 2


def test_lookup_with_mocked_api(monkeypatch):
    monkeypatch.setenv("VT_API_KEY", "fake")
    monkeypatch.delenv("ABUSEIPDB_API_KEY", raising=False)
    monkeypatch.delenv("OTX_API_KEY", raising=False)

    class FakeResponse:
        status_code = 200

        def json(self):
            return {"data": {"attributes": {"last_analysis_stats": {
                "malicious": 12, "suspicious": 0, "harmless": 50, "undetected": 10}}}}

        def raise_for_status(self):
            pass

    monkeypatch.setattr(checker.requests.Session, "get", lambda *a, **k: FakeResponse())
    results = checker.check_iocs(["45.142.212.61"], delay=0, include_private=False, verbose=False)
    assert results[0].vt_malicious == 12
    assert results[0].verdict == "MALICIOUS"
