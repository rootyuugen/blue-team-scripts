from pathlib import Path

import analyzer

SAMPLES = Path(__file__).resolve().parent.parent / "email-header-analyzer" / "samples"


def _report(name):
    return analyzer.analyze(analyzer.load_message(str(SAMPLES / name)))


def test_phishing_sample_is_high_risk():
    r = _report("phishing_sample.eml")
    titles = {f.title for f in r.findings}
    assert r.risk == "HIGH"
    assert r.spf == "softfail" and r.dmarc == "fail"
    assert r.origin_ip == "45.142.212.61"
    assert "Display name contém outro e-mail" in titles
    assert "Reply-To aponta para outro domínio" in titles


def test_legit_sample_is_low_risk():
    r = _report("legit_sample.eml")
    assert r.risk == "LOW"
    assert r.findings == []
    assert r.dkim_domain == "empresa-exemplo.com.br"


def test_hops_are_chronological():
    r = _report("phishing_sample.eml")
    assert r.hops[0].from_host == "localhost"
    assert r.hops[-1].by_host == "mbx01.empresa-exemplo.com.br"
    assert r.hops[1].delay_seconds == 9


def test_org_domain_alignment():
    assert analyzer.aligned("mail.empresa.com.br", "empresa.com.br")
    assert not analyzer.aligned("empresa.com.br", "outra.com.br")
