from pathlib import Path

import extractor

SAMPLE = Path(__file__).resolve().parent.parent / "ioc-extractor" / "samples" / "threat_report.txt"


def test_refang():
    assert extractor.refang("hxxps://evil[.]com/a") == "https://evil.com/a"
    assert extractor.refang("1.2.3[.]4") == "1.2.3.4"
    assert extractor.refang("user[at]evil[dot]com") == "user@evil.com"


def test_defang():
    assert extractor.defang("https://evil.com/path") == "hxxps://evil[.]com/path"
    assert extractor.defang("185.220.101.47") == "185.220.101[.]47"


def test_private_ips_filtered_by_default():
    iocs = extractor.extract("c2 8.8.4.4 interno 10.0.0.5 e 192.168.1.1")
    assert iocs["ipv4"] == ["8.8.4.4"]
    iocs = extractor.extract("10.0.0.5", include_private=True)
    assert iocs["ipv4"] == ["10.0.0.5"]


def test_filenames_and_header_tokens_are_not_domains():
    text = "abriu invoice.pdf e payload.exe; header.from=x smtp.mailfrom=y; evil-site.top"
    assert extractor.extract(text)["domain"] == ["evil-site.top"]


def test_hash_lengths():
    text = "a" * 32 + " " + "b" * 40 + " " + "c" * 64
    iocs = extractor.extract(text)
    assert iocs["md5"] == ["a" * 32]
    assert iocs["sha1"] == ["b" * 40]
    assert iocs["sha256"] == ["c" * 64]


def test_sample_report():
    iocs = extractor.extract(SAMPLE.read_text(encoding="utf-8"))
    assert set(iocs["ipv4"]) == {"185.220.101.47", "45.142.212.61"}
    assert "cdn-update.xyz" in iocs["domain"]
    assert "attack.mitre.org" not in iocs["domain"]
    assert set(iocs["cve"]) == {"CVE-2024-3400", "CVE-2021-26855"}
