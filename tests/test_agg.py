import json
from pathlib import Path
from iocagg.cli import main
from iocagg.core import normalise

FX = Path(__file__).parent / "fixtures"


def run(tmp):
    main(["--raw", str(FX), "-o", str(tmp)])
    return json.load(open(tmp / "summary.json")), (tmp / "iocs.csv").read_text()


def test_dedupe_and_merge_across_feeds(tmp_path):
    s, csv = run(tmp_path)
    line = [l for l in csv.splitlines() if l.startswith("ipv4,162.243.103.246,")][0]
    assert "blocklist_de_ssh;feodo;threatfox" in line and line.endswith(",100")
    assert s["stats"]["duplicates"] >= 3


def test_invalid_private_and_allowlisted_dropped(tmp_path):
    s, csv = run(tmp_path)
    assert "10.0.0.1" not in csv and "not a url" not in csv and "not-an-ip" not in csv
    assert "x.workers.dev" not in csv            # shared hosting domain dropped
    assert "https://github.com/evil/repo/raw/main/x.exe" in csv  # specific URL kept, host lowercased
    assert s["stats"]["invalid"] == 4 and s["stats"]["allow_listed"] == 1


def test_url_corroborated_by_host(tmp_path):
    s, _ = run(tmp_path)
    assert s["stats"]["url_host_corroborated"] == 2   # urlhaus URL on listed IP, openphish URL on listed domain


def test_hash_lowercased_and_stix_valid(tmp_path):
    s, csv = run(tmp_path)
    assert "e3b0c442" in csv
    b = json.load(open(tmp_path / "iocs.stix.json"))
    pats = [o["pattern"] for o in b["objects"] if o["type"] == "indicator"]
    assert len(pats) == s["stats"]["unique"]
    assert any(p.startswith("[file:hashes.'SHA-256'") for p in pats)


def test_normalise_rejects_ipv6_and_bad_hash():
    assert normalise({"type": "ipv4", "value": "::1"}) is None
    assert normalise({"type": "md5", "value": "zz"}) is None


def test_rfc5737_documentation_ip_rejected():
    # Python 3.13 marks 198.51.100.0/24 is_private; a doc-range IP in a feed is junk, not intel
    assert normalise({"type": "ipv4", "value": "198.51.100.7"}) is None
