"""Public feed definitions + parsers. Each parser yields normalised IOC dicts:
{type: ipv4|domain|url|sha256|md5, value, feed, threat, malware, first_seen, confidence}"""
import csv, io

FEEDS = {
    "feodo": "https://feodotracker.abuse.ch/downloads/ipblocklist.csv",
    "urlhaus": "https://urlhaus.abuse.ch/downloads/csv_recent/",
    "threatfox": "https://threatfox.abuse.ch/export/csv/recent/",
    "openphish": "https://openphish.com/feed.txt",
    "blocklist_de_ssh": "https://lists.blocklist.de/lists/ssh.txt",
}


def _csv(text):
    lines = [l for l in text.splitlines() if l.strip() and not l.startswith("#")]
    return csv.reader(io.StringIO("\n".join(lines)), skipinitialspace=True)


def parse_feodo(text):
    for r in _csv(text):
        if r[0] == "first_seen_utc": continue
        yield {"type": "ipv4", "value": r[1], "feed": "feodo", "threat": "botnet_cc", "malware": r[5], "first_seen": r[0], "confidence": 90 if r[3] == "online" else 60}


def parse_urlhaus(text):
    for r in _csv(text):
        yield {"type": "url", "value": r[2], "feed": "urlhaus", "threat": r[5], "malware": None if r[6] == "None" else r[6], "first_seen": r[1], "confidence": 80 if r[3] == "online" else 50}


TF_TYPES = {"ip:port": "ipv4", "domain": "domain", "url": "url", "sha256_hash": "sha256", "md5_hash": "md5"}


def parse_threatfox(text):
    for r in _csv(text):
        t = TF_TYPES.get(r[3])
        if not t: continue
        v = r[2].rsplit(":", 1)[0] if r[3] == "ip:port" else r[2]
        yield {"type": t, "value": v, "feed": "threatfox", "threat": r[4], "malware": r[7], "first_seen": r[0], "confidence": int(r[9] or 50)}


def parse_lines(feed, typ, threat, conf):
    def p(text):
        for l in text.splitlines():
            l = l.strip()
            if l and not l.startswith("#"):
                yield {"type": typ, "value": l, "feed": feed, "threat": threat, "malware": None, "first_seen": None, "confidence": conf}
    return p


PARSERS = {"feodo": parse_feodo, "urlhaus": parse_urlhaus, "threatfox": parse_threatfox,
           "openphish": parse_lines("openphish", "url", "phishing", 70),
           "blocklist_de_ssh": parse_lines("blocklist_de_ssh", "ipv4", "ssh_bruteforce", 40)}
