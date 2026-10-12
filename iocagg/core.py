"""Normalise, validate, allow-list, de-duplicate and merge IOCs across feeds; export CSV/STIX."""
import csv, ipaddress, json, re, urllib.parse
from collections import Counter

ALLOW_DOMAINS = {"github.com", "raw.githubusercontent.com", "drive.google.com", "docs.google.com", "dropbox.com",
                 "dl.dropboxusercontent.com", "onedrive.live.com", "1drv.ms", "discord.com", "cdn.discordapp.com",
                 "pastebin.com", "workers.dev", "pages.dev", "trycloudflare.com", "bitbucket.org", "gitlab.com"}
HASH = {"sha256": re.compile(r"^[a-f0-9]{64}$"), "md5": re.compile(r"^[a-f0-9]{32}$")}
DOMAIN = re.compile(r"^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$")


def normalise(i):
    v = i["value"].strip()
    t = i["type"]
    if t == "url":
        v = v.replace("hxxp", "http").replace("[.]", ".")
        u = urllib.parse.urlsplit(v)
        if u.scheme not in ("http", "https") or not u.hostname: return None
        v = urllib.parse.urlunsplit((u.scheme, u.netloc.lower(), u.path or "/", u.query, ""))
    elif t == "domain":
        v = v.lower().rstrip(".")
        if not DOMAIN.match(v): return None
    elif t == "ipv4":
        try:
            a = ipaddress.ip_address(v)
        except ValueError:
            return None
        if a.version != 4 or a.is_private or a.is_loopback or a.is_reserved or a.is_multicast or a.is_unspecified: return None
        v = str(a)
    elif t in HASH:
        v = v.lower()
        if not HASH[t].match(v): return None
    else:
        return None
    return {**i, "value": v}


def host_of(i):
    if i["type"] == "url": return urllib.parse.urlsplit(i["value"]).hostname
    if i["type"] == "domain": return i["value"]
    return None


def allow_listed(i):
    h = host_of(i)
    if i["type"] == "domain" and h:
        return any(h == d or h.endswith("." + d) for d in ALLOW_DOMAINS)
    return False  # URLs on shared hosting stay (full URL is specific); only bare domains are dropped


def aggregate(raw_iter):
    stats = Counter()
    merged = {}
    for i in raw_iter:
        stats["raw"] += 1; stats[f"raw:{i['feed']}"] += 1
        n = normalise(i)
        if not n:
            stats["invalid"] += 1; continue
        if allow_listed(n):
            stats["allow_listed"] += 1; continue
        k = (n["type"], n["value"])
        if k in merged:
            m = merged[k]; stats["duplicates"] += 1
            m["feeds"] = sorted(set(m["feeds"]) | {n["feed"]})
            m["confidence"] = max(m["confidence"], n["confidence"])
            m["malware"] = m["malware"] or n["malware"]
            m["first_seen"] = min(filter(None, [m["first_seen"], n["first_seen"]]), default=None)
        else:
            merged[k] = {"type": n["type"], "value": n["value"], "feeds": [n["feed"]], "threat": n["threat"], "malware": n["malware"],
                         "first_seen": n["first_seen"], "confidence": n["confidence"]}
    # cross-type corroboration: URL host IP/domain also listed as an IOC elsewhere
    hosts = {v for (t, v) in merged if t in ("ipv4", "domain")}
    for (t, v), m in merged.items():
        if t == "url" and urllib.parse.urlsplit(v).hostname in hosts:
            m["corroborated_by_host"] = True; stats["url_host_corroborated"] += 1
    for m in merged.values():
        if len(m["feeds"]) > 1 or m.get("corroborated_by_host"):
            m["confidence"] = min(100, m["confidence"] + 10)
    stats["unique"] = len(merged)
    return sorted(merged.values(), key=lambda m: (m["type"], m["value"])), stats


def export_csv(iocs, path):
    with open(path, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=["type", "value", "feeds", "threat", "malware", "first_seen", "confidence"]); w.writeheader()
        for i in iocs: w.writerow({**{k: i.get(k) for k in w.fieldnames}, "feeds": ";".join(i["feeds"])})


PATTERN = {"ipv4": "ipv4-addr:value", "domain": "domain-name:value", "url": "url:value", "sha256": "file:hashes.'SHA-256'", "md5": "file:hashes.MD5"}


def export_stix(iocs, path, limit=None):
    import stix2
    ident = stix2.Identity(id="identity--0f4e6b2a-3c1d-5e7f-8a9b-1c2d3e4f5a6b", name="ioc-aggregator (lab)", identity_class="individual")
    objs = [ident]
    for i in (iocs[:limit] if limit else iocs):
        val = i["value"].replace("\\", "\\\\").replace("'", "\\'")
        objs.append(stix2.Indicator(name=f"{i['type']} {i['value'][:80]}", pattern=f"[{PATTERN[i['type']]} = '{val}']", pattern_type="stix",
                                    confidence=i["confidence"], created_by_ref=ident.id, indicator_types=["malicious-activity"],
                                    labels=sorted(filter(None, [i["threat"], i["malware"]])), description="sources: " + ",".join(i["feeds"])))
    b = stix2.Bundle(objects=objs)
    open(path, "w").write(b.serialize())
    return len(objs) - 1
