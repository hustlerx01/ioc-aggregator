import argparse, json, time, urllib.request
from pathlib import Path
from .feeds import FEEDS, PARSERS
from .core import aggregate, export_csv, export_stix


def fetch(name, url, raw_dir):
    p = Path(raw_dir) / f"{name}.txt"
    req = urllib.request.Request(url, headers={"User-Agent": "ioc-aggregator-lab/0.1 (portfolio project)"})
    p.write_bytes(urllib.request.urlopen(req, timeout=60).read())
    return p


def main(argv=None):
    ap = argparse.ArgumentParser(); ap.add_argument("--fetch", action="store_true", help="download feeds into --raw")
    ap.add_argument("--raw", default="data/raw"); ap.add_argument("-o", "--out", default="results"); ap.add_argument("--stix-limit", type=int, default=None)
    a = ap.parse_args(argv)
    Path(a.raw).mkdir(parents=True, exist_ok=True); out = Path(a.out); out.mkdir(exist_ok=True)
    timing = {}
    def gen():
        for name, url in FEEDS.items():
            p = Path(a.raw) / f"{name}.txt"
            if a.fetch:
                t = time.time()
                try: fetch(name, url, a.raw)
                except Exception as e: print(f"fetch {name} FAILED: {e}"); continue
                timing[name] = round(time.time() - t, 2)
            if p.exists():
                yield from PARSERS[name](p.read_text(errors="replace"))
    t0 = time.time()
    iocs, stats = aggregate(gen())
    export_csv(iocs, out / "iocs.csv")
    n = export_stix(iocs, out / "iocs.stix.json", a.stix_limit)
    by_type = {}
    for i in iocs: by_type[i["type"]] = by_type.get(i["type"], 0) + 1
    multi = sum(len(i["feeds"]) > 1 for i in iocs)
    summary = {"stats": dict(stats), "by_type": by_type, "multi_feed": multi, "stix_indicators": n, "fetch_seconds": timing, "total_seconds": round(time.time() - t0, 2)}
    json.dump(summary, open(out / "summary.json", "w"), indent=2)
    print(json.dumps(summary, indent=1))


if __name__ == "__main__":
    main()
