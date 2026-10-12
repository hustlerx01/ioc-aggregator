# Interview talking points: ioc-aggregator

1. **The pipeline.** Parse, normalise, validate, allow-list, de-dupe, score, export. Most of the value is in normalisation: lowercase hosts, refang, strip `ip:port`, lowercase hashes. Without it, de-duplication misses.
2. **Why not just block everything?** 73 IOCs were bare domains on shared platforms (workers.dev, GitHub, Google Drive). Blocking `github.com` takes out engineering. I keep the *specific URL* and drop the bare domain.
3. **Confidence.** I start from the feed's own confidence (ThreatFox's `confidence_level`, online/offline status), then add +10 if the IOC appears in more than one feed or if a URL's host is itself listed. Only 12 of 43k IOCs were multi-feed, so free feeds rarely overlap.
4. **Feed quality is a finding.** Feodo hadn't updated since March. A TI pipeline needs health checks (staleness, row-count drop alerts), not just parsing.
5. **STIX 2.1.** Indicator objects with `[url:value = '...']` / `[file:hashes.'SHA-256' = '...']` patterns, confidence, labels and created_by Identity. I can explain SDOs vs SCOs and why TAXII exists for distribution.
6. **The bug.** `ipaddress.is_private` is True for RFC 5737 ranges on Python 3.13, so my fixtures vanished. It's the same root cause as in L1-Copilot, so now I write a regression test for it every time.
7. **Next.** Ageing/expiry, a Tranco allow-list, MISP push, and feeding this list into soar-mini as an offline enrichment source.
