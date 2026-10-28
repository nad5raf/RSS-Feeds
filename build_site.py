#!/usr/bin/env python3
"""Builds a static site from security RSS feeds. Standard library only.

Outputs to ./site/:
  index.html      the reader page (from threat-feed.html)
  feeds-data.js   the fetched articles, read by the page
  feed.xml        NEW combined RSS feed of every source, newest first
  kev.xml         NEW RSS feed of the latest CISA KEV (CVE) additions

Usage:  python3 build_site.py
Env:    SITE_URL  public base URL, e.g. https://user.github.io/repo/  (used in feed links)
"""
import html, json, os, re, shutil, sys, time
import urllib.request
import xml.etree.ElementTree as ET
from datetime import datetime, timezone, timedelta
from email.utils import parsedate_to_datetime, format_datetime
from pathlib import Path
from xml.sax.saxutils import escape

SOURCES = [  # (id, display name, feed URL)
    ("bleeping",  "BleepingComputer",  "https://www.bleepingcomputer.com/feed/"),
    ("dark",      "Dark Reading",      "https://www.darkreading.com/rss.xml"),
    ("thn",       "The Hacker News",   "https://feeds.feedburner.com/TheHackersNews"),
]
KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
KEEP_DAYS = 7
MAX_ITEMS = 150
SITE_TITLE = "Threat Feed"
SITE_URL = os.environ.get("SITE_URL", "").rstrip("/") + ("/" if os.environ.get("SITE_URL") else "")
HERE = Path(__file__).parent
OUT = HERE / "site"
UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0 Safari/537.36"

def get(url):
    req = urllib.request.Request(url, headers={"User-Agent": UA, "Accept": "application/rss+xml, application/atom+xml, application/xml, text/xml, application/json, */*"})
    with urllib.request.urlopen(req, timeout=25) as r:
        return r.read()

def local(tag): return tag.rsplit("}", 1)[-1]
def clean(s): return re.sub(r"\s+", " ", html.unescape(re.sub(r"<[^>]+>", " ", s or ""))).strip()

def parse_date(s):
    s = (s or "").strip()
    try: d = parsedate_to_datetime(s)
    except Exception: d = datetime.fromisoformat(s.replace("Z", "+00:00"))
    return d if d.tzinfo else d.replace(tzinfo=timezone.utc)

def parse(raw, src):
    out = []
    for e in ET.fromstring(raw).iter():
        if local(e.tag) not in ("item", "entry"): continue
        f, link = {}, ""
        for c in e:
            n = local(c.tag)
            if n == "link":
                href = c.get("href")
                if href and c.get("rel") in (None, "alternate"): link = href
                elif c.text and not link: link = c.text.strip()
            elif n not in f: f[n] = c.text or ""
        date = f.get("pubDate") or f.get("published") or f.get("updated") or f.get("date")
        title = clean(f.get("title"))
        if not (title and link.startswith(("http://", "https://")) and date): continue
        try: d = parse_date(date)
        except Exception: continue
        out.append({"title": title, "link": link, "ts": int(d.timestamp() * 1000),
                    "desc": clean(f.get("description") or f.get("summary") or f.get("encoded"))[:320], "src": src})
    return out

def collect():
    cutoff = (datetime.now(timezone.utc) - timedelta(days=KEEP_DAYS)).timestamp() * 1000
    data = {"generated": int(time.time() * 1000), "sources": {}, "kev": []}
    for sid, _name, url in SOURCES:
        try:
            items = [i for i in parse(get(url), sid) if i["ts"] >= cutoff]
            data["sources"][sid] = {"ok": True, "items": items}
            print(f"ok    {sid:10} {len(items)} items")
        except Exception as e:
            data["sources"][sid] = {"ok": False, "error": f"{type(e).__name__}: {e}"[:160]}
            print(f"FAIL  {sid:10} {e}")
    try:
        v = json.loads(get(KEV_URL))["vulnerabilities"]
        v.sort(key=lambda x: x["dateAdded"], reverse=True)
        keys = ("cveID", "vendorProject", "product", "vulnerabilityName", "shortDescription", "requiredAction", "dueDate", "dateAdded", "knownRansomwareCampaignUse")
        data["kev"] = [{k: x.get(k) for k in keys} for x in v[:25]]
        print(f"ok    KEV        {len(data['kev'])} entries")
    except Exception as e:
        print(f"FAIL  KEV        {e}")
    return data

def rfc822(ms): return format_datetime(datetime.fromtimestamp(ms / 1000, timezone.utc))

def rss(title, desc, filename, items):
    """items: list of dicts with title, link, ts, desc, guid, category"""
    now = format_datetime(datetime.now(timezone.utc))
    self_link = f'<atom:link href="{escape(SITE_URL + filename)}" rel="self" type="application/rss+xml"/>' if SITE_URL else ""
    parts = ['<?xml version="1.0" encoding="UTF-8"?>',
             '<rss version="2.0" xmlns:atom="http://www.w3.org/2005/Atom"><channel>',
             f"<title>{escape(title)}</title><link>{escape(SITE_URL or 'https://example.invalid/')}</link>",
             f"<description>{escape(desc)}</description><language>en</language>",
             f"<lastBuildDate>{now}</lastBuildDate>", self_link]
    for i in items:
        parts.append("<item>"
            f"<title>{escape(i['title'])}</title><link>{escape(i['link'])}</link>"
            f"<guid isPermaLink=\"{'true' if i['guid'] == i['link'] else 'false'}\">{escape(i['guid'])}</guid>"
            f"<pubDate>{rfc822(i['ts'])}</pubDate><category>{escape(i['category'])}</category>"
            f"<description>{escape(i['desc'])}</description></item>")
    parts.append("</channel></rss>")
    (OUT / filename).write_text("\n".join(p for p in parts if p), encoding="utf-8")

def build(data):
    names = {sid: n for sid, n, _ in SOURCES}
    seen, items = set(), []
    for sid, d in data["sources"].items():
        if not d["ok"]: continue
        for i in d["items"]:
            if i["link"] in seen: continue
            seen.add(i["link"])
            items.append({"title": f"[{names[sid]}] {i['title']}", "link": i["link"], "ts": i["ts"],
                          "desc": i["desc"], "guid": i["link"], "category": names[sid]})
    items.sort(key=lambda x: x["ts"], reverse=True)
    items = items[:MAX_ITEMS]

    OUT.mkdir(exist_ok=True)
    rss(SITE_TITLE, "Combined cybersecurity news from BleepingComputer, Dark Reading and The Hacker News.", "feed.xml", items)

    kev_items = []
    for v in data["kev"]:
        ts = int(datetime.strptime(v["dateAdded"], "%Y-%m-%d").replace(tzinfo=timezone.utc).timestamp() * 1000)
        extra = " Known ransomware campaign use." if v.get("knownRansomwareCampaignUse") == "Known" else ""
        kev_items.append({"title": f"{v['cveID']}: {v['vendorProject']} {v['product']}",
                          "link": "https://nvd.nist.gov/vuln/detail/" + v["cveID"], "ts": ts, "guid": v["cveID"],
                          "category": "CISA KEV",
                          "desc": clean(f"{v.get('vulnerabilityName') or ''}. {v.get('shortDescription') or ''} Action: {v.get('requiredAction') or ''} Due: {v.get('dueDate') or ''}.{extra}")})
    if kev_items:
        rss(SITE_TITLE + ": CISA KEV", "Latest additions to the CISA Known Exploited Vulnerabilities catalog.", "kev.xml", kev_items)

    (OUT / "feeds-data.js").write_text("window.FEED_DATA = " + json.dumps(data) + ";\n", encoding="utf-8")

    page = (HERE / "threat-feed.html").read_text(encoding="utf-8")
    page = page.replace("</head>", '<link rel="alternate" type="application/rss+xml" title="Threat Feed" href="feed.xml">\n'
                        '<link rel="alternate" type="application/rss+xml" title="CISA KEV" href="kev.xml">\n'
                        '<style>a.btn{font:500 13px var(--sans);color:var(--text);background:var(--panel);border:1px solid var(--line);border-radius:6px;padding:7px 12px}a.btn:hover{background:var(--panel-2)}</style>\n</head>', 1)
    subs = '<a class="btn" href="feed.xml">RSS: all feeds</a><a class="btn" href="kev.xml">RSS: KEV</a>'
    page = page.replace('<button id="refresh">Refresh</button>', subs + '<button id="refresh">Refresh</button>', 1)
    (OUT / "index.html").write_text(page, encoding="utf-8")
    print(f"wrote {OUT}/ ({len(items)} items in feed.xml)")

if __name__ == "__main__":
    data = collect()
    if not any(d["ok"] for d in data["sources"].values()):
        sys.exit("All sources failed; not writing a site.")
    build(data)
