# Threat Feed site

Run locally:   python3 build_site.py   then   cd site && python3 -m http.server 8000   (open http://localhost:8000)
Publish:       push this folder to a GitHub repo, enable Settings > Pages > Source: GitHub Actions.
               The workflow rebuilds every 10 minutes.
New feeds:     site/feed.xml (all sources), site/kev.xml (CISA KEV), site/trending.xml (trending CVEs).
Edit sources:  SOURCES list at the top of build_site.py.
