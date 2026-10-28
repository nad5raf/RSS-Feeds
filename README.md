# Threat Feed site

Run locally:   python3 build_site.py   then   cd site && python3 -m http.server 8000   (open http://localhost:8000)
Publish:       push this folder to a GitHub repo, enable Settings > Pages > Source: GitHub Actions.
               The workflow rebuilds every 30 minutes.
New feeds:     site/feed.xml (BleepingComputer).
Edit sources:  SOURCES list at the top of build_site.py.
