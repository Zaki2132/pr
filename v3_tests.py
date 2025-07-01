import requests
import json
from urllib.parse import urljoin

# —— CONFIGURE THESE —————————————————————————————————————————————
INSTANCE    = "https://<your-instance>.cloud.rapid7.com"  # e.g. https://mycompany.cloud.rapid7.com
USERNAME    = "YOUR_USERNAME"
PASSWORD    = "YOUR_PASSWORD"
OUTPUT_FILE = "all_assets.json"
PAGE_SIZE   = 500  # the maximum page size allowed by the API
# ————————————————————————————————————————————————————————————————

session = requests.Session()
session.auth = (USERNAME, PASSWORD)
session.headers.update({"Accept": "application/json"})

all_assets = []
next_url   = f"{INSTANCE}/api/3/assets?page[size]={PAGE_SIZE}"

while next_url:
    resp = session.get(next_url)
    resp.raise_for_status()
    data = resp.json()

    # 1) collect this page’s resources
    assets = data.get("resources", [])
    all_assets.extend(assets)

    # 2) figure out if there’s another page
    links    = data.get("_links", {})
    next_rel = links.get("next", {}).get("href")
    if next_rel:
        # the href is usually relative, so build the absolute URL
        next_url = urljoin(INSTANCE, next_rel)
    else:
        next_url = None

# 3) write them all out
with open(OUTPUT_FILE, "w") as f:
    json.dump(all_assets, f, indent=2)

print(f"Fetched {len(all_assets)} assets → {OUTPUT_FILE}")
