import requests
from requests.auth import HTTPBasicAuth
import json
import pandas as pd

# 1) Fetch paginated data of a given type
def get_data_from_url(type_data):
    all_data = []
    user = "fkjsdbff"
    pw   = "kjsdbvnkjsbd_"
    BASE_URL = "https://rapid7.ctdi.eu/api/3"
    auth1 = HTTPBasicAuth(user, pw)
    url = f"{BASE_URL}/{type_data}"
    
    while url:
        response = requests.get(url, auth=auth1, headers=HEADERS, verify=False)
        data = response.json()
        batch = data.get("resources", [])
        all_data.extend(batch)
        print(f"{len(batch)} added (Total: {len(all_data)})")
        # find next link
        url = next((l["href"] for l in data.get("links",[]) if l.get("rel")=="next"), None)
    return all_data

# 2) (Optional) Filter assets by whatever criteria you choose
def filter_assets(assets):
    """
    Return only those assets that match your conditions.
    E.g.: return [a for a in assets if a.get('status')=='active']
    """
    filtered = []
    for asset in assets:
        # ---- your filter condition here ----
        if True:  
            filtered.append(asset)
    return filtered

# 3) Process each asset (same as your 2nd script)
def process_assets(data):
    processed = []
    for asset in data:
        asset_copy = {k:v for k,v in asset.items()
                      if k not in ['history','links','configurations','userGroups','files','addresses']}
        # services
        services = [
            {k:v for k,v in svc.items() if k in ['name','port','protocol']}
            for svc in asset.get('services',[])
        ]
        asset_copy['services'] = services
        # software
        software = [
            {'id':sw['id']} for sw in asset.get('software',[])
            if 'id' in sw
        ]
        asset_copy['software'] = software
        processed.append(asset_copy)
    return processed

def main():
    # fetch all assets
    assets = get_data_from_url('assets')
    
    # filter them—► you tell me the exact criteria
    assets = filter_assets(assets)
    
    # process & dump out
    processed = process_assets(assets)
    pd.json_normalize(processed).to_csv('assets_r7_v3.csv', index=False)
    with open('v3_assets_processed_2.json','w') as f:
        json.dump(processed, f, indent=2, ensure_ascii=False)

if __name__ == '__main__':
    main()
