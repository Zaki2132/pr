import pandas as pd
import ast

# 1. Chargement
assets = pd.read_csv("dim_assets.csv")
scans  = pd.read_csv("dim_scans.csv")

# Parser la colonne history
assets["history_list"] = assets["history"].apply(ast.literal_eval)

# 2. Aplatir l’historique
records = []
for _, row in assets.iterrows():
    aid = row["id"]
    for entry in row["history_list"]:
        # on convertit en datetime UTC en gérant le 'Z'
        records.append({
            "asset_id": aid,
            "scanId": entry["scanId"],
            "scan_date": pd.to_datetime(entry["date"], utc=True)
        })
hist = pd.DataFrame(records)

# Merge avec dim_scans
hist = (
    hist
    .merge(scans, left_on="scanId", right_on="id", how="left")
    .rename(columns={"scan_date": "date"})
)

# 3. Masques pour vulnérabilités et auth/unauth
mask_vuln = hist["scanName"].str.contains(
    r"Vuln|VUN|Vulnerability|audit", case=False, na=False
)
mask_auth = hist["scanName"].str.contains(
    r"Auth|Unauth", case=False, na=False
)

# Dernier scan vulnérabilité par asset
last_vuln = (
    hist[mask_vuln]
    .sort_values(["asset_id", "date"])
    .groupby("asset_id", as_index=False)
    .last()[["asset_id", "scanId", "scanName", "date"]]
    .set_index("asset_id")
)

# Dernier scan auth/unauth par asset
last_auth = (
    hist[mask_auth]
    .sort_values(["asset_id", "date"])
    .groupby("asset_id", as_index=False)
    .last()[["asset_id", "scanId", "scanName", "date"]]
    .set_index("asset_id")
)

# Résultat final
result = last_vuln.join(
    last_auth,
    lsuffix="_vuln",
    rsuffix="_auth",
    how="outer"
).reset_index()

print(result)
