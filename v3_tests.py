import pandas as pd
import ast
import re

# 1. Chargement des fichiers
assets = pd.read_csv('dim_assets.csv')
scans  = pd.read_csv('dim_scans.csv', parse_dates=['startTime', 'endTime'])

# 2. Renommer l'ID de scan pour plus de clarté
scans.rename(columns={'id': 'scan_id'}, inplace=True)

# 3. Déserialisation de la colonne history et explosion en lignes asset↔scan
assets['history'] = assets['history'].apply(ast.literal_eval)
asset_scans = (
    assets[['id', 'history']]
    .explode('history')
    .rename(columns={'id': 'asset_id', 'history': 'scan_id'})
)

# 4. Uniformisation du type de scan_id en str pour éviter les conflits
asset_scans['scan_id'] = asset_scans['scan_id'].astype(str)
scans   ['scan_id'] = scans   ['scan_id'].astype(str)

# 5. Jointure pour récupérer les détails de chaque scan
df = asset_scans.merge(scans, on='scan_id', how='left')

# 6. S’assurer que scanName est une chaîne (remplace NaN par '')
df['scanName'] = df['scanName'].fillna('').astype(str)

# 7. Catégorisation en deux types de scan
def categorize(name: str) -> str | None:
    # si vide ou non-chaîne, on ignore
    if not name:
        return None
    # vulnérabilités : on inclut aussi les “Audit”
    if re.search(r'Vun|Vuln|Audit', name, re.IGNORECASE):
        return 'last_vulnerability_scan'
    # découverte/auth : Discovery, Auth, Unauth
    if re.search(r'Auth|Unauth|Discovery', name, re.IGNORECASE):
        return 'last_discovery_scan'
    return None

df['category'] = df['scanName'].apply(categorize)
df = df[df['category'].notna()]

# 8. Pour chaque asset_id + catégorie, ne garder que le scan le plus récent
latest = (
    df
    .sort_values('endTime')
    .groupby(['asset_id', 'category'], as_index=False)
    .last()
)

# 9. Pivot pour obtenir deux colonnes dans assets
pivot = latest.pivot(
    index='asset_id',
    columns='category',
    values='scan_id'
)

# 10. Fusionner dans le DataFrame assets original
assets_updated = assets.merge(
    pivot,
    left_on='id',
    right_index=True,
    how='left'
)

# 11. Sauvegarde du nouveau CSV
assets_updated.to_csv('dim_assets_updated.csv', index=False)
print("OK — généré → dim_assets_updated.csv")
