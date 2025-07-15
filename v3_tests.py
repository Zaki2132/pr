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

# 4. Uniformisation du type de scan_id pour éviter le ValueError
asset_scans['scan_id'] = pd.to_numeric(asset_scans['scan_id'],
                                       errors='raise',
                                       downcast='integer')
scans['scan_id'] = scans['scan_id'].astype('int64')

# 5. Jointure pour récupérer les détails de chaque scan
df = asset_scans.merge(scans, on='scan_id', how='left')

# 6. Catégorisation en deux types de scan
def categorize(name: str) -> str | None:
    if re.search(r'Vun|Vuln|Audit', name, re.IGNORECASE):
        return 'last_vulnerability_scan'
    elif re.search(r'Auth|Unauth|Discovery', name, re.IGNORECASE):
        return 'last_discovery_scan'
    else:
        return None

df['category'] = df['scanName'].apply(categorize)
df = df[df['category'].notna()]

# 7. Sélection du scan le plus récent par asset et catégorie
latest = (
    df
    .sort_values('endTime')
    .groupby(['asset_id', 'category'], as_index=False)
    .last()
)

# 8. Pivot pour passer de lignes “asset+cat” à deux colonnes
pivot = latest.pivot(
    index='asset_id',
    columns='category',
    values='scan_id'
)

# 9. Fusion avec le DataFrame assets d’origine
assets_updated = assets.merge(
    pivot,
    left_on='id',
    right_index=True,
    how='left'
)

# 10. Écriture du fichier CSV mis à jour
assets_updated.to_csv('dim_assets_updated.csv', index=False)
print("→ 'dim_assets_updated.csv' généré avec les colonnes last_vulnerability_scan et last_discovery_scan.")
