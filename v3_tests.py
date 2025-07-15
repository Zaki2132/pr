import pandas as pd
import ast
import re
import ace_tools as tools

# 1. Chargement des fichiers CSV
assets = pd.read_csv('dim_assets.csv')
scans = pd.read_csv('dim_scans.csv', parse_dates=['startTime', 'endTime'])
scans = scans.rename(columns={'id': 'scan_id'})

# 2. Parsing et explosion de la colonne 'history'
assets['history'] = assets['history'].apply(ast.literal_eval)
asset_scans = (
    assets[['id', 'history']]
    .explode('history')
    .rename(columns={'id': 'asset_id', 'history': 'scan_id'})
)

# 3. Jointure pour récupérer les données des scans
df = asset_scans.merge(scans, on='scan_id')

# 4. Catégorisation des scans
def categorize(name):
    if re.search(r'Vun|Vuln', name, re.I):
        return 'vuln'
    elif re.search(r'Auth|Unauth|Discovery', name, re.I):
        return 'discovery'
    else:
        return None

df['category'] = df['scanName'].apply(categorize)
df = df[df['category'].notnull()]

# 5. Sélection du scan le plus récent par asset et catégorie
latest = (
    df.sort_values('endTime')
      .groupby(['asset_id', 'category'], as_index=False)
      .last()
)

# 6. Pivot pour créer deux colonnes
pivot = latest.pivot(
    index='asset_id',
    columns='category',
    values='scan_id'
).rename(columns={
    'vuln': 'last_vulnerability_scan',
    'discovery': 'last_discovery_scan'
})

# 7. Fusion avec le DataFrame assets original
assets_updated = assets.merge(
    pivot,
    left_on='id',
    right_index=True,
    how='left'
)

# 8. Sauvegarde du nouveau CSV
output_path = '/mnt/data/dim_assets_updated.csv'
assets_updated.to_csv(output_path, index=False)

# 9. Affichage d'un aperçu
tools.display_dataframe_to_user('Aperçu des assets mis à jour', assets_updated.head())
