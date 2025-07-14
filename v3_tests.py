import pandas as pd
import ast

# Charger les fichiers CSV
dim_assets = pd.read_csv('dim_assets.csv')
dim_scans = pd.read_csv('dim_scans.csv')

# Fonction pour parser la colonne history (liste de dicts au format texte)
def parse_history(history_str):
    try:
        return ast.literal_eval(history_str)
    except Exception:
        return []

# Développer la colonne history en DataFrame individuelle
hist_df = dim_assets[['id', 'history']].copy()
hist_df['history_list'] = hist_df['history'].apply(parse_history)
hist_exploded = hist_df.explode('history_list').dropna(subset=['history_list']).reset_index(drop=True)
hist_exploded['scanId'] = hist_exploded['history_list'].apply(lambda x: x.get('scanId'))
hist_exploded['scanDate'] = hist_exploded['history_list'].apply(lambda x: x.get('date'))
# Conversion en datetime
hist_exploded['scanDate'] = pd.to_datetime(hist_exploded['scanDate'])

# Faire la jointure avec dim_scans pour récupérer scanName, endTime, etc.
merged = hist_exploded.merge(dim_scans, left_on='scanId', right_on='id', suffixes=('_asset', '_scan'))

# Définir les filtres pour vulnérabilité et auth/unauth scans
vuln_pattern = r'VUN|Vuln|vulnerability|vuln'
auth_pattern = r'Auth|Unauth'

vuln_scans = merged[merged['scanName'].str.contains(vuln_pattern, case=False, na=False)]
auth_scans = merged[merged['scanName'].str.contains(auth_pattern, case=False, na=False)]

# Sélectionner le dernier scan par asset (scanDate le plus récent)
last_vuln = vuln_scans.sort_values('scanDate').groupby('id_asset').tail(1)
last_auth = auth_scans.sort_values('scanDate').groupby('id_asset').tail(1)

# Construire le DataFrame final des résultats
result = pd.DataFrame({'asset_id': dim_assets['id'].unique()})

result = result.merge(
    last_vuln[['id_asset', 'scanId', 'scanName', 'scanDate']],
    left_on='asset_id', right_on='id_asset', how='left'
).rename(columns={
    'scanId': 'last_vuln_scanId',
    'scanName': 'last_vuln_scanName',
    'scanDate': 'last_vuln_date'
}).drop(columns=['id_asset'])

result = result.merge(
    last_auth[['id_asset', 'scanId', 'scanName', 'scanDate']],
    left_on='asset_id', right_on='id_asset', how='left'
).rename(columns={
    'scanId': 'last_auth_scanId',
    'scanName': 'last_auth_scanName',
    'scanDate': 'last_auth_date'
}).drop(columns=['id_asset'])

# Enregistrer le résultat et l'afficher
result.to_csv('last_scans_per_asset.csv', index=False)
print(result)
