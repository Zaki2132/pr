import pandas as pd
import ast

# 1. Lecture des fichiers
assets = pd.read_csv('dim_assets.csv', dtype={'history': str})
scans  = pd.read_csv('dim_scans.csv', dtype={'scanName': str})

# 2. Parse the JSON-like history column
# On transforme la chaîne en liste de dicts Python
assets['history_list'] = assets['history'].apply(ast.literal_eval)

# 3. Exploser les historiques pour avoir une ligne par scanId
hist = assets[['id', 'history_list']].explode('history_list')
# Récupérer les colonnes date et scanId
hist = pd.concat([
    hist.drop(columns='history_list'),
    pd.json_normalize(hist['history_list'])
], axis=1).rename(columns={'id': 'assetId', 'date': 'scanDate', 'scanId': 'scanId'})

# 4. Jointure avec dim_scans
# Convertir les dates en datetime pandas en traitant le 'Z'
hist['scanDate'] = pd.to_datetime(hist['scanDate'], utc=True)
scans['startTime'] = pd.to_datetime(scans['startTime'], utc=True)

# Joindre sur les IDs
df = hist.merge(scans, left_on='scanId', right_on='id', how='left',
                suffixes=('_hist', '_scan'))

# 5. Filtrer et agréger
# Définir un marqueur de type
df['type_scan'] = df['scanName'].str.lower().apply(
    lambda x: 'vuln' if 'vuln' in x else ('auth' if ('auth' in x or 'unauth' in x) else None)
)

# Ne garder que vulnéré + auth/unauth
df2 = df[df['type_scan'].isin(['vuln', 'auth'])]

# Pour chaque asset et chaque type, prendre la date max
result = (
    df2.groupby(['assetId', 'type_scan'])
       .agg(last_scan=('scanDate', 'max'))
       .reset_index()
       .pivot(index='assetId', columns='type_scan', values='last_scan')
       .reset_index()
       .rename(columns={'auth': 'last_auth_scan',
                        'vuln': 'last_vuln_scan'})
)

# Afficher le résultat
print(result)
