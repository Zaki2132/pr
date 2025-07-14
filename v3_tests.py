```python
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
extract_last_scans.py

Ce script :
 1. Lit les CSV dim_assets.csv et dim_scans.csv
 2. Parse la colonne `history` (liste de dicts)  
 3. Joint avec dim_scans pour récupérer les détails des scans
 4. Filtre les scans de vulnérabilité et les scans auth/unauth
 5. Sélectionne le scan le plus récent de chaque catégorie par asset
 6. Exporte le résultat dans last_scans_per_asset.csv
"""

import pandas as pd
import ast
import sys


def parse_history(history_str):
    """
    Transforme la chaîne history (liste de dicts au format Python) en liste de dict.
    """
    try:
        return ast.literal_eval(history_str)
    except Exception:
        return []


def main():
    # Chargement des fichiers CSV
    try:
        dim_assets = pd.read_csv('dim_assets.csv')
        dim_scans = pd.read_csv('dim_scans.csv')
    except FileNotFoundError as e:
        print(f"Erreur : CSV non trouvé - {e}")
        sys.exit(1)

    # Extraction et parsing de la colonne history
    hist_df = dim_assets[['id', 'history']].copy()
    hist_df['history_list'] = hist_df['history'].apply(parse_history)

    # Explosion en lignes individuelles
    hist_exploded = hist_df.explode('history_list').dropna(subset=['history_list']).reset_index(drop=True)
    hist_exploded['scanId'] = hist_exploded['history_list'].apply(lambda x: x.get('scanId'))
    hist_exploded['scanDate'] = hist_exploded['history_list'].apply(lambda x: x.get('date'))

    # Conversion en datetime (inférence de format pour gérer les millis ou pas)
    hist_exploded['scanDate'] = pd.to_datetime(
        hist_exploded['scanDate'],
        infer_datetime_format=True,
        utc=True
    )

    # Jointure pour récupérer scanName, vulnerabilities, etc.
    merged = hist_exploded.merge(
        dim_scans,
        left_on='scanId',
        right_on='id',
        suffixes=('_asset', '_scan')
    )

    # Patterns pour filtrer
    vuln_pattern = r'VUN|Vuln|vulnerability|vuln'
    auth_pattern = r'Auth|Unauth'

    vuln_scans = merged[merged['scanName'].str.contains(vuln_pattern, case=False, na=False)]
    auth_scans = merged[merged['scanName'].str.contains(auth_pattern, case=False, na=False)]

    # Sélection du dernier scan de chaque type par asset
    last_vuln = (
        vuln_scans
        .sort_values('scanDate')
        .groupby('id_asset', as_index=False)
        .tail(1)
    )
    last_auth = (
        auth_scans
        .sort_values('scanDate')
        .groupby('id_asset', as_index=False)
        .tail(1)
    )

    # Construction du DataFrame résultat
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

    # Enregistrement et affichage
    output_file = 'last_scans_per_asset.csv'
    result.to_csv(output_file, index=False)
    print(f"Export terminé : {output_file}")
    print(result)


if __name__ == '__main__':
    main()
```
