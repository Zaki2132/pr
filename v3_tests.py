import pandas as pd
import ast

def main():
    # 1) Charger les CSV (adapter les chemins si besoin)
    assets = pd.read_csv('dim_assets.csv', dtype={'history': str})
    scans  = pd.read_csv('dim_scans.csv', dtype={'scanName': str})

    # 2) Transformer la colonne history en liste de dicts Python
    assets['history_list'] = assets['history'].apply(ast.literal_eval)

    # 3) Exploser la liste pour avoir une ligne par événement d'historique
    hist = (
        assets[['id', 'history_list']]
        .explode('history_list')
        .reset_index(drop=True)  # <— indispensable pour un index unique
    )

    # 4) Séparer les clés du dict (date, scanId, type, version…) en colonnes
    hist = pd.concat([
        hist.drop(columns='history_list'),
        pd.json_normalize(hist['history_list'])
    ], axis=1).rename(columns={
        'id':       'assetId',
        'date':     'scanDate',
        'scanId':   'scanId',
        'type':     'histType',
        'version':  'histVersion'
    })

    # 5) Conversion des dates en datetime pandas (UTC)
    hist['scanDate']    = pd.to_datetime(hist['scanDate'], utc=True)
    scans['startTime']  = pd.to_datetime(scans['startTime'], utc=True)
    scans['endTime']    = pd.to_datetime(scans['endTime'], utc=True)

    # 6) Jointure historique ↔ dim_scans sur scanId
    df = hist.merge(
        scans,
        left_on='scanId',
        right_on='id',
        how='left',
        suffixes=('_hist', '_scan')
    )

    # 7) Détecter les scans vulnérabilité vs auth/unauth
    def classify(name: str) -> str:
        if not isinstance(name, str):
            return None
        low = name.lower()
        if 'vuln' in low or 'vun' in low:
            return 'vuln'
        if 'auth' in low or 'unauth' in low:
            return 'auth'
        return None

    df['type_scan'] = df['scanName'].apply(classify)

    # 8) Filtrer seulement vuln + auth
    df2 = df[df['type_scan'].isin(['vuln', 'auth'])].copy()

    # 9) Pour chaque asset et chaque type, prendre la date la plus récente
    summary = (
        df2.groupby(['assetId', 'type_scan'])
           .agg(last_scanDate=('scanDate', 'max'))
           .reset_index()
           .pivot(
               index='assetId',
               columns='type_scan',
               values='last_scanDate'
           )
           .rename(columns={
               'vuln': 'last_vuln_scan',
               'auth': 'last_auth_scan'
           })
           .reset_index()
    )

    # 10) (Optionnel) Joindre cette synthèse à dim_assets d’origine
    result = assets.merge(
        summary,
        left_on='id',
        right_on='assetId',
        how='left'
    )

    # 11) Sauvegarder ou afficher
    result.to_csv('assets_with_last_scans.csv', index=False)
    print(result[['id', 'last_vuln_scan', 'last_auth_scan']].head())

if __name__ == '__main__':
    main()
