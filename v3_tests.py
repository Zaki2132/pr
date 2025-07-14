import pandas as pd
import json
import numpy as np

def load_data(assets_csv: str, scans_csv: str) -> tuple[pd.DataFrame, pd.DataFrame]:
    """
    Charge les deux CSV.
    :param assets_csv: chemin vers dim_assets.csv
    :param scans_csv:  chemin vers dim_scans.csv
    :return: (assets_df, scans_df)
    """
    assets = pd.read_csv(assets_csv)
    scans  = pd.read_csv(scans_csv)
    return assets, scans

def extract_history(assets: pd.DataFrame,
                    id_col: str = "id",
                    history_col: str = "history") -> pd.DataFrame:
    """
    Transforme la colonne JSON-like 'history' en DataFrame exploded.
    :param assets: DataFrame des assets
    :param id_col: nom de la colonne identifiant l'asset
    :param history_col: nom de la colonne historique
    :return: DataFrame avec colonnes ['asset_id','scan_id','scan_date']
    """
    records = []
    for _, row in assets.iterrows():
        raw = row[history_col]
        if pd.isna(raw) or not raw.strip():
            continue
        try:
            items = json.loads(raw.replace("'", '"'))
        except json.JSONDecodeError:
            # si le JSON est malformé, on skip
            continue
        for entry in items:
            # Gestion des clés 'scanId' ou 'scanID'
            scan_id = entry.get("scanId") or entry.get("scanID")
            if scan_id is None:
                continue
            try:
                scan_id = int(scan_id)
            except (ValueError, TypeError):
                continue
            # Date du scan extraite de l'historique
            scan_date = pd.to_datetime(entry.get("date"), errors="coerce")
            if pd.isna(scan_date):
                continue
            records.append({
                "asset_id": row[id_col],
                "scan_id": scan_id,
                "scan_date": scan_date
            })
    return pd.DataFrame(records)

def merge_and_classify(hist: pd.DataFrame,
                       scans: pd.DataFrame,
                       name_col: str = "scan_name") -> pd.DataFrame:
    """
    Joint history exploded à dim_scans et ajoute une colonne 'type' ("vuln" ou "auth").
    :param hist: DataFrame exploded issu de extract_history
    :param scans: DataFrame dim_scans
    :param name_col: nom de la colonne de nom de scan
    :return: merged DataFrame avec colonne 'type'
    """
    df = hist.merge(scans, on="scan_id", how="left", validate="m:1")
    # Regex pour vulnérabilité et auth/unauth
    vuln_re = r"(?i)\b(vuln|vulnerability|vun)\b"
    auth_re = r"(?i)\b(auth|unauth)\b"
    df["type"] = np.where(
        df[name_col].str.contains(vuln_re, regex=True, na=False),
        "vuln",
        np.where(
            df[name_col].str.contains(auth_re, regex=True, na=False),
            "auth",
            np.nan
        )
    )
    return df

def aggregate_latest(df: pd.DataFrame) -> pd.DataFrame:
    """
    Agrège pour garder la date max par asset_id et par type.
    :param df: DataFrame issu de merge_and_classify
    :return: DataFrame wide ['asset_id','last_vuln_scan','last_auth_or_unauth_scan']
    """
    latest = (
        df.dropna(subset=["type"])
          .groupby(["asset_id","type"])["scan_date"]
          .max()
          .unstack(fill_value=pd.NaT)
          .reset_index()
          .rename(columns={
              "vuln": "last_vuln_scan",
              "auth": "last_auth_or_unauth_scan"
          })
    )
    return latest

def merge_into_assets(assets: pd.DataFrame,
                      latest: pd.DataFrame,
                      id_col: str = "id") -> pd.DataFrame:
    """
    Fusionne les dates calculées dans le DataFrame assets original.
    :param assets: DataFrame original
    :param latest: DataFrame wide des dates max
    :param id_col: nom de la colonne asset_id dans assets
    :return: DataFrame enrichi
    """
    return assets.merge(
        latest,
        left_on=id_col,
        right_on="asset_id",
        how="left",
        validate="1:1"
    )

def compute_asset_scan_dates(assets_csv: str, scans_csv: str) -> pd.DataFrame:
    """
    Point d'entrée : lit, transforme, agrège et retourne le DataFrame final.
    :param assets_csv: chemin vers dim_assets.csv
    :param scans_csv:  chemin vers dim_scans.csv
    :return: DataFrame de dim_assets + colonnes
             'last_vuln_scan' et 'last_auth_or_unauth_scan'
    """
    assets, scans = load_data(assets_csv, scans_csv)
    hist          = extract_history(assets)
    merged        = merge_and_classify(hist, scans)
    latest        = aggregate_latest(merged)
    result        = merge_into_assets(assets, latest)
    return result

# Exemple d'utilisation :
# df_final = compute_asset_scan_dates("dim_assets.csv", "dim_scans.csv")
# print(df_final[["id", "last_vuln_scan", "last_auth_or_unauth_scan"]])
