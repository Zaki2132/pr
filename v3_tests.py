import pandas as pd
import json
import numpy as np

def load_data(assets_csv: str, scans_csv: str,
              scan_id_col: str, scan_name_col: str, scan_date_col: str
             ) -> tuple[pd.DataFrame, pd.DataFrame]:
    """
    Charge le CSV des assets et renomme les colonnes clés de dim_scans
    pour unifier l'ID, le nom et la date du scan.
    :param assets_csv: chemin vers dim_assets.csv
    :param scans_csv:  chemin vers dim_scans.csv
    :param scan_id_col:   nom de la colonne d'ID de scan dans dim_scans
    :param scan_name_col: nom de la colonne de nom de scan dans dim_scans
    :param scan_date_col: nom de la colonne de date de scan dans dim_scans
    :return: (assets_df, scans_df_renamed)
    """
    assets = pd.read_csv(assets_csv)
    scans  = (pd.read_csv(scans_csv)
                .rename(columns={
                    scan_id_col:   "scan_id",
                    scan_name_col: "scan_name",
                    scan_date_col: "scan_date"
                }))
    return assets, scans


def extract_history(assets: pd.DataFrame,
                    id_col: str = "id",
                    history_col: str = "history"
                   ) -> pd.DataFrame:
    """
    Explose la colonne JSON-like 'history' en DataFrame avec colonnes
    ['asset_id','scan_id','scan_date'].
    :param assets: DataFrame des assets
    :param id_col: nom de la colonne identifiant l'asset
    :param history_col: nom de la colonne historique
    """
    records = []
    for _, row in assets.iterrows():
        raw = row[history_col]
        if pd.isna(raw) or not raw.strip():
            continue
        try:
            items = json.loads(raw.replace("'", '"'))
        except json.JSONDecodeError:
            continue
        for entry in items:
            sid = entry.get("scanId") or entry.get("scanID")
            if sid is None:
                continue
            try:
                sid = int(sid)
            except (ValueError, TypeError):
                continue
            dt = pd.to_datetime(entry.get("date"), errors="coerce")
            if pd.isna(dt):
                continue
            records.append({
                "asset_id": row[id_col],
                "scan_id":  sid,
                "scan_date": dt
            })
    return pd.DataFrame(records)


def merge_and_classify(hist: pd.DataFrame,
                       scans: pd.DataFrame
                      ) -> pd.DataFrame:
    """
    Joint l'historique explosé à dim_scans, puis classe chaque ligne
    en 'vuln' ou 'auth' selon le nom du scan.
    """
    df = hist.merge(scans, on="scan_id", how="left", validate="m:1")
    # Force scan_name en str pour éviter mix dtype
    df["scan_name"] = df["scan_name"].astype(str)
    # Regex pour vulnérabilité et auth/unauth
    vuln_re = r"(?i)\b(vuln|vulnerability|vun)\b"
    auth_re = r"(?i)\b(auth|unauth)\b"
    df["type"] = np.where(
        df["scan_name"].str.contains(vuln_re, regex=True, na=False),
        "vuln",
        np.where(
            df["scan_name"].str.contains(auth_re, regex=True, na=False),
            "auth",
            np.nan
        )
    )
    return df


def aggregate_latest(df: pd.DataFrame) -> pd.DataFrame:
    """
    Agrège pour garder la date max par asset_id et par type
    ('vuln' et 'auth') et retourne un DataFrame large.
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
                      id_col: str = "id"
                     ) -> pd.DataFrame:
    """
    Ajoute les colonnes 'last_vuln_scan' et
    'last_auth_or_unauth_scan' dans le DataFrame assets.
    """
    return assets.merge(
        latest,
        left_on=id_col,
        right_on="asset_id",
        how="left",
        validate="1:1"
    )


def compute_asset_scan_dates(assets_csv: str,
                             scans_csv: str,
                             scan_id_col: str = "id",
                             scan_name_col: str = "scanName",
                             scan_date_col: str = "startTime"
                            ) -> pd.DataFrame:
    """
    Lit, transforme et agrège les données pour retourner le DataFrame final
    contenant dim_assets + 'last_vuln_scan' et 'last_auth_or_unauth_scan'.
    Les paramètres scans_* doivent correspondre aux colonnes de dim_scans.
    """
    assets, scans = load_data(
        assets_csv, scans_csv,
        scan_id_col, scan_name_col, scan_date_col
    )
    hist   = extract_history(assets)
    merged = merge_and_classify(hist, scans)
    latest = aggregate_latest(merged)
    return merge_into_assets(assets, latest)


if __name__ == "__main__":
    df_final = compute_asset_scan_dates(
        "dim_assets.csv",
        "dim_scans.csv",
        scan_id_col="id",
        scan_name_col="scanName",
        scan_date_col="startTime"
    )
    print(df_final[["id", "last_vuln_scan", "last_auth_or_unauth_scan"]])
