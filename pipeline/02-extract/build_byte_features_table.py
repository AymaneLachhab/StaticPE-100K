"""Generate complete CSV and LaTeX catalogs for byte_features columns."""

from pathlib import Path
import csv
import pyarrow.parquet as pq


ROOT = Path(__file__).resolve().parent
PARQUET = ROOT / "dataset" / "by_feature_group" / "byte_features.parquet"
OUT_CSV = ROOT / "dataset" / "byte_features_columns.csv"
OUT_TEX = ROOT / "dataset" / "byte_features_table.tex"
OUT_CSV_FR = ROOT / "dataset" / "byte_features_explanations_fr.csv"
OUT_TEX_FR = ROOT / "dataset" / "byte_features_explanations_fr.tex"
META = {"sha256", "raw_label", "category_label", "binary_label",
        "category_label_corrected", "label_type", "normalized_label",
        "alt_category_labels"}


def latex(value: str) -> str:
    return value.replace("\\", r"\textbackslash{}").replace("_", r"\_")


def main():
    columns = pq.read_schema(PARQUET).names
    if len(columns) != 521:
        raise ValueError(f"Expected 521 total columns, found {len(columns)}")

    rows = []
    rows_fr = []
    for index, name in enumerate(columns, 1):
        if name in META:
            family = "Metadata"
            descriptions = {
                "sha256": "SHA-256 identifier of the PE sample.",
                "raw_label": "Original label present in the source report.",
                "category_label": "Primary category label used for the dataset.",
                "binary_label": "Binary class label: benign or malicious.",
                "category_label_corrected": "Corrected capability-category label.",
                "label_type": "Label status: category, family, actor, review, or unknown.",
                "normalized_label": "Normalized form of the original label.",
                "alt_category_labels": "Additional category labels, when available.",
            }
            description = descriptions[name]
            family_fr = "Métadonnée"
            descriptions_fr = {
                "sha256": "Identifiant SHA-256 unique de l'échantillon PE.",
                "raw_label": "Étiquette originale du rapport source.",
                "category_label": "Étiquette de catégorie principale utilisée dans le jeu de données.",
                "binary_label": "Classe binaire : bénin ou malveillant.",
                "category_label_corrected": "Catégorie de capacité corrigée après normalisation des familles.",
                "label_type": "Type d'étiquette : catégorie, famille, acteur, à vérifier ou inconnue.",
                "normalized_label": "Forme normalisée de l'étiquette originale.",
                "alt_category_labels": "Catégories supplémentaires éventuelles.",
            }
            description_fr = descriptions_fr[name]
        elif name == "file_entropy":
            family = "Entropy"
            description = "Global Shannon entropy of the file, in the range [0, 8]."
            family_fr = "Entropie"
            description_fr = "Entropie de Shannon globale du fichier, comprise entre 0 et 8."
        elif name.startswith("bh_"):
            bin_id = int(name.split("_")[1])
            family = "Byte histogram"
            description = f"Normalized frequency of byte value {bin_id} (0x{bin_id:02X})."
            family_fr = "Histogramme des octets"
            description_fr = f"Fréquence normalisée de la valeur d'octet {bin_id} (0x{bin_id:02X})."
        elif name.startswith("beh_"):
            bin_id = int(name.split("_")[1])
            family = "Entropy histogram"
            description = f"Normalized entropy-histogram bin {bin_id}."
            family_fr = "Histogramme d'entropie"
            description_fr = f"Fréquence normalisée de la classe d'histogramme d'entropie {bin_id}."
        else:
            family = "Other"
            description = "Feature from the byte-level static analysis block."
            family_fr = "Autre"
            description_fr = "Caractéristique issue de l'analyse statique au niveau des octets."
        rows.append((index, name, family, description))
        rows_fr.append((index, name, family_fr, description_fr))

    with OUT_CSV.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.writer(handle)
        writer.writerow(["index", "feature", "family", "description"])
        writer.writerows(rows)

    lines = [
        r"% Requires: \usepackage{longtable,booktabs}",
        r"\begin{longtable}{rllp{7.0cm}}",
        r"\caption{Complete byte\_features feature catalog.}\label{tab:byte_features_full}\\",
        r"\toprule",
        r"\textbf{Index} & \textbf{Feature} & \textbf{Family} & \textbf{Description}\\",
        r"\midrule",
        r"\endfirsthead",
        r"\toprule",
        r"\textbf{Index} & \textbf{Feature} & \textbf{Family} & \textbf{Description}\\",
        r"\midrule",
        r"\endhead",
    ]
    for index, name, family, description in rows:
        lines.append(f"{index} & \\texttt{{{latex(name)}}} & {latex(family)} & {latex(description)}\\\\")
    lines.extend([r"\bottomrule", r"\end{longtable}", ""])
    OUT_TEX.write_text("\n".join(lines), encoding="utf-8")
    print(f"wrote {OUT_CSV} ({len(rows)} rows)")
    print(f"wrote {OUT_TEX} ({len(rows)} rows)")

    with OUT_CSV_FR.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.writer(handle)
        writer.writerow(["index", "colonne", "famille", "explication"])
        writer.writerows(rows_fr)

    lines_fr = [
        r"% Requires: \usepackage{longtable,booktabs}",
        r"\begin{longtable}{rllp{7.0cm}}",
        r"\caption{Explication des 521 colonnes de byte\_features.}\label{tab:byte_features_explanations_fr}\\",
        r"\toprule",
        r"\textbf{No.} & \textbf{Colonne} & \textbf{Famille} & \textbf{Explication}\\",
        r"\midrule",
        r"\endfirsthead",
        r"\toprule",
        r"\textbf{No.} & \textbf{Colonne} & \textbf{Famille} & \textbf{Explication}\\",
        r"\midrule",
        r"\endhead",
    ]
    for index, name, family, description in rows_fr:
        lines_fr.append(f"{index} & \\texttt{{{latex(name)}}} & {latex(family)} & {latex(description)}\\\\")
    lines_fr.extend([r"\bottomrule", r"\end{longtable}", ""])
    OUT_TEX_FR.write_text("\n".join(lines_fr), encoding="utf-8")
    print(f"wrote {OUT_CSV_FR} ({len(rows_fr)} rows)")
    print(f"wrote {OUT_TEX_FR} ({len(rows_fr)} rows)")


if __name__ == "__main__":
    main()
