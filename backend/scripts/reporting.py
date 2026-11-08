"""Small helpers shared by the scripts that write reports/."""

import pandas as pd

# Required by the dataset authors (https://zenodo.org/records/8339691, CC BY 4.0: attribution required).
DATASET_CITATION = (
    "Dataset: [Phishing Email Curated Datasets](https://zenodo.org/records/8339691), "
    "licensed under CC BY 4.0. Please cite:\n\n"
    '1. A. I. Champa, M. F. Rabbi, and M. F. Zibran, "Why phishing emails escape detection: '
    'A closer look at the failure points," in *12th International Symposium on Digital Forensics '
    "and Security (ISDFS)*, 2024, pp. 1–6.\n"
    '2. A. I. Champa, M. F. Rabbi, and M. F. Zibran, "Curated datasets and feature analysis for '
    'phishing email detection with machine learning," in *3rd IEEE International Conference on '
    "Computing and Machine Intelligence (ICMI)*, 2024, pp. 1–7.\n"
)


def markdown_table(df: pd.DataFrame, float_format: str = "{:.4f}") -> str:
    """Render a DataFrame as a Markdown table (avoids the extra tabulate dependency)."""

    def fmt(value) -> str:
        if isinstance(value, float):
            return "n/a" if pd.isna(value) else float_format.format(value)
        return str(value)

    header = [str(df.index.name or "")] + [str(c) for c in df.columns]
    rows = [[str(i)] + [fmt(v) for v in row] for i, row in zip(df.index, df.itertuples(index=False), strict=True)]
    lines = [header, ["---"] * len(header), *rows]
    return "\n".join("| " + " | ".join(line) + " |" for line in lines)
