
import pandas as pd
import os

# Configuration
INPUT_FILE = "../data/output/error_nfts.csv"
OUTPUT_EXACT = "../data/errors_analysis/error_analysis_report_latest.csv"
OUTPUT_SUMMARY = "../data/errors_analysis/error_analysis_summary_latest.csv"


def analyze():
    try:
        df = pd.read_csv(INPUT_FILE)
    except FileNotFoundError:
        print(f"Error: {INPUT_FILE} not found.")
        return

    total = df['error'].notna().sum()
    if total == 0:
        print("No errors found in the file.")
        return

    # --- Exact report ---
    error_counts = df['error'].value_counts()
    exact_df = pd.DataFrame({
        'ERROR_TYPE': error_counts.index,
        'COUNT': error_counts.values,
        'PERCENTAGE': (error_counts.values / total * 100).round(2).astype(str) + '%'
    })

    # --- Summary: group by the prefix tag before the first colon ---
    df['category'] = df['error'].dropna().apply(
        lambda e: e.split(':')[0].strip()
    )
    summary_counts = df['category'].value_counts()
    summary_df = pd.DataFrame({
        'CATEGORY': summary_counts.index,
        'COUNT': summary_counts.values,
        'PERCENTAGE': (summary_counts.values / total * 100).round(2).astype(str) + '%'
    })

    print(f"Analyzing {INPUT_FILE} — {total} errors across {len(df)} rows\n")
    print("=== SUMMARY (by error tag) ===")
    print(summary_df.to_string(index=False))
    print(
        f"\n=== EXACT (by unique error string) — {len(exact_df)} distinct errors ===")
    print(exact_df.to_string(index=False))

    os.makedirs(os.path.dirname(OUTPUT_EXACT), exist_ok=True)
    exact_df.to_csv(OUTPUT_EXACT, index=False)
    summary_df.to_csv(OUTPUT_SUMMARY, index=False)
    print(f"\n✅ Exact report:   {OUTPUT_EXACT}")
    print(f"✅ Summary report: {OUTPUT_SUMMARY}")


if __name__ == "__main__":
    analyze()
