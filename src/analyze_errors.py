import re
import pandas as pd
import os

# Configuration
INPUT_FILE = "../data/output/error_nfts.csv"
OUTPUT_EXACT = "../data/errors_analysis/error_analysis_report_latest.csv"
OUTPUT_SUMMARY = "../data/errors_analysis/error_analysis_summary_latest.csv"


def categorise(err: str) -> str:
    if 'No URI found' in err:              return 'No URI found'
    if 'True Negative' in err:             return 'Dead contract'
    if '429' in err:                       return 'Rate limited (429)'
    if 'NameResolution' in err:            return 'DNS failure (dead domain)'
    if '404' in err:                       return '404 Not Found'
    if 'HTML instead of JSON' in err:      return 'Server returned HTML'
    if 'empty body' in err:                return 'Empty body (HTTP 200)'
    if 'Invalid URI' in err:               return 'Invalid URI'
    if 'On-Chain Parse Error' in err:      return 'On-Chain Parse Error'
    if 'JSON parse failed' in err:         return 'JSON parse failed'
    if '403' in err:                       return '403 Forbidden'
    if 'timed out' in err:                 return 'Timeout'
    if re.search(r'[^0-9][45]\d\d[^0-9]', err): return 'Server error (4xx/5xx)'
    return 'Other'


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

    # --- Exact report (one row per unique error string) ---
    error_counts = df['error'].value_counts()
    exact_df = pd.DataFrame({
        'ERROR_TYPE': error_counts.index,
        'COUNT': error_counts.values,
        'PERCENTAGE': (error_counts.values / total * 100).round(2).astype(str) + '%'
    })

    # --- Summary report (grouped by category) ---
    df['category'] = df['error'].dropna().apply(categorise)
    summary_counts = df['category'].value_counts()
    summary_df = pd.DataFrame({
        'CATEGORY': summary_counts.index,
        'COUNT': summary_counts.values,
        'PERCENTAGE': (summary_counts.values / total * 100).round(2).astype(str) + '%'
    })

    # --- Print both ---
    print(f"Analyzing {INPUT_FILE} — {total} errors across {len(df)} rows\n")
    print("=== SUMMARY (by category) ===")
    print(summary_df.to_string(index=False))
    print(f"\n=== EXACT (by unique error string) — {len(exact_df)} distinct errors ===")
    print(exact_df.head(30).to_string(index=False))
    if len(exact_df) > 30:
        print(f"  ... and {len(exact_df) - 30} more (see {OUTPUT_EXACT})")

    # --- Save both ---
    os.makedirs(os.path.dirname(OUTPUT_EXACT), exist_ok=True)
    exact_df.to_csv(OUTPUT_EXACT, index=False)
    summary_df.to_csv(OUTPUT_SUMMARY, index=False)
    print(f"\n✅ Exact report:   {OUTPUT_EXACT}")
    print(f"✅ Summary report: {OUTPUT_SUMMARY}")


if __name__ == "__main__":
    analyze()
