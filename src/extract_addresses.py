import pandas as pd
import os

# Point this to the original dataset where you first found these URIs
ORIGINAL_CSV = "../data/output/success_nfts.csv"

# The new, fixed output file
OUTPUT_CSV = "../data/output/token_uris_with_addresses_success.csv"


def main():
    print(f"Loading {ORIGINAL_CSV}...")
    try:
        df = pd.read_csv(ORIGINAL_CSV, on_bad_lines='skip', low_memory=False)
    except FileNotFoundError:
        print(f"Error: Could not find {ORIGINAL_CSV}. Please check the path.")
        return

    df.columns = df.columns.str.strip()  # Clean headers just in case

    # FIXED: The raw dataset uses 'extracted_urls' for the links!
    uri_col = 'token_uri'

    if 'address' in df.columns and uri_col in df.columns:
        print("Columns found! Extracting...")

        # 1. Extract just the two columns
        extracted_df = df[['address', uri_col]].copy()

        # 2. Drop rows where the URI is completely blank or missing
        extracted_df = extracted_df.dropna(subset=[uri_col])
        extracted_df = extracted_df[extracted_df[uri_col].astype(
            str).str.strip() != '']

        # 3. Rename the column to 'token_uri' for consistency in your output
        extracted_df.rename(columns={uri_col: 'token_uri'}, inplace=True)

        os.makedirs(os.path.dirname(OUTPUT_CSV), exist_ok=True)
        extracted_df.to_csv(OUTPUT_CSV, index=False)

        print(
            f"✅ Successfully extracted {len(extracted_df)} URIs perfectly paired with their addresses!")
        print(f"Saved to {OUTPUT_CSV}")
    else:
        print(
            f"Error: Could not find 'address' or '{uri_col}' columns in {ORIGINAL_CSV}")
        print("Available columns are:", list(df.columns))


if __name__ == "__main__":
    main()
