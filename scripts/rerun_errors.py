import pandas as pd
import os

output_csv = "data/output/nft_metadata.csv"
input_csv = "/home/leyla/blockchain-phishing/data/nft_tokens.csv"  # your original input

output = pd.read_csv(output_csv)
original = pd.read_csv(input_csv)

# Get addresses that have errors
error_addrs = output[output["error"].notna()]["address"]

# Pull those rows from the original input (preserves all original columns)
retry_df = original[original["address"].str.lower().isin(
    error_addrs.str.lower())]

os.makedirs("data/input", exist_ok=True)
retry_df.to_csv("data/input/retry_errors.csv", index=False)
print(f"Wrote {len(retry_df)} rows to data/input/retry_errors.csv")
    