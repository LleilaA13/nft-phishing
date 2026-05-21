#!/usr/bin/env python3
import argparse
import csv
import json
import sys
from collections import Counter

DEFAULT_COLS = ["scam_type", "error", "error_class"]


def parse_args():
    p = argparse.ArgumentParser(
        description="Count and list error types from a CSV export.")
    p.add_argument("csv", nargs="?", default="data/output/nft_full_rerun.csv",
                   help="Path to the CSV file")
    p.add_argument("--cols", nargs="+", default=DEFAULT_COLS,
                   help="Columns to aggregate (defaults: scam_type,error,error_class)")
    p.add_argument("--out", help="Write JSON summary to this file")
    p.add_argument("--top", type=int, default=200,
                   help="Show top N values per column (0 = show all)")
    return p.parse_args()


def main():
    args = parse_args()
    counters = {col: Counter() for col in args.cols}

    try:
        with open(args.csv, newline="", encoding="utf-8") as fh:
            reader = csv.DictReader(fh)
            headers = reader.fieldnames or []
            missing = [c for c in args.cols if c not in headers]
            if missing:
                print("Warning: the following requested columns are missing from the CSV:", ", ".join(
                    missing), file=sys.stderr)

            for row in reader:
                for col in args.cols:
                    if col not in row:
                        continue
                    val = (row[col] or "").strip()
                    if val:
                        counters[col][val] += 1
    except FileNotFoundError:
        print(f"CSV not found: {args.csv}", file=sys.stderr)
        sys.exit(2)

    # Print summary to stdout
    for col in args.cols:
        print(f"\n== {col} ==")
        counter = counters.get(col)
        if not counter:
            print("(no values)")
            continue
        limit = args.top
        items = counter.most_common() if limit == 0 else counter.most_common(limit)
        for val, cnt in items:
            print(f"{cnt}\t{val}")

    # Optionally write JSON
    if args.out:
        outdata = {col: dict(counters[col]) for col in args.cols}
        with open(args.out, "w", encoding="utf-8") as of:
            json.dump(outdata, of, indent=2, ensure_ascii=False)
        print(f"\nWrote JSON summary to {args.out}")


if __name__ == "__main__":
    main()
