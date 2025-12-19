# rules/process_dataset_csv.py

import pandas as pd
import ast
import re
import os
from rules.rule_engine import run_rules, ALL_RULES

def extract_domain(addr: str):
    """
    Extract domain from a sender like:
    "Name" <email@domain.com>
    """
    match = re.search(r"<[^@]+@([^>]+)>", str(addr))
    if match:
        return match.group(1).lower()
    return ""

def build_parsed_email(row):
    """
    Turn one CSV row into the parsed_email dict
    expected by rule_engine.run_rules().
    """
    raw_urls = row.get("urls", "")

    # Try to parse the urls column safely
    urls_list = []
    try:
        # literal_eval will turn "['http://a.com']" into a list,
        # "[]" into [], "0" into int(0), etc.
        parsed = ast.literal_eval(str(raw_urls))
        if isinstance(parsed, list):
            urls_list = parsed
        elif isinstance(parsed, str):
            # single URL as string
            urls_list = [parsed]
        else:
            # int/float/other → treat as no URLs
            urls_list = []
    except Exception:
        # if it’s not valid Python literal, just ignore
        urls_list = []

    # Convert to rule_engine URL format
    urls = [{"href": u, "text": u} for u in urls_list]

    return {
        "from_addr": row.get("sender", ""),
        "from_domain": extract_domain(row.get("sender", "")),
        "reply_to_domain": None,
        "message_id": None,
        "received_headers": [],

        "body_text": row.get("body", ""),
        "html": "",
        "urls": urls,
        "attachments": [],
    }

def process_csv(input_csv, output_csv, threshold=4.0):
    df = pd.read_csv(input_csv)

    # All rule names
    rule_names = [fn.__name__.replace("rule_", "") for fn in ALL_RULES]

    # Prepare new columns
    df["rule_score_total"] = 0.0
    df["rule_pred"] = 0

    for name in rule_names:
        df[f"rule_{name}"] = 0

    # Process each row
    for i, row in df.iterrows():
        parsed = build_parsed_email(row)
        score, flags, results = run_rules(parsed)

        df.at[i, "rule_score_total"] = score
        df.at[i, "rule_pred"] = int(score >= threshold)

        for rule_fn_name, hit in flags.items():
            short_name = rule_fn_name.replace("rule_", "")
            col_name = f"rule_{short_name}"
            if col_name in df.columns:
                df.at[i, col_name] = hit

    # Save processed dataset
    os.makedirs(os.path.dirname(output_csv), exist_ok=True)
    df.to_csv(output_csv, index=False)
    print(f"Saved processed dataset to {output_csv}")

if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument("--threshold", default=4.0, type=float)
    
    args = parser.parse_args()
    process_csv(args.input, args.output, args.threshold)
