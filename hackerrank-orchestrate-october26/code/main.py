"""Main runner for Ghost Data Still Exists deletion audit agent."""
import csv
import json
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).parent))
from auditor import Auditor
from evidence_indexer import EvidenceIndexer
from identity_resolver import IdentityResolver

ROOT = Path(__file__).resolve().parent.parent
DATASET = ROOT / "dataset"


def case_sort_key(cid: str):
    parts = cid.split("_")
    if len(parts) == 2 and parts[1].isdigit():
        return (parts[0], int(parts[1]))
    return (cid, 0)


def build_auditor(dataset_dir=DATASET):
    res = IdentityResolver(dataset_dir / "user_identities.csv", dataset_dir / "user_audit_log.csv")
    idx = EvidenceIndexer(dataset_dir)
    return Auditor(str(dataset_dir), res, idx)


def run(requests_csv=DATASET / "deletion_requests.csv", out_csv=ROOT / "output.csv", dataset_dir=DATASET):
    aud = build_auditor(dataset_dir)
    rows = []

    with open(requests_csv, newline="", encoding="utf-8") as f:
        for case in csv.DictReader(f):
            status, steps = aud.audit(case)
            rows.append((case["case_id"], status, json.dumps(steps, ensure_ascii=False)))

    rows.sort(key=lambda r: case_sort_key(r[0]))

    with open(out_csv, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["case_id", "deletion_status", "steps_json"])
        w.writerows(rows)

    return rows


if __name__ == "__main__":
    req_file = DATASET / "deletion_requests.csv"
    out_file = ROOT / "output.csv"
    print(f"Auditing cases from {req_file}...")
    res_rows = run(req_file, out_file)
    print(f"Successfully generated {len(res_rows)} rows in {out_file}")
