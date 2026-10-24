"""Parses evidence files into uniform 'facts'.
Extracts resource states from SQLite snapshot dumps, structured logs (with trace correlation),
pipe-delimited handovers, and JSON bundles.
"""
import csv
import json
from pathlib import Path
import re
import sqlite3
from identity_resolver import parse_ts

KV = re.compile(r'(\w+)=("[^"]*"|\S+)')


def _tbl_service(name: str):
    n = name.lower()
    if "tombstone" in n:
        return "identity_service"
    if "profile" in n or "account" in n:
        return "account_service"
    if "search" in n:
        return "search_service"
    if "analytics" in n:
        return "analytics_platform"
    if "support" in n:
        return "support_platform"
    if "backup" in n:
        return "backup_service"
    if "connector" in n or "integration" in n:
        return "integration_service"
    if "audit" in n or "security" in n:
        return "security_service"
    return None


class EvidenceIndexer:
    def __init__(self, dataset_dir):
        self.root = Path(dataset_dir)
        self.manifest = []
        self._cache = {}

        with open(self.root / "evidence_files.csv", newline="", encoding="utf-8") as f:
            for r in csv.DictReader(f):
                r["_ts"] = parse_ts(r["captured_at"])
                self.manifest.append(r)

    def _path(self, rel: str):
        for p in (self.root / rel, self.root / "evidence" / rel, self.root.parent / rel):
            if p.exists():
                return p
        hits = list(self.root.rglob(Path(rel).name))
        return hits[0] if hits else None

    def facts_upto(self, audit_at: str):
        """Returns all facts from files captured at or before audit_at."""
        t = parse_ts(audit_at)
        out = []
        for m in self.manifest:
            if m["_ts"] and m["_ts"] <= t:
                out.extend(self._facts(m))
        return out

    def _facts(self, m: dict):
        fid = m["file_id"]
        if fid in self._cache:
            return self._cache[fid]

        p = self._path(m["file_path"])
        facts = []
        if p:
            try:
                ext = p.suffix.lower()
                if ext == ".log":
                    facts = self._log(p, m)
                elif ext == ".json":
                    facts = self._json(p, m)
                elif ext == ".sql":
                    facts = self._sql(p, m)
                elif ext == ".txt":
                    facts = self._txt(p, m)
            except Exception as e:
                print(f"[indexer] {p.name}: {e}")

        self._cache[fid] = facts
        return facts

    def _mk(self, m: dict, service: str | None, event: str | None, rid: str | None, attrs: dict, raw: str):
        return {
            "file_id": m["file_id"],
            "captured_at": m["_ts"],
            "service": service,
            "event": event,
            "resource_id": rid,
            "attrs": attrs,
            "raw": raw.lower(),
            "file": m["file_path"],
        }

    def _log(self, p: Path, m: dict):
        lines = p.read_text(encoding="utf-8", errors="ignore").splitlines()
        parsed_lines = []
        trace_to_ids = {}

        # Pass 1: parse each line and build trace_id correlation map
        for line in lines:
            s = line.strip()
            kv = {}
            if "{" in s and s.endswith("}"):
                json_part = s[s.find("{") :]
                try:
                    kv = json.loads(json_part)
                except Exception:
                    kv = {}
            if not kv:
                kv = {k: v.strip('"') for k, v in KV.findall(line)}

            tid = kv.get("trace_id")
            if tid:
                for id_key in ("lookup_key", "subject_ref", "subject_key", "match_key", "correlation_key", "email", "customer_reference"):
                    v = kv.get(id_key)
                    if v and str(v).lower() != "null":
                        trace_to_ids.setdefault(tid, set()).add(str(v).lower())

            parsed_lines.append((line, kv))

        # Pass 2: generate facts, injecting correlated trace identifiers
        out = []
        for line, kv in parsed_lines:
            ev = kv.get("event", "")
            rid = kv.get("resource_id")
            svc = kv.get("service") or kv.get("logger")
            tid = kv.get("trace_id")

            raw_str = line.lower()
            if tid and tid in trace_to_ids:
                raw_str += " " + " ".join(trace_to_ids[tid])

            if rid:
                out.append(self._mk(m, svc, ev, rid, kv, raw_str))
            elif kv:
                out.append(self._mk(m, svc, ev, None, kv, raw_str))

        return out

    def _txt(self, p: Path, m: dict):
        out = []
        for line in p.read_text(encoding="utf-8", errors="ignore").splitlines():
            s = line.strip()
            if s.startswith("- ") and "|" in s:
                parts = [x.strip() for x in s[2:].split("|")]
                if len(parts) >= 6:
                    ts_str, svc, rid, cat, status, ident = parts[:6]
                    attrs = {
                        "category": cat,
                        "status": status,
                        "identifier": ident,
                        "timestamp": ts_str,
                    }
                    raw_str = f"{line.lower()} {ident.lower()} {rid.lower()}"
                    out.append(self._mk(m, svc, "txt_entry", rid, attrs, raw_str))
        if not out:
            raw = p.read_text(encoding="utf-8", errors="ignore")
            out.append(self._mk(m, None, "txt", None, {}, raw))
        return out

    def _json(self, p: Path, m: dict):
        data = json.loads(p.read_text(encoding="utf-8"))
        out = []
        name = p.name.lower()
        default = "analytics_platform" if "analytics" in name else None

        def walk(o, parent_service=None):
            if isinstance(o, dict):
                cur_service = o.get("data_store") or o.get("service") or parent_service or default
                rid = o.get("resource_id") or o.get("ticket_id")
                if rid:
                    svc = cur_service
                    if not svc:
                        r_str = str(rid)
                        if r_str.startswith("account_"):
                            svc = "account_service"
                        elif r_str.startswith("search_"):
                            svc = "search_service"
                        elif r_str.startswith("analytics_"):
                            svc = "analytics_platform"
                        elif r_str.startswith("support_"):
                            svc = "support_platform"
                        elif r_str.startswith("audit_record_"):
                            svc = "security_service"
                        elif r_str.startswith("backup_"):
                            svc = "backup_service"
                        elif r_str.startswith("data_flow_"):
                            svc = "integration_service"
                        elif r_str.startswith("export_"):
                            svc = "export_service"
                        elif r_str.startswith("tombstone_"):
                            svc = "identity_service"
                    out.append(self._mk(m, svc, "json_record", str(rid), o, json.dumps(o)))
                for v in o.values():
                    walk(v, cur_service)
            elif isinstance(o, list):
                for v in o:
                    walk(v, parent_service)

        walk(data)
        if not out:
            out.append(self._mk(m, None, "json_blob", None, {}, json.dumps(data)))
        return out

    def _sql(self, p: Path, m: dict):
        con = sqlite3.connect(":memory:")
        txt = p.read_text(encoding="utf-8", errors="ignore")
        try:
            con.executescript(txt)
        except sqlite3.Error:
            for stmt in re.split(r";\s*\n", txt):
                try:
                    con.execute(stmt)
                except sqlite3.Error:
                    pass

        con.row_factory = sqlite3.Row
        out = []
        tables = [r[0] for r in con.execute("select name from sqlite_master where type='table'").fetchall()]

        for t in tables:
            rows = con.execute(f'select * from "{t}"').fetchall()
            for row in rows:
                d = dict(row)
                rid = d.get("resource_id") or next((str(v) for k, v in d.items() if k.endswith("_id") and v), None)
                svc = d.get("origin_system") or _tbl_service(t)

                attrs = dict(d)
                if "record_json" in d and d["record_json"]:
                    try:
                        rec = json.loads(d["record_json"])
                        if isinstance(rec, dict):
                            attrs.update(rec)
                            rid = rec.get("resource_id") or rid
                    except Exception:
                        pass

                f = self._mk(m, svc, "sql_row", rid, attrs, json.dumps(attrs, default=str))
                f["table"] = t
                out.append(f)

        return out
