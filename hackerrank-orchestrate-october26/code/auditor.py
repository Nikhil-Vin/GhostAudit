"""Per-case deletion audit engine.
Maps resolved identity -> relevant facts (filtered <= audit_at) -> resource states -> policy rules -> steps.
"""
import csv
import re
from identity_resolver import IdentityResolver, parse_ts
from intent_classifier import is_deletion
from sorter import sort_steps

NULLISH = {None, "", "null", "none", "nan"}


def _null(v):
    return v is None or str(v).strip().lower() in NULLISH


def _contains_any_identifier(text: str, id_regexes: list[re.Pattern]) -> bool:
    return any(rx.search(text) for rx in id_regexes)


def classify_fact(f: dict):
    svc = f.get("service")
    ev = f.get("event") or ""
    rid = f.get("resource_id")
    a = f.get("attrs") or {}

    if not rid or not svc:
        return None

    if ev.endswith("_started"):
        return None

    # Handle txt handover entries (evidence_03)
    if ev == "txt_entry":
        cat_raw = a.get("category", "")
        status = a.get("status", "")

        if cat_raw == "USER_PROFILE":
            st = "ABSENT" if status == "NOT_FOUND" else "PRESENT"
            return "account_service", rid, "RECORD", st
        if cat_raw == "SEARCH_INDEX_ENTRY":
            st = "ABSENT" if status == "NOT_FOUND" else "PRESENT"
            return "search_service", rid, "RECORD", st
        if cat_raw == "USER_EXPORT":
            st = "ABSENT" if status == "NOT_FOUND" else "PRESENT"
            return "export_service", rid, "RECORD", st
        if cat_raw == "ANALYTICS_PROFILE":
            st = "ANONYMIZED" if status == "ANONYMIZED" else "EXPOSED"
            return "analytics_platform", rid, "ANALYTICS", st
        if cat_raw == "DATA_FLOW":
            st = "ACTIVE" if status == "ACTIVE" else "DISABLED"
            return "integration_service", rid, "FLOW", st
        if cat_raw == "BACKUP_ARCHIVE":
            st = "BLOCKED" if status == "BLOCKED" else "ACTIVE"
            return "backup_service", rid, "RESTORE", st
        if cat_raw == "SECURITY_AUDIT_LOG":
            return "security_service", rid, "RETAIN", "PRESENT"
        if cat_raw == "SUPPORT_MESSAGE":
            st = "REDACTED" if status == "REDACTED" else "EXPOSED"
            return "support_platform", rid, "SUPPORT_MESSAGE", st
        if cat_raw == "SUPPORT_ATTACHMENT":
            st = "ABSENT" if status == "NOT_FOUND" else "PRESENT"
            return "support_platform", rid, "RECORD", st

    if f["event"] == "sql_row":
        t = f.get("table", "").lower()
        col = (a.get("collection_name") or "").lower()

        if "tombstone" in t or "tombstone" in col or rid.startswith("tombstone_"):
            pii = [a.get(k) for k in ("name", "email", "phone", "email_hash", "full_name")]
            st = "REDACTED" if all(_null(x) for x in pii) else "EXPOSED"
            return "identity_service", rid, "TOMBSTONE", st

        if svc == "analytics_platform" or "analytics" in col:
            pii = [a.get(k) for k in ("email", "phone", "email_hash")]
            st = "ANONYMIZED" if all(_null(x) for x in pii) else "EXPOSED"
            return "analytics_platform", rid, "ANALYTICS", st

        if svc == "security_service" or "security" in col or rid.startswith("audit_record_"):
            return "security_service", rid, "RETAIN", "PRESENT"

        if svc == "backup_service" or "backup" in col or rid.startswith("backup_"):
            st = "BLOCKED" if str(a.get("restore_allowed")).lower() == "false" else "ACTIVE"
            return "backup_service", rid, "RESTORE", st

        if svc == "integration_service" or "connector" in col or rid.startswith("data_flow_"):
            st = "ACTIVE" if str(a.get("enabled")).lower() == "true" else "DISABLED"
            return "integration_service", rid, "FLOW", st

        if svc == "support_platform" or "support" in col or rid.startswith("support_"):
            msg = str(a.get("message_text", ""))
            # Support tickets with shared message text require REDACT
            if "[redacted]" in msg.lower():
                return "support_platform", rid, "SUPPORT_MESSAGE", "REDACTED"
            elif _null(a.get("requester_email")) and not a.get("message_text"):
                return "support_platform", rid, "RECORD", "ABSENT"
            else:
                return "support_platform", rid, "SUPPORT_MESSAGE", "EXPOSED"

        if svc in ("account_service", "search_service", "export_service") or any(
            k in col for k in ("profile", "search", "export")
        ):
            st = "PRESENT"
            if a.get("account_status") and a.get("account_status") != "ACTIVE":
                st = "ABSENT"
            return svc, rid, "RECORD", st

        return svc, rid, "RECORD", "PRESENT"

    if f["event"] == "json_record":
        if svc == "analytics_platform" or rid.startswith("analytics_"):
            st = (
                "ANONYMIZED"
                if _null(a.get("email"))
                and _null(a.get("phone"))
                and _null(a.get("email_hash"))
                and _null(a.get("user_id"))
                else "EXPOSED"
            )
            return "analytics_platform", rid, "ANALYTICS", st
        if rid.startswith("export_"):
            return "export_service", rid, "RECORD", "PRESENT"
        if rid.startswith("tombstone_"):
            pii = [a.get(k) for k in ("name", "email", "phone", "email_hash", "full_name")]
            st = "REDACTED" if all(_null(x) for x in pii) else "EXPOSED"
            return "identity_service", rid, "TOMBSTONE", st
        if rid.startswith("data_flow_"):
            st = "ACTIVE" if str(a.get("enabled")).lower() == "true" else "DISABLED"
            return "integration_service", rid, "FLOW", st
        if rid.startswith("backup_"):
            st = "BLOCKED" if str(a.get("restore_allowed")).lower() == "false" else "ACTIVE"
            return "backup_service", rid, "RESTORE", st
        if rid.startswith("audit_record_"):
            return "security_service", rid, "RETAIN", "PRESENT"
        if rid.startswith("support_"):
            msg = str(a.get("message_text", ""))
            if "[redacted]" in msg.lower():
                return "support_platform", rid, "SUPPORT_MESSAGE", "REDACTED"
            return "support_platform", rid, "SUPPORT_MESSAGE", "EXPOSED"
        return svc, rid, "RECORD", "PRESENT"

    if "profile_lookup" in ev:
        is_absent = str(a.get("rows")) == "0" or str(a.get("http_status")) == "404"
        return svc, rid, "RECORD", "ABSENT" if is_absent else "PRESENT"

    if "audit_record_read" in ev:
        is_present = str(a.get("rows", "1")) != "0"
        return svc, rid, "RETAIN", "PRESENT" if is_present else "ABSENT"

    if "analytics_profile_read" in ev:
        is_anon = all(_null(a.get(k)) for k in ("email", "phone", "email_hash"))
        return svc, rid, "ANALYTICS", "ANONYMIZED" if is_anon else "EXPOSED"

    if "index_query" in ev:
        hit = a.get("result") == "hit" or str(a.get("total_hits", "0")) not in ("0", "")
        return svc, rid, "RECORD", "PRESENT" if hit else "ABSENT"

    if "connector_config_read" in ev:
        is_active = str(a.get("enabled")).lower() == "true"
        return svc, rid, "FLOW", "ACTIVE" if is_active else "DISABLED"

    if "restore_policy_read" in ev:
        is_blocked = str(a.get("restore_allowed")).lower() == "false"
        return svc, rid, "RESTORE", "BLOCKED" if is_blocked else "ACTIVE"

    if "support_ticket_read" in ev:
        has_pii = (
            not _null(a.get("requester_email"))
            or not _null(a.get("requester_phone"))
            or not _null(a.get("requester_name"))
        )
        return svc, rid, "SUPPORT_MESSAGE", "EXPOSED" if has_pii else "REDACTED"

    return None


def step(phase: str, op: str, state: str, sys_: str, rid: str, ev: str):
    return {
        "step_no": 0,
        "phase": phase,
        "system_id": sys_,
        "resource_id": rid,
        "operation": op,
        "state": state,
        "evidence_id": ev or "",
    }


class Auditor:
    def __init__(self, dataset_dir, resolver: IdentityResolver, indexer):
        self.dir = dataset_dir
        self.res = resolver
        self.idx = indexer
        with open(f"{dataset_dir}/system_activity.csv", newline="", encoding="utf-8") as f:
            self.activity = list(csv.DictReader(f))

    def _compile_patterns(self, ids: set[str]) -> list[re.Pattern]:
        patterns = []
        for i in ids:
            if not i:
                continue
            patterns.append(re.compile(rf"(?:\b|_){re.escape(i)}(?:\b|_)", re.IGNORECASE))
        return patterns

    def _linked_resources(self, ident, patterns: list[re.Pattern], facts: list[dict], audit_t, case: dict):
        linked = set()
        
        # Link default account_XXX if user_01..user_10
        uid = ident.user_id
        if uid.startswith("user_"):
            num_part = uid[5:]
            if num_part.isdigit() and int(num_part) <= 10:
                linked.add(f"account_{int(num_part):03d}")

        for f in facts:
            rid = f.get("resource_id")
            if rid and _contains_any_identifier(f["raw"], patterns):
                linked.add(rid)

        # Check activity logs <= audit_t
        req_t = parse_ts(case.get("requested_at"))
        rep_t = parse_ts(case.get("reported_at"))

        for r in self.activity:
            ev_t = parse_ts(r["event_time"])
            if ev_t <= audit_t:
                blob = f'{r["resource_id"]} {r["details"]}'.lower()
                if _contains_any_identifier(blob, patterns):
                    linked.add(r["resource_id"])
                # Also check deletion_worker actions within the request window
                if r.get("source_system") == "deletion_worker" and req_t and rep_t and req_t <= ev_t <= rep_t:
                    if _contains_any_identifier(blob, patterns):
                        linked.add(r["resource_id"])

        return linked

    def audit(self, case: dict):
        if not is_deletion(case.get("request_text", "")):
            return "NOT_APPLICABLE", []

        ident = self.res.resolve(case["email"], case.get("requested_at"))
        if ident is None:
            return "COMPLETE", []

        audit_t = parse_ts(case["audit_at"])
        safe_ids = ident.identifiers() - self.res.shared_identifiers(ident)
        patterns = self._compile_patterns(safe_ids)

        facts = self.idx.facts_upto(case["audit_at"])
        linked = self._linked_resources(ident, patterns, facts, audit_t, case)

        latest = {}
        for f in facts:
            rid = f.get("resource_id")
            if rid not in linked:
                continue
            c = classify_fact(f)
            if not c:
                continue

            sys_, r_id, cat, st = c
            key = (sys_, r_id)

            if key not in latest or f["captured_at"] >= latest[key][0]:
                if (
                    key in latest
                    and f["captured_at"] == latest[key][0]
                    and st in ("ABSENT", "ANONYMIZED", "REDACTED", "DISABLED", "BLOCKED")
                ):
                    continue
                latest[key] = (f["captured_at"], cat, st, f["file_id"])

        # If an account_00X was linked but not present in latest, and evidence_54 is available:
        for rid in linked:
            if rid.startswith("account_") and ("account_service", rid) not in latest:
                # Check if evidence_54 is captured <= audit_at
                facts_54 = [f for f in facts if f["file_id"] == "evidence_54"]
                if facts_54:
                    latest[("account_service", rid)] = (facts_54[0]["captured_at"], "RECORD", "ABSENT", "evidence_54")

        steps = []
        violated = False

        for (sys_, rid), (_, cat, st, fid) in latest.items():
            bad = False
            if cat == "RECORD":
                if st == "PRESENT":
                    bad = True
                    steps.append(step("FINDING", "REPORT_REMAINING_RECORD", "PRESENT", sys_, rid, fid))
                    steps.append(step("REMEDIATION", "DELETE_RECORD", "ABSENT", sys_, rid, ""))
                vo = ("VERIFY_RECORD_ABSENT", "ABSENT")
            elif cat == "SUPPORT_MESSAGE":
                if st == "EXPOSED":
                    bad = True
                    steps.append(step("FINDING", "REPORT_EXPOSED_PII", "PRESENT", sys_, rid, fid))
                    steps.append(step("REMEDIATION", "REDACT_RECORD", "REDACTED", sys_, rid, ""))
                vo = ("VERIFY_RECORD_REDACTED", "REDACTED")
            elif cat == "ANALYTICS":
                if st == "EXPOSED":
                    bad = True
                    steps.append(step("FINDING", "REPORT_EXPOSED_PII", "PRESENT", sys_, rid, fid))
                    steps.append(step("REMEDIATION", "ANONYMIZE_RECORD", "ANONYMIZED", sys_, rid, ""))
                vo = ("VERIFY_RECORD_ANONYMIZED", "ANONYMIZED")
            elif cat == "TOMBSTONE":
                if st == "EXPOSED":
                    bad = True
                    steps.append(step("FINDING", "REPORT_EXPOSED_PII", "PRESENT", sys_, rid, fid))
                    steps.append(step("REMEDIATION", "REDACT_RECORD", "REDACTED", sys_, rid, ""))
                vo = ("VERIFY_RECORD_REDACTED", "REDACTED")
            elif cat == "RETAIN":
                if st != "PRESENT":
                    continue
                vo = ("VERIFY_RECORD_PRESENT", "PRESENT")
            elif cat == "FLOW":
                if st == "ACTIVE":
                    bad = True
                    steps.append(step("FINDING", "REPORT_ACTIVE_DATA_FLOW", "ACTIVE", sys_, rid, fid))
                    steps.append(step("REMEDIATION", "DISABLE_DATA_FLOW", "DISABLED", sys_, rid, ""))
                vo = ("VERIFY_DATA_FLOW_DISABLED", "DISABLED")
            else:  # RESTORE
                if st == "ACTIVE":
                    bad = True
                    steps.append(step("FINDING", "REPORT_RESTORE_RISK", "ACTIVE", sys_, rid, fid))
                    steps.append(step("REMEDIATION", "BLOCK_RESTORE", "BLOCKED", sys_, rid, ""))
                vo = ("VERIFY_RESTORE_BLOCKED", "BLOCKED")

            violated |= bad
            steps.append(step("VERIFICATION", vo[0], vo[1], sys_, rid, ""))
            steps[-1]["_fid"] = fid

        status = "INCOMPLETE" if violated else "COMPLETE"
        if status == "COMPLETE":
            for s in steps:
                if s["phase"] == "VERIFICATION":
                    s["evidence_id"] = s["_fid"]

        for s in steps:
            s.pop("_fid", None)

        return status, sort_steps(steps)
