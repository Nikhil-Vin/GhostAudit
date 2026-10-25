"""Per-case deletion audit engine.
Maps resolved identity -> relevant facts (filtered <= audit_at) -> resource states -> policy rules -> steps.
"""
import csv
import re
from datetime import timedelta
from identity_resolver import IdentityResolver, parse_ts
from intent_classifier import is_deletion
from sorter import sort_steps

NULLISH = {None, "", "null", "none", "nan"}
EMAIL_RX = re.compile(r"[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}")
USER_RX = re.compile(r"\buser_\d+\b")
HASH_RX = re.compile(r"\b[0-9a-f]{64}\b")
CHAIN_BEFORE = timedelta(minutes=-80)
CHAIN_AFTER = timedelta(minutes=10)
RESULT_FOR_STATUS = {"COMPLETE": "SUCCESS", "PARTIALLY_COMPLETE": "PARTIAL", "NOT_STARTED": "FAILED"}


def _null(v):
    return v is None or str(v).strip().lower() in NULLISH


def _contains_any_identifier(text: str, id_regexes: list[re.Pattern]) -> bool:
    return any(rx.search(text) for rx in id_regexes)

PREFIX_SYSTEM = {
    "account": "account_service",
    "search": "search_service",
    "analytics": "analytics_platform",
    "support": "support_platform",
    "audit_record": "security_service",
    "backup": "backup_service",
    "data_flow": "integration_service",
    "export": "export_service",
    "tombstone": "identity_service",
}


def system_for(rid: str, fallback):
    """System that owns a resource, derived from the resource_id prefix (log `service=` is unreliable)."""
    for pre, sysid in PREFIX_SYSTEM.items():
        if str(rid).startswith(pre + "_"):
            return sysid
    return fallback


def _truthy(v):
    return str(v).strip().lower() in ("true", "1", "yes", "y", "t")


def category_state(category: str, status: str):
    """Maps a (record_type, result) pair from handover/lookup records onto (category, state)."""
    status = (status or "").upper()
    absent = status in ("NOT_FOUND", "ABSENT", "DELETED")
    if category in ("USER_PROFILE", "SEARCH_INDEX_ENTRY", "USER_EXPORT", "SUPPORT_ATTACHMENT",
                    "MARKETING_PROFILE", "SECONDARY_IDENTIFIER", "CACHE_ENTRY"):
        return "RECORD", "ABSENT" if absent else "PRESENT"
    if category == "ANALYTICS_PROFILE":
        return "ANALYTICS", "ANONYMIZED" if status == "ANONYMIZED" else "EXPOSED"
    if category == "PRODUCT_TELEMETRY":
        return "ANALYTICS", "ANONYMIZED" if status == "ANONYMIZED" else "EXPOSED"
    if category == "DATA_FLOW":
        return "FLOW", "ACTIVE" if status == "ACTIVE" else "DISABLED"
    if category == "BACKUP_ARCHIVE":
        return "RESTORE", "BLOCKED" if status == "BLOCKED" else "ACTIVE"
    if category in ("SECURITY_AUDIT_LOG", "LEGAL_HOLD_RECORD"):
        return "RETAIN", "PRESENT"
    if category in ("SUPPORT_MESSAGE", "EMAIL_DELIVERY_LOG"):
        return "SUPPORT_MESSAGE", "REDACTED" if status == "REDACTED" else "EXPOSED"
    if category == "ACCOUNT_TOMBSTONE":
        return "TOMBSTONE", "REDACTED" if status == "REDACTED" else "EXPOSED"
    return None


def _present(v):
    return not _null(v)


def classify_record(rid: str, a: dict):
    """Resource state implied by a structured record (JSON export, SQL row), from its fields.

    Returns (category, state) or None when the fields say nothing about deletion state.
    """
    pre = re.sub(r"_\d+$", "", str(rid))

    # generic typed lookups: {record_type, result}
    if a.get("record_type") and a.get("result") is not None:
        return category_state(a["record_type"], a["result"])

    if pre == "account":
        if "status_code" in a:
            return "RECORD", "ABSENT" if str(a["status_code"]) == "404" or _null(a.get("profile")) else "PRESENT"
        if a.get("account_status"):
            return "RECORD", "PRESENT" if str(a["account_status"]).upper() == "ACTIVE" else "ABSENT"
        return "RECORD", "PRESENT"
    if pre == "analytics":
        keys = ("email", "phone", "email_hash", "customer_reference", "user_id")
        if not any(k in a for k in keys):
            return None
        return "ANALYTICS", "EXPOSED" if any(_present(a.get(k)) for k in keys) else "ANONYMIZED"
    if pre == "backup":
        if "restore_allowed" not in a:
            return None
        return "RESTORE", "ACTIVE" if _truthy(a["restore_allowed"]) else "BLOCKED"
    if pre == "data_flow":
        if "enabled" not in a:
            return None
        return "FLOW", "ACTIVE" if _truthy(a["enabled"]) else "DISABLED"
    if pre == "export":
        if "download_available" in a:
            return "RECORD", "PRESENT" if _truthy(a["download_available"]) else "ABSENT"
        return "RECORD", "PRESENT"
    if pre == "search":
        if "hits" in a:
            return "RECORD", "PRESENT" if str(a["hits"]) not in ("0", "", "None", "[]") else "ABSENT"
        return "RECORD", "PRESENT"
    if pre == "audit_record":
        return "RETAIN", "PRESENT"
    if pre == "tombstone":
        pii = ("name", "full_name", "email", "phone", "email_hash")
        return "TOMBSTONE", "EXPOSED" if any(_present(a.get(k)) for k in pii) else "REDACTED"
    if pre == "support":
        if "requester_email" in a or "requester_name" in a or "requester_phone" in a:
            exposed = any(_present(a.get(k)) for k in ("requester_email", "requester_name", "requester_phone"))
            return "SUPPORT_MESSAGE", "EXPOSED" if exposed else "REDACTED"
        if "message_text" in a:
            return "SUPPORT_MESSAGE", "REDACTED" if "[redacted]" in str(a["message_text"]).lower() else "EXPOSED"
        if "file_name" in a or "storage_class" in a:
            return "RECORD", "PRESENT"
    return None


def classify_log_event(ev: str, rid: str, a: dict):
    """Resource state implied by one operational log event (any log dialect).

    Returns (system_id, resource_id, category, state) or None when the event says nothing
    about whether the resource is present, exposed, active or protected.
    """
    sysid = system_for(rid, a.get("service"))

    if ev == "record_lookup":
        cs = category_state(a.get("record_type", ""), a.get("result", ""))
        return (sysid, rid, cs[0], cs[1]) if cs else None

    # account profile / search index presence
    if ev == "profile_lookup_completed":
        gone = str(a.get("rows")) == "0" or str(a.get("http_status")) == "404"
        return sysid, rid, "RECORD", "ABSENT" if gone else "PRESENT"
    if ev == "index_query_completed":
        hit = a.get("result") == "hit" or str(a.get("total_hits", "0")) not in ("0", "")
        return sysid, rid, "RECORD", "PRESENT" if hit else "ABSENT"

    # exports, marketing contact profiles
    if ev in ("export_download_check_completed", "export_metadata_read_completed"):
        return sysid, rid, "RECORD", "PRESENT" if _truthy(a.get("available")) else "ABSENT"
    if ev == "contact_lookup_completed" and str(rid).startswith("analytics_"):
        return sysid, rid, "RECORD", "PRESENT" if str(a.get("rows", "1")) != "0" else "ABSENT"
    if ev == "contact_query_completed" and str(rid).startswith("support_"):
        return sysid, rid, "RECORD", "PRESENT" if str(a.get("rows", "1")) != "0" else "ABSENT"

    # analytics exposure
    if ev == "analytics_identity_scan":
        return sysid, rid, "ANALYTICS", "EXPOSED"
    if ev.startswith("analytics_profile_read") and "direct_identifiers" in a:
        return sysid, rid, "ANALYTICS", "EXPOSED" if str(a.get("direct_identifiers")) not in ("0", "") else "ANONYMIZED"

    # support content
    if ev == "message_pii_scan":
        return sysid, rid, "SUPPORT_MESSAGE", "EXPOSED"
    if ev == "attachment_pii_scan":
        return sysid, rid, "RECORD", "PRESENT"
    if ev == "message_read":
        red = "[redacted]" in str(a.get("message_text", "")).lower()
        return sysid, rid, "SUPPORT_MESSAGE", "REDACTED" if red else "EXPOSED"

    # documents (PDF): an attachment or retained audit extract that names the resource
    if ev == "pdf_document":
        if str(rid).startswith("support_"):
            return sysid, rid, "RECORD", "PRESENT"
        if str(rid).startswith("audit_record_"):
            return sysid, rid, "RETAIN", "PRESENT"
        return None

    # restore paths
    if ev == "restore_candidate_evaluated":
        open_ = _truthy(a.get("eligible")) and not _truthy(a.get("deletion_block"))
        return sysid, rid, "RESTORE", "ACTIVE" if open_ else "BLOCKED"
    if ev == "restore_authorization_completed":
        return sysid, rid, "RESTORE", "BLOCKED" if str(a.get("decision")).lower() == "deny" else "ACTIVE"

    # data flows
    if ev in ("connector_heartbeat", "connector_config_loaded"):
        live = _truthy(a.get("enabled")) or _truthy(a.get("scheduler_registered"))
        return sysid, rid, "FLOW", "ACTIVE" if live else "DISABLED"

    return None


def classify_fact(f: dict):
    ev = f.get("event") or ""
    rid = f.get("resource_id")
    svc = f.get("service") or (system_for(rid, None) if rid else None)
    a = f.get("attrs") or {}

    if not rid or not svc:
        return None

    if ev.endswith("_started"):
        return None

    # Handover text entries
    if ev == "txt_entry":
        cs = category_state(a.get("category", ""), a.get("status", ""))
        if cs:
            return system_for(rid, svc), rid, cs[0], cs[1]

    if ev not in ("sql_row", "json_record", "txt_entry"):
        logged = classify_log_event(ev, rid, dict(a, service=svc))
        if logged:
            return logged

    if ev in ("json_record", "sql_row"):
        rec = classify_record(rid, a)
        if rec:
            return system_for(rid, svc), rid, rec[0], rec[1]

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
        self._owner_cache = None
        with open(f"{dataset_dir}/system_activity.csv", newline="", encoding="utf-8") as f:
            self.activity = list(csv.DictReader(f))

    def _compile_patterns(self, ids: set[str]) -> list[re.Pattern]:
        patterns = []
        for i in ids:
            if not i:
                continue
            patterns.append(re.compile(rf"(?:\b|_){re.escape(i)}(?:\b|_)", re.IGNORECASE))
        return patterns

    def _owners(self):
        """resource_id -> user_ids named beside it anywhere in the evidence (any capture time).

        A resource id never changes, so an identifier printed next to it in a later export still
        ties it to that user; only the *state* of the resource is time-bound by audit_at.
        """
        if self._owner_cache is None:
            owners = {}
            for f in self.idx.facts_upto("9999-12-31T00:00:00Z"):
                rid = f.get("resource_id")
                if not rid:
                    continue
                raw = f["raw"]
                uids = set()
                for e in EMAIL_RX.findall(raw):
                    holders = self.res.email_to_uids.get(e, set())
                    if len(holders) == 1:
                        uids |= holders
                for u in USER_RX.findall(raw):
                    if u in self.res.users:
                        uids.add(u)
                for h in HASH_RX.findall(raw):
                    hs = self.res.hash_to_uids.get(h, set())
                    if len(hs) == 1:
                        uids |= hs
                if uids:
                    owners.setdefault(rid, set()).update(uids)
            self._owner_cache = owners
        return self._owner_cache

    def _linked_resources(self, ident, patterns: list[re.Pattern], facts: list[dict], audit_t, case: dict):
        linked = set()
        for f in facts:
            rid = f.get("resource_id")
            if rid and _contains_any_identifier(f["raw"], patterns):
                linked.add(rid)

        req_t = parse_ts(case.get("requested_at"))
        rep_t = parse_ts(case.get("reported_at"))

        # Activity rows whose text names one of the user's identifiers
        for r in self.activity:
            ev_t = parse_ts(r["event_time"])
            if ev_t <= audit_t and req_t <= ev_t:
                blob = f'{r["resource_id"]} {r["details"]}'.lower()
                if _contains_any_identifier(blob, patterns):
                    linked.add(r["resource_id"])

        # The primary-account deletion is the one step every request goes through, and the worker
        # log records it without naming a user. When no identifier has claimed an account, attach
        # the unclaimed account deletion that sits just before the workflow's report. Among several
        # candidates prefer the one whose recorded result mirrors the workflow's reported_status
        # (never guess when that still leaves more than one).
        if "account" not in {self._prefix(r) for r in linked} and rep_t:
            owners = self._owners()
            cands = []
            for r in self.activity:
                if r.get("source_system") != "deletion_worker" or r["event_type"] != "DELETE_RECORD":
                    continue
                rid = r["resource_id"]
                if self._prefix(rid) != "account":
                    continue
                ev_t = parse_ts(r["event_time"])
                if not (CHAIN_BEFORE <= (ev_t - rep_t) <= CHAIN_AFTER) or ev_t > audit_t:
                    continue
                holders = owners.get(rid, set())
                if holders and ident.user_id not in holders:
                    continue
                cands.append((rid, r["reported_result"]))
            want = RESULT_FOR_STATUS.get(case.get("reported_status"))
            matching = [c for c in cands if c[1] == want] or cands
            ids = {c[0] for c in matching}
            if len(ids) == 1:
                linked |= ids
        return linked

    @staticmethod
    def _prefix(rid: str) -> str:
        return re.sub(r"_\d+$", "", str(rid))

    def audit(self, case: dict):
        if not is_deletion(case.get("request_text", "")):
            return "NOT_APPLICABLE", []

        ident = self.res.resolve(case["email"], case.get("requested_at"))
        if ident is None:
            return "COMPLETE", []

        audit_t = parse_ts(case["audit_at"])
        safe_ids = ident.identifiers() - self.res.shared_identifiers(ident)
        patterns = self._compile_patterns(safe_ids)

        # Deletion state is judged from readbacks made after the request; earlier observations
        # describe the pre-deletion world and must not create findings or verification steps.
        requested_t = parse_ts(case.get("requested_at"))

        def seen(f):
            return f.get("ts") or f["captured_at"]

        link_facts = [f for f in self.idx.facts_upto("9999-12-31T00:00:00Z") if requested_t is None or seen(f) >= requested_t]
        facts = [f for f in link_facts if seen(f) <= audit_t and f["captured_at"] <= audit_t]
        linked = self._linked_resources(ident, patterns, link_facts, audit_t, case)

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
            seen_at = f.get("ts") or f["captured_at"]

            if key not in latest or seen_at >= latest[key][0]:
                if (
                    key in latest
                    and seen_at == latest[key][0]
                    and st in ("ABSENT", "ANONYMIZED", "REDACTED", "DISABLED", "BLOCKED")
                ):
                    continue
                latest[key] = (seen_at, cat, st, f["file_id"])

        # A linked primary account or retained audit record that no readback inside the audit window
        # mentions still needs its required end state verified. The account is cited against the
        # latest profile-table snapshot in the window (its absence from that snapshot is the proof).
        snapshot = None
        for f in facts:
            if f.get("event") == "sql_row" and "profile" in f.get("table", "").lower():
                if snapshot is None or f["captured_at"] > snapshot[0]:
                    snapshot = (f["captured_at"], f["file_id"])
        for rid in sorted(linked):
            if rid.startswith("account_") and ("account_service", rid) not in latest:
                latest[("account_service", rid)] = (
                    snapshot[0] if snapshot else audit_t, "RECORD", "ABSENT", snapshot[1] if snapshot else "")
            elif rid.startswith("audit_record_") and ("security_service", rid) not in latest:
                latest[("security_service", rid)] = (audit_t, "RETAIN", "PRESENT", "")

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
