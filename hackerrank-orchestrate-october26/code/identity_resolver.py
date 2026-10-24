"""Identity resolver: maps current & historical identifiers into an alias graph."""
import csv
from dataclasses import dataclass, field
from datetime import datetime, timezone
import hashlib


def sha256_email(e: str) -> str:
    return hashlib.sha256(e.strip().lower().encode("utf-8")).hexdigest()


def parse_ts(s):
    if not s:
        return None
    raw = str(s).strip()
    if "T" not in raw and " " in raw:
        raw = raw.replace(" ", "T", 1)
    raw = raw.replace("Z", "+00:00")
    d = datetime.fromisoformat(raw)
    return d if d.tzinfo else d.replace(tzinfo=timezone.utc)


@dataclass
class Identity:
    user_id: str
    names: set = field(default_factory=set)
    emails: set = field(default_factory=set)
    phones: set = field(default_factory=set)
    hashes: set = field(default_factory=set)
    audit_ids: list = field(default_factory=list)

    def identifiers(self) -> set[str]:
        """All unique lowercase identifiers belonging to this user."""
        res = {self.user_id.lower()}
        res.update({e.lower() for e in self.emails if e})
        res.update({p.lower() for p in self.phones if p})
        res.update({h.lower() for h in self.hashes if h})
        return res


class IdentityResolver:
    def __init__(self, identities_csv, audit_csv):
        self.users: dict[str, Identity] = {}
        self.email_to_uids: dict[str, set[str]] = {}

        # 1. Ingest current snapshot
        with open(identities_csv, newline="", encoding="utf-8") as f:
            for r in csv.DictReader(f):
                uid = r["user_id"].strip()
                ident = self.users.setdefault(uid, Identity(uid))
                self._email(ident, r.get("email"))
                self._phone(ident, r.get("phone"))
                if r.get("name"):
                    ident.names.add(r["name"].strip())
                if r.get("email_hash"):
                    ident.hashes.add(r["email_hash"].strip().lower())

        # 2. Ingest historical audit log (ordered by event_time)
        with open(audit_csv, newline="", encoding="utf-8") as f:
            self.audit = sorted(csv.DictReader(f), key=lambda r: r["event_time"])

        for r in self.audit:
            uid = r.get("user_id", "").strip()
            ident = self.users.setdefault(uid, Identity(uid))
            if r.get("audit_id"):
                ident.audit_ids.append(r["audit_id"].strip())

            fld = (r.get("field_name") or "").strip().lower()
            for v in (r.get("old_value"), r.get("new_value")):
                if not v:
                    continue
                v_clean = v.strip()
                if fld == "email":
                    self._email(ident, v_clean)
                elif fld == "email_hash":
                    ident.hashes.add(v_clean.lower())
                elif fld == "phone":
                    self._phone(ident, v_clean)
                elif fld == "name":
                    ident.names.add(v_clean)

    def _email(self, ident: Identity, e: str | None):
        if not e:
            return
        clean = e.strip().lower()
        ident.emails.add(clean)
        ident.hashes.add(sha256_email(clean))
        self.email_to_uids.setdefault(clean, set()).add(ident.user_id)

    def _phone(self, ident: Identity, p: str | None):
        if p:
            ident.phones.add(p.strip())

    def _held_at(self, uid: str, email: str, t) -> bool | None:
        """Checks if user uid held email at time t by replaying the audit log."""
        held = None
        for r in self.audit:
            if r["user_id"] != uid or (r.get("field_name") or "").lower() != "email":
                continue
            if t and parse_ts(r["event_time"]) > t:
                break
            if (r.get("new_value") or "").strip().lower() == email:
                held = True
            elif (r.get("old_value") or "").strip().lower() == email:
                held = False
        return held

    def resolve(self, email: str, at=None) -> Identity | None:
        e = email.strip().lower()
        uids = sorted(self.email_to_uids.get(e, ()))
        if not uids:
            return None
        if len(uids) > 1:
            t = parse_ts(at) if at else None
            holders = [u for u in uids if self._held_at(u, e, t)]
            if holders:
                return self.users[holders[0]]
        return self.users[uids[0]]

    def shared_identifiers(self, ident: Identity) -> set[str]:
        """Identifiers shared across reassignments."""
        shared = set()
        for e in ident.emails:
            if len(self.email_to_uids.get(e, ())) > 1:
                shared.add(e)
                shared.add(sha256_email(e))
        return shared
