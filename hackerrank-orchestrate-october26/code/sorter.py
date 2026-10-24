"""Deterministic sorter and validator for audit steps.
Enforces problem statement phase, operation, system_id, and resource_id order.
"""

PHASE_ORDER = {"FINDING": 1, "REMEDIATION": 2, "VERIFICATION": 3}

_OPS = [
    # Phase 1: FINDING
    ("FINDING", "REPORT_REMAINING_RECORD", "PRESENT"),
    ("FINDING", "REPORT_EXPOSED_PII", "PRESENT"),
    ("FINDING", "REPORT_ACTIVE_DATA_FLOW", "ACTIVE"),
    ("FINDING", "REPORT_RESTORE_RISK", "ACTIVE"),
    # Phase 2: REMEDIATION
    ("REMEDIATION", "DISABLE_DATA_FLOW", "DISABLED"),
    ("REMEDIATION", "BLOCK_RESTORE", "BLOCKED"),
    ("REMEDIATION", "DELETE_RECORD", "ABSENT"),
    ("REMEDIATION", "REDACT_RECORD", "REDACTED"),
    ("REMEDIATION", "ANONYMIZE_RECORD", "ANONYMIZED"),
    # Phase 3: VERIFICATION
    ("VERIFICATION", "VERIFY_RECORD_ABSENT", "ABSENT"),
    ("VERIFICATION", "VERIFY_RECORD_PRESENT", "PRESENT"),
    ("VERIFICATION", "VERIFY_RECORD_REDACTED", "REDACTED"),
    ("VERIFICATION", "VERIFY_RECORD_ANONYMIZED", "ANONYMIZED"),
    ("VERIFICATION", "VERIFY_DATA_FLOW_DISABLED", "DISABLED"),
    ("VERIFICATION", "VERIFY_RESTORE_BLOCKED", "BLOCKED"),
]

OP_ORDER = {op: idx for idx, (_, op, _) in enumerate(_OPS, 1)}
OP_RULES = {op: (ph, st) for ph, op, st in _OPS}


def validate_step(s: dict) -> None:
    op = s.get("operation")
    if op not in OP_RULES:
        raise ValueError(f"Unknown operation: {op}")
    expected_phase, expected_state = OP_RULES[op]
    if s.get("phase") != expected_phase:
        raise ValueError(f"Operation {op} must be in phase {expected_phase}, got {s.get('phase')}")
    if s.get("state") != expected_state:
        raise ValueError(f"Operation {op} must have state {expected_state}, got {s.get('state')}")


def sort_steps(steps: list[dict]) -> list[dict]:
    """Deduplicates, validates, and sorts steps deterministically."""
    seen = set()
    unique = []
    for s in steps:
        k = (s["phase"], s["operation"], s["system_id"], s["resource_id"])
        if k in seen:
            continue
        seen.add(k)
        validate_step(s)
        unique.append(s)

    unique.sort(
        key=lambda s: (
            PHASE_ORDER[s["phase"]],
            OP_ORDER[s["operation"]],
            s["system_id"],
            s["resource_id"],
        )
    )

    for idx, s in enumerate(unique, 1):
        s["step_no"] = idx

    return unique
