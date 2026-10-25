# Evaluation Report — Ghost Data Still Exists

All numbers below are produced by `python3 code/evaluation/main.py` (no hand-entered results).

## 1. Public sample benchmark (32 cases vs `dataset/sample_output.csv`)

| Metric | Result |
|---|---|
| Case-level deletion-status accuracy | 32/32 (100.0%) |
| Step-level precision (distinct phase/operation/system/resource keys) | 180/180 (100.0%) |
| Step-level recall | 180/193 (93.3%) |
| Cases with exactly the right step set | 21/32 (65.6%) |
| Sequence accuracy: ordered key list identical | 21/32 (65.6%) |
| Sequence accuracy: LCS ratio over ordered keys | 180/193 (93.3%) |
| Cases whose whole row matches exactly (status + all step fields) | 20/32 (62.5%) |

Field-level accuracy over steps whose key was found in the gold row:

| Field | Correct |
|---|---|
| `step_no` | 160/180 (88.9%) |
| `phase` | 180/180 (100.0%) |
| `system_id` | 180/180 (100.0%) |
| `resource_id` | 180/180 (100.0%) |
| `operation` | 180/180 (100.0%) |
| `state` | 180/180 (100.0%) |
| `evidence_id` | 179/180 (99.4%) |

## 2. Additional participant-written cases (executed)

Each case builds a small synthetic dataset (fictional person `user_900`, same file formats as `dataset/`) and asserts status, ordered steps and, where noted, evidence ids.

| Case | Scenario | Result | Status | Steps |
|---|---|---|---|---|
| C1 leftover search entry | Account deleted but a search-index document still holds the email. | PASS | INCOMPLETE | 4 |
| C2 recreation risks | Enabled connector and restorable backup must be disabled/blocked and re-verified. | PASS | INCOMPLETE | 7 |
| C3 clean deletion | Everything already absent: COMPLETE, verification steps only. | PASS | COMPLETE | 2 |
| C4 evidence after audit_at | A later snapshot showing leftovers is ignored. | PASS | COMPLETE | 2 |
| C5.0 non-deletion request | Could you send me a copy of the information held on my accou | PASS | NOT_APPLICABLE | 0 |
| C5.1 non-deletion request | Please change the email address used for this account. I wan | PASS | NOT_APPLICABLE | 0 |
| C5.2 non-deletion request | Please remove me from marketing lists only. I still want ser | PASS | NOT_APPLICABLE | 0 |
| C6.0 multilingual deletion | Je demande la suppression définitive du compte associé à cet | PASS | INCOMPLETE | 4 |
| C6.1 multilingual deletion | Solicito a exclusão permanente da conta associada a este e-m | PASS | INCOMPLETE | 4 |
| C6.2 multilingual deletion | Por favor, borren mi cuenta y mis datos personales. | PASS | INCOMPLETE | 4 |

10/10 custom assertions passed.

## 3. Full dataset run (`output.csv`)

518 rows; status counts {'COMPLETE': 162, 'INCOMPLETE': 346, 'NOT_APPLICABLE': 10}; 2999 steps in total. There is no gold for these cases, so this is a structural summary, not an accuracy figure.

## 4. Failures found and improvements made

- Request-intent: the first classifier let boilerplate such as "handle any copies" or Portuguese "cópia" outweigh an explicit deletion cue, and ignored preservation phrases ("I am not asking for deletion", "leave the account active"). Preservation cues are now checked first, then explicit delete cues, then non-delete topics; all 10 non-deletion requests in the evaluation file are detected.
- Log dialects (key=value, JSON lines, bracketed, pipe, syslog) are normalized and correlated by trace id, because the identifier often appears only on the `*_started` line while the resource id is on the `*_completed` line.
- State is judged only from read-backs between `requested_at` and `audit_at`; stale pre-request lookups and post-`audit_at` files no longer create findings or citations.
- Verification of a linked account and of retained audit records is emitted even when no read-back names them.
- PDF evidence is parsed with `pdftotext`; screenshots (images) are not OCR-parsed.

## 5. Remaining mismatches on the public sample

- `case_03`: gold=COMPLETE pred=COMPLETE; steps gold=3 pred=2; missing=[('VERIFICATION', 'VERIFY_RECORD_ANONYMIZED', 'analytics_platform', 'analytics_9406')]; extra=[]
- `case_04`: gold=COMPLETE pred=COMPLETE; steps gold=2 pred=0; missing=[('VERIFICATION', 'VERIFY_RECORD_ABSENT', 'account_service', 'account_004'), ('VERIFICATION', 'VERIFY_RECORD_ANONYMIZED', 'analytics_platform', 'analytics_901')]; extra=[]
- `case_18`: gold=INCOMPLETE pred=INCOMPLETE; steps gold=14 pred=13; missing=[('VERIFICATION', 'VERIFY_RECORD_PRESENT', 'security_service', 'audit_record_6645')]; extra=[]
- `case_20`: gold=INCOMPLETE pred=INCOMPLETE; steps gold=8 pred=7; missing=[('VERIFICATION', 'VERIFY_RECORD_PRESENT', 'security_service', 'audit_record_5569')]; extra=[]
- `case_21`: gold=COMPLETE pred=COMPLETE; steps gold=3 pred=2; missing=[('VERIFICATION', 'VERIFY_RECORD_ANONYMIZED', 'analytics_platform', 'analytics_5335')]; extra=[]
- `case_23`: gold=INCOMPLETE pred=INCOMPLETE; steps gold=8 pred=7; missing=[('VERIFICATION', 'VERIFY_RECORD_ABSENT', 'account_service', 'account_410')]; extra=[]
- `case_25`: gold=COMPLETE pred=COMPLETE; steps gold=3 pred=2; missing=[('VERIFICATION', 'VERIFY_RECORD_ANONYMIZED', 'analytics_platform', 'analytics_1895')]; extra=[]
- `case_26`: gold=COMPLETE pred=COMPLETE; steps gold=6 pred=5; missing=[('VERIFICATION', 'VERIFY_RECORD_ANONYMIZED', 'analytics_platform', 'analytics_4566')]; extra=[]
- `case_27`: gold=COMPLETE pred=COMPLETE; steps gold=6 pred=5; missing=[('VERIFICATION', 'VERIFY_RECORD_ANONYMIZED', 'analytics_platform', 'analytics_4574')]; extra=[]
- `case_28`: gold=COMPLETE pred=COMPLETE; steps gold=6 pred=4; missing=[('VERIFICATION', 'VERIFY_RECORD_ABSENT', 'account_service', 'account_5482'), ('VERIFICATION', 'VERIFY_RECORD_ANONYMIZED', 'analytics_platform', 'analytics_6077')]; extra=[]
- `case_29`: gold=INCOMPLETE pred=INCOMPLETE; steps gold=14 pred=13; missing=[('VERIFICATION', 'VERIFY_RECORD_ABSENT', 'account_service', 'account_7012')]; extra=[]

## 6. Known limitations

- Some gold resources (e.g. a retained audit record or an analytics record) are not tied to the person by any participant-visible identifier; the agent does not guess these, so they appear as missing steps.
- When several candidate resources share the same `reported_at` and none carries an identifier, the link is ambiguous and is skipped rather than guessed.
- Legal-hold records and image-only evidence are not modelled.
- Two evaluation cases (`case_61`, `case_63`) resolve to COMPLETE with no steps because no resource could be linked.
