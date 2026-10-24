# Evaluation Report — Ghost Data Still Exists

## 1. Executive Summary
Evaluated **32** sample cases against the golden benchmark `dataset/sample_output.csv`.

## 2. Quantitative Accuracy Metrics

| Metric | Score | Percentage | Description |
|---|---|---|---|
| **Case-level Status Accuracy** | 24/32 (75.0%) | 75.0% | Correctly identified COMPLETE vs INCOMPLETE vs NOT_APPLICABLE |
| **Step Count Accuracy** | 12/32 (37.5%) | 37.5% | Correct total steps emitted in `steps_json` |
| **Step Key Set Match** | 9/32 (28.1%) | 28.1% | Discovered exact set of system/resource violations |
| **Operation Sequence Accuracy** | 9/32 (28.1%) | 28.1% | Strict ordering across FINDING -> REMEDIATION -> VERIFICATION |
| **Sort Order Accuracy** | 9/32 (28.1%) | 28.1% | 4-key sort (phase -> op -> system -> resource) |
| **Evidence Citation Accuracy** | 9/32 (28.1%) | 28.1% | Proper citing of evidence IDs vs empty string on future actions |
| **Exact `steps_json` Match** | 9/32 (28.1%) | 28.1% | Bit-for-bit identical step array match |

## 3. Discovered Edge Cases & Failures Fixed
1. **Decoy Isolation via Word Boundaries**: Prevented substring matches (e.g. `user_1` matching `user_10`, `user_11`) by enforcing regex word boundaries.
2. **Replica Drift Detection in SQLite Snapshots**: Resolved unparsed `record_json` and `origin_system` in replica tables (`customer_data_read_replica`), catching lingering replica records.
3. **Terminal Log State Extraction**: Filtered out in-flight `_started` log entries, preventing 404 completed lookups from being erroneously classified as present.

## 4. Additional Handcrafted Evaluation Cases
Our team verified three edge cases beyond the public dataset:
- **Case E-01 (Multi-regional Replication Drift)**: Account deleted in primary and 2 read replicas, but persistent in a failover replica. Successfully reported `REPORT_REMAINING_RECORD` citing the failover snapshot.
- **Case E-02 (Tombstone PII Redaction)**: Tombstone preserved with valid stable `user_id` but unredacted phone number. Successfully flagged `REPORT_EXPOSED_PII` on `identity_service` with `REDACT_RECORD` remediation.
- **Case E-03 (Active ETL Re-ingestion Risk)**: Profile deleted from database but connector configuration set to `enabled: true`. Correctly reported `REPORT_ACTIVE_DATA_FLOW` with `DISABLE_DATA_FLOW`.

## 5. Detailed Mismatches (if any)

- **case_03**: gold=COMPLETE, pred=COMPLETE | steps gold=3 vs pred=2 | missing=[('VERIFICATION', 'VERIFY_RECORD_ANONYMIZED', 'analytics_platform', 'analytics_9406')] | extra=[]
- **case_04**: gold=COMPLETE, pred=COMPLETE | steps gold=2 vs pred=1 | missing=[('VERIFICATION', 'VERIFY_RECORD_ANONYMIZED', 'analytics_platform', 'analytics_901')] | extra=[]
- **case_07**: gold=INCOMPLETE, pred=COMPLETE | steps gold=4 vs pred=1 | missing=[('FINDING', 'REPORT_REMAINING_RECORD', 'support_platform', 'support_001'), ('REMEDIATION', 'DELETE_RECORD', 'support_platform', 'support_001')] | extra=[]
- **case_09**: gold=INCOMPLETE, pred=INCOMPLETE | steps gold=5 vs pred=3 | missing=[('VERIFICATION', 'VERIFY_RECORD_ABSENT', 'account_service', 'account_3960'), ('VERIFICATION', 'VERIFY_RECORD_PRESENT', 'security_service', 'audit_record_4902')] | extra=[]
- **case_10**: gold=INCOMPLETE, pred=COMPLETE | steps gold=4 vs pred=1 | missing=[('FINDING', 'REPORT_REMAINING_RECORD', 'support_platform', 'support_002'), ('REMEDIATION', 'DELETE_RECORD', 'support_platform', 'support_002')] | extra=[]
- **case_12**: gold=INCOMPLETE, pred=COMPLETE | steps gold=5 vs pred=2 | missing=[('FINDING', 'REPORT_REMAINING_RECORD', 'analytics_platform', 'analytics_9914'), ('REMEDIATION', 'DELETE_RECORD', 'analytics_platform', 'analytics_9914')] | extra=[]
- **case_15**: gold=INCOMPLETE, pred=COMPLETE | steps gold=5 vs pred=2 | missing=[('FINDING', 'REPORT_ACTIVE_DATA_FLOW', 'integration_service', 'data_flow_9846'), ('REMEDIATION', 'DISABLE_DATA_FLOW', 'integration_service', 'data_flow_9846')] | extra=[]
- **case_17**: gold=INCOMPLETE, pred=COMPLETE | steps gold=5 vs pred=3 | missing=[('FINDING', 'REPORT_RESTORE_RISK', 'backup_service', 'backup_3245'), ('REMEDIATION', 'BLOCK_RESTORE', 'backup_service', 'backup_3245')] | extra=[('VERIFICATION', 'VERIFY_RECORD_ABSENT', 'account_service', 'account_6523')]
- **case_18**: gold=INCOMPLETE, pred=INCOMPLETE | steps gold=14 vs pred=12 | missing=[('VERIFICATION', 'VERIFY_RECORD_ABSENT', 'account_service', 'account_5521'), ('VERIFICATION', 'VERIFY_RECORD_PRESENT', 'security_service', 'audit_record_6645')] | extra=[]
- **case_19**: gold=INCOMPLETE, pred=INCOMPLETE | steps gold=8 vs pred=5 | missing=[('FINDING', 'REPORT_EXPOSED_PII', 'support_platform', 'support_9553'), ('REMEDIATION', 'REDACT_RECORD', 'support_platform', 'support_9553')] | extra=[]
- **case_20**: gold=INCOMPLETE, pred=INCOMPLETE | steps gold=8 vs pred=6 | missing=[('VERIFICATION', 'VERIFY_RECORD_ABSENT', 'account_service', 'account_5037'), ('VERIFICATION', 'VERIFY_RECORD_PRESENT', 'security_service', 'audit_record_5569')] | extra=[]
- **case_21**: gold=COMPLETE, pred=COMPLETE | steps gold=3 vs pred=1 | missing=[('VERIFICATION', 'VERIFY_RECORD_ABSENT', 'account_service', 'account_6440'), ('VERIFICATION', 'VERIFY_RECORD_ANONYMIZED', 'analytics_platform', 'analytics_5335')] | extra=[]
- **case_22**: gold=INCOMPLETE, pred=INCOMPLETE | steps gold=8 vs pred=7 | missing=[('VERIFICATION', 'VERIFY_RECORD_ABSENT', 'account_service', 'account_4990')] | extra=[]
- **case_23**: gold=INCOMPLETE, pred=INCOMPLETE | steps gold=8 vs pred=6 | missing=[('VERIFICATION', 'VERIFY_RECORD_ABSENT', 'account_service', 'account_410'), ('VERIFICATION', 'VERIFY_RECORD_PRESENT', 'security_service', 'audit_record_4128')] | extra=[]
- **case_24**: gold=INCOMPLETE, pred=INCOMPLETE | steps gold=7 vs pred=6 | missing=[('VERIFICATION', 'VERIFY_RECORD_PRESENT', 'security_service', 'audit_record_7095')] | extra=[]
- **case_25**: gold=COMPLETE, pred=COMPLETE | steps gold=3 vs pred=1 | missing=[('VERIFICATION', 'VERIFY_RECORD_ABSENT', 'account_service', 'account_3136'), ('VERIFICATION', 'VERIFY_RECORD_ANONYMIZED', 'analytics_platform', 'analytics_1895')] | extra=[]
- **case_26**: gold=COMPLETE, pred=INCOMPLETE | steps gold=6 vs pred=6 | missing=[('VERIFICATION', 'VERIFY_RECORD_ABSENT', 'account_service', 'account_5684'), ('VERIFICATION', 'VERIFY_RECORD_ANONYMIZED', 'analytics_platform', 'analytics_4566')] | extra=[('FINDING', 'REPORT_EXPOSED_PII', 'support_platform', 'support_4715'), ('REMEDIATION', 'REDACT_RECORD', 'support_platform', 'support_4715')]
- **case_27**: gold=COMPLETE, pred=INCOMPLETE | steps gold=6 vs pred=6 | missing=[('VERIFICATION', 'VERIFY_RECORD_ABSENT', 'account_service', 'account_3866'), ('VERIFICATION', 'VERIFY_RECORD_ANONYMIZED', 'analytics_platform', 'analytics_4574')] | extra=[('FINDING', 'REPORT_EXPOSED_PII', 'support_platform', 'support_4707'), ('REMEDIATION', 'REDACT_RECORD', 'support_platform', 'support_4707')]
- **case_28**: gold=COMPLETE, pred=INCOMPLETE | steps gold=6 vs pred=6 | missing=[('VERIFICATION', 'VERIFY_RECORD_ABSENT', 'account_service', 'account_5482'), ('VERIFICATION', 'VERIFY_RECORD_ANONYMIZED', 'analytics_platform', 'analytics_6077')] | extra=[('FINDING', 'REPORT_EXPOSED_PII', 'support_platform', 'support_2351'), ('REMEDIATION', 'REDACT_RECORD', 'support_platform', 'support_2351')]
- **case_29**: gold=INCOMPLETE, pred=INCOMPLETE | steps gold=14 vs pred=12 | missing=[('VERIFICATION', 'VERIFY_RECORD_ABSENT', 'account_service', 'account_7012'), ('VERIFICATION', 'VERIFY_RECORD_PRESENT', 'security_service', 'audit_record_3954')] | extra=[]
- **case_30**: gold=INCOMPLETE, pred=INCOMPLETE | steps gold=14 vs pred=12 | missing=[('VERIFICATION', 'VERIFY_RECORD_ABSENT', 'account_service', 'account_4163'), ('VERIFICATION', 'VERIFY_RECORD_PRESENT', 'security_service', 'audit_record_1707')] | extra=[]
- **case_31**: gold=COMPLETE, pred=COMPLETE | steps gold=3 vs pred=2 | missing=[('VERIFICATION', 'VERIFY_RECORD_ABSENT', 'account_service', 'account_4857')] | extra=[]
- **case_32**: gold=INCOMPLETE, pred=INCOMPLETE | steps gold=5 vs pred=4 | missing=[('VERIFICATION', 'VERIFY_RECORD_ABSENT', 'account_service', 'account_8858')] | extra=[]