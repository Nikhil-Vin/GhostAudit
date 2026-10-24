# Token Usage & Cost Report

## 1. Run Summary
- **Pipeline Architecture**: Deterministic Multi-modal Engine & Rule Engine (Python 3)
- **Model Providers / Names**: None (Fully deterministic rule & indexer pipeline)
- **Total Model Calls**: 0
- **Total Input Tokens**: 0
- **Total Output Tokens**: 0
- **Average Tokens per Request**: 0
- **Total Estimated Cost**: $0.00

## 2. Rationale & Efficiency
The deterministic pipeline parses SQLite-compatible SQL snapshots, JSON bundles, and structured logs directly with zero external latency and zero token cost, guaranteeing reproducible results and instant verification.